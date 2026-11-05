"""DORE Afloat concept demo. Python standard library only; runs with no network.

Rule-based agents brief the watch, run the casualty with them, and write it up after.
No AI model runs here, so nothing depends on a GPU or a connection.

Start it with:  python dore-afloat/server.py
Then open:      http://127.0.0.1:8765
"""
import atexit
import hashlib
import json
import os
import re
import secrets
import sqlite3
import statistics
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from packet_pdf import build_packet
from reasoner import LIBRARY, LIBRARY_TEXT, reason

ROOT = Path(__file__).parent
PACKS = ROOT / "packs"
STATIC = ROOT / "static"
DB_PATH = Path(tempfile.gettempdir()) / "dore-afloat-audit.db"  # Kept out of OneDrive sync.
PORT = 8765
SENSOR_STALE_S = 60
STEP_DUE_BASE_S = 15  # Demo step clock: the first step is due at 30 s, then 15 s more per step.
STEP_DUE_EACH_S = 15
VOICE_COOLDOWN_S = 3  # One spoken command can't fire twice in a row.
VOICE_RELEASE_S = 2.5  # Recognition finishes just after the talk key is released.
VOICE_LATE_S = 8  # A result may arrive this long after release if its speech began during the hold.
VOICE_MIN_SPEECH_S = 0.7  # Shorter sound can't be a whole command.
VOICE_COMMANDS = {"fire", "collision", "overboard", "overboard_port", "overboard_starboard", "done", "repeat",
                  "brief", "summary", "end", "status_boundaries", "status_fuel", "status_ventilation", "status_firemain", "status_lookouts"}
VOICE_TOKEN = secrets.token_hex(16)  # Only the listener this server starts can send commands.

# Policy gate: which roles may do what. Enforced here, never in the browser.
ROLES = {
    "EOOW": {"label": "Engineering Officer of the Watch", "confirm": True},
    "DCA": {"label": "Damage Control Assistant", "confirm": True},
    "OOD": {"label": "Officer of the Deck", "confirm": True},
    "MESSENGER": {"label": "Messenger of the Watch", "confirm": False},
}

sessions = {}  # token -> {"name", "role", "pack"}
incident = {}  # the open incident
counters = {"incident": int(time.time())}  # Unique across restarts, so open screens notice a new casualty.
voice = {"queue": [], "listener": None, "level": 0, "peak": 0, "running": False, "heard": [],
         "armed": False, "armed_at": 0.0, "released_at": 0.0, "armed_until": 0.0, "next_ok": 0.0}  # Heard text stays in memory only.
db = sqlite3.connect(DB_PATH, check_same_thread=False)
state_lock = threading.Lock()  # One request at a time touches shared state.


def now(fmt="%H:%M:%SZ"):
    return datetime.now(timezone.utc).strftime(fmt)


# ---------- Audit log: each entry's hash covers the entry before it ----------
def reset_audit():
    db.execute("DROP TABLE IF EXISTS audit")
    db.execute(
        "CREATE TABLE audit (seq INTEGER PRIMARY KEY, ts TEXT, actor TEXT, role TEXT,"
        " event TEXT, detail TEXT, prev_hash TEXT, hash TEXT)"
    )
    db.commit()


def entry_hash(seq, ts, actor, role, event, detail, prev_hash):
    raw = "|".join([str(seq), ts, actor, role, event, detail, prev_hash])
    return hashlib.sha256(raw.encode()).hexdigest()


def audit(actor, role, event, detail):
    row = db.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
    seq, prev = (row[0] + 1, row[1]) if row else (1, "GENESIS")
    ts = now("%Y-%m-%dT%H:%M:%SZ")
    text = json.dumps(detail, sort_keys=True)
    digest = entry_hash(seq, ts, actor, role, event, text, prev)
    db.execute(
        "INSERT INTO audit VALUES (?,?,?,?,?,?,?,?)",
        (seq, ts, actor, role, event, text, prev, digest),
    )
    db.commit()


def audit_rows():
    cols = ("seq", "ts", "actor", "role", "event", "detail", "prev_hash", "hash")
    rows = db.execute(f"SELECT {','.join(cols)} FROM audit ORDER BY seq").fetchall()
    return [dict(zip(cols, r)) for r in rows]


def verify_audit():
    prev = "GENESIS"
    rows = audit_rows()
    for r in rows:
        expected = entry_hash(
            r["seq"], r["ts"], r["actor"], r["role"], r["event"], r["detail"], prev
        )
        if r["prev_hash"] != prev or r["hash"] != expected:
            return {"ok": False, "entries": len(rows), "broken_at": r["seq"]}
        prev = r["hash"]
    return {"ok": True, "entries": len(rows), "broken_at": None}


# ---------- Ship packs: everything that changes per ship lives here ----------
def normalize(text):
    return re.sub(r"\s+", " ", text).strip().lower()


def load_pack(pack_id):
    folder = PACKS / pack_id
    pack = json.loads((folder / "pack.json").read_text(encoding="utf-8"))
    pack["id"] = pack_id
    pack["documents"]["GEN"] = LIBRARY["document"]
    pack["source_text"] = {
        key: LIBRARY_TEXT if key == "GEN" else (folder / doc["file"]).read_text(encoding="utf-8")
        for key, doc in pack["documents"].items()
    }
    return pack


def list_packs():
    return sorted(p.parent.name for p in PACKS.glob("*/pack.json"))


def citation(pack, doc_key, para, quote):
    doc = pack["documents"][doc_key]
    return {"doc": doc_key, "title": doc["title"], "rev": doc["rev"], "para": para, "quote": quote}


# ---------- The agents ----------
def check_sensors(pack, space_id):
    group = [s for s in pack["sensors"] if s["space"] == space_id]
    middle = statistics.median(s["value"] for s in group) if group else 0
    results = []
    for s in group:
        problems = []
        if s["age_s"] > SENSOR_STALE_S:
            problems.append(f"no update for {s['age_s']} s")
        if abs(s["value"] - middle) > pack["sensor_tolerance"].get(s["unit"], float("inf")):
            problems.append(f"off by {abs(s['value'] - middle):.0f} {s['unit']} from nearby sensors")
        results.append({**s, "trusted": not problems, "problems": problems})
    return results


def unavailable(pack, failed=()):
    """Equipment that can't be used: active tag-outs plus failures during this casualty."""
    down = {t["equipment"]: {**t, "kind": "TAGGED OUT"} for t in pack["tagouts"] if t["status"] == "Active"}
    for equipment in failed:
        down[equipment] = {"id": "FAILED", "equipment": equipment, "reason": "Failed during the casualty",
                           "authorized_by": "Reported by watch", "kind": "FAILED", "rule": None}
    return down


def agent_triage(pack, casualty, understood, report, failed=(), reported_at=None):
    """A1: classify the casualty and pull ship state for this space."""
    needed = {n for a in casualty["actions"] for n in a["needs"]}
    names = {e["id"]: e for e in pack["equipment"]}
    down = unavailable(pack, failed)
    space_id, side = understood["space_id"], understood["side"]
    location = f"{side.capitalize()} side" if side else understood["location"] or "Location unknown"
    tagouts = [
        {"id": down[e]["id"], "equipment": names[e]["name"], "reason": down[e]["reason"],
         "authorized_by": down[e]["authorized_by"], "kind": down[e]["kind"]}
        for e in needed if e in down
    ]
    equipment = [
        {**e, "state": down[e["id"]]["kind"].capitalize() if e["id"] in down else e["state"]}
        for e in pack["equipment"] if e["space"] == space_id or e["id"] in needed
    ]
    return {
        "casualty": casualty["name"],
        "severity": casualty["severity"],
        "location": location,
        "report": report,
        "time": reported_at or now(),
        "equipment": equipment,
        "tagouts": tagouts,
        "sensors": check_sensors(pack, space_id),
        "reasoning": understood["reasoning"],
    }


def agent_actions(pack, casualty, side, failed=()):
    """A2: build the DO NOW list. Every step must quote its source or it is dropped."""
    down = unavailable(pack, failed)
    names = {e["id"]: e["name"] for e in pack["equipment"]}
    verified, dropped = [], []
    for card in casualty["actions"]:
        if normalize(card["quote"]) in normalize(pack["source_text"].get(card["doc"], "")):
            verified.append(card)
        else:
            dropped.append({"id": card["id"], "title": card["title"]})

    blocked_ids = {c["id"] for c in verified if any(n in down for n in c["needs"])}
    fallback_for = {c["only_if_blocked"]: c for c in verified if c.get("only_if_blocked")}

    def replacement(card_id):
        option = fallback_for.get(card_id)
        while option and option["id"] in blocked_ids:
            option = fallback_for.get(option["id"])
        return option

    steps, blocked = [], []
    for card in sorted(verified, key=lambda c: c["rank"]):
        trigger = card.get("only_if_blocked")
        if trigger and trigger not in blocked_ids:
            continue  # A fallback applies only when its primary step is blocked.
        title = card["title"].replace("{side}", side or "reported side")
        cite = citation(pack, card["doc"], card["para"], card["quote"])
        if card["id"] in blocked_ids:
            item = next(down[n] for n in card["needs"] if n in down)
            option = replacement(card["id"])
            rule = item["rule"]
            blocked.append({
                "id": card["id"],
                "title": title,
                "equipment": names[item["equipment"]],
                "kind": item["kind"],
                "tagout": item["id"],
                "reason": item["reason"],
                "use_instead": option["title"] if option else None,
                "citation": citation(pack, rule["doc"], rule["para"], rule["quote"]) if rule else cite,
            })
            continue
        steps.append({"id": card["id"], "title": title, "owner": card["owner"], "citation": cite,
                      "fallback": bool(trigger), "status": card.get("status"), "needs": card["needs"]})
    for number, step in enumerate(steps, 1):
        step["order"] = number
        step["due_s"] = STEP_DUE_BASE_S + STEP_DUE_EACH_S * number
    return {"steps": steps, "blocked": blocked, "dropped": dropped, "verified": len(verified)}


def agent_tasking(actions):
    """A3: turn the steps into an ICS-204 style assignment list, grouped by team."""
    teams = {}
    for step in actions["steps"]:
        teams.setdefault(step["owner"], []).append(
            {"title": step["title"], "ref": f"{step['citation']['doc']} {step['citation']['para']}"}
        )
    return {"teams": [{"station": k, "tasks": v} for k, v in teams.items()]}


def agent_comms(casualty, triage, actions, side):
    """A4: write ready-to-read announcements and reports."""
    lines = [f"{b['equipment']} {b['kind'].lower()}." for b in actions["blocked"]]
    options = list(dict.fromkeys(b["use_instead"] for b in actions["blocked"] if b["use_instead"]))
    status = " ".join(lines + [f"{option}." for option in options])
    fields = {"{location}": triage["location"], "{side}": side or "reported side", "{status}": status}
    messages = []
    for item in casualty["comms"]:
        text = item["text"]
        for key, value in fields.items():
            text = text.replace(key, value)
        messages.append({"channel": item["channel"], "speaker": item["speaker"],
                         "text": re.sub(r"\s+", " ", text).strip()})
    return {"messages": messages}


def agent_records():
    """A5: keep the watch log and the ICS-201 handoff current."""
    if not incident:
        return None
    triage, actions = incident["triage"], incident["actions"]
    done = incident["done"]
    log = [f"{triage['time']}  {triage['casualty']} reported, {triage['location']}."]
    log += [f"{triage['time']}  DORE: {b['equipment']} tagged out ({b['tagout']})." for b in actions["blocked"] if b["kind"] != "FAILED"]
    log += [f"{c['at']}  PLAN CHANGE: {c['note']}" for c in incident["changes"]]
    log += [f"{d['at']}  {d['role']} {d['verb']}: {d['title']}." for d in done]
    if incident["ended"]:
        log.append(f"{incident['ended_at']}  Casualty secured.")
    untrusted = [s["name"] for s in triage["sensors"] if not s["trusted"]]
    return {
        "watch_log": log,
        "ics201": [
            ["Incident", f"{incident['ship']} {triage['casualty']}"],
            ["Time", now("%Y-%m-%d ") + triage["time"]],
            ["Location", f"{incident['ship']}, {triage['location']}"],
            ["Situation", triage["report"]],
            ["Actions complete", "; ".join(d["title"] for d in done) or "None yet"],
            ["Out of service", "; ".join(f"{t['equipment']} ({t['id']})" for t in triage["tagouts"]) or "None"],
            ["Do not trust", "; ".join(untrusted) or "None"],
            ["Prepared by", f"{incident['name']}, {incident['role']}"],
        ],
    }


def agent_debrief():
    """A6: turn the record into a timeline, practice list and casualty report draft."""
    if not incident:
        return None
    triage = incident["triage"]
    done = {d["id"]: d for d in incident["done"]}
    length = incident["ended_s"] if incident["ended"] else round(time.time() - incident["started"])
    rows = []
    for step in incident["actions"]["steps"]:
        record = done.get(step["id"])
        if record:
            result = "Late" if record["elapsed_s"] > step["due_s"] else "On time"
        else:
            result = "Overdue" if length > step["due_s"] else "Open"
        rows.append({"id": step["id"], "order": step["order"], "title": step["title"], "owner": step["owner"], "due_s": step["due_s"],
                     "done_s": record["elapsed_s"] if record else None, "result": result})
    on_time = sum(r["result"] == "On time" for r in rows)
    late = sum(r["result"] == "Late" for r in rows)
    overdue = sum(r["result"] == "Overdue" for r in rows)
    still_open = sum(r["result"] in ("Open", "Overdue") for r in rows)
    # While the casualty is open, a step that isn't due yet isn't a miss.
    judged = len(rows) if incident["ended"] else on_time + late + overdue
    missed = ("Late", "Overdue", "Open") if incident["ended"] else ("Late", "Overdue")
    practice = [f"{r['title']} ({r['owner']})" for r in rows if r["result"] in missed][:3]
    report = [
        ["Ship", incident["ship"]],
        ["Casualty", triage["casualty"]],
        ["Location", triage["location"]],
        ["Reported", triage["time"]],
        ["Duration", f"{length} seconds"],
        ["Cause", "Under investigation"],
        ["Equipment affected", "; ".join(f"{t['equipment']} ({t['kind'].lower()})" for t in triage["tagouts"]) or "None"],
        ["Plan changes", "; ".join(c["note"] for c in incident["changes"]) or "None"],
        ["Actions complete", "; ".join(d["title"] for d in incident["done"]) or "None"],
        ["Actions open", "; ".join(r["title"] for r in rows if r["result"] == "Open") or "None"],
        ["Status", "Secured" if incident["ended"] else "Open"],
    ]
    return {"rows": rows, "on_time": on_time, "late": late, "overdue": overdue, "open": still_open, "total": len(rows),
            "score": round(100 * on_time / judged) if judged else 100, "practice": practice, "length_s": length,
            "drill": incident["drill"], "ended": incident["ended"], "report": report,
            "changes": [c["note"] for c in incident["changes"]], "casualty": triage["casualty"], "location": triage["location"]}


def agent_brief(user):
    """Before the casualty: what tonight's ship state changes in each procedure."""
    pack = load_pack(user["pack"])
    stations = pack["role_stations"].get(user["role"])
    plans = []
    for casualty in pack["casualties"]:
        actions = agent_actions(pack, casualty, None)
        mine = [s for s in actions["steps"] if stations is None or s["owner"] in stations]
        plans.append({
            "casualty": casualty["name"],
            "changes": [{"equipment": b["equipment"], "tagout": b["tagout"], "use_instead": b["use_instead"]} for b in actions["blocked"]],
            "first": mine[0]["title"].replace("reported side", "the reported side") if mine else None,
        })
    distrust = []
    for space_id in {s["space"] for s in pack["sensors"]}:
        distrust += [{"name": s["name"], "problems": s["problems"]} for s in check_sensors(pack, space_id) if not s["trusted"]]
    distrust.sort(key=lambda s: s["name"])
    parts = [f"Watch brief for {user['role']} on {pack['ship']['name']}."]
    for plan in plans:
        for change in plan["changes"]:
            parts.append(f"{plan['casualty']}: {change['equipment']} is down. {change['use_instead'] or 'No substitute'}.")
        if plan["first"]:
            parts.append(f"Your first step: {plan['first']}.")
    for sensor in distrust:
        parts.append(f"Do not trust {sensor['name']}.")
    return {"ship": pack["ship"]["name"], "plans": plans, "distrust": distrust, "speech": " ".join(parts),
            "map": map_view(pack, None, [], unavailable(pack))}


def map_view(pack, space_id, steps, down):
    """What the ship map should show: the space, its boundaries and key equipment."""
    plan = pack.get("map", {"spaces": [], "boundaries": {}})
    boundaries = plan["boundaries"].get(space_id, []) if space_id else []
    use = {n for s in steps if s["fallback"] for n in s["needs"]}
    marks = []
    for e in pack["equipment"]:
        if e["id"] in down:
            marks.append({"space": e["space"], "name": e["name"], "state": "down"})
        elif e["id"] in use:
            marks.append({"space": e["space"], "name": e["name"], "state": "use"})
    spaces = [{**s, "state": "casualty" if s["id"] == space_id else "boundary" if s["id"] in boundaries else "normal"} for s in plan["spaces"]]
    return {"spaces": spaces, "marks": marks}


def payload():
    """Everything a screen needs to show the open incident."""
    if not incident:
        return {"id": 0, "ver": 0}
    keys = ("id", "ver", "drill", "triage", "actions", "tasking", "comms", "timings", "total_ms", "changes", "map")
    injects = [{"id": i["id"], "label": i["label"]} for i in incident["casualty"].get("injects", []) if i["equipment"] not in incident["failed"]]
    return {**{k: incident[k] for k in keys}, "kind": "answer", "records": agent_records(),
            "done": [d["id"] for d in incident["done"]], "done_detail": incident["done"], "ended": incident["ended"], "injects": injects,
            "debrief": agent_debrief() if incident["ended"] else None}


def overdue_steps():
    if not incident or incident["ended"]:
        return []
    elapsed = time.time() - incident["started"]
    done = {d["id"] for d in incident["done"]}
    late = []
    for step in incident["actions"]["steps"]:
        if step["id"] not in done and elapsed > step["due_s"]:
            late.append({"id": step["id"], "title": step["title"], "owner": step["owner"],
                         "late_s": round(elapsed - step["due_s"]),
                         "script": f"{step['owner']}, report status: {step['title']}."})
            if step["id"] not in incident["overdue_logged"]:
                incident["overdue_logged"].append(step["id"])
                audit("DORE", "AGENT", "OVERDUE", {"step": step["id"], "owner": step["owner"]})
    return late


def run_agents(user, report, drill=False):
    pack = load_pack(user["pack"])
    casualty, understood = reason(pack, report)
    if not casualty:
        audit(user["name"], user["role"], "REFUSED", {"report": report})
        return {"kind": "refusal", "message": "No approved procedure found",
                "hint": "DORE answers only from approved documents. State the hazard you see and the space."}
    space_id, side = understood["space_id"], understood["side"]

    timings = {}

    def timed(key, fn, *args):
        start = time.perf_counter()
        result = fn(*args)
        timings[key] = round((time.perf_counter() - start) * 1000, 2)
        audit("DORE", "AGENT", key, {"casualty": casualty["id"]})
        return result

    audit(user["name"], user["role"], "DRILL_REPORT" if drill else "REPORT", {"report": report})
    triage = timed("A1_TRIAGE", agent_triage, pack, casualty, understood, report)
    actions = timed("A2_ACTIONS", agent_actions, pack, casualty, side)
    tasking = timed("A3_TASKING", agent_tasking, actions)
    comms = timed("A4_COMMS", agent_comms, casualty, triage, actions, side)
    counters["incident"] += 1
    incident.clear()
    incident.update({
        "id": counters["incident"], "ver": 1, "drill": bool(drill), "started": time.time(),
        "pack": pack["id"], "ship": pack["ship"]["name"], "casualty": casualty, "understood": understood,
        "space_id": space_id, "side": side, "triage": triage, "actions": actions,
        "tasking": tasking, "comms": comms, "name": user["name"], "role": user["role"],
        "done": [], "failed": [], "changes": [], "overdue_logged": [], "ended": False, "ended_at": None, "ended_s": 0,
        "timings": timings, "total_ms": 0,
        "map": map_view(pack, space_id, actions["steps"], unavailable(pack)),
    })
    timed("A5_RECORDS", agent_records)
    incident["total_ms"] = round(sum(timings.values()), 1)
    return payload()


def replan(user, inject_id):
    """Living plan: something failed, so rerun the agents against the new ship state."""
    if not incident or incident["ended"]:
        return 400, {"error": "No open casualty"}
    pack = load_pack(incident["pack"])
    casualty = incident["casualty"]
    inject = next((i for i in casualty.get("injects", []) if i["id"] == inject_id), None)
    if not inject or inject["equipment"] in incident["failed"]:
        return 400, {"error": "Nothing to change"}
    start = time.perf_counter()
    incident["failed"].append(inject["equipment"])
    failed, side = incident["failed"], incident["side"]
    triage = agent_triage(pack, casualty, incident["understood"], incident["triage"]["report"], failed, incident["triage"]["time"])
    actions = agent_actions(pack, casualty, side, failed)
    incident.update({"triage": triage, "actions": actions, "tasking": agent_tasking(actions),
                     "comms": agent_comms(casualty, triage, actions, side),
                     "map": map_view(pack, incident["space_id"], actions["steps"], unavailable(pack, failed))})
    names = {e["id"]: e["name"] for e in pack["equipment"]}
    option = next((b["use_instead"] for b in actions["blocked"] if b["equipment"] == names[inject["equipment"]]), None)
    note = f"{names[inject['equipment']]} failed. {option or 'No approved substitute'}."
    ms = round((time.perf_counter() - start) * 1000, 2)
    incident["changes"].append({"at": now(), "note": note, "ms": ms})
    incident["ver"] += 1
    audit(user["name"], user["role"], "PLAN_CHANGE", {"failed": inject["equipment"], "note": note, "ms": ms})
    return 200, payload()


def record_step(user, step, verb):
    elapsed = round(time.time() - incident["started"])
    incident["done"].append({"id": step["id"], "title": step["title"], "role": user["role"],
                             "at": now(), "elapsed_s": elapsed, "verb": verb})
    incident["ver"] += 1
    cite = step["citation"]
    audit(user["name"], user["role"], "STEP_DONE" if verb == "completed" else "STATUS_LOGGED", {
        "step": step["id"], "source": f"{cite['title']} {cite['rev']} para {cite['para']}",
    })


def mark_done(user, step_id):
    if incident.get("ended"):
        return 409, {"error": "Casualty is secured"}
    steps = {s["id"]: s for s in incident.get("actions", {}).get("steps", [])}
    if step_id not in steps:
        return 400, {"error": "Unknown step."}
    if not ROLES[user["role"]]["confirm"]:
        audit(user["name"], user["role"], "DENIED", {"step": step_id, "why": "role cannot confirm"})
        return 403, {"error": f"{user['role']} can view but cannot confirm steps"}
    if any(d["id"] == step_id for d in incident["done"]):
        return 409, {"error": "Step already complete"}
    step = steps[step_id]
    allowed = load_pack(user["pack"])["role_stations"].get(user["role"], [])
    if step["owner"] not in allowed:
        audit(user["name"], user["role"], "DENIED", {"step": step_id, "why": "other station"})
        return 403, {"error": f"This step belongs to {step['owner']}"}
    record_step(user, step, "completed")
    return 200, payload()


def log_status(user, key):
    """A report came in from another station. Log it against the matching step."""
    if not incident or incident["ended"]:
        return 400, {"error": "No open casualty"}
    if not ROLES[user["role"]]["confirm"]:
        return 403, {"error": f"{user['role']} can view but cannot log status"}
    finished = {d["id"] for d in incident["done"]}
    step = next((s for s in incident["actions"]["steps"] if s.get("status") == key and s["id"] not in finished), None)
    if not step:
        return 400, {"error": "No open step matches that report"}
    record_step(user, step, f"logged report from {step['owner']}")
    return 200, {**payload(), "logged": step["title"]}


def end_casualty(user):
    if not incident or incident["ended"]:
        return 400, {"error": "No open casualty"}
    if not ROLES[user["role"]]["confirm"]:
        return 403, {"error": f"{user['role']} can view but cannot end the casualty"}
    incident["ended"] = True
    incident["ended_at"] = now()
    incident["ended_s"] = round(time.time() - incident["started"])
    incident["ver"] += 1
    audit("DORE", "AGENT", "A6_DEBRIEF", {"score": agent_debrief()["score"]})
    audit(user["name"], user["role"], "CASUALTY_SECURED", {"seconds": incident["ended_s"]})
    return 200, payload()


# ---------- HTTP ----------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send_bytes(self, status, data, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, status, body):
        self.send_bytes(status, json.dumps(body).encode(), "application/json")

    def user(self):
        return sessions.get(self.headers.get("X-Session", ""))

    def body(self):
        size = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(size) or b"{}")

    def do_GET(self):
        with state_lock:
            self.route_get()

    def do_POST(self):
        body = self.body()  # Read before locking, so a slow client holds nothing.
        with state_lock:
            self.route_post(body)

    def route_get(self):
        path = self.path.split("?")[0]
        font = re.fullmatch(r"/fonts/([A-Za-z0-9.-]+\.(woff2|css))", path)
        if path == "/":
            self.send_bytes(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
        elif font and (STATIC / "fonts" / font[1]).is_file():
            kind = "font/woff2" if font[2] == "woff2" else "text/css"
            self.send_bytes(200, (STATIC / "fonts" / font[1]).read_bytes(), kind)
        elif path == "/api/config":
            packs = []
            for pack_id in list_packs():
                pack = load_pack(pack_id)
                buttons = [{"label": c["button"], "report": c["sample_report"]} for c in pack["casualties"]]
                packs.append({"id": pack_id, **pack["ship"], "buttons": buttons, "role_stations": pack["role_stations"]})
            self.send_json(200, {"packs": packs, "roles": ROLES})
        elif path == "/api/voice/next":
            item = voice["queue"].pop(0) if voice["queue"] else None
            listener = voice["listener"]
            self.send_json(200, {"item": item, "listening": bool(listener and listener.poll() is None),
                                 "level": voice["level"], "peak": voice["peak"], "armed": voice["armed"], "running": voice["running"], "heard": voice["heard"][-10:]})
        elif path == "/api/state":
            if not self.user():
                return self.send_json(401, {"error": "Sign in first."})
            query = parse_qs(urlparse(self.path).query)
            have = (query.get("id", ["0"])[0], query.get("ver", ["0"])[0])
            current = (str(incident.get("id", 0)), str(incident.get("ver", 0)))
            self.send_json(200, {"id": incident.get("id", 0), "ver": incident.get("ver", 0), "overdue": overdue_steps(),
                                 "elapsed": round(time.time() - incident["started"]) if incident else 0,
                                 "full": payload() if have != current else None})
        elif path == "/api/summary":
            user = self.user()
            if not user:
                return self.send_json(401, {"error": "Sign in first."})
            if not incident:
                return self.send_json(400, {"error": "Run a casualty first"})
            audit(user["name"], user["role"], "SUMMARY_VIEWED", {"ended": incident["ended"]})
            self.send_json(200, agent_debrief())
        elif path == "/api/brief":
            user = self.user()
            if not user:
                return self.send_json(401, {"error": "Sign in first."})
            if "log=1" in self.path:
                audit(user["name"], user["role"], "WATCH_BRIEF", {"pack": user["pack"]})
            self.send_json(200, agent_brief(user))
        elif path == "/api/audit":
            self.send_json(200, {"rows": audit_rows(), "verify": verify_audit()})
        elif path == "/api/packet.pdf":
            user = self.user()
            if not user:
                return self.send_json(401, {"error": "Sign in first."})
            if not incident:
                return self.send_json(400, {"error": "Run a casualty first"})
            start = time.perf_counter()
            data = build_packet(incident, agent_records(), verify_audit(), agent_debrief())
            elapsed = round((time.perf_counter() - start) * 1000, 1)
            audit(user["name"], user["role"], "PACKET_PDF", {"bytes": len(data), "ms": elapsed})
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Build-Ms", str(elapsed))
            self.end_headers()
            self.wfile.write(data)
        elif path == "/api/source":
            user = self.user()
            if not user:
                return self.send_json(401, {"error": "Sign in first."})
            doc = self.path.split("doc=")[-1]
            pack = load_pack(user["pack"])
            if doc not in pack["source_text"]:
                return self.send_json(404, {"error": "Unknown document."})
            self.send_json(200, {"text": pack["source_text"][doc]})
        else:
            self.send_json(404, {"error": "Not found."})

    def route_post(self, body):
        path = self.path
        if path == "/api/signin":
            if body.get("role") not in ROLES or body.get("pack") not in list_packs():
                return self.send_json(400, {"error": "Unknown role or ship pack."})
            name = (body.get("name") or "Demo Watchstander").strip()[:40]
            token = secrets.token_hex(16)
            sessions[token] = {"name": name, "role": body["role"], "pack": body["pack"]}
            if incident.get("pack") != body["pack"]:
                incident.clear()  # A role change on the same ship keeps the incident open.
            audit(name, body["role"], "SIGN_IN", {"pack": body["pack"]})
            return self.send_json(200, {"token": token})
        if path == "/api/voice":
            if body.get("token") != VOICE_TOKEN:
                return self.send_json(403, {"error": "Unknown listener."})
            if body.get("command") == "level":
                voice["level"] = int(body.get("confidence", 0))
                voice["peak"] = max(voice["peak"], voice["level"])
                voice["running"] = body.get("phrase") == "running"
            elif body.get("command") == "heard":
                voice["heard"].append({"text": str(body.get("phrase", ""))[:120], "confidence": round(float(body.get("confidence", 0)), 2)})
                del voice["heard"][:-10]
            elif body.get("command") in VOICE_COMMANDS:
                clock = time.time()
                started = float(body.get("started", 0))
                seconds = float(body.get("seconds", 0))
                # Judge by when the speech began, not when recognition finished.
                held_until = clock if voice["armed"] else voice["released_at"]
                talking = voice["armed_at"] - 0.25 <= started <= held_until and clock < held_until + VOICE_LATE_S
                if not talking or seconds < VOICE_MIN_SPEECH_S or clock < voice["next_ok"]:
                    voice["heard"].append({"text": f"blocked {body['command']}", "confidence": round(float(body.get("confidence", 0)), 2),
                                           "talking": talking, "lead_s": round(started - voice["armed_at"], 2), "seconds": round(seconds, 2)})
                    del voice["heard"][:-10]
                    return self.send_json(200, {"ok": True})  # Push-to-talk: all other sound is ignored.
                voice["next_ok"] = clock + VOICE_COOLDOWN_S
                phrase = str(body.get("phrase", "")).replace("door", "DORE", 1)
                confidence = round(float(body.get("confidence", 0)), 2)
                voice["queue"].append({"command": body["command"], "phrase": phrase})
                audit("Voice Listener", "INPUT", "VOICE", {"phrase": phrase, "confidence": confidence})
            return self.send_json(200, {"ok": True, "talk": voice["armed"] or time.time() < voice["armed_until"]})
        if path == "/api/reset":
            sessions.clear()
            incident.clear()
            reset_audit()
            return self.send_json(200, {"ok": True})
        if path == "/api/demo/tamper":
            # Demo only: edits a stored entry so the audit check can be seen failing.
            row = db.execute("SELECT seq FROM audit ORDER BY seq LIMIT 1 OFFSET 1").fetchone()
            if not row:
                return self.send_json(400, {"error": "Not enough entries yet."})
            db.execute("UPDATE audit SET actor = 'Someone Else' WHERE seq = ?", (row[0],))
            db.commit()
            return self.send_json(200, verify_audit())
        user = self.user()
        if not user:
            return self.send_json(401, {"error": "Sign in first."})
        if path == "/api/voice/armed":
            voice["armed"] = bool(body.get("armed"))
            if voice["armed"]:
                voice["armed_at"] = time.time()
                voice["peak"] = 0
                voice["heard"].clear()
                voice["queue"].clear()
            else:
                voice["released_at"] = time.time()
                voice["armed_until"] = voice["released_at"] + VOICE_RELEASE_S
            return self.send_json(200, {"armed": voice["armed"]})
        if path == "/api/report":
            return self.send_json(200, run_agents(user, str(body.get("text", ""))[:500], body.get("drill")))
        if path == "/api/done":
            status, result = mark_done(user, body.get("step"))
            return self.send_json(status, result)
        if path == "/api/inject":
            status, result = replan(user, body.get("inject"))
            return self.send_json(status, result)
        if path == "/api/status":
            status, result = log_status(user, body.get("key"))
            return self.send_json(status, result)
        if path == "/api/end":
            status, result = end_casualty(user)
            return self.send_json(status, result)
        self.send_json(404, {"error": "Not found."})


def start_voice_listener():
    """Start offline voice commands on Windows. The demo still works without them."""
    if os.name != "nt":
        return
    try:
        listener = subprocess.Popen(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
             str(ROOT / "voice_listener.ps1"), "-Port", str(PORT)],
            env={**os.environ, "DORE_VOICE_TOKEN": VOICE_TOKEN},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        voice["listener"] = listener
        atexit.register(listener.terminate)
    except OSError as error:
        print(f"Voice commands unavailable: {error}")


if __name__ == "__main__":
    reset_audit()
    start_voice_listener()
    print(f"DORE Afloat demo running at http://127.0.0.1:{PORT}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
