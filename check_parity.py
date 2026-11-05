"""Checks that the standalone browser engine matches the Python server.

Run this after changing either one:  python dore-afloat/check_parity.py
Needs Node.js. It compares plans, assignments, scripts and re-plans for a set of reports.
"""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))
import build_standalone  # noqa: E402
import server  # noqa: E402

REPORTS = [
    "Fire in crew space, heavy smoke", "Fire in main engine room 1, heavy smoke near the fuel pumps",
    "electrical fire in the galley, one sailor burned", "water coming in fast in the laundry", "flodding in aux 1",
    "smell of smoke in the passageway", "I see smoke", "steam leak in main engine room 2", "fuel leak on the flight deck",
    "blackout, we lost power", "lost steering", "man down in the pump room, ammonia fumes", "fire near the magazine",
    "Collision forward, flooding in the forward pump room", "Man overboard, port side", "Man overboard, starboard side",
    "sparks from the switchboard in the shop", "Flames in diesel engine room 2, space filling with smoke",
    "electrical fire in crew berthing", "How do I fire the gun?", "How do I fix a jammed galley oven?", "What is for dinner?",
    "fire control radar is down for maintenance", "there is no fire in the galley", "we have a fire drill tomorrow",
    "he got fired from the galley", "good morning", "the steam line inspection is done", "where is the fire pump",
]
ROLES = ["EOOW", "DCA", "OOD", "MESSENGER"]


def view(result):
    """The parts of a result that must match. Times and hashes are left out."""
    if result["kind"] != "answer":
        return {"kind": result["kind"], "message": result["message"]}
    triage, actions = result["triage"], result["actions"]
    return {
        "casualty": triage["casualty"], "severity": triage["severity"], "location": triage["location"],
        "reasoning": triage["reasoning"], "tagouts": sorted(t["equipment"] for t in triage["tagouts"]),
        "sensors": [[s["name"], s["trusted"], s["problems"]] for s in triage["sensors"]],
        "steps": [[s["id"], s["title"], s["owner"], s["due_s"], s["citation"]["para"]] for s in actions["steps"]],
        "blocked": [[b["id"], b["equipment"], b["kind"], b["use_instead"]] for b in actions["blocked"]],
        "dropped": [d["title"] for d in actions["dropped"]], "tasking": result["tasking"],
        "comms": result["comms"]["messages"], "injects": result["injects"], "map": result["map"],
    }


def python_results():
    server.db = sqlite3.connect(":memory:", check_same_thread=False)
    server.reset_audit()
    out = {}
    for pack in ("alpha", "bravo"):
        user = {"name": "Demo", "role": "EOOW", "pack": pack}
        for report in REPORTS:
            result = server.run_agents(user, report)
            entry = {"first": view(result)}
            if result["kind"] == "answer" and result["injects"]:
                entry["replan"] = view(server.replan(user, result["injects"][0]["id"])[1])
            out[f"{pack}|{report}"] = entry
        for role in ROLES:
            brief = server.agent_brief({**user, "role": role})
            out[f"{pack}|brief|{role}"] = {k: brief[k] for k in ("plans", "distrust", "speech", "map")}
    return out


NODE = r"""
const fs = require('fs');
const [dataFile, engineFile, listFile, outFile] = process.argv.slice(2);
global.window = { DORE_DATA: JSON.parse(fs.readFileSync(dataFile, 'utf8')) };
eval(fs.readFileSync(engineFile, 'utf8'));
const E = window.DORE_ENGINE, reports = JSON.parse(fs.readFileSync(listFile, 'utf8'));
const by = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const view = r => r.kind !== 'answer' ? { kind: r.kind, message: r.message } : {
  casualty: r.triage.casualty, severity: r.triage.severity, location: r.triage.location, reasoning: r.triage.reasoning,
  tagouts: r.triage.tagouts.map(t => t.equipment).sort(by), sensors: r.triage.sensors.map(s => [s.name, s.trusted, s.problems]),
  steps: r.actions.steps.map(s => [s.id, s.title, s.owner, s.due_s, s.citation.para]),
  blocked: r.actions.blocked.map(b => [b.id, b.equipment, b.kind, b.use_instead]), dropped: r.actions.dropped.map(d => d.title),
  tasking: r.tasking, comms: r.comms.messages, injects: r.injects, map: r.map };
const out = {};
for (const pack of ['alpha', 'bravo']) {
  const user = { name: 'Demo', role: 'EOOW', pack };
  for (const report of reports.reports) {
    const result = E.runAgents(user, report), entry = { first: view(result) };
    if (result.kind === 'answer' && result.injects.length) entry.replan = view(E.replan(user, result.injects[0].id)[1]);
    out[`${pack}|${report}`] = entry;
  }
  for (const role of reports.roles) {
    const b = E.agentBrief({ ...user, role });
    out[`${pack}|brief|${role}`] = { plans: b.plans, distrust: b.distrust, speech: b.speech, map: b.map };
  }
}
out.sha = E.sha256('door shipboard fire');
fs.writeFileSync(outFile, JSON.stringify(out));
"""


def difference(a, b, path=""):
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) | set(b)):
            found = difference(a.get(key), b.get(key), f"{path}.{key}")
            if found:
                return found
        return None
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return f"{path}: length {len(a)} vs {len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            found = difference(x, y, f"{path}[{i}]")
            if found:
                return found
        return None
    return None if a == b else f"{path}: {a!r} vs {b!r}"


def main():
    expected = python_results()
    with tempfile.TemporaryDirectory() as folder:
        folder = Path(folder)
        (folder / "data.json").write_text(json.dumps(build_standalone.load_data()), encoding="utf-8")
        (folder / "list.json").write_text(json.dumps({"reports": REPORTS, "roles": ROLES}), encoding="utf-8")
        (folder / "run.js").write_text(NODE, encoding="utf-8")
        subprocess.run(["node", str(folder / "run.js"), str(folder / "data.json"), str(ROOT / "static" / "offline-engine.js"),
                       str(folder / "list.json"), str(folder / "out.json")], check=True)
        actual = json.loads((folder / "out.json").read_text(encoding="utf-8"))
    problems = 0
    for key, value in expected.items():
        found = difference(value, actual.get(key))
        if found:
            problems += 1
            print(f"MISMATCH {key}\n   {found[:300]}")
    import hashlib
    if actual["sha"] != hashlib.sha256(b"door shipboard fire").hexdigest():
        problems += 1
        print("MISMATCH sha256")
    print(f"{len(expected) - problems} of {len(expected)} match, audit hash {'OK' if actual['sha'] == hashlib.sha256(b'door shipboard fire').hexdigest() else 'WRONG'}")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
