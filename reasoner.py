"""Reasons about a free-text report, then builds a plan from approved general actions.

This code never writes a procedure step. It only selects, orders and combines steps
that already exist in the approved library, so every step keeps its citation.
"""
import copy
import difflib
import json
import re
from pathlib import Path

LIBRARY_DIR = Path(__file__).parent / "library"
LIBRARY = json.loads((LIBRARY_DIR / "general.json").read_text(encoding="utf-8"))
LIBRARY_TEXT = (LIBRARY_DIR / LIBRARY["document"]["file"]).read_text(encoding="utf-8")
SINGLE_WORDS = sorted({w for h in LIBRARY["hazards"] for w in h["words"] if " " not in w and len(w) >= 5})


def clean(text):
    return re.sub(r"\s+", " ", text.lower()).strip()


def fix_typos(low):
    """Correct near-misses of hazard words, such as 'flodding' or 'electricl'."""
    fixed = []
    for word in low.split():
        bare = word.strip(".,;:!?")
        known = any(bare == w for w in SINGLE_WORDS)
        close = difflib.get_close_matches(bare, SINGLE_WORDS, n=1, cutoff=0.84) if len(bare) >= 5 and not known else []
        fixed.append(word.replace(bare, close[0]) if close else word)
    return " ".join(fixed)


def word_found(word, low):
    match = re.search(r"\b" + re.escape(word) + r"\b", low)
    if not match:
        return False
    before = low[:match.start()]
    return not any(before.endswith(n) for n in LIBRARY["negations"])


def find_location(pack, low):
    """Return (space_id, display name). A known space beats a phrase from the report."""
    aliases = [(a, sid) for sid, s in pack["spaces"].items() for a in s["aliases"]]
    for alias, space_id in sorted(aliases, key=lambda pair: -len(pair[0])):
        if re.search(r"\b" + re.escape(alias) + r"\b", low):
            return space_id, pack["spaces"][space_id]["name"]
    nouns = "|".join(LIBRARY["location_words"])
    pattern = r"\b(?:in|at|on|near|inside|from)\s+(?:the\s+|a\s+|our\s+)?((?:[a-z0-9]+\s+){0,2}?(?:" + nouns + r")(?:\s+[0-9]+)?)\b"
    matches = re.findall(pattern, low)
    if matches:
        return None, matches[-1].strip().capitalize()  # The last place named is the most specific.
    return None, None


def understand(pack, report):
    """Read the report: hazards, location, what's missing, and whether it's a casualty."""
    low = fix_typos(clean(report))
    guard = next((g for g in LIBRARY["not_a_casualty"] if g in f"{low} "), None)
    hazards = [h for h in LIBRARY["hazards"] if any(word_found(w, low) for w in h["words"])]
    keyword_hits = [(sum(word_found(k, low) for k in c["keywords"]), c) for c in pack["casualties"]]
    named = [c for score, c in keyword_hits if score and c.get("always")]
    if (guard or (not hazards and not named)):
        return {"casualty": False, "guard": guard}

    space_id, location = find_location(pack, low)
    side = next((s for s in ("port", "starboard") if word_found(s, low)), None)
    magazine = any(word_found(w, low) for w in LIBRARY["magazine"]["words"])

    exact = None
    ids = {h["id"] for h in hazards}
    if named:
        exact = named[0]
    else:
        for casualty in pack["casualties"]:
            covers = set(casualty.get("hazards", []))
            if covers and ids <= covers and space_id in casualty.get("spaces", []) and not magazine:
                exact = casualty
                break
    if exact and not space_id and not casualty_has_side(exact, side):
        space_id = exact.get("default_space")
        location = pack["spaces"][space_id]["name"] if space_id else location
    return {"casualty": True, "low": low, "hazards": hazards, "space_id": space_id, "location": location,
            "side": side, "magazine": magazine, "exact": exact}


def casualty_has_side(casualty, side):
    return bool(side and casualty.get("default_space") is None)


def needs_location(u):
    return not u["hazards"] or not all(h.get("shipwide") for h in u["hazards"])


def asks(u):
    questions = []
    if needs_location(u) and not u["location"]:
        questions.append("Which compartment?")
    elif needs_location(u) and not u["space_id"]:
        questions.append(f"What is the compartment number for {u['location']}?")
    questions += [h["ask"] for h in u["hazards"] if h.get("ask")]
    if not any(h["id"] == "injury" for h in u["hazards"]):
        questions.append("Is anyone injured or missing?")
    return questions[:4]


def explain(u, exact):
    """Plain reasons the watchstander and the judges can read."""
    names = [h["label"].lower() for h in u["hazards"]]
    ids = {h["id"] for h in u["hazards"]}
    lines = []
    if names:
        lines.append("Heard: " + ", ".join(names) + ".")
    if not needs_location(u):
        lines.append("This affects the whole ship, so no compartment is needed.")
    elif u["location"] and u["space_id"]:
        lines.append(f"Location matched to the ship map: {u['location']}.")
    elif u["location"]:
        lines.append(f"Location '{u['location']}' isn't on the ship map, so confirm it.")
    else:
        lines.append("No location given, so confirming it comes first.")
    if exact:
        lines.append(f"Exact procedure found: {exact['name']}.")
    else:
        lines.append("No exact procedure, so this plan is built from approved general actions.")
    if {"electrical", "fire"} <= ids or {"electrical", "flooding"} <= ids:
        lines.append("Electrical hazard moved first: no water until the circuit is dead.")
    if "smoke" in ids and "fire" not in ids:
        lines.append("Smoke is treated as a fire until the source is found.")
    if "injury" in ids:
        lines.append("Injury raises life safety ahead of fighting the casualty.")
    if u["magazine"]:
        lines.append("Magazine or ammunition nearby, so that report moves up.")
    return lines


def confidence(u, exact):
    if exact and (u["space_id"] or u["side"] or exact.get("always")):
        return "HIGH"
    return "MEDIUM" if u["location"] or not needs_location(u) else "LOW"


PRIORITY = ["fire", "flooding", "gas", "steam", "fuel", "electrical", "smoke", "power", "steering", "injury"]


def lead_hazard(hazards):
    """Name the main hazard the way a watch team would say it."""
    ids = {h["id"] for h in hazards}
    if {"fire", "electrical"} <= ids:
        return "Electrical Fire"
    if not hazards:
        return "Casualty"
    return min(hazards, key=lambda h: PRIORITY.index(h["id"]))["label"]


def plan_name(hazards):
    lead = lead_hazard(hazards)
    covered = {"Electrical Fire": {"fire", "electrical", "smoke"}, "Fire": {"fire", "smoke"}}.get(lead, {h["id"] for h in hazards if h["label"] == lead})
    others = [h["label"] for h in sorted(hazards, key=lambda h: PRIORITY.index(h["id"])) if h["id"] not in covered]
    return lead + (" with " + " and ".join(others) if others else "")


def compose(pack, u):
    """Build a casualty in the same shape as a written one, from library steps only."""
    equipment = pack["general_equipment"]
    names = {e["id"]: e["name"] for e in pack["equipment"]}
    station = pack.get("station_map", {})
    chosen = copy.deepcopy(LIBRARY["common"])
    if not u["space_id"] and needs_location(u):
        chosen.append(copy.deepcopy(LIBRARY["confirm_location"]))
    ids = {h["id"] for h in u["hazards"]}
    for hazard in u["hazards"]:
        chosen += copy.deepcopy(hazard["steps"])
    if "smoke" in ids and "fire" not in ids:
        fire = next(h for h in LIBRARY["hazards"] if h["id"] == "fire")
        chosen += copy.deepcopy([s for s in fire["steps"] if s["id"] in ("F2", "F3", "F4", "F5", "F6")])
    if u["magazine"]:
        chosen.append(copy.deepcopy(LIBRARY["magazine"]["step"]))
    seen, actions = set(), []
    for step in sorted(chosen, key=lambda s: s["rank"]):
        if step["quote"] in seen:
            continue
        seen.add(step["quote"])
        step["doc"] = "GEN"
        step["owner"] = station.get(step["owner"], step["owner"])
        step["needs"] = [equipment[n[1:]] for n in step.get("needs", [])]
        for key, value in equipment.items():
            step["title"] = step["title"].replace("{" + key + "}", names[value])
        actions.append(step)

    injects = []
    for hazard in u["hazards"]:
        if hazard.get("inject"):
            item = dict(hazard["inject"])
            item["equipment"] = equipment[item["equipment"][1:]]
            item["label"] = f"{names[item['equipment']].upper()} FAILS"
            injects.append(item)
    top = lead_hazard(u["hazards"])
    comms = []
    for item in LIBRARY["comms"]:
        text = item["text"].replace("{hazard_list}", plan_name(u["hazards"])).replace("{hazard}", top)
        if not needs_location(u):
            text = text.replace(" reported in {location}.", " reported.").replace(" All hands stand clear of {location}.", " All hands stand by.").replace("Investigate {location}.", "Stand by to assist.")
        comms.append({**item, "speaker": station.get(item["speaker"], item["speaker"]), "text": text})
    serious = any(h["serious"] for h in u["hazards"]) or u["magazine"]
    return {"id": "built-" + "-".join(sorted(ids)), "name": plan_name(u["hazards"]), "severity": "CRITICAL" if serious else "SERIOUS",
            "actions": actions, "comms": comms, "injects": injects, "built": True}


def reason(pack, report):
    """Return (casualty, understanding) or (None, why) when it isn't a casualty."""
    u = understand(pack, report)
    if not u["casualty"]:
        return None, u
    if not u["location"] and not needs_location(u):
        u["location"] = "Ship-wide"
    casualty = u["exact"] or compose(pack, u)
    u["reasoning"] = {"built": not u["exact"], "confidence": confidence(u, u["exact"]),
                      "lines": explain(u, u["exact"]), "ask": asks(u),
                      "hazards": [h["label"] for h in u["hazards"]]}
    return casualty, u
