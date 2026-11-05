# DORE Afloat concept demo

DORE briefs the watch before a casualty, runs with them during it, and writes it up after. It needs Python only: no installs, GPU, network or API key.

```bash
python dore-afloat/server.py
```

Then open http://127.0.0.1:8765.

All ships, procedures and data are fictional and notional. Nothing here is Navy doctrine. The agents are rule-based code, not AI models.

| Agent | Product |
| --- | --- |
| Watch Brief | What tonight's tag-outs and bad sensors change in each casualty |
| A1 Triage | Casualty brief: what, where, what is down |
| A2 Immediate Actions | DO NOW card with a step clock, read aloud and checked against sources |
| A3 Team Tasking | ICS-204 style assignments by team |
| A4 Comms | Ready-to-read announcements and reports |
| A5 Records | Watch log and ICS-201 draft |
| A6 Debrief | Timeline, practice list and casualty report draft |

## Demo run

1. Click **RESET DEMO**, turn off Wi-Fi, and click **OPEN SECOND SEAT** for a DCA window.
2. Click **WATCH BRIEF**. It reads what tonight's ship state changes.
3. Hold **V** and say "DORE shipboard fire." Let the readout play.
4. Point out the tag-out swap, the distrusted sensor, the blocked draft and the ship map.
5. Press **Space** to complete a step, and show it appear on the second seat.
6. Click **INJECT: FIRE PUMP 3 FAILS**. The plan, scripts and map change immediately.
7. Hold **V** and say "DORE log boundaries set" to log a report from another station.
8. Wait for a step to go overdue, and show who to call.
9. Click a citation to show the highlighted source text.
10. Click **END CASUALTY** to see the debrief, then **PDF PACKET**.
11. Switch **DRILL** on and run **MAN OVERBOARD** as OOD. Then switch ship to Demo Ship Bravo.
12. Click **SIMULATE TAMPERING** to show the audit chain catching it.

Step clocks are short for the demo: the first step is due at 30 seconds, then 15 seconds more per step.

**RESPONSE SUMMARY** shows the timeline, who has each step, what needs attention and the report draft at any time, live or in a drill, and before or after the casualty is secured.

Keys: **Space** completes the current step, **R** repeats the readout, **B** reads the watch brief, **S** opens the response summary, and **V** is push-to-talk.

**PDF PACKET** downloads the whole casualty packet, including the timeline and report draft. It's built on the laptop, so no network is needed.

## Reasoning

Type any casualty, in plain words. DORE works out the hazards, the location and what's missing.

- **Exact match:** if a written procedure fits, DORE uses it.
- **No exact match:** DORE builds a plan from approved general actions in `library/`, and labels it BUILT with a confidence level. It selects, orders and combines approved steps, but never writes one.
- **Order of steps:** life safety and isolating the hazard come first. For example, an electrical fire de-energizes the circuit before water is used.
- **Not a casualty:** questions and non-casualty talk are refused.

The A1 card shows the reasoning and what to ask next. This is rule-based, so it recognizes only the hazards and wording in `library/general.json`.

## Roles

Each role sees its own DO NOW step, plus a Who Has What board showing every step with its role, station and status. Its assignments and scripts move to the top, and the voice readout covers its own steps. Set which stations belong to a role in `role_stations` in the ship pack.

## Voice commands

Voice is push-to-talk, like a radio. Hold **V** or the on-screen label, wait for LISTENING, say the command, then release. All other sound is ignored, and keying the mic interrupts DORE's readout. On Windows it runs offline through the built-in speech recognizer, with nothing to install.

| Say | What happens |
| --- | --- |
| "DORE shipboard fire" | Runs the fire scenario |
| "DORE shipboard collision" | Runs the collision scenario |
| "DORE shipboard man overboard", optionally "port side" or "starboard side" | Runs the overboard scenario |
| "DORE step complete" | Completes the current step |
| "DORE repeat the steps" | Repeats the readout |
| "DORE watch brief" | Reads the watch brief |
| "DORE response summary" | Opens the response summary |
| "DORE log boundaries set" | Logs that report. Also "fuel secured", "ventilation secured", "firemain pressurized" and "lookouts posted" |
| "DORE casualty is secured" | Ends the casualty and opens the debrief |

These are fixed phrases, not free speech. "DORE shipboard fire" uses the location set in the ship pack's demo scenario. LEVEL shows the live input level.

## Add a ship

Copy a folder in `packs/`, then edit `pack.json` and the text files. To use real procedures, put their text in the source files and update each card's `quote` and `para`.
