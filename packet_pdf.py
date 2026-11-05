"""Builds the casualty packet PDF with the Python standard library only."""
from datetime import datetime, timezone

PAGE_W, PAGE_H, MARGIN = 612, 792, 48
BOTTOM = 56
WIDTH = PAGE_W - 2 * MARGIN
NAVY, INK, QUIET, RULE = (0.03, 0.10, 0.17), (0.08, 0.10, 0.13), (0.38, 0.43, 0.48), (0.80, 0.83, 0.86)
RED, BLUE, ORANGE, GREEN, VIOLET = (0.80, 0.10, 0.10), (0.0, 0.42, 0.72), (0.85, 0.42, 0.0), (0.0, 0.50, 0.32), (0.45, 0.20, 0.72)
FONTS = {"body": "F1", "bold": "F2", "mono": "F3"}


def escape(text):
    raw = str(text).encode("cp1252", "replace").decode("latin-1")
    return raw.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def wrap(text, size, width, font="body"):
    """Split text into lines. Widths are estimates, so they lean conservative."""
    per_char = {"body": 0.5, "bold": 0.55, "mono": 0.6}[font] * size
    limit = max(1, int(width / per_char))
    lines, line = [], ""
    for word in str(text).split():
        if line and len(line) + 1 + len(word) > limit:
            lines.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    return lines + [line] if line else [""]


class Packet:
    def __init__(self):
        self.pages = []
        self.y = 0
        self.new_page()

    def new_page(self):
        self.pages.append([])
        self.y = PAGE_H - 48

    def need(self, height):
        if self.y - height < BOTTOM:
            self.new_page()

    def draw(self, command):
        self.pages[-1].append(command)

    def text(self, x, y, value, size=10, font="body", color=INK):
        self.draw(f"{color[0]} {color[1]} {color[2]} rg BT /{FONTS[font]} {size} Tf {x} {y} Td ({escape(value)}) Tj ET")

    def rect(self, x, y, w, h, color):
        self.draw(f"{color[0]} {color[1]} {color[2]} rg {x} {y} {w} {h} re f")

    def box(self, x, y, w, h, color, line=0.8):
        self.draw(f"{color[0]} {color[1]} {color[2]} RG {line} w {x} {y} {w} {h} re S")

    def rule(self, y):
        self.draw(f"{RULE[0]} {RULE[1]} {RULE[2]} RG 0.5 w {MARGIN} {y} m {PAGE_W - MARGIN} {y} l S")

    def paragraph(self, value, x=MARGIN, width=WIDTH, size=10, font="body", color=INK, leading=None):
        leading = leading or size + 3.5
        for line in wrap(value, size, width, font):
            self.need(leading)
            self.y -= leading
            self.text(x, self.y, line, size, font, color)

    def heading(self, title, color, tag=""):
        self.need(52)
        self.y -= 12
        self.rect(MARGIN, self.y - 18, 4, 18, color)
        self.text(MARGIN + 12, self.y - 13, title.upper(), 11.5, "bold", NAVY)
        if tag:
            self.text(PAGE_W - MARGIN - 46, self.y - 13, tag, 9, "mono", color)
        self.y -= 23
        self.rule(self.y)
        self.y -= 3

    def field(self, label, value, color=INK):
        lines = wrap(value, 10, WIDTH - 112)
        self.need(14 * len(lines) + 2)
        self.y -= 14
        self.text(MARGIN, self.y, label.upper(), 8, "mono", QUIET)
        self.text(MARGIN + 112, self.y, lines[0], 10, "body", color)
        for line in lines[1:]:
            self.y -= 13
            self.text(MARGIN + 112, self.y, line, 10, "body", color)

    def finish(self, footer):
        total = len(self.pages)
        for number, page in enumerate(self.pages, 1):
            page.append(f"{RULE[0]} {RULE[1]} {RULE[2]} RG 0.5 w {MARGIN} 42 m {PAGE_W - MARGIN} 42 l S")
            page.append(f"{QUIET[0]} {QUIET[1]} {QUIET[2]} rg BT /F1 7.5 Tf {MARGIN} 30 Td ({escape(footer)}) Tj ET")
            page.append(f"{QUIET[0]} {QUIET[1]} {QUIET[2]} rg BT /F1 7.5 Tf {PAGE_W - MARGIN - 44} 30 Td (Page {number} of {total}) Tj ET")
        return self.to_bytes()

    def to_bytes(self):
        objects = {
            1: "<< /Type /Catalog /Pages 2 0 R >>",
            3: "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
            4: "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
            5: "<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>",
        }
        kids = []
        next_id = 6
        for page in self.pages:
            stream = "\n".join(page).encode("latin-1")
            page_id, content_id = next_id, next_id + 1
            next_id += 2
            kids.append(f"{page_id} 0 R")
            objects[page_id] = (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] /Contents {content_id} 0 R "
                "/Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> >>"
            )
            objects[content_id] = stream
        objects[2] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>"

        out = bytearray(b"%PDF-1.4\n")
        offsets = {}
        for number in sorted(objects):
            offsets[number] = len(out)
            body = objects[number]
            out += f"{number} 0 obj\n".encode()
            if isinstance(body, bytes):
                out += f"<< /Length {len(body)} >>\nstream\n".encode() + body + b"\nendstream"
            else:
                out += body.encode("latin-1")
            out += b"\nendobj\n"
        xref = len(out)
        size = max(objects) + 1
        out += f"xref\n0 {size}\n0000000000 65535 f \n".encode()
        for number in range(1, size):
            out += f"{offsets[number]:010d} 00000 n \n".encode()
        out += f"trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
        return bytes(out)


def build_packet(incident, records, audit_status, debrief):
    triage, actions = incident["triage"], incident["actions"]
    done = {d["id"]: d for d in incident["done"]}
    pdf = Packet()

    pdf.rect(0, PAGE_H - 92, PAGE_W, 92, NAVY)
    pdf.text(MARGIN, PAGE_H - 42, "D.O.R.E. AFLOAT", 20, "bold", (1, 1, 1))
    pdf.text(MARGIN, PAGE_H - 60, "CASUALTY RESPONSE PACKET", 10, "mono", (0.55, 0.80, 1))
    pdf.text(MARGIN, PAGE_H - 78, f"{incident['ship']}  //  {triage['location']}", 10, "body", (1, 1, 1))
    pdf.rect(PAGE_W - MARGIN - 128, PAGE_H - 50, 128, 22, RED)
    label = "DRILL" if incident["drill"] else f"{triage['severity']} CASUALTY"
    pdf.text(PAGE_W - MARGIN - 118, PAGE_H - 43, label, 9.5, "bold", (1, 1, 1))
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    pdf.text(PAGE_W - MARGIN - 144, PAGE_H - 78, f"Generated {stamp}", 8, "mono", (0.75, 0.85, 0.95))
    pdf.y = PAGE_H - 100

    pdf.heading("Casualty brief", BLUE, "AGENT 1")
    pdf.field("Casualty", triage["casualty"], RED)
    pdf.field("Location", triage["location"])
    pdf.field("Reported", triage["time"])
    pdf.field("Report", triage["report"])
    pdf.field("Out of service", "; ".join(f"{t['equipment']} ({t['id']}, {t['reason']})" for t in triage["tagouts"]) or "None", RED if triage["tagouts"] else INK)
    distrust = [f"{s['name']}: {s['value']} {s['unit']} ({', '.join(s['problems'])})" for s in triage["sensors"] if not s["trusted"]]
    pdf.field("Do not trust", "; ".join(distrust) or "None", RED if distrust else INK)

    pdf.heading("Immediate actions", RED, "AGENT 2")
    for step in actions["steps"]:
        cite = step["citation"]
        pdf.need(32)
        pdf.y -= 16
        pdf.box(MARGIN, pdf.y - 2, 10, 10, QUIET)
        finished = done.get(step["id"])
        if finished:
            pdf.rect(MARGIN + 2, pdf.y, 6, 6, GREEN)
        pdf.text(MARGIN + 18, pdf.y, f"{step['order']}. {step['title']}", 11, "bold")
        if finished:
            pdf.text(PAGE_W - MARGIN - 112, pdf.y, f"Done {finished['at']} {finished['role']}", 8, "mono", GREEN)
        pdf.y -= 12
        pdf.text(MARGIN + 18, pdf.y, f"{step['owner']}  //  {cite['title']}, {cite['rev']}, para {cite['para']}", 8, "body", QUIET)
    for item in actions["blocked"]:
        instead = f" Use instead: {item['use_instead']}." if item["use_instead"] else ""
        pdf.y -= 5
        state = "has failed" if item["kind"] == "FAILED" else f"is tagged out under {item['tagout']}"
        pdf.paragraph(f"BLOCKED: {item['title']}. {item['equipment']} {state}.{instead}", size=9.5, font="bold", color=RED)
    for item in actions["dropped"]:
        pdf.y -= 3
        pdf.paragraph(f"Draft removed: {item['title']}. Its quote is not in the source document.", size=9, color=ORANGE)

    pdf.heading("Team assignments", ORANGE, "AGENT 3")
    for team in incident["tasking"]["teams"]:
        pdf.need(30)
        pdf.y -= 7
        pdf.paragraph(team["station"].upper(), size=9, font="bold", color=ORANGE)
        for task in team["tasks"]:
            pdf.paragraph(f"{task['title']}  ({task['ref']})", x=MARGIN + 12, width=WIDTH - 12, size=10)

    pdf.heading("Say this", GREEN, "AGENT 4")
    for message in incident["comms"]["messages"]:
        pdf.need(44)
        pdf.y -= 7
        pdf.paragraph(message["channel"].upper(), size=8.5, font="bold", color=GREEN)
        pdf.paragraph(message["text"], x=MARGIN + 12, width=WIDTH - 12, size=10.5)

    pdf.heading("Watch log", VIOLET, "AGENT 5")
    for line in records["watch_log"]:
        pdf.paragraph(line, size=8.5, font="mono", leading=12)

    pdf.heading("ICS-201 draft", VIOLET, "AGENT 5")
    for label, value in records["ics201"]:
        pdf.field(label, value)

    pdf.heading("After-action timeline", BLUE, "AGENT 6")
    pdf.paragraph(f"{debrief['on_time']} on time, {debrief['late']} late, {debrief['open']} open, out of {debrief['total']} steps.", size=10, font="bold")
    for row in debrief["rows"]:
        result = row["result"] if row["done_s"] is None else f"{row['result']} at {row['done_s']} s"
        color = GREEN if row["result"] == "On time" else RED
        pdf.need(15)
        pdf.y -= 14
        pdf.text(MARGIN, pdf.y, f"{row['order']}. {row['title']}", 9.5)
        pdf.text(MARGIN + 300, pdf.y, f"due {row['due_s']} s", 8, "mono", QUIET)
        pdf.text(MARGIN + 370, pdf.y, result, 9, "bold", color)
    if debrief["practice"]:
        pdf.y -= 6
        pdf.paragraph("Practice next: " + "; ".join(debrief["practice"]), size=9.5, color=ORANGE)

    pdf.heading("Casualty report draft", BLUE, "AGENT 6")
    for label, value in debrief["report"]:
        pdf.field(label, value)
    pdf.y -= 4
    pdf.paragraph("Draft for review. Not a formal Navy report.", size=8.5, color=QUIET)

    pdf.heading("Audit status", QUIET)
    if audit_status["ok"]:
        pdf.paragraph(f"Chain intact across {audit_status['entries']} entries.", size=10, color=GREEN)
    else:
        pdf.paragraph(f"TAMPERING DETECTED at entry {audit_status['broken_at']}.", size=10, font="bold", color=RED)

    return pdf.finish("CONCEPT DEMO. Fictional ship, notional procedures, synthetic data. Not for operational use.")
