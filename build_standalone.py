"""Builds DORE-Afloat.html: one file that runs with no server, Python or network.

Run this after changing the screen, ship packs or library:  python dore-afloat/build_standalone.py
"""
import base64
import json
import re
from pathlib import Path

ROOT = Path(__file__).parent
STATIC = ROOT / "static"
OUTPUT = ROOT / "DORE-Afloat.html"


def load_data():
    library = json.loads((ROOT / "library" / "general.json").read_text(encoding="utf-8"))
    library_text = (ROOT / "library" / library["document"]["file"]).read_text(encoding="utf-8")
    packs = {}
    for file in sorted((ROOT / "packs").glob("*/pack.json")):
        pack = json.loads(file.read_text(encoding="utf-8"))
        pack["documents"]["GEN"] = library["document"]
        pack["source_text"] = {
            key: library_text if key == "GEN" else (file.parent / doc["file"]).read_text(encoding="utf-8")
            for key, doc in pack["documents"].items()
        }
        packs[file.parent.name] = pack
    return {"library": library, "packs": packs}


def inline_fonts():
    css = (STATIC / "fonts" / "fonts.css").read_text(encoding="utf-8")

    def embed(match):
        font = (STATIC / "fonts" / match.group(1)).read_bytes()
        return "url(data:font/woff2;base64," + base64.b64encode(font).decode() + ")"

    return re.sub(r"url\(/fonts/([^)]+)\)", embed, css)


def script_safe(text):
    return text.replace("</script", "<\\/script")


def build():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    link = '<link rel="stylesheet" href="/fonts/fonts.css">'
    assert link in html
    html = html.replace(link, "<style>" + inline_fonts() + "</style>")
    data = script_safe(json.dumps(load_data()))
    engine = script_safe((STATIC / "offline-engine.js").read_text(encoding="utf-8"))
    block = f"<script>window.DORE_DATA = {data};</script>\n<script>{engine}</script>\n<script>\n"
    assert html.count("<script>\n") == 1
    OUTPUT.write_text(html.replace("<script>\n", block), encoding="utf-8")
    print(f"Built {OUTPUT.name}: {OUTPUT.stat().st_size // 1024} KB")


if __name__ == "__main__":
    build()
