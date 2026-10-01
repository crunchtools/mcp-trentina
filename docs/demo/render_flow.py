"""Render flow.html to numbered PNG frames, one render(t) call per frame.

    python render_flow.py OUT_DIR [FPS]

Run in the Playwright image (see render.sh). The page's own animation loop
is off under automation, so each frame is exactly render(i / FPS).
"""

from __future__ import annotations

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

# Matches the VHS terminal half, so the two join without scaling.
WIDTH = 1200
HEIGHT = 720
DEFAULT_FPS = 20

out = Path(sys.argv[1])
fps = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_FPS
out.mkdir(parents=True, exist_ok=True)
page_url = (Path(__file__).parent / "flow.html").resolve().as_uri()

with sync_playwright() as pw:
    browser = pw.chromium.launch()
    page = browser.new_page(viewport={"width": WIDTH, "height": HEIGHT})
    page.goto(page_url)
    duration = page.evaluate("window.DURATION")
    for i in range(int(duration * fps) + 1):
        page.evaluate(f"window.render({i / fps})")
        page.screenshot(path=str(out / f"{i:05d}.png"))
    browser.close()
