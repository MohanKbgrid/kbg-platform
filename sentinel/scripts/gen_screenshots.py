# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""Regenerate the console screenshots and the demo GIF in docs/img/ from the synthetic Acme Retail demo.

    cd sentinel && python scripts/gen_screenshots.py [--out docs/img] [--no-gif]

Needs the dev extras, Playwright's Chromium (``playwright install chromium``) and Pillow for the GIF
(``pip install pillow``). Everything shown is invented: nothing here reads a real system.
The server runs on a free local port with a temporary database, so running it twice gives the same pictures.
"""
from __future__ import annotations

import argparse
import io
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sentinel import demo  # noqa: E402

VIEWPORT = {"width": 1440, "height": 900}
GIF_WIDTH = 720


def sign_in(page, base: str, person: str) -> None:
    page.goto(base + "/console")
    page.fill("#token", demo.TOKENS[person])
    page.click("#signin")
    page.wait_for_selector(".topbar h1")


def goto(page, base: str, route: str) -> None:
    page.goto(f"{base}/console#/{route}")
    page.reload()                      # the same hash does not re-render: always show the current state
    page.wait_for_timeout(700)


def png(page) -> bytes:
    return page.screenshot()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", default=str(ROOT / "docs" / "img"))
    ap.add_argument("--no-gif", action="store_true")
    a = ap.parse_args(argv)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)

    from playwright.sync_api import sync_playwright
    eng, _systems, _model = demo.build_engine()
    demo.seed(eng)
    run = demo.RunningDemo(eng).start()
    frames: list[tuple[bytes, int]] = []            # (png, milliseconds shown)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            errors: list[str] = []

            def as_person(person: str):
                """A fresh browser context signed in as one person (their own session, nothing shared)."""
                pg = browser.new_context(viewport=VIEWPORT).new_page()
                pg.on("pageerror", lambda e: errors.append(str(e)))
                sign_in(pg, run.base, person)
                return pg

            page = as_person("nora")
            goto(page, run.base, "reviews")
            page.locator("select").first.select_option("order_stuck_no_stock")
            page.wait_for_timeout(500)
            (out / "console-review-card.png").write_bytes(png(page))
            print("wrote", out / "console-review-card.png")
            page = as_person("dev")
            for route, name in (("overview", "console-overview"), ("exceptions", "console-exceptions"),
                                ("people", "console-people")):
                goto(page, run.base, route)
                (out / f"{name}.png").write_bytes(png(page))
                print("wrote", out / f"{name}.png")

            goto(page, run.base, "reviews")
            (out / "console-reviews.png").write_bytes(png(page))
            print("wrote", out / "console-reviews.png")

            if not a.no_gif:
                # the story in seven frames: a case arrives, a person approves, the step up is signed off,
                # the next case is handled by the model, a reversal, and the pattern steps back to a person
                def frame(ms: int = 1600) -> None:
                    frames.append((png(page), ms))

                def queue(pg) -> None:
                    goto(pg, run.base, "reviews")
                    pg.locator("select").first.select_option("order_stuck_no_stock")
                    pg.wait_for_timeout(500)

                def arrive(key: str, order: str) -> Any:
                    return eng.ingest(demo._ev("order.unfulfilled", key, "oms", order_id=order, channel="webstore",
                                               location="WH-NORTH", stock_status="out_of_stock", hours_since_paid=52,
                                               alt_location="WH-SOUTH"))

                goto(page, run.base, "overview")
                frame(1400)                                       # the overview: most things already handled
                res = arrive("gif-1", "AR-10199")
                page = as_person("nora")
                queue(page)
                frame()                                           # a case has arrived and waits for Nora
                eng.decide(eng.store.open_review_for(res.incident_id).id,
                           demo.Decision(kind=demo.DecisionKind.APPROVE, actor="nora"))
                queue(page)
                frame()                                           # she approved the suggested move
                page = as_person("dev")
                goto(page, run.base, "exceptions")
                frame(2200)                                       # the pattern has earned a step up: ready for llm
                eng.approve_promotion("order_stuck_no_stock", "dev")
                goto(page, run.base, "exceptions")
                frame(2200)                                       # the operations head approved it: model route
                res = arrive("gif-2", "AR-10200")                 # the next one needs nobody
                goto(page, run.base, "cases")
                frame()
                eng.reverse(res.incident_id, "dev", "the other warehouse was already committed")
                goto(page, run.base, "exceptions")
                frame(2600)                                       # reversed: the pattern is back to a person
            browser.close()
            if errors:
                print("script errors in the console:", errors, file=sys.stderr)
                return 1
    finally:
        run.stop()

    if frames:
        from PIL import Image
        imgs = []
        for data, _ms in frames:
            im = Image.open(io.BytesIO(data)).convert("RGB")
            im = im.resize((GIF_WIDTH, int(im.height * GIF_WIDTH / im.width)), Image.LANCZOS)
            imgs.append(im.quantize(colors=96, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE))
        path = out / "demo.gif"
        imgs[0].save(path, save_all=True, append_images=imgs[1:], duration=[ms for _d, ms in frames], loop=0,
                     optimize=True, disposal=1)
        print("wrote", path, f"{path.stat().st_size / 1024:.0f} KB, {len(imgs)} frames")
    time.sleep(0.1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
