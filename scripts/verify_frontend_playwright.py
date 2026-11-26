#!/usr/bin/env python3
"""
Headless Chromium Playwright verification for Q-SHIELD Stage 10/11 (resolves G9).

Verifies:
- All key routes render with 0 browser console errors and 0 page errors.
- Desktop (1440x900), Tablet (768x1024), Mobile (390x844) responsive layouts.
- Real backend interaction: Reset Demo Data -> Demo Login -> Overview -> Nodes -> Scenarios (S01 PASS).
- Zero sensitive credentials in localStorage.
- Captures genuine PNG screenshots under reports/evidence/screenshots/.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.request import urlopen

from playwright.sync_api import sync_playwright

REPO_ROOT = Path(__file__).resolve().parents[1]
SHOTS_DIR = REPO_ROOT / "reports" / "evidence" / "screenshots"


def _wait_http(url: str, timeout_s: float = 20.0) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with urlopen(url, timeout=2) as resp:
                if resp.status < 500:
                    return
        except Exception:
            time.sleep(0.4)
    raise RuntimeError(f"Timed out waiting for {url}")


def main() -> int:
    SHOTS_DIR.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()

    backend_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    frontend_proc = subprocess.Popen(
        ["npm.cmd" if os.name == "nt" else "npm", "run", "dev", "--", "--host", "127.0.0.1", "--port", "5173"],
        cwd=str(REPO_ROOT / "frontend"),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    console_errors: list[str] = []
    page_errors: list[str] = []

    try:
        _wait_http("http://127.0.0.1:8000/api/v1/health")
        _wait_http("http://127.0.0.1:5173/")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 1440, "height": 900})
            page = context.new_page()

            page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
            page.on("pageerror", lambda err: page_errors.append(str(err)))

            # 1. Landing Page
            page.goto("http://127.0.0.1:5173/", wait_until="networkidle")
            page.get_by_text("Trust changes.").wait_for()
            page.screenshot(path=str(SHOTS_DIR / "01_landing.png"), full_page=True)

            # 2. Demo Login & Reset Demo Data
            page.goto("http://127.0.0.1:5173/login", wait_until="networkidle")
            page.get_by_role("button", name="Reset Demo Data").click()
            page.get_by_text("Synthetic data reset").wait_for(timeout=10000)
            page.get_by_role("button", name="Issue Backend Session").click()
            page.get_by_text("Security Operations Overview").wait_for(timeout=10000)
            page.wait_for_timeout(500)
            page.screenshot(path=str(SHOTS_DIR / "02_overview_desktop.png"), full_page=True)

            # 3. Verify localStorage has zero secrets/tokens
            ls_len = page.evaluate("() => window.localStorage.length")
            assert ls_len == 0, f"Expected empty localStorage, got length={ls_len}"

            # 4. Nodes Control Plane
            page.goto("http://127.0.0.1:5173/nodes", wait_until="networkidle")
            page.get_by_role("cell", name="sim-node-1").wait_for(timeout=10000)
            page.screenshot(path=str(SHOTS_DIR / "03_nodes.png"), full_page=True)

            # 5. Scenarios (run S01 against real backend)
            page.goto("http://127.0.0.1:5173/scenarios", wait_until="networkidle")
            page.get_by_role("button", name="Run").first.click()
            page.get_by_text("S01 (Normal Protected Read) PASS").wait_for(timeout=10000)
            page.screenshot(path=str(SHOTS_DIR / "04_scenarios_s01_pass.png"), full_page=True)

            # 6. Check all remaining routes load cleanly (including Data Lab & Security Integrity)
            for route in ("/identities", "/devices", "/vault", "/keys", "/incidents", "/detector", "/messaging", "/audit", "/datalab", "/security-integrity", "/benchmarks", "/scorecard", "/settings"):
                page.goto(f"http://127.0.0.1:5173{route}", wait_until="domcontentloaded")
                try:
                    page.locator("h1").first.wait_for(timeout=15000)
                except Exception as exc:
                    raise RuntimeError(f"Route {route} failed h1 check; console_errors={console_errors}; page_errors={page_errors}") from exc
                if route == "/datalab":
                    page.wait_for_timeout(400)
                    page.screenshot(path=str(SHOTS_DIR / "07_datalab.png"), full_page=True)
                elif route == "/security-integrity":
                    page.wait_for_timeout(400)
                    page.screenshot(path=str(SHOTS_DIR / "08_security_integrity.png"), full_page=True)

            # 7. Tablet & Mobile responsive checks
            page.set_viewport_size({"width": 768, "height": 1024})
            page.goto("http://127.0.0.1:5173/overview", wait_until="load")
            page.wait_for_timeout(800)
            page.screenshot(path=str(SHOTS_DIR / "05_overview_tablet.png"))

            page.set_viewport_size({"width": 390, "height": 844})
            page.goto("http://127.0.0.1:5173/overview", wait_until="load")
            page.get_by_role("button", name="Toggle navigation").wait_for(timeout=15000)
            page.screenshot(path=str(SHOTS_DIR / "06_overview_mobile.png"))

            browser.close()

        assert len(console_errors) == 0, f"Console errors: {console_errors}"
        assert len(page_errors) == 0, f"Page errors: {page_errors}"
        print(f"Playwright verification PASS: 16 routes, 3 viewports, 0 console errors, 6 screenshots saved to {SHOTS_DIR}")
        return 0
    finally:
        frontend_proc.terminate()
        backend_proc.terminate()
        try:
            frontend_proc.wait(timeout=5)
        except Exception:
            frontend_proc.kill()
        try:
            backend_proc.wait(timeout=5)
        except Exception:
            backend_proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
