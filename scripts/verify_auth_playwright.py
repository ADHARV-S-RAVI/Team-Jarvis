"""Live Playwright E2E verification of Real Registration, Login, Cookies, Refresh, New Tab, RBAC & Logout (Phase 8)."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

from alembic import command
from alembic.config import Config
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait_http(url: str, timeout: float = 25.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status < 500:
                    return
        except Exception:
            time.sleep(0.3)
    raise RuntimeError(f"Timed out waiting for {url}")


def main() -> None:
    tmp_dir = Path(tempfile.mkdtemp(prefix="qshield_pw_auth_"))
    backend_proc = None
    frontend_proc = None
    try:
        db_path = tmp_dir / "pw_auth.db"
        db_url = f"sqlite:///{db_path.as_posix()}"

        alembic_cfg = Config(str(ROOT / "backend" / "alembic.ini"))
        alembic_cfg.set_main_option("script_location", str(ROOT / "backend" / "alembic"))
        alembic_cfg.set_main_option("sqlalchemy.url", db_url)
        command.upgrade(alembic_cfg, "head")

        be_port = _free_port()
        fe_port = _free_port()
        env = os.environ.copy()
        env["QSHIELD_DATABASE_URL"] = db_url
        env["QSHIELD_KEY_STORE_DIR"] = str(tmp_dir / "keystore")
        env["QSHIELD_ENABLE_DEV_DEMO_AUTH"] = "false"

        backend_proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "backend.app.main:app", "--host", "127.0.0.1", "--port", str(be_port)],
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _wait_http(f"http://127.0.0.1:{be_port}/api/v1/health")

        fe_env = os.environ.copy()
        fe_env["VITE_API_BASE_URL"] = f"http://127.0.0.1:{be_port}"
        frontend_proc = subprocess.Popen(
            ["npm.cmd" if os.name == "nt" else "npm", "run", "dev", "--", "--host", "127.0.0.1", "--port", str(fe_port)],
            cwd=str(ROOT / "frontend"),
            env=fe_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _wait_http(f"http://127.0.0.1:{fe_port}/")

        base_url = f"http://127.0.0.1:{fe_port}"
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()

            # 1. Open /login, confirm no Demo Login, unauthenticated /dashboard/user blocked
            page.goto(f"{base_url}/login", wait_until="networkidle")
            assert "Demo Login" not in page.inner_text("body")
            page.goto(f"{base_url}/dashboard/user", wait_until="networkidle")
            assert "/login" in page.url

            # 2. Register new User account (Full Name, Email, Username, Password, Confirm Password)
            page.get_by_role("button", name="Create User Account").click()
            page.locator("#reg-label").fill("E2E User")
            page.locator("#reg-email").fill("e2e_user@qshield.local")
            page.locator("#reg-username").fill("e2e_user")
            page.locator("#reg-password").fill("RealE2EPass#2026")
            page.locator("#reg-confirm-password").fill("RealE2EPass#2026")
            page.locator("form button[type='submit']").click()
            page.wait_for_url("**/dashboard/user", timeout=10000)
            page.wait_for_selector("h1:has-text('User Dashboard')", timeout=10000)

            # 3. Refresh page & open new tab -> HttpOnly cookies restore valid session
            page.reload(wait_until="networkidle")
            assert "/dashboard/user" in page.url
            assert "User Dashboard" in page.inner_text("body")
            page2 = context.new_page()
            page2.goto(f"{base_url}/dashboard/user", wait_until="networkidle")
            assert "/dashboard/user" in page2.url
            page2.close()

            # 4. Logout -> invalidates session & blocks reopening
            page.get_by_role("button", name="Logout").click()
            page.wait_for_url("**/login", timeout=10000)
            page.goto(f"{base_url}/dashboard/user", wait_until="networkidle")
            assert "/login" in page.url

            # 5. Wrong password rejected
            page.locator("#rbac-identifier").fill("e2e_user")
            page.locator("#rbac-password").fill("WrongPassword!")
            page.locator("form button[type='submit']").click()
            page.wait_for_selector("text=Invalid credentials", timeout=10000)

            # 6. Login with registered credentials -> Continue to User Dashboard -> 403 on Admin Dashboard
            page.locator("#rbac-password").fill("RealE2EPass#2026")
            page.locator("form button[type='submit']").click()
            page.wait_for_selector("text=Account & Role Verified", timeout=10000)
            assert "FACIAL BIOMETRIC MATCHING: NOT IMPLEMENTED" in page.inner_text("body")
            page.get_by_role("button", name="Continue to User Dashboard").click()
            page.wait_for_url("**/dashboard/user", timeout=10000)

            page.goto(f"{base_url}/dashboard/admin", wait_until="networkidle")
            page.wait_for_url("**/access-denied", timeout=10000)
            assert "Access Denied (403)" in page.inner_text("body")

            # 7. Final Logout
            page.goto(f"{base_url}/dashboard/user", wait_until="networkidle")
            page.get_by_role("button", name="Logout").click()
            page.wait_for_url("**/login", timeout=10000)

            browser.close()
        print("PLAYWRIGHT_REAL_AUTH_E2E_PASS")
    finally:
        if frontend_proc is not None:
            frontend_proc.terminate()
        if backend_proc is not None:
            backend_proc.terminate()
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
