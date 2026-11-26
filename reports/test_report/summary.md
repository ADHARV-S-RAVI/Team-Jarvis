# Q-SHIELD — Test, Migration & Build Report

**Date:** 2026-11-26  
**Environment:** Windows 11 (`Windows-11-10.0.26200-SP0`), Python `3.12.3`, Node.js / Vite `6.4.6`

| Suite | Command | Result | Exit Code |
| :--- | :--- | :--- | :---: |
| **Backend Tests** | `py -3.12 -m pytest -v backend/tests/` | `46 passed, 33 warnings in 29.71s` | `0` |
| **Adapter Tests** | `py -3.12 -m pytest -v tests/adapter/test_track4_service.py` | `9 passed in 8.58s` | `0` |
| **Alembic Migrations** | `py -3.12 -m alembic -c backend/alembic.ini upgrade head` | Applied `0001`–`0007` cleanly | `0` |
| **Frontend Unit Tests** | `npm run test` (`vitest run`) | `4 passed (4)` in `6.36s` | `0` |
| **Frontend Build** | `npm run build` (`tsc -b && vite build`) | `built in 13.83s` | `0` |
| **Official Track 4 Validator** | `py -3.12 validate.py --entry "../../track4_service.py"` | `Local scenario passed.` (`21/21` checks PASS) | `0` |
| **Headless Browser E2E** | `py -3.12 scripts/verify_frontend_playwright.py` | `16` routes, `3` viewports, `0` console/page errors, `6` PNG screenshots | `0` |
| **Coverage** | — | `NOT MEASURED` (not run with `pytest-cov`) | — |
