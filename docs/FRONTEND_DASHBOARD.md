# Q-SHIELD — Frontend Operator Console (Stage 10)

**Stack:** React `18.3.1`, TypeScript `5.6.3`, Vite `6.4.6`, Tailwind CSS `3.4.16`, React Router `7.0.2`, TanStack Query `5.62.0`, Recharts `2.14.1`, Lucide React `0.468.0`, Vitest `2.1.9`  
**Status:** Build & unit/smoke tests **PASS** (`tsc -b && vite build` exit `0`; `vitest run` 4/4 PASS). Live Chrome browser screenshots **BLOCKED** (Chrome remote debugging `DevToolsActivePort` not enabled).

---

## 1. Architecture & Security Model

- **Centralized API Client (`frontend/src/services/api.ts`):** Typed `fetch` wrapper using `VITE_API_BASE_URL` (default `http://127.0.0.1:8000`). Never puts server-side secrets in `VITE_*` variables.
- **In-Memory Session State (`frontend/src/app/AuthContext.tsx`):** Synthetic demo `sessionToken` is held strictly in React memory (never `localStorage`).
- **Confirmation Dialogs (`ConfirmDialog` in `frontend/src/components/ui.tsx`):** Destructive/security actions (lost-device revocation, key rotation, key compromise) require explicit confirmation and an audit reason.
- **Honest Labelling:** Simulated nodes are labelled `SIMULATED`; unreachable nodes show `NOT CONVERGED`; forward secrecy shows `NOT_ESTABLISHED`; Stage 11 benchmarks show `NOT RUN (Stage 11)`.

---

## 2. Implemented Pages (16)

1. `/` — `LandingPage` ("Trust changes. Security follows.")
2. `/login` — `DemoLoginPage` (Synthetic demo login + `Reset Demo Data`)
3. `/overview` — `OverviewPage` (KPIs, Recharts node delay chart, audit timeline, health)
4. `/identities` — `IdentityAccessPage` (Identity CRUD + 9-step policy evaluator)
5. `/devices` — `DevicesPage` (Devices table, lost-device workflow, replacement enrolment)
6. `/vault` — `VaultPage` (AES-256-GCM store + authorized decrypt + `in_flight` flag)
7. `/keys` — `KeysPage` (4-phase key rotation, compromise, backup manifest)
8. `/nodes` — `NodesPage` (3–7 simulated nodes, partition/recover/reconcile, convergence metrics)
9. `/incidents` — `IncidentsPage` (Incident center & proof-carrying receipt verification)
10. `/detector` — `DetectorPage` (Zero-ML deterministic rules & lateral-movement alerts)
11. `/messaging` — `MessagingPage` (AEAD messaging lab, replay/wrong-recipient tests, `NOT_ESTABLISHED` FS)
12. `/audit` — `AuditPage` (Searchable ledger, hash-chain verification, non-destructive tamper demo)
13. `/benchmarks` — `BenchmarksPage` (Truthful `NOT RUN` Stage 11 status + live node delays)
14. `/scenarios` — `ScenariosPage` (14 resettable scenarios wired to live backend endpoints)
15. `/scorecard` — `ScorecardPage` (Live gate scorecard from `GET /api/v1/evidence/scorecard`)
16. `/settings` — `SettingsPage` (Dark/light theme toggle, reduced-motion toggle, disclosures)

---

## 3. Setup & Run Commands

```sh
# 1. Start FastAPI backend
py -3.12 -m alembic -c backend/alembic.ini upgrade head
py -3.12 -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000

# 2. Start Vite frontend (in frontend/)
npm install
npm run dev
```

- **Frontend Tests:** `npm run test` (`vitest run`: **4 passed**, `exit=0`)
- **Type Check & Production Build:** `npm run build` (`tsc -b && vite build`: **`exit=0`**)
