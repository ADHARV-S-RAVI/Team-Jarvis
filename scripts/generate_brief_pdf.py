#!/usr/bin/env python3
"""Generate the two-page Q-SHIELD Project Brief PDF using the official template structure."""

from __future__ import annotations

from pathlib import Path
import re
from playwright.sync_api import sync_playwright

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_PDF = REPO_ROOT / "reports" / "submission" / "QSHIELD_Project_Brief.pdf"

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<style>
  @page { size: Letter; margin: 0.55in 0.6in; }
  body { font-family: 'Segoe UI', Arial, sans-serif; color: #0f172a; font-size: 9.5pt; line-height: 1.38; margin: 0; }
  h1 { font-size: 16pt; color: #0b3b60; margin: 0 0 6px 0; border-bottom: 2px solid #0b3b60; padding-bottom: 4px; }
  h2 { font-size: 12pt; color: #0b3b60; margin: 8px 0 4px 0; }
  h3 { font-size: 10pt; color: #1e293b; margin: 8px 0 3px 0; }
  p, li { margin: 3px 0; }
  ul { padding-left: 16px; margin: 3px 0; }
  .meta { background: #f1f5f9; padding: 6px 10px; border-radius: 4px; font-size: 8.8pt; margin-bottom: 8px; }
  .diagram { background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 4px; padding: 6px 8px; font-family: Consolas, monospace; font-size: 7.8pt; white-space: pre; line-height: 1.25; margin: 5px 0; }
  table { width: 100%; border-collapse: collapse; font-size: 8.4pt; margin: 4px 0; }
  th, td { border: 1px solid #cbd5e1; padding: 3px 6px; text-align: left; vertical-align: top; }
  th { background: #e2e8f0; color: #0f172a; }
  .page-break { page-break-before: always; }
</style>
</head>
<body>
<h1>Track 4: Trust, but verify &mdash; Q-SHIELD</h1>
<h2>Page 1: USP, Architecture, and Observed Outcomes</h2>
<div class="meta">
  <strong>Project:</strong> Q-SHIELD &mdash; Quantum-Ready Trust &amp; Revocation Control Plane &nbsp;|&nbsp;
  <strong>Team:</strong> Yugaantar DevForge Track 4 Team<br>
  <strong>Demo Entry Point:</strong> <code>uvicorn backend.app.main:app --port 8000</code> + <code>npm run dev</code> (<code>http://127.0.0.1:5173</code>) &nbsp;|&nbsp;
  <strong>CLI Adapter:</strong> <code>track4_service.py</code>
</div>

<h3>Unique Selling Proposition (USP)</h3>
<p>Security operators and protected-resource owners need immediate, verifiable proof that lost devices, rotated keys, and tampered logs cannot be abused after trust changes. Q-SHIELD addresses silent post-revocation key reuse, partial-node stale access, crash-induced key inconsistency, and undetected lateral movement. Its distinguishing capability is <strong>Proof-Carrying Trust Changes</strong>: every authorization decision, revocation, 4-phase key rotation, signed backup, and message delivery emits deterministic cryptographic or ledger evidence under strict fail-closed enforcement.</p>

<h3>Architecture</h3>
<p>Q-SHIELD runs 100% offline with three decoupled layers: (1) the official Track 4 stdin/stdout JSON adapter (<code>track4_service.py</code>), (2) a FastAPI control plane (<code>fastapi 0.165.0</code>, <code>SQLAlchemy 2.1.9</code>, <code>alembic 1.20.1</code>, SQLite WAL), and (3) a 16-page React 18 + TypeScript operator console. Cryptography uses vetted libraries only: <code>pqcrypto 0.4.0</code> (ML-KEM-768) and <code>cryptography 50.0.2</code> (AES-256-GCM, HKDF-SHA-256), plus stdlib HMAC-SHA-256. Working components include the 9-step fail-closed authz pipeline, encrypted vault, device/session lifecycle, 3&ndash;7 in-process simulated nodes, 7-point crash recovery journal, hash-chained audit ledger, zero-ML lateral-movement detector, and AEAD messaging with durable replay ledger. Out-of-scope components: physical distributed nodes, HSM key storage, ML-DSA signatures, and ephemeral forward-secrecy ratchets.</p>
<div class="diagram">[React 18 UI :5173] --HTTP--&gt; [FastAPI Control Plane :8000] &lt;--&gt; [9-Step Fail-Closed Authz]
[Track 4 CLI Adapter] --------&gt; [Crypto/Vault | Simulated Nodes | Audit | Detector | Messaging]
                                        |
                                        v
                        [SQLite WAL + .qshield_keys/master_kek.key]</div>

<h3>Five-Minute Walkthrough &amp; Observed Benchmarks</h3>
<p><strong>Demo Sequence:</strong> <code>docs/demo_script.md</code> (5-minute live local walkthrough covering authorized read/denial, lost-device receipt, simulated-node rotation cutoff, crash/backup tamper rejection, audit + lateral movement alerts, messaging replay/FS status, and scorecard). <em>Fallback video URL: Not recorded (live local reproducible run &amp; Playwright E2E screenshots verified).</em></p>
<p><strong>Observed Outcome:</strong> Official Track 4 validator passed <code>21/21</code> checks (<code>exit 0</code>); backend passed <code>46/46</code> tests; adapter passed <code>9/9</code> tests; frontend passed <code>4/4</code> Vitest + Vite build + Playwright E2E across <code>16</code> routes and <code>3</code> viewports with <code>0</code> console errors. Benchmarks (<code>perf_counter_ns</code>, 35 ops, 1,475 samples, seed=42): ML-KEM-768 keygen <code>0.160 ms</code> p50, AES-256-GCM 1KB encrypt <code>0.0067 ms</code> p50, 9-step authz <code>2.860 ms</code> p50, 7-simulated-node convergence <code>2.923 ms</code> p50.</p>

<div class="page-break"></div>
<h2>Page 2: One-Page Threat Model</h2>

<h3>Assets</h3>
<ul>
  <li><strong>Vault Plaintext &amp; Per-Resource DEKs:</strong> Confidentiality and integrity via AES-256-GCM + AAD (<code>vault_entries</code>).</li>
  <li><strong>Master KEK &amp; Key Versions (<code>.qshield_keys/</code>):</strong> Confidentiality and lifecycle integrity; retired/compromised keys denied post-cutoff.</li>
  <li><strong>Identities, Devices &amp; Sessions:</strong> Authentication and irreversible revocation state across restarts.</li>
  <li><strong>Hash-Chained Audit Ledger &amp; Backups:</strong> Tamper-evidence via <code>prev_hash</code> + <code>entry_hash</code> + HMAC-SHA-256.</li>
</ul>

<h3>Adversaries</h3>
<ul>
  <li><strong>Unauthorized / Wrong-Owner Caller:</strong> Attempts cross-owner vault read or privileged operator action.</li>
  <li><strong>Stolen / Lost Device Holder:</strong> Possesses previously valid session token or device credential prior to revocation.</li>
  <li><strong>Insider / Malicious Operator:</strong> Attempts unapproved privilege escalation, lateral movement, or audit/backup tampering.</li>
  <li><strong>Network / Replay Attacker:</strong> Replays, reorders, drops, or misdirects encrypted messages across peers.</li>
</ul>

<h3>Trust Boundaries</h3>
<p>Trust boundaries lie between: (1) UI/CLI callers and the FastAPI/adapter input boundary (enforced by Pydantic v2 + 9-step fail-closed authz), (2) control plane and SQLite/<code>.qshield_keys/</code> storage (enforced by AES-256-GCM + HMAC), and (3) control plane and simulated nodes (tracked via explicit convergence acknowledgements).</p>

<h3>Assumptions</h3>
<p>Assumes host OS filesystem permissions protect <code>.qshield_keys/</code> and SQLite, system clocks stay within configured skew/reorder tolerance (500ms / 5000ms), and operators follow reset/migration procedures.</p>

<h3>Defenses &amp; Evidence</h3>
<table>
  <tr><th>Threat</th><th>Working Defense</th><th>Verified Evidence</th></tr>
  <tr><td>Wrong-owner / unauthorized read</td><td>9-step fail-closed authz + AES-256-GCM</td><td><code>test_authz_pipeline.py</code> (11/11), <code>validate.py</code> (21/21)</td></tr>
  <tr><td>Lost device / session reuse</td><td>Irreversible revocation + incident receipt</td><td><code>test_stage4_devices_sessions.py</code> (4/4)</td></tr>
  <tr><td>Stale key / mid-rotation crash</td><td>4-phase cutoff + 7-point crash journal + HMAC backup</td><td><code>test_stage5</code> (3/3), <code>test_stage6</code> (9/9)</td></tr>
  <tr><td>Audit tamper &amp; lateral movement</td><td>Hash-chain verifier + zero-ML deterministic rules</td><td><code>test_stage7</code> (2/2), <code>test_stage8</code> (3/3, practice F1=1.0)</td></tr>
  <tr><td>Message replay &amp; cross-peer reuse</td><td>Recipient AAD + durable replay ledger + peer binding</td><td><code>test_stage9_messaging.py</code> (3/3)</td></tr>
</table>

<h3>Exclusions &amp; Remaining Risks</h3>
<p><strong>Largest Remaining Risks:</strong> (1) Local filesystem KEK storage without HSM/KMS; (2) <strong>Simulated</strong> in-process nodes rather than physical distributed hosts; (3) Forward secrecy honestly marked <strong>NOT ESTABLISHED</strong> (no per-message ephemeral ratchet); (4) <strong>ML-DSA NOT IMPLEMENTED</strong>; (5) Practice detector F1=1.0 is on synthetic fixtures and does not establish production security.</p>
</body>
</html>
"""


def main() -> int:
    OUT_PDF.parent.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_content(HTML, wait_until="load")
        page.pdf(path=str(OUT_PDF), format="Letter", print_background=True)
        browser.close()
    data = OUT_PDF.read_bytes()
    pages = len(re.findall(rb"/Type\s*/Page\b", data))
    print(f"PDF_SAVED={OUT_PDF} SIZE={len(data)} PAGES={pages}")
    assert pages == 2, f"Expected 2 pages, got {pages}"
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
