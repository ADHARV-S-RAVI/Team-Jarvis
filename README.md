# Q-SHIELD
### Quantum-Ready Trust & Revocation Control Plane

**Team Jarvis | Yugaantar DevForge | Track 4 — Trust, but Verify**

Q-SHIELD is a security-focused prototype designed to demonstrate identity verification, role-based access control, device lifecycle management, cryptographic protection, revocation propagation and tamper-evident auditing in a distributed environment.

It provides a centralized trust and revocation control plane with a web dashboard for managing identities, devices, sessions, security events and protected resources.

---

## Project Preview

<!-- IMAGE 1: Replace with the Q-SHIELD main dashboard screenshot -->
<p align="center">
  <img src="docs/assets/qshield-dashboard.png" alt="Q-SHIELD Dashboard" width="90%">
</p>

<!-- IMAGE 2: Replace with the authentication and identity verification screenshot -->
<p align="center">
  <img src="docs/assets/qshield-authentication.png" alt="Q-SHIELD Authentication" width="90%">
</p>

<!-- IMAGE 3: Replace with the security integrity and audit screenshot -->
<p align="center">
  <img src="docs/assets/qshield-security.png" alt="Q-SHIELD Security and Audit Center" width="90%">
</p>

---

## Key Capabilities

| Capability | Description |
|---|---|
| Identity & Authentication | Password authentication, account provisioning and WebAuthn/passkey support. |
| Role-Based Access Control | Separate User, Employee and Admin permissions, enforced by the backend. |
| Device Lifecycle | Device registration, trust status and lost-device incident handling. |
| Revocation Control | Revocation propagation across simulated distributed nodes. |
| Cryptographic Protection | ML-KEM-768 integration, AES-256-GCM, HKDF-SHA-256 and HMAC-SHA-256. |
| Key Lifecycle | Journaled key rotation, recovery and backup integrity verification. |
| Tamper-Evident Audit | Hash-chained security event ledger. |
| Security Analytics | Deterministic security-event detection and risk analysis. |
| Secure Messaging | Message integrity and replay protection. |
| File Protection | Role- and permission-based access to protected resources. |
| Security Dashboard | Centralized visibility into identities, devices, sessions and security events. |

## Authentication & Identity Verification

Q-SHIELD uses backend-verified authentication rather than demo login.

- Passwords are protected using salted Scrypt hashing.
- User registration and account provisioning are supported.
- User, Employee and Admin roles are enforced through backend RBAC.
- HTTP-only session cookies support authenticated sessions.
- Session expiration, revocation and logout invalidation are implemented.
- WebAuthn/passkey authentication is integrated.
- Compatible platform authenticators may use Windows Hello for local user verification.

**Biometric privacy:** Windows Hello performs biometric verification locally. Q-SHIELD does not receive Windows Hello facial data or biometric templates.

**Camera status:** Camera preview is available with explicit permission. Custom facial biometric matching is not implemented. Camera preview must not be treated as proof of identity.

Real Windows Hello hardware verification remains subject to device-level testing.

## Security Architecture

Q-SHIELD follows a layered security architecture:

1. **Identity Layer:** Account authentication and identity verification.
2. **Authorization Layer:** Backend-enforced role and resource permissions.
3. **Device Trust Layer:** Device lifecycle and trust-state management.
4. **Cryptographic Layer:** Encryption, key derivation and integrity protection.
5. **Revocation Layer:** Trust revocation and simulated node propagation.
6. **Audit Layer:** Hash-chained security event records.
7. **Detection Layer:** Deterministic analysis of security events.

### Cryptographic Components

| Component | Implementation |
|---|---|
| Post-quantum key encapsulation | ML-KEM-768 |
| Symmetric encryption | AES-256-GCM |
| Key derivation | HKDF-SHA-256 |
| Message authentication | HMAC-SHA-256 |
| Password hashing | Scrypt |
| Authentication | WebAuthn / Passkeys |
| Audit integrity | Hash-chained ledger |

Cryptographic operations use established libraries rather than custom cryptographic primitives.

## System Architecture

```text
             Q-SHIELD Web Application
                       |
                React + TypeScript
                       |
                  FastAPI Backend
                       |
          Authentication & RBAC Layer
                       |
       +---------------+---------------+
       |               |               |
   Identity        Device &        Security
   Management      Revocation      Services
       |               |               |
       +---------------+---------------+
                       |
             Cryptographic Services
                       |
              Audit & Detection
                       |
             Database / Storage
                       |
             Simulated Trust Nodes
```

## Technology Stack

**Backend:** Python 3.12, FastAPI, SQLAlchemy, Alembic, Pydantic.

**Frontend:** React, TypeScript, Vite, Tailwind CSS.

**Security:** Scrypt, ML-KEM-768, AES-256-GCM, HKDF, HMAC, WebAuthn.

**Database:** SQLite with SQLAlchemy and Alembic migrations.

**Testing:** Pytest, HTTPX, Vitest, Playwright and the official Track 4 validator.

## Repository Structure

```text
Q-SHIELD/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── services/
│   │   ├── models.py
│   │   └── main.py
│   ├── migrations/
│   └── tests/
├── frontend/
│   └── src/
│       ├── app/
│       ├── components/
│       ├── pages/
│       └── services/
├── docs/
│   └── assets/
├── scripts/
├── tests/
├── tools/
├── track4_service.py
├── requirements.txt
└── README.md
```

## Setup & Execution

### 1. Clone the repository

```bash
git clone https://github.com/ADHARV-S-RAVI/Team-Jarvis.git
cd Team-Jarvis
```

### 2. Backend setup

```bash
py -3.12 -m venv .venv
```

Activate the virtual environment and install dependencies:

```bash
pip install -r requirements.txt
```

Configure the required environment variables using the project's environment example.

Run database migrations:

```bash
py -3.12 -m alembic -c backend/alembic.ini upgrade head
```

Start the backend:

```bash
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

### 3. Frontend setup

```bash
cd frontend
npm ci
npm run dev
```

Application endpoints:

- Frontend: `http://127.0.0.1:5173`
- Backend: `http://127.0.0.1:8000`

Refer to the project configuration for environment-specific settings.

## Testing & Verification

The following results were reported by the development verification runs:

| Test Suite | Result |
|---|---:|
| Backend tests | 54 passed |
| Adapter tests | 9 passed |
| Frontend tests | 7 passed |
| Frontend production build | Passed |
| Official Track 4 validator | 21/21 passed |
| Real-authentication Playwright E2E | Passed |

The reported authentication E2E workflow covers registration, login, invalid credentials, session persistence, role restrictions and logout.

Run the official validator from the toolkit directory:

```bash
py -3.12 validate.py --entry "../../track4_service.py"
```

Run backend tests:

```bash
py -3.12 -m pytest backend/tests/ -q
```

Run frontend tests and build:

```bash
cd frontend
npm run test
npm run build
```

Test counts should be updated whenever the test suite changes.

## Track 4 Evaluation Alignment

| Evaluation Area | Q-SHIELD Evidence |
|---|---|
| Security Correctness | Authentication, RBAC, cryptographic protection, revocation and integrity controls. |
| Live Security Assessment | Security assessment scripts, authorization tests and negative authentication scenarios. |
| Functionality & Reliability | Device lifecycle, key rotation, recovery, protected resources and automated tests. |
| Threat Model & Honesty | Documented security architecture, implementation status and limitations. |
| Performance & Overhead | Benchmarking scripts and measured operation results. |
| Usability & Documentation | Role-specific dashboards, authentication interface, setup instructions and technical documentation. |



## Team

**Team Jarvis**  
**Project:** Q-SHIELD — Quantum-Ready Trust & Revocation Control Plane  
**Event:** Yugaantar DevForge  
**Track:** Track 4 — Trust, but Verify

---

*Built as a security-focused prototype demonstrating identity, trust, revocation and cryptographic control mechanisms.*
