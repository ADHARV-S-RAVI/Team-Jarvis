# Q-SHIELD — API Reference (`/api/v1`)

All endpoints run locally on `http://127.0.0.1:8000` and return `X-Correlation-ID` headers. Structured errors return `400` (`validation_error`), `403` (`forbidden`), `404` (`not_found`), `409` (`conflict`), or `422` (schema validation) with `{"error", "message", "correlation_id"}` and never leak plaintext, keys, or session tokens.

## Endpoint Groups (66 Routes)

| Group | Endpoints |
| :--- | :--- |
| **Health & Simulation** | `GET /api/v1/health`, `POST /api/v1/simulation/reset`, `POST /api/v1/auth/demo-login`, `GET /api/v1/evidence/scorecard` |
| **Identities & Resources** | `POST /api/v1/identities`, `GET /api/v1/identities`, `GET /api/v1/identities/{actor_id}`, `POST /api/v1/resources`, `GET /api/v1/resources`, `GET /api/v1/resources/{resource_id}` |
| **Devices & Sessions** | `POST /api/v1/devices`, `POST /api/v1/devices/enroll`, `GET /api/v1/devices`, `GET /api/v1/devices/{device_id}`, `POST /api/v1/devices/{device_id}/{suspend,restore,revoke,replace}`, `POST /api/v1/sessions`, `GET /api/v1/sessions`, `POST /api/v1/sessions/validate`, `POST /api/v1/sessions/{session_id}/revoke` |
| **Policy & Vault** | `POST /api/v1/policy/evaluate`, `POST /api/v1/vault/resources`, `POST /api/v1/vault/resources/{resource_id}/read` |
| **Revocations & Incidents** | `POST /api/v1/revocations`, `GET /api/v1/revocations/{subject_type}/{subject_id}`, `POST /api/v1/incidents/lost-device`, `GET /api/v1/incidents`, `GET /api/v1/incidents/{incident_id}`, `GET /api/v1/incidents/{incident_id}/receipt`, `GET /api/v1/incidents/{incident_id}/verify` |
| **Simulated Nodes** | `GET /api/v1/nodes`, `POST /api/v1/nodes/configure`, `POST /api/v1/nodes/{node_id}/{partition,recover,latency}`, `POST /api/v1/nodes/reconcile`, `GET /api/v1/nodes/metrics` |
| **Keys, Rotation & Backups** | `GET /api/v1/keys`, `POST /api/v1/keys/generate`, `POST /api/v1/keys/rotate`, `POST /api/v1/keys/{key_id}/compromise`, `POST /api/v1/keys/rotate/journaled`, `POST /api/v1/keys/recover/{operation_id}`, `POST /api/v1/keys/backups/{create,verify,restore}` |
| **Audit Ledger** | `GET /api/v1/audit/events`, `GET /api/v1/audit/events/{event_id}`, `POST /api/v1/audit/verify`, `GET /api/v1/audit/timeline/{correlation_id}`, `GET /api/v1/audit/export`, `POST /api/v1/audit/tamper-demo` |
| **Detector** | `POST /api/v1/detector/ingest`, `POST /api/v1/detector/run`, `GET /api/v1/detector/alerts`, `POST /api/v1/detector/metrics`, `GET /api/v1/detector/rules` |
| **Messaging** | `POST /api/v1/messages/send`, `POST /api/v1/messages/{message_id}/deliver`, `GET /api/v1/messages`, `POST /api/v1/messages/recover`, `POST /api/v1/messages/resumption-token`, `POST /api/v1/messages/resume`, `GET /api/v1/messages/security-status` |

## Example Synthetic Requests

```bash
# Reset synthetic demo state
curl -X POST http://127.0.0.1:8000/api/v1/simulation/reset

# Issue demo session for synthetic user 'alice'
curl -X POST http://127.0.0.1:8000/api/v1/auth/demo-login \
  -H "Content-Type: application/json" -d '{"actor_id":"alice"}'

# Evaluate 9-step fail-closed authorization
curl -X POST http://127.0.0.1:8000/api/v1/policy/evaluate \
  -H "Content-Type: application/json" \
  -d '{"actor_id":"alice","session_id":"<sid>","session_token":"<tok>","device_id":"dev-alice-1","resource_id":"res-alpha","action":"resource:read"}'
```
