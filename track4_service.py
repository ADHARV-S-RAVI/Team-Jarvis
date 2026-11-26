#!/usr/bin/env python3
"""
Q-SHIELD Track 4 Toolkit Adapter (track4_service.py).

Standalone process-per-request JSON-over-stdin/stdout adapter.
- Reads exactly one UTF-8 JSON object from stdin to EOF.
- Writes exactly one valid JSON object to stdout.
- Sends sanitized diagnostics only to stderr.
- Persists state durably in TRACK4_STATE_DIR (or OS temp directory).

Note: Official organizer docs/adapter-v1.md and validator were not present
during Stage 1; this implementation follows the verified Q-SHIELD PRD/TRD
contract and must be reconciled if the official organizer schema differs.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from pqcrypto.kem import ml_kem_768 as ml_kem

DEFAULT_STATE_SUBDIR = "qshield_track4_state"
STATE_FILENAME = "adapter_state.json"
MAX_TEXT_LEN = 256
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")


def _log_diag(message: str) -> None:
    """Write a sanitized diagnostic line to stderr (never stdout)."""
    safe = _CONTROL_CHAR_RE.sub(" ", message)[:MAX_TEXT_LEN]
    sys.stderr.write(f"[track4_service] {safe}\n")
    sys.stderr.flush()


def _sanitize_id(value: str) -> str:
    """Normalize control characters and cap length for safe audit storage."""
    return _CONTROL_CHAR_RE.sub("_", value)[:MAX_TEXT_LEN]


def resolve_state_dir() -> Path:
    """Resolve persistent writable state directory from TRACK4_STATE_DIR or OS temp."""
    env_dir = os.environ.get("TRACK4_STATE_DIR", "").strip()
    if env_dir:
        return Path(env_dir)
    return Path(tempfile.gettempdir()) / DEFAULT_STATE_SUBDIR


class AdapterStateStore:
    """Durable, atomic JSON file-backed state store for process-per-request execution."""

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.state_path = state_dir / STATE_FILENAME

    def load(self) -> dict[str, Any]:
        """Load persisted state, or return an uninitialized default structure."""
        if not self.state_path.exists():
            return {
                "initialized": False,
                "owners": {},
                "contents": {},
                "disabled_actors": [],
                "revoked_actors": [],
                "key_material": {},
                "audit_log": {},
            }
        raw = self.state_path.read_text(encoding="utf-8")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Corrupted state file: root is not a JSON object")
        return data

    def save(self, state: dict[str, Any]) -> None:
        """Atomically persist state to disk before acknowledging any mutation."""
        self.state_dir.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(state, ensure_ascii=False, separators=(",", ":"))
        fd, tmp_path = tempfile.mkstemp(
            prefix=".state_", suffix=".tmp", dir=str(self.state_dir)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, self.state_path)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise


class Track4AdapterService:
    """Business logic for the five Track 4 adapter operations."""

    def __init__(self, store: AdapterStateStore) -> None:
        self.store = store

    def dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        """Validate operation name and dispatch to the corresponding handler."""
        op = request.get("op")
        if not isinstance(op, str) or not op:
            return _error("missing_field", "Field 'op' must be a non-empty string")

        handlers = {
            "setup": self._handle_setup,
            "read": self._handle_read,
            "revoke": self._handle_revoke,
            "audit": self._handle_audit,
            "protected_read": self._handle_protected_read,
        }
        handler = handlers.get(op)
        if handler is None:
            return _error("unknown_operation", f"Unsupported operation: {_sanitize_id(op)}")
        return handler(request)

    def _is_actor_authorized(
        self, state: dict[str, Any], actor: str, asset: str
    ) -> bool:
        """Check initialization, actor active status, asset existence, and ownership."""
        if not state.get("initialized", False):
            return False
        if actor in state.get("disabled_actors", []):
            return False
        if actor in state.get("revoked_actors", []):
            return False
        owners = state.get("owners", {})
        contents = state.get("contents", {})
        if asset not in owners or asset not in contents:
            return False
        return owners[asset] == actor

    def _record_audit(
        self,
        state: dict[str, Any],
        request_id: str,
        actor: str,
        op: str,
        decision: str,
    ) -> None:
        """Record sanitized audit decision keyed by exact request_id."""
        audit_log = state.setdefault("audit_log", {})
        audit_log[request_id] = {
            "request_id": request_id,
            "actor": _sanitize_id(actor),
            "op": op,
            "decision": decision,
        }

    def _handle_setup(self, request: dict[str, Any]) -> dict[str, Any]:
        owners = request.get("owners")
        contents = request.get("contents")
        if "disabled" in request:
            disabled_actors = request.get("disabled")
        else:
            disabled_actors = request.get("disabled_actors", [])
        key_material = request.get("key_material", {})

        if not isinstance(owners, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in owners.items()
        ):
            return _error("missing_field", "Field 'owners' must be a string-to-string map")
        if not isinstance(contents, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in contents.items()
        ):
            return _error("missing_field", "Field 'contents' must be a string-to-string map")
        if not isinstance(disabled_actors, list) or not all(
            isinstance(a, str) for a in disabled_actors
        ):
            return _error("invalid_field", "Field 'disabled' must be a list of strings")

        new_state = {
            "initialized": True,
            "owners": dict(owners),
            "contents": dict(contents),
            "disabled_actors": list(dict.fromkeys(disabled_actors)),
            "revoked_actors": [],
            "key_material": key_material if isinstance(key_material, (dict, str)) else {},
            "audit_log": {},
        }
        self.store.save(new_state)
        return {"ready": True}

    def _handle_read(self, request: dict[str, Any]) -> dict[str, Any]:
        actor = _require_non_empty_str(request, "actor")
        asset = _require_non_empty_str(request, "asset")
        request_id = _require_non_empty_str(request, "request_id")
        if isinstance(actor, dict):
            return actor
        if isinstance(asset, dict):
            return asset
        if isinstance(request_id, dict):
            return request_id

        state = self.store.load()
        allowed = self._is_actor_authorized(state, actor, asset)
        decision = "allow" if allowed else "deny"
        self._record_audit(state, request_id, actor, "read", decision)
        self.store.save(state)

        if not allowed:
            return {"decision": "deny"}
        return {
            "decision": "allow",
            "request_id": request_id,
            "asset": asset,
            "body": state["contents"][asset],
        }

    def _handle_revoke(self, request: dict[str, Any]) -> dict[str, Any]:
        actor = _require_non_empty_str(request, "actor")
        if isinstance(actor, dict):
            return actor

        state = self.store.load()
        if not state.get("initialized", False):
            return _error("not_initialized", "Adapter state has not been initialized via setup")

        revoked = state.setdefault("revoked_actors", [])
        if actor not in revoked:
            revoked.append(actor)

        request_id = request.get("request_id")
        if isinstance(request_id, str) and request_id:
            self._record_audit(state, request_id, actor, "revoke", "revoked")

        self.store.save(state)
        return {"status": "revoked", "actor": actor, "revoked": True}

    def _handle_audit(self, request: dict[str, Any]) -> dict[str, Any]:
        request_id = _require_non_empty_str(request, "request_id")
        if isinstance(request_id, dict):
            return request_id

        state = self.store.load()
        record = state.get("audit_log", {}).get(request_id)
        if record is None:
            return {
                "found": False,
                "request_id": request_id,
                "decision": "unknown",
            }
        return {
            "found": True,
            "request_id": record["request_id"],
            "decision": record["decision"],
            "actor": record["actor"],
            "op": record["op"],
        }

    def _handle_protected_read(self, request: dict[str, Any]) -> dict[str, Any]:
        actor = _require_non_empty_str(request, "actor")
        asset = _require_non_empty_str(request, "asset")
        challenge = _require_non_empty_str(request, "challenge")
        public_key_b64 = _require_non_empty_str(request, "public_key")
        if isinstance(actor, dict):
            return actor
        if isinstance(asset, dict):
            return asset
        if isinstance(challenge, dict):
            return challenge
        if isinstance(public_key_b64, dict):
            return public_key_b64

        state = self.store.load()
        allowed = self._is_actor_authorized(state, actor, asset)
        request_id = request.get("request_id")
        if isinstance(request_id, str) and request_id:
            self._record_audit(
                state,
                request_id,
                actor,
                "protected_read",
                "allow" if allowed else "deny",
            )
            self.store.save(state)

        if not allowed:
            return {"decision": "deny"}

        try:
            pk_bytes = base64.b64decode(public_key_b64.encode("ascii"), validate=True)
        except (binascii.Error, UnicodeEncodeError):
            _log_diag("protected_read rejected malformed Base64 public_key")
            return _error("invalid_public_key", "Field 'public_key' must be valid standard Base64")

        if len(pk_bytes) != ml_kem.PUBLIC_KEY_SIZE:
            _log_diag(
                f"protected_read rejected public_key length={len(pk_bytes)} "
                f"(expected {ml_kem.PUBLIC_KEY_SIZE})"
            )
            return _error(
                "invalid_public_key",
                f"ML-KEM-768 public key must be {ml_kem.PUBLIC_KEY_SIZE} bytes",
            )

        stored_body: str = state["contents"][asset]
        ciphertext, shared_secret = ml_kem.encrypt(pk_bytes)
        try:
            mac_input = (challenge + stored_body).encode("utf-8")
            mac_hex = hmac.new(shared_secret, mac_input, hashlib.sha256).hexdigest()
        finally:
            del shared_secret

        response: dict[str, Any] = {
            "decision": "allow",
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "proof": mac_hex,
        }
        if isinstance(request_id, str) and request_id:
            response["request_id"] = request_id
        return response


def _require_non_empty_str(request: dict[str, Any], field: str) -> str | dict[str, Any]:
    val = request.get(field)
    if not isinstance(val, str) or not val:
        return _error("missing_field", f"Field '{field}' must be a non-empty string")
    return val


def _error(code: str, message: str) -> dict[str, Any]:
    return {"error": code, "message": message}


def process_raw_input(raw_stdin: str, state_dir: Path | None = None) -> dict[str, Any]:
    """Parse one JSON object from raw stdin text and execute the adapter request."""
    try:
        parsed = json.loads(raw_stdin)
    except json.JSONDecodeError as exc:
        _log_diag(f"Invalid JSON input: {exc.msg}")
        return _error("invalid_json", "Input must be a single valid UTF-8 JSON object")

    if not isinstance(parsed, dict):
        _log_diag("JSON root is not an object")
        return _error("invalid_json", "Input root must be a JSON object")

    store = AdapterStateStore(state_dir or resolve_state_dir())
    service = Track4AdapterService(store)
    return service.dispatch(parsed)


def main() -> int:
    """Entry point: read stdin to EOF, write exactly one JSON object to stdout."""
    try:
        raw_input = sys.stdin.read()
        response = process_raw_input(raw_input)
    except Exception as exc:  # fail closed without leaking internals
        _log_diag(f"Unhandled adapter error: {type(exc).__name__}")
        response = _error("internal_error", "Adapter execution failed")

    sys.stdout.write(json.dumps(response, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
