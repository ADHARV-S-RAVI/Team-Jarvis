"""Secure messaging lab: AEAD recipient binding, replay ledger, loss/reorder recovery, and peer-bound resumption (Stage 9)."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.crypto.provider import (
    AES_256_KEY_BYTES,
    ALG_AES_256_GCM,
    CryptoError,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    hkdf_sha256,
)
from backend.app.db.models import (
    Actor,
    AuthSession,
    Message,
    ReplayRecord,
    SessionResumptionToken,
)
from backend.app.devices.service import DomainPermissionError
from backend.app.keys.service import KeyMaterialStore, get_active_key_metadata
from backend.app.services.foundation_service import (
    DomainNotFoundError,
    DomainValidationError,
    record_audit_event,
)

PROTOCOL_VERSION = "1.0"
MAX_REORDER_BUFFER = 32


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _derive_msg_key(key_version: int, session_id: str, key_store: KeyMaterialStore | None = None) -> bytes:
    store = key_store or KeyMaterialStore()
    kek = store.ensure_version_secret(key_version)
    info = f"qshield:msg-aead:v{key_version}:{session_id}".encode("utf-8")
    return hkdf_sha256(kek, AES_256_KEY_BYTES, salt=None, info=info)


def _derive_resumption_key(key_store: KeyMaterialStore | None = None) -> bytes:
    store = key_store or KeyMaterialStore()
    return store.derive_wrapping_key(1, purpose="session-resumption-token")


def _build_message_aad(
    *,
    message_id: str,
    sender_id: str,
    recipient_id: str,
    session_id: str,
    key_version: int,
    sequence: int,
    timestamp_iso: str,
    expiry_iso: str,
) -> bytes:
    payload = {
        "protocol_version": PROTOCOL_VERSION,
        "message_id": message_id,
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "session_id": session_id,
        "key_version": key_version,
        "sequence": sequence,
        "timestamp": timestamp_iso,
        "expiry": expiry_iso,
        "algorithm": ALG_AES_256_GCM,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def send_secure_message(
    db: Session,
    *,
    sender_id: str,
    recipient_id: str,
    session_id: str,
    plaintext: str,
    ttl_seconds: int = 300,
    simulate_pending_recovery: bool = False,
    correlation_id: str = "msg-send",
    key_store: KeyMaterialStore | None = None,
) -> Message:
    """Encrypt a synthetic message with AES-256-GCM and bind recipient/session/key in AAD."""
    sender = db.get(Actor, sender_id)
    recipient = db.get(Actor, recipient_id)
    if sender is None or not sender.enabled or recipient is None or not recipient.enabled:
        raise DomainValidationError("Sender or recipient identity is missing or disabled")

    session = db.get(AuthSession, session_id)
    if session is None or session.actor_id != sender_id or session.revoked_at is not None:
        raise DomainPermissionError("Authenticated sender session is invalid or revoked")
    if _as_utc(session.expires_at) <= datetime.now(timezone.utc):
        raise DomainPermissionError("Authenticated sender session is expired")

    active_key = get_active_key_metadata(db)
    max_seq = (
        db.execute(select(func.max(Message.sequence)).where(Message.session_id == session_id)).scalar_one_or_none()
        or 0
    )
    next_seq = max_seq + 1
    msg_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=ttl_seconds)

    aad = _build_message_aad(
        message_id=msg_id,
        sender_id=sender_id,
        recipient_id=recipient_id,
        session_id=session_id,
        key_version=active_key.version,
        sequence=next_seq,
        timestamp_iso=now.isoformat(),
        expiry_iso=expires_at.isoformat(),
    )
    msg_key = _derive_msg_key(active_key.version, session_id, key_store=key_store)
    sealed = aes_gcm_encrypt(msg_key, plaintext.encode("utf-8"), aad=aad)
    del msg_key

    msg = Message(
        id=msg_id,
        sender_id=sender_id,
        recipient_id=recipient_id,
        session_id=session_id,
        sequence=next_seq,
        key_version=active_key.version,
        nonce_b64=base64.b64encode(sealed.nonce).decode("ascii"),
        ciphertext_b64=base64.b64encode(sealed.ciphertext).decode("ascii"),
        tag_b64=base64.b64encode(sealed.tag).decode("ascii"),
        aad_b64=base64.b64encode(aad).decode("ascii"),
        protocol_version=PROTOCOL_VERSION,
        status="pending_recovery" if simulate_pending_recovery else "encrypted",
        created_at=now,
        expires_at=expires_at,
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)

    # Never log plaintext or key material
    record_audit_event(
        db,
        actor_id=sender_id,
        action="messaging:send",
        target=msg.id,
        decision="ALLOW",
        reason=msg.status.upper(),
        correlation_id=correlation_id,
        metadata={"recipient_id": recipient_id, "session_id": session_id, "sequence": next_seq},
    )
    return msg


def deliver_secure_message(
    db: Session,
    *,
    message_id: str,
    recipient_id: str,
    override_aad_b64: str | None = None,
    correlation_id: str = "msg-deliver",
    key_store: KeyMaterialStore | None = None,
) -> dict[str, object]:
    """
    Verify recipient binding, expiry, completeness, and durable replay ledger BEFORE decryption.
    Never returns plaintext on authentication or replay failure.
    """
    msg = db.get(Message, message_id)
    if msg is None:
        raise DomainNotFoundError(f"Message '{message_id}' not found")

    # 1. Recipient binding check BEFORE decryption
    if recipient_id != msg.recipient_id:
        record_audit_event(
            db,
            actor_id=recipient_id,
            action="messaging:deliver",
            target=message_id,
            decision="DENY",
            reason="RECIPIENT_MISMATCH",
            correlation_id=correlation_id,
        )
        raise DomainPermissionError("Recipient identity does not match authenticated message recipient")

    # 2. Completeness check
    if not msg.nonce_b64 or not msg.ciphertext_b64 or not msg.tag_b64 or not msg.aad_b64:
        msg.status = "failed"
        msg.failure_reason = "INCOMPLETE_MESSAGE"
        db.commit()
        raise DomainValidationError("Incomplete message discarded")

    # 3. Expiry check
    now = datetime.now(timezone.utc)
    if _as_utc(msg.expires_at) <= now:
        msg.status = "failed"
        msg.failure_reason = "MESSAGE_EXPIRED"
        db.commit()
        raise DomainValidationError("Expired message rejected")

    # 4. Durable replay ledger check (duplicate message_id or repeated sequence)
    dup_id = db.execute(select(ReplayRecord).where(ReplayRecord.message_id == message_id)).scalar_one_or_none()
    dup_seq = db.execute(
        select(ReplayRecord).where(
            ReplayRecord.session_id == msg.session_id,
            ReplayRecord.sequence == msg.sequence,
        )
    ).scalar_one_or_none()
    if dup_id is not None or dup_seq is not None:
        msg.status = "rejected/replayed"
        msg.failure_reason = "DUPLICATE_REPLAY"
        db.commit()
        record_audit_event(
            db,
            actor_id=recipient_id,
            action="messaging:deliver",
            target=message_id,
            decision="DENY",
            reason="DUPLICATE_REPLAY",
            correlation_id=correlation_id,
        )
        raise DomainValidationError("Duplicate message replay rejected")

    # 5. Decrypt and verify AEAD tag + AAD
    aad_bytes = base64.b64decode((override_aad_b64 or msg.aad_b64).encode("ascii"), validate=True)
    msg_key = _derive_msg_key(msg.key_version, msg.session_id, key_store=key_store)
    try:
        pt_bytes = aes_gcm_decrypt(
            msg_key,
            nonce=base64.b64decode(msg.nonce_b64.encode("ascii"), validate=True),
            ciphertext=base64.b64decode(msg.ciphertext_b64.encode("ascii"), validate=True),
            tag=base64.b64decode(msg.tag_b64.encode("ascii"), validate=True),
            aad=aad_bytes,
        )
    except (CryptoError, Exception) as exc:
        msg.status = "failed"
        msg.failure_reason = "AEAD_AUTHENTICATION_FAILED"
        db.commit()
        raise DomainValidationError("Message authentication failed; no plaintext released") from exc
    finally:
        del msg_key

    # 6. Persist replay record and mark delivered
    db.add(
        ReplayRecord(
            message_id=msg.id,
            recipient_id=recipient_id,
            session_id=msg.session_id,
            sequence=msg.sequence,
            result="ACCEPTED",
        )
    )
    msg.status = "delivered"
    msg.delivered_at = now
    msg.failure_reason = None
    db.commit()
    db.refresh(msg)

    record_audit_event(
        db,
        actor_id=recipient_id,
        action="messaging:deliver",
        target=msg.id,
        decision="ALLOW",
        reason="DELIVERED",
        correlation_id=correlation_id,
        metadata={"sequence": msg.sequence},
    )
    return {
        "message_id": msg.id,
        "status": msg.status,
        "sequence": msg.sequence,
        "sender_id": msg.sender_id,
        "recipient_id": msg.recipient_id,
        "plaintext": pt_bytes.decode("utf-8"),
    }


def recover_pending_messages(
    db: Session,
    *,
    session_id: str,
    recipient_id: str,
    correlation_id: str = "msg-recover",
    key_store: KeyMaterialStore | None = None,
) -> dict[str, object]:
    """Bounded loss/reordering recovery delivering complete authenticated messages in sequence order."""
    pending = list(
        db.execute(
            select(Message)
            .where(Message.session_id == session_id, Message.status == "pending_recovery")
            .order_by(Message.sequence.asc())
            .limit(MAX_REORDER_BUFFER)
        )
        .scalars()
        .all()
    )
    delivered_ids: list[str] = []
    failed_ids: list[str] = []

    for msg in pending:
        try:
            deliver_secure_message(
                db,
                message_id=msg.id,
                recipient_id=recipient_id,
                correlation_id=correlation_id,
                key_store=key_store,
            )
            delivered_ids.append(msg.id)
        except (DomainValidationError, DomainPermissionError):
            failed_ids.append(msg.id)

    return {
        "session_id": session_id,
        "delivered_count": len(delivered_ids),
        "failed_count": len(failed_ids),
        "delivered_ids": delivered_ids,
        "failed_ids": failed_ids,
    }


def issue_resumption_token(
    db: Session,
    *,
    session_id: str,
    actor_id: str,
    peer_id: str,
    ttl_seconds: int = 300,
    key_store: KeyMaterialStore | None = None,
) -> dict[str, object]:
    """Issue an AEAD-protected, expiry-bound, peer-bound session resumption token."""
    session = db.get(AuthSession, session_id)
    if session is None or session.actor_id != actor_id or session.peer_id != peer_id:
        raise DomainPermissionError("Session does not match actor and peer")
    if session.revoked_at is not None or _as_utc(session.expires_at) <= datetime.now(timezone.utc):
        raise DomainPermissionError("Session is revoked or expired")

    token_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=ttl_seconds)
    payload = json.dumps(
        {
            "token_id": token_id,
            "session_id": session_id,
            "actor_id": actor_id,
            "peer_id": peer_id,
            "expires_at": expires_at.isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    r_key = _derive_resumption_key(key_store)
    sealed = aes_gcm_encrypt(r_key, payload, aad=b"qshield:resumption:v1")
    del r_key

    db.add(
        SessionResumptionToken(
            id=token_id,
            session_id=session_id,
            actor_id=actor_id,
            peer_id=peer_id,
            expires_at=expires_at,
        )
    )
    db.commit()

    return {
        "token_id": token_id,
        "nonce_b64": base64.b64encode(sealed.nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(sealed.ciphertext).decode("ascii"),
        "tag_b64": base64.b64encode(sealed.tag).decode("ascii"),
        "expires_at": expires_at.isoformat(),
    }


def resume_session_with_token(
    db: Session,
    *,
    token_bundle: dict[str, str],
    actor_id: str,
    peer_id: str,
    correlation_id: str = "msg-resume",
    key_store: KeyMaterialStore | None = None,
) -> dict[str, object]:
    """Verify AEAD resumption token, expiry, and strict actor/peer binding."""
    r_key = _derive_resumption_key(key_store)
    try:
        pt = aes_gcm_decrypt(
            r_key,
            nonce=base64.b64decode(token_bundle["nonce_b64"].encode("ascii"), validate=True),
            ciphertext=base64.b64decode(token_bundle["ciphertext_b64"].encode("ascii"), validate=True),
            tag=base64.b64decode(token_bundle["tag_b64"].encode("ascii"), validate=True),
            aad=b"qshield:resumption:v1",
        )
    except Exception as exc:
        raise DomainPermissionError("Invalid session resumption token") from exc
    finally:
        del r_key

    claims = json.loads(pt.decode("utf-8"))
    if claims["actor_id"] != actor_id or claims["peer_id"] != peer_id:
        record_audit_event(
            db,
            actor_id=actor_id,
            action="messaging:resume",
            target=str(claims["session_id"]),
            decision="DENY",
            reason="CROSS_PEER_OR_IDENTITY_INHERITANCE_BLOCKED",
            correlation_id=correlation_id,
        )
        raise DomainPermissionError("Cross-peer or cross-identity session resumption denied")

    if datetime.fromisoformat(claims["expires_at"]) <= datetime.now(timezone.utc):
        raise DomainPermissionError("Resumption token expired")

    session = db.get(AuthSession, claims["session_id"])
    if session is None or session.revoked_at is not None:
        raise DomainPermissionError("Underlying session is missing or revoked")

    return {
        "resumed": True,
        "session_id": session.id,
        "actor_id": actor_id,
        "peer_id": peer_id,
        "forward_secrecy": "NOT_ESTABLISHED",
    }


def get_messaging_security_status() -> dict[str, str]:
    """Truthful forward-secrecy and protocol status."""
    return {
        "protocol_version": PROTOCOL_VERSION,
        "aead_algorithm": ALG_AES_256_GCM,
        "forward_secrecy": "NOT_ESTABLISHED",
        "forward_secrecy_note": "Static HKDF+AES-256-GCM session keys; no ephemeral ratcheting implemented",
    }
