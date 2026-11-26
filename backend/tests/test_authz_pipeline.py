"""Independent unit tests for the 9-step fail-closed authorization pipeline."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from sqlalchemy.orm import Session, sessionmaker

from backend.app.db.models import (
    Actor,
    AuthSession,
    Base,
    Device,
    IncidentPolicyDenial,
    KeyMetadata,
    Resource,
    RevocationTombstone,
)
from backend.app.db.session import create_db_engine
from backend.app.policy.authz import AuthzRequest, evaluate_authorization
from backend.app.services.foundation_service import (
    create_device,
    create_identity,
    create_resource,
    create_session,
    ensure_foundation_defaults,
)


@pytest.fixture()
def db_session(tmp_path: Path):
    db_file = tmp_path / "authz_test.db"
    engine = create_db_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    db = TestingSession()
    ensure_foundation_defaults(db)
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


def _seed_valid_context(db: Session) -> dict[str, str]:
    create_identity(
        db, actor_id="alice", display_label="Alice", role="Owner/User", enabled=True, correlation_id="c0"
    )
    create_identity(
        db, actor_id="bob", display_label="Bob", role="Owner/User", enabled=True, correlation_id="c0"
    )
    create_device(
        db,
        device_id="dev-alice-1",
        owner_actor_id="alice",
        credential_fingerprint="fp-alice-0001",
        state="TRUSTED",
        correlation_id="c0",
    )
    create_device(
        db,
        device_id="dev-bob-1",
        owner_actor_id="bob",
        credential_fingerprint="fp-bob-0001",
        state="TRUSTED",
        correlation_id="c0",
    )
    session, raw_token = create_session(
        db,
        actor_id="alice",
        device_id="dev-alice-1",
        peer_id="peer-vault",
        ttl_seconds=3600,
        correlation_id="c0",
    )
    create_resource(
        db,
        resource_id="res-alice-1",
        owner_actor_id="alice",
        content_ref="vault://alice/doc1",
        key_version=1,
        state="ACTIVE",
        correlation_id="c0",
    )
    return {
        "actor_id": "alice",
        "session_id": session.id,
        "session_token": raw_token,
        "device_id": "dev-alice-1",
        "resource_id": "res-alice-1",
        "peer_id": "peer-vault",
    }


def test_complete_pipeline_allows_valid_request(db_session: Session) -> None:
    ctx = _seed_valid_context(db_session)
    decision = evaluate_authorization(
        db_session,
        AuthzRequest(
            actor_id=ctx["actor_id"],
            session_id=ctx["session_id"],
            session_token=ctx["session_token"],
            device_id=ctx["device_id"],
            resource_id=ctx["resource_id"],
            action="resource:read",
            peer_id=ctx["peer_id"],
        ),
    )
    assert decision.decision == "ALLOW"
    assert decision.reason_code == "AUTHORIZED"
    assert decision.failed_step is None
    assert len(decision.checks_passed) == 9


def test_step1_invalid_request_denies(db_session: Session) -> None:
    decision = evaluate_authorization(
        db_session,
        AuthzRequest(actor_id="", session_id="s1", device_id="d1", resource_id="r1", action="resource:read"),
    )
    assert decision.decision == "DENY"
    assert decision.failed_step == 1
    assert decision.reason_code == "INVALID_REQUEST"


def test_step2_unknown_or_disabled_identity_denies(db_session: Session) -> None:
    ctx = _seed_valid_context(db_session)
    unknown = evaluate_authorization(
        db_session,
        AuthzRequest(
            actor_id="ghost",
            session_id=ctx["session_id"],
            device_id=ctx["device_id"],
            resource_id=ctx["resource_id"],
            action="resource:read",
        ),
    )
    assert unknown.decision == "DENY"
    assert unknown.failed_step == 2
    assert unknown.reason_code == "IDENTITY_NOT_FOUND"

    actor = db_session.get(Actor, "alice")
    assert actor is not None
    actor.enabled = False
    db_session.commit()

    disabled = evaluate_authorization(
        db_session,
        AuthzRequest(
            actor_id="alice",
            session_id=ctx["session_id"],
            device_id=ctx["device_id"],
            resource_id=ctx["resource_id"],
            action="resource:read",
        ),
    )
    assert disabled.decision == "DENY"
    assert disabled.failed_step == 2
    assert disabled.reason_code == "IDENTITY_DISABLED_OR_REVOKED"


def test_step3_session_actor_token_and_peer_binding(db_session: Session) -> None:
    ctx = _seed_valid_context(db_session)

    # Actor mismatch
    wrong_actor = evaluate_authorization(
        db_session,
        AuthzRequest(
            actor_id="bob",
            session_id=ctx["session_id"],
            device_id="dev-bob-1",
            resource_id=ctx["resource_id"],
            action="resource:read",
        ),
    )
    assert wrong_actor.decision == "DENY"
    assert wrong_actor.failed_step == 3
    assert wrong_actor.reason_code == "SESSION_ACTOR_MISMATCH"

    # Bad token
    wrong_token = evaluate_authorization(
        db_session,
        AuthzRequest(
            actor_id=ctx["actor_id"],
            session_id=ctx["session_id"],
            session_token="forged-token",
            device_id=ctx["device_id"],
            resource_id=ctx["resource_id"],
            action="resource:read",
        ),
    )
    assert wrong_token.decision == "DENY"
    assert wrong_token.failed_step == 3
    assert wrong_token.reason_code == "SESSION_TOKEN_INVALID"

    # Peer mismatch
    wrong_peer = evaluate_authorization(
        db_session,
        AuthzRequest(
            actor_id=ctx["actor_id"],
            session_id=ctx["session_id"],
            device_id=ctx["device_id"],
            resource_id=ctx["resource_id"],
            action="resource:read",
            peer_id="wrong-peer",
        ),
    )
    assert wrong_peer.decision == "DENY"
    assert wrong_peer.failed_step == 3
    assert wrong_peer.reason_code == "SESSION_PEER_MISMATCH"


def test_step4_expired_or_revoked_session_denies(db_session: Session) -> None:
    ctx = _seed_valid_context(db_session)
    sess = db_session.get(AuthSession, ctx["session_id"])
    assert sess is not None
    sess.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
    db_session.commit()

    expired = evaluate_authorization(
        db_session,
        AuthzRequest(
            actor_id=ctx["actor_id"],
            session_id=ctx["session_id"],
            device_id=ctx["device_id"],
            resource_id=ctx["resource_id"],
            action="resource:read",
        ),
    )
    assert expired.decision == "DENY"
    assert expired.failed_step == 4
    assert expired.reason_code == "SESSION_EXPIRED"

    sess.revoked_at = datetime.now(timezone.utc)
    db_session.commit()
    revoked = evaluate_authorization(
        db_session,
        AuthzRequest(
            actor_id=ctx["actor_id"],
            session_id=ctx["session_id"],
            device_id=ctx["device_id"],
            resource_id=ctx["resource_id"],
            action="resource:read",
        ),
    )
    assert revoked.decision == "DENY"
    assert revoked.failed_step == 4
    assert revoked.reason_code == "SESSION_REVOKED"


def test_step5_untrusted_or_mismatched_device_denies(db_session: Session) -> None:
    ctx = _seed_valid_context(db_session)

    # Device belongs to Bob, not Alice
    mismatch = evaluate_authorization(
        db_session,
        AuthzRequest(
            actor_id=ctx["actor_id"],
            session_id=ctx["session_id"],
            device_id="dev-bob-1",
            resource_id=ctx["resource_id"],
            action="resource:read",
        ),
    )
    assert mismatch.decision == "DENY"
    assert mismatch.failed_step == 5
    assert mismatch.reason_code == "DEVICE_OWNERSHIP_MISMATCH"

    # Suspended device
    dev = db_session.get(Device, ctx["device_id"])
    assert dev is not None
    dev.state = "SUSPENDED"
    db_session.commit()
    suspended = evaluate_authorization(
        db_session,
        AuthzRequest(
            actor_id=ctx["actor_id"],
            session_id=ctx["session_id"],
            device_id=ctx["device_id"],
            resource_id=ctx["resource_id"],
            action="resource:read",
        ),
    )
    assert suspended.decision == "DENY"
    assert suspended.failed_step == 5
    assert suspended.reason_code == "DEVICE_NOT_TRUSTED"


def test_step6_permission_and_cross_user_ownership_denies(db_session: Session) -> None:
    ctx = _seed_valid_context(db_session)

    # Disallowed action for Owner/User
    no_perm = evaluate_authorization(
        db_session,
        AuthzRequest(
            actor_id=ctx["actor_id"],
            session_id=ctx["session_id"],
            device_id=ctx["device_id"],
            resource_id=ctx["resource_id"],
            action="policy:configure",
        ),
    )
    assert no_perm.decision == "DENY"
    assert no_perm.failed_step == 6
    assert no_perm.reason_code == "PERMISSION_DENIED"

    # Cross-user IDOR attempt: Bob tries to read Alice's resource
    bob_sess, _ = create_session(
        db_session, actor_id="bob", device_id="dev-bob-1", peer_id="peer-vault", ttl_seconds=3600, correlation_id="c1"
    )
    idor = evaluate_authorization(
        db_session,
        AuthzRequest(
            actor_id="bob",
            session_id=bob_sess.id,
            device_id="dev-bob-1",
            resource_id=ctx["resource_id"],
            action="resource:read",
        ),
    )
    assert idor.decision == "DENY"
    assert idor.failed_step == 6
    assert idor.reason_code == "RESOURCE_OWNERSHIP_DENIED"


def test_step7_disabled_resource_denies(db_session: Session) -> None:
    ctx = _seed_valid_context(db_session)
    res = db_session.get(Resource, ctx["resource_id"])
    assert res is not None
    res.state = "DISABLED"
    db_session.commit()

    decision = evaluate_authorization(
        db_session,
        AuthzRequest(
            actor_id=ctx["actor_id"],
            session_id=ctx["session_id"],
            device_id=ctx["device_id"],
            resource_id=ctx["resource_id"],
            action="resource:read",
        ),
    )
    assert decision.decision == "DENY"
    assert decision.failed_step == 7
    assert decision.reason_code == "RESOURCE_DISABLED"


def test_step8_revoked_key_version_denies(db_session: Session) -> None:
    ctx = _seed_valid_context(db_session)
    key = db_session.get(KeyMetadata, "key-v1-default")
    assert key is not None
    key.state = "REVOKED"
    db_session.commit()

    decision = evaluate_authorization(
        db_session,
        AuthzRequest(
            actor_id=ctx["actor_id"],
            session_id=ctx["session_id"],
            device_id=ctx["device_id"],
            resource_id=ctx["resource_id"],
            action="resource:read",
        ),
    )
    assert decision.decision == "DENY"
    assert decision.failed_step == 8
    assert decision.reason_code == "KEY_VERSION_INACTIVE_OR_REVOKED"


def test_step9_incident_policy_denial_denies(db_session: Session) -> None:
    ctx = _seed_valid_context(db_session)
    db_session.add(
        IncidentPolicyDenial(
            subject_type="actor",
            subject_id="alice",
            active=True,
            reason="Active lost-device investigation",
        )
    )
    db_session.commit()

    decision = evaluate_authorization(
        db_session,
        AuthzRequest(
            actor_id=ctx["actor_id"],
            session_id=ctx["session_id"],
            device_id=ctx["device_id"],
            resource_id=ctx["resource_id"],
            action="resource:read",
        ),
    )
    assert decision.decision == "DENY"
    assert decision.failed_step == 9
    assert decision.reason_code == "INCIDENT_POLICY_DENIED"


def test_fail_closed_on_database_error() -> None:
    broken_db = MagicMock()
    broken_db.get.side_effect = RuntimeError("DB connection lost")
    decision = evaluate_authorization(
        broken_db,
        AuthzRequest(
            actor_id="alice",
            session_id="s1",
            device_id="d1",
            resource_id="r1",
            action="resource:read",
        ),
    )
    assert decision.decision == "DENY"
    assert decision.reason_code == "POLICY_EVALUATION_ERROR"
