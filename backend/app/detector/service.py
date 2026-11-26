"""Deterministic, explainable threat-detection and lateral-movement engine (Stage 8, Zero ML)."""

from __future__ import annotations

import csv
from datetime import datetime, timedelta, timezone
import io
import json
import math
import random
import time
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.db.models import (
    DetectorAlert,
    DetectorEvent,
    IdentityVerificationEvent,
    IntegrityFinding,
    IntegrityManifest,
    IntegrityScan,
    RevocationTombstone,
)
from backend.app.services.foundation_service import DomainValidationError, record_audit_event

DEFAULT_REORDER_WINDOW_MS = 5000
DEFAULT_CLOCK_UNCERTAINTY_MS = 500

# Generic baseline edges (not hardcoded to attack actors; represents normal portal/service flows)
DEFAULT_BASELINE_EDGES: set[tuple[str, str]] = {
    ("portal", "identity"),
    ("portal", "catalog"),
    ("admin-console", "identity"),
    ("reports", "catalog"),
}

PRIVILEGED_ROLES = {"operator", "admin", "security operator", "report-reader"}

DETECTOR_RULES = [
    {"rule_id": "RULE_PRIV_UNAPPROVED_CHANGE", "severity": "HIGH", "description": "Role/privilege change without valid matching approval"},
    {"rule_id": "RULE_PRIV_SELF_ESCALATION", "severity": "CRITICAL", "description": "Actor self-escalation to privileged role without operator approval"},
    {"rule_id": "RULE_PRIV_SENSITIVE_AFTER_CHANGE", "severity": "HIGH", "description": "Allowed service access following an unapproved role change in same session"},
    {"rule_id": "RULE_PRIV_REVOKED_ACTOR_ATTEMPT", "severity": "HIGH", "description": "Access attempt by an actor with an active revocation tombstone"},
    {"rule_id": "RULE_LATERAL_MULTI_HOP", "severity": "HIGH", "description": "Time-aware multi-hop unexpected service-to-service path"},
    {"rule_id": "RULE_SERVICE_ANOMALY", "severity": "MEDIUM", "description": "High-frequency unexpected service access burst in short window"},
    {"rule_id": "RULE_IDENTITY_REPEATED_FAILURE", "severity": "HIGH", "description": "Repeated WebAuthn / identity verification failures for an actor"},
    {"rule_id": "RULE_IDENTITY_UNEXPECTED_CREDENTIAL", "severity": "MEDIUM", "description": "Credential registration anomalies or rapid multi-credential enrolment"},
    {"rule_id": "RULE_IDENTITY_REVOKED_DEVICE", "severity": "CRITICAL", "description": "Identity verification attempted with credential bound to revoked device"},
    {"rule_id": "RULE_INTEGRITY_MODIFIED_FILE", "severity": "CRITICAL", "description": "Protected application file SHA-256 differs from baseline manifest"},
    {"rule_id": "RULE_INTEGRITY_MISSING_FILE", "severity": "CRITICAL", "description": "Baseline-tracked application file is missing"},
    {"rule_id": "RULE_INTEGRITY_UNEXPECTED_FILE", "severity": "HIGH", "description": "Unexpected file detected outside trusted baseline manifest"},
    {"rule_id": "RULE_INTEGRITY_BASELINE_TAMPER", "severity": "CRITICAL", "description": "Baseline manifest canonical hash or HMAC verification failed"},
    {"rule_id": "RULE_INTEGRITY_SCAN_FAILURE", "severity": "HIGH", "description": "Application file integrity scan aborted or failed"},
]


def _parse_iso_utc(raw: str) -> datetime:
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize_event_dict(raw: dict[str, object]) -> dict[str, object]:
    """Schema-flexible parser supporting unknown fields while validating required core fields."""
    event_id = str(raw.get("event_id") or raw.get("id") or "").strip()
    actor = str(raw.get("actor") or raw.get("actor_id") or "").strip()
    action = str(raw.get("action") or "").strip()
    event_time_raw = str(raw.get("event_time_utc") or raw.get("event_time") or "").strip()
    if not event_id or not actor or not action or not event_time_raw:
        raise DomainValidationError("Malformed detector event: missing event_id, actor, action, or event_time")

    try:
        event_time = _parse_iso_utc(event_time_raw)
    except ValueError as exc:
        raise DomainValidationError(f"Malformed event_time_utc in '{event_id}'") from exc

    observed_raw = str(raw.get("received_time_utc") or raw.get("observed_at") or event_time_raw).strip()
    try:
        observed_at = _parse_iso_utc(observed_raw)
    except ValueError:
        observed_at = event_time

    try:
        offset_ms = int(raw.get("source_clock_offset_ms") or raw.get("clock_offset_ms") or 0)
    except (TypeError, ValueError) as exc:
        raise DomainValidationError(f"Malformed clock offset in '{event_id}'") from exc

    adjusted_time = event_time - timedelta(milliseconds=offset_ms)

    known_keys = {
        "event_id", "id", "event_time_utc", "event_time", "received_time_utc", "observed_at",
        "source_clock_offset_ms", "clock_offset_ms", "actor", "actor_id",
        "source_service", "target_service", "action", "session_id", "correlation_id",
    }
    extra_payload = {str(k): v for k, v in raw.items() if str(k) not in known_keys}

    return {
        "id": event_id,
        "source": str(raw.get("source") or "telemetry"),
        "event_time": event_time,
        "observed_at": observed_at,
        "adjusted_event_time": adjusted_time,
        "clock_offset_ms": offset_ms,
        "actor": actor,
        "source_service": str(raw.get("source_service") or "unknown"),
        "target_service": str(raw.get("target_service") or "unknown"),
        "action": action,
        "session_id": str(raw.get("session_id") or "no-session"),
        "correlation_id": str(raw.get("correlation_id") or "no-corr"),
        "payload": extra_payload,
    }


def parse_events_csv(csv_text: str) -> list[dict[str, object]]:
    """Parse organizer/synthetic CSV telemetry into normalized event dicts."""
    reader = csv.DictReader(io.StringIO(csv_text))
    return [normalize_event_dict(dict(row)) for row in reader]


def ingest_detector_events(
    db: Session,
    *,
    events: list[dict[str, object]],
    reorder_window_ms: int = DEFAULT_REORDER_WINDOW_MS,
    clock_uncertainty_ms: int = DEFAULT_CLOCK_UNCERTAINTY_MS,
) -> dict[str, object]:
    """Ingest events, track watermarks/out-of-order arrivals, and flag uncertain order intervals."""
    t0_ns = time.perf_counter_ns()
    watermark: datetime | None = None
    ingested_ids: list[str] = []
    out_of_order_count = 0
    uncertain_count = 0

    prev_adjusted_by_actor: dict[str, datetime] = {}

    for raw in events:
        norm = normalize_event_dict(raw)
        adj: datetime = norm["adjusted_event_time"]  # type: ignore[assignment]
        actor = str(norm["actor"])

        out_of_order = False
        if watermark is not None and adj < watermark:
            # Within or beyond reorder window, mark honestly as out-of-order
            out_of_order = True
            out_of_order_count += 1
        if watermark is None or adj > watermark:
            watermark = adj

        order_uncertain = False
        prev_adj = prev_adjusted_by_actor.get(actor)
        if prev_adj is not None:
            diff_ms = abs((adj - prev_adj).total_seconds() * 1000.0)
            if diff_ms <= clock_uncertainty_ms:
                order_uncertain = True
                uncertain_count += 1
        prev_adjusted_by_actor[actor] = adj

        existing = db.get(DetectorEvent, str(norm["id"]))
        if existing is None:
            db.add(
                DetectorEvent(
                    id=str(norm["id"]),
                    source=str(norm["source"]),
                    observed_at=norm["observed_at"],  # type: ignore[arg-type]
                    event_time=norm["event_time"],  # type: ignore[arg-type]
                    adjusted_event_time=adj,
                    clock_offset_ms=int(norm["clock_offset_ms"]),  # type: ignore[arg-type]
                    order_uncertain=order_uncertain,
                    out_of_order=out_of_order,
                    actor=actor,
                    source_service=str(norm["source_service"]),
                    target_service=str(norm["target_service"]),
                    action=str(norm["action"]),
                    session_id=str(norm["session_id"]),
                    correlation_id=str(norm["correlation_id"]),
                    schema_version="v1",
                    payload_json=json.dumps(norm["payload"], separators=(",", ":")),
                )
            )
        ingested_ids.append(str(norm["id"]))

    db.commit()
    elapsed_ms = (time.perf_counter_ns() - t0_ns) / 1_000_000.0
    return {
        "ingested_count": len(ingested_ids),
        "out_of_order_count": out_of_order_count,
        "order_uncertain_count": uncertain_count,
        "reorder_window_ms": reorder_window_ms,
        "clock_uncertainty_ms": clock_uncertainty_ms,
        "ingestion_latency_ms": round(elapsed_ms, 3),
    }


def _find_matching_approval(
    approvals: list[dict[str, object]],
    *,
    approval_id: str,
    subject: str,
    role_after: str,
    event_time: datetime,
) -> dict[str, object] | None:
    for ch in approvals:
        if approval_id and str(ch.get("approval_id", "")) != approval_id:
            continue
        if str(ch.get("subject", "")) != subject:
            continue
        if str(ch.get("role", "")) != role_after:
            continue
        vf_raw = ch.get("valid_from_utc")
        vu_raw = ch.get("valid_until_utc")
        if vf_raw and vu_raw:
            vf = _parse_iso_utc(str(vf_raw))
            vu = _parse_iso_utc(str(vu_raw))
            # valid_until_utc is exclusive per practice/README.md
            if not (vf <= event_time < vu):
                continue
        return ch
    return None


def _is_scope_approved(
    approvals: list[dict[str, object]],
    *,
    actor: str,
    target_service: str,
    event_time: datetime,
) -> bool:
    for ch in approvals:
        if str(ch.get("subject", "")) != actor:
            continue
        scope = ch.get("scope") or []
        if not isinstance(scope, list) or target_service not in scope:
            continue
        vf_raw = ch.get("valid_from_utc")
        vu_raw = ch.get("valid_until_utc")
        if vf_raw and vu_raw:
            vf = _parse_iso_utc(str(vf_raw))
            vu = _parse_iso_utc(str(vu_raw))
            if vf <= event_time < vu:
                return True
    return False


def run_deterministic_detection(
    db: Session,
    *,
    approvals: list[dict[str, object]] | None = None,
    baseline_edges: set[tuple[str, str]] | None = None,
    correlation_id: str = "detector-run",
) -> list[DetectorAlert]:
    """
    Execute deterministic rules and time-aware directed graph analysis over ingested DetectorEvents.
    Zero AI/ML runtime dependencies.
    """
    approvals_list = approvals or []
    base_edges = baseline_edges if baseline_edges is not None else DEFAULT_BASELINE_EDGES

    # Clear prior alerts for clean deterministic re-evaluation over current event window
    for old_alert in db.execute(select(DetectorAlert)).scalars().all():
        db.delete(old_alert)
    db.flush()

    events = list(
        db.execute(select(DetectorEvent).order_by(DetectorEvent.adjusted_event_time.asc())).scalars().all()
    )
    revoked_actors = set(
        db.execute(
            select(RevocationTombstone.subject_id).where(RevocationTombstone.subject_type == "actor")
        )
        .scalars()
        .all()
    )

    alerts: list[DetectorAlert] = []
    unapproved_priv_sessions: dict[str, str] = {}  # session_id -> role_change_event_id

    # Track directed edges per (actor, session_id) for time-aware lateral movement graph
    session_unexpected_edges: dict[tuple[str, str], list[dict[str, object]]] = {}

    for ev in events:
        payload = json.loads(ev.payload_json or "{}")
        role_before = str(payload.get("role_before") or "")
        role_after = str(payload.get("role_after") or "")
        outcome = str(payload.get("outcome") or "").lower()
        approval_id = str(payload.get("approval_id") or "")
        adj_time = ev.adjusted_event_time
        if adj_time.tzinfo is None:
            adj_time = adj_time.replace(tzinfo=timezone.utc)

        # 1. Revoked actor attempt (against active Q-SHIELD revocation tombstones)
        if ev.actor in revoked_actors:
            alerts.append(
                DetectorAlert(
                    rule_id="RULE_PRIV_REVOKED_ACTOR_ATTEMPT",
                    severity="HIGH",
                    actor=ev.actor,
                    score_breakdown_json=json.dumps({"weight": 0.9, "tombstone": True}),
                    path_json=json.dumps([ev.source_service, ev.target_service]),
                    event_refs_json=json.dumps([ev.id]),
                    explanation=f"Revoked actor '{ev.actor}' attempted '{ev.action}' on '{ev.target_service}'.",
                )
            )

        # 2. Privilege-change & self-escalation detection
        if ev.action == "role_change" or (role_before and role_after and role_before != role_after):
            matched = _find_matching_approval(
                approvals_list,
                approval_id=approval_id,
                subject=ev.actor,
                role_after=role_after,
                event_time=adj_time,
            )
            if matched is None:
                is_priv = role_after.lower() in PRIVILEGED_ROLES
                rule_id = "RULE_PRIV_SELF_ESCALATION" if is_priv else "RULE_PRIV_UNAPPROVED_CHANGE"
                unapproved_priv_sessions[ev.session_id] = ev.id
                alerts.append(
                    DetectorAlert(
                        rule_id=rule_id,
                        severity="CRITICAL" if is_priv else "HIGH",
                        actor=ev.actor,
                        score_breakdown_json=json.dumps({"unapproved": True, "privileged_target": is_priv}),
                        path_json=json.dumps([ev.source_service, ev.target_service]),
                        event_refs_json=json.dumps([ev.id]),
                        explanation=(
                            f"Actor '{ev.actor}' changed role '{role_before}' -> '{role_after}' "
                            f"without valid approval (approval_id='{approval_id or 'none'}')."
                        ),
                    )
                )

        # 3. Sensitive/allowed access after unapproved privilege change in same session
        elif ev.session_id in unapproved_priv_sessions and outcome == "allow":
            alerts.append(
                DetectorAlert(
                    rule_id="RULE_PRIV_SENSITIVE_AFTER_CHANGE",
                    severity="HIGH",
                    actor=ev.actor,
                    score_breakdown_json=json.dumps({"after_unapproved_change": True}),
                    path_json=json.dumps([ev.source_service, ev.target_service]),
                    event_refs_json=json.dumps([unapproved_priv_sessions[ev.session_id], ev.id]),
                    explanation=(
                        f"Allowed '{ev.action}' on '{ev.target_service}' followed unapproved role change "
                        f"'{unapproved_priv_sessions[ev.session_id]}' in session '{ev.session_id}'."
                    ),
                )
            )

        # 4. Time-aware directed graph edge tracking (exclude baseline, approvals, and sign-in/out)
        edge = (ev.source_service, ev.target_service)
        is_auth_lifecycle = ev.action in {"sign_in", "sign_out", "approve_role_change", "revoke_role", "role_change"}
        if (
            not is_auth_lifecycle
            and ev.source_service != "unknown"
            and ev.target_service != "unknown"
            and edge not in base_edges
            and not _is_scope_approved(approvals_list, actor=ev.actor, target_service=ev.target_service, event_time=adj_time)
        ):
            # Also treat expected single-hop post-revocation denials with approval_id as non-lateral
            is_expected_revocation_deny = outcome == "deny" and bool(approval_id)
            if not is_expected_revocation_deny:
                key = (ev.actor, ev.session_id)
                session_unexpected_edges.setdefault(key, []).append(
                    {
                        "event_id": ev.id,
                        "source": ev.source_service,
                        "target": ev.target_service,
                        "time": adj_time.isoformat(),
                    }
                )

    # Flag multi-hop lateral movement paths (>= 2 unexpected edges in a session)
    for (actor, session_id), hops in session_unexpected_edges.items():
        if len(hops) >= 2:
            path_nodes = [str(hops[0]["source"])] + [str(h["target"]) for h in hops]
            ev_refs = [str(h["event_id"]) for h in hops]
            alerts.append(
                DetectorAlert(
                    rule_id="RULE_LATERAL_MULTI_HOP",
                    severity="HIGH",
                    actor=actor,
                    score_breakdown_json=json.dumps({"hop_count": len(hops), "session_id": session_id}),
                    path_json=json.dumps(path_nodes),
                    event_refs_json=json.dumps(ev_refs),
                    explanation=(
                        f"Actor '{actor}' traversed {len(hops)} unexpected service hops "
                        f"({' -> '.join(path_nodes)}) in session '{session_id}'."
                    ),
                )
            )
        if len(hops) >= 4:
            alerts.append(
                DetectorAlert(
                    rule_id="RULE_SERVICE_ANOMALY",
                    severity="MEDIUM",
                    actor=actor,
                    score_breakdown_json=json.dumps({"burst_count": len(hops)}),
                    path_json=json.dumps([str(h["target"]) for h in hops]),
                    event_refs_json=json.dumps([str(h["event_id"]) for h in hops]),
                    explanation=f"High-frequency unexpected service access burst ({len(hops)} events) for '{actor}'.",
                )
            )

    # Stage 13 deterministic rules over Identity Assurance & File Integrity state
    id_events = list(db.execute(select(IdentityVerificationEvent)).scalars().all())
    fail_counts: dict[str, int] = {}
    for iev in id_events:
        if iev.verification_status == "REVOKED_REJECTED":
            alerts.append(
                DetectorAlert(
                    rule_id="RULE_IDENTITY_REVOKED_DEVICE",
                    severity="CRITICAL",
                    actor=iev.actor_id,
                    score_breakdown_json=json.dumps({"revoked_device_auth": True}),
                    path_json=json.dumps([iev.actor_id, iev.device_id or "credential"]),
                    event_refs_json=json.dumps([iev.id]),
                    explanation=f"Verification rejected for '{iev.actor_id}': {iev.reason}",
                )
            )
        elif iev.verification_status in ("FAILED", "EXPIRED"):
            fail_counts[iev.actor_id] = fail_counts.get(iev.actor_id, 0) + 1
    for fail_actor, cnt in fail_counts.items():
        if cnt >= 3:
            alerts.append(
                DetectorAlert(
                    rule_id="RULE_IDENTITY_REPEATED_FAILURE",
                    severity="HIGH",
                    actor=fail_actor,
                    score_breakdown_json=json.dumps({"failed_attempts": cnt}),
                    path_json=json.dumps([fail_actor, "identity-assurance"]),
                    event_refs_json=json.dumps([]),
                    explanation=f"Repeated identity verification failures ({cnt}x) for actor '{fail_actor}'.",
                )
            )

    tampered_manifests = list(db.execute(select(IntegrityManifest).where(IntegrityManifest.status == "TAMPERED")).scalars().all())
    for tm in tampered_manifests:
        alerts.append(
            DetectorAlert(
                rule_id="RULE_INTEGRITY_BASELINE_TAMPER",
                severity="CRITICAL",
                actor="integrity-verifier",
                score_breakdown_json=json.dumps({"manifest_tampered": True}),
                path_json=json.dumps(["integrity-manifest", tm.id]),
                event_refs_json=json.dumps([tm.id]),
                explanation=f"Integrity manifest v{tm.manifest_version} failed canonical hash or HMAC verification.",
            )
        )

    failed_scans = list(db.execute(select(IntegrityScan).where(IntegrityScan.scan_status == "FAILED")).scalars().all())
    for fs in failed_scans:
        alerts.append(
            DetectorAlert(
                rule_id="RULE_INTEGRITY_SCAN_FAILURE",
                severity="HIGH",
                actor="integrity-scanner",
                score_breakdown_json=json.dumps({"scan_failed": True}),
                path_json=json.dumps(["integrity-scanner", fs.id]),
                event_refs_json=json.dumps([fs.id]),
                explanation=f"File integrity scan '{fs.id}' failed ({fs.scan_scope}).",
            )
        )

    bad_findings = list(
        db.execute(
            select(IntegrityFinding).where(IntegrityFinding.finding_type.in_(("MODIFIED", "MISSING", "UNEXPECTED")))
        ).scalars().all()
    )
    for bf in bad_findings:
        rule_map = {
            "MODIFIED": ("RULE_INTEGRITY_MODIFIED_FILE", "CRITICAL"),
            "MISSING": ("RULE_INTEGRITY_MISSING_FILE", "CRITICAL"),
            "UNEXPECTED": ("RULE_INTEGRITY_UNEXPECTED_FILE", "HIGH"),
        }
        rid, rsev = rule_map[bf.finding_type]
        alerts.append(
            DetectorAlert(
                rule_id=rid,
                severity=rsev,
                actor="integrity-scanner",
                score_breakdown_json=json.dumps({"finding_type": bf.finding_type}),
                path_json=json.dumps(["app-root", bf.relative_path]),
                event_refs_json=json.dumps([bf.id]),
                explanation=f"Application integrity finding ({bf.finding_type}) on '{bf.relative_path}'.",
            )
        )

    for alert in alerts:
        db.add(alert)
    db.commit()
    for alert in alerts:
        db.refresh(alert)

    record_audit_event(
        db,
        actor_id="system",
        action="detector:run",
        target=f"events:{len(events)}",
        decision="COMPLETED",
        reason=f"ALERTS_{len(alerts)}",
        correlation_id=correlation_id,
        metadata={"event_count": len(events), "alert_count": len(alerts)},
    )
    return alerts


def evaluate_detector_metrics(
    *,
    events: list[DetectorEvent],
    alerts: list[DetectorAlert],
    labels: dict[str, str] | None,
    positive_labels: set[str] | None = None,
    dataset_version: str = "practice-v1",
    seed: int | None = None,
) -> dict[str, object]:
    """Compute TP, FP, TN, FN, precision, recall, F1, false alerts/1k, and time-to-alert."""
    if not labels:
        return {"status": "NOT_EVALUATED", "reason": "No ground-truth labels provided"}

    pos_set = positive_labels or {
        "unexpected_role_change",
        "review_after_role_change",
        "lateral_movement_candidate",
    }

    alerted_event_ids: set[str] = set()
    per_rule: dict[str, int] = {}
    for a in alerts:
        per_rule[a.rule_id] = per_rule.get(a.rule_id, 0) + 1
        for eid in json.loads(a.event_refs_json or "[]"):
            alerted_event_ids.add(str(eid))

    tp = fp = tn = fn = 0
    alert_latencies_ms: list[float] = []

    for ev in events:
        if ev.id not in labels:
            continue
        is_pos = labels[ev.id] in pos_set
        is_pred = ev.id in alerted_event_ids
        if is_pos and is_pred:
            tp += 1
            if ev.observed_at and ev.adjusted_event_time:
                obs = ev.observed_at if ev.observed_at.tzinfo else ev.observed_at.replace(tzinfo=timezone.utc)
                adj = ev.adjusted_event_time if ev.adjusted_event_time.tzinfo else ev.adjusted_event_time.replace(tzinfo=timezone.utc)
                alert_latencies_ms.append(max(0.0, (obs - adj).total_seconds() * 1000.0))
        elif not is_pos and is_pred:
            fp += 1
        elif not is_pos and not is_pred:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    benign_total = tn + fp
    false_per_1k = (fp / benign_total) * 1000.0 if benign_total > 0 else 0.0

    sorted_lat = sorted(alert_latencies_ms)
    median_lat = sorted_lat[len(sorted_lat) // 2] if sorted_lat else 0.0
    p95_lat = sorted_lat[min(len(sorted_lat) - 1, math.ceil(0.95 * len(sorted_lat)) - 1)] if sorted_lat else 0.0

    return {
        "status": "EVALUATED",
        "dataset_version": dataset_version,
        "seed": seed,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_alerts_per_1000_benign": round(false_per_1k, 2),
        "median_time_to_alert_ms": round(median_lat, 2),
        "p95_time_to_alert_ms": round(p95_lat, 2),
        "per_rule_breakdown": per_rule,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
    }


def generate_synthetic_events(*, seed: int = 42, count: int = 30) -> tuple[list[dict[str, object]], dict[str, str]]:
    """Deterministic seeded synthetic event & label generator (zero ML)."""
    rng = random.Random(seed)
    base_time = datetime(2026, 2, 1, 10, 0, 0, tzinfo=timezone.utc)
    events: list[dict[str, object]] = []
    labels: dict[str, str] = {}

    for i in range(count):
        eid = f"syn-{seed}-{i:04d}"
        t_ev = base_time + timedelta(seconds=i * 2)
        t_obs = t_ev + timedelta(milliseconds=rng.randint(50, 300))
        actor = f"syn-user-{i % 4}"
        events.append(
            {
                "event_id": eid,
                "event_time_utc": t_ev.isoformat(),
                "received_time_utc": t_obs.isoformat(),
                "source_clock_offset_ms": 0,
                "actor": actor,
                "source_service": "portal",
                "target_service": "catalog",
                "action": "read",
                "role_before": "viewer",
                "role_after": "viewer",
                "outcome": "allow",
                "approval_id": "",
                "session_id": f"sess-{actor}",
                "correlation_id": f"flow-{i}",
            }
        )
        labels[eid] = "routine"

    return events, labels
