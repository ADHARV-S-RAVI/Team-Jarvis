"""Deterministic 3-7 simulated node control plane for revocation & key propagation (Stage 5).

Clearly labelled SIMULATED: these are local logical nodes in SQLite, not physical distributed servers.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import math
import time
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.db.models import NodeAcknowledgement, RevocationTombstone, SimulatedNode
from backend.app.services.foundation_service import DomainNotFoundError, DomainValidationError

DEFAULT_NODE_DEFS = [
    ("sim-node-1", "auth-edge-sim", 2),
    ("sim-node-2", "vault-core-sim", 4),
    ("sim-node-3", "audit-relay-sim", 6),
    ("sim-node-4", "policy-gw-sim", 3),
    ("sim-node-5", "session-gw-sim", 5),
    ("sim-node-6", "backup-gw-sim", 7),
    ("sim-node-7", "edge-cache-sim", 8),
]


def configure_simulated_nodes(db: Session, count: int = 3) -> list[SimulatedNode]:
    """Ensure between 3 and 7 simulated logical nodes exist."""
    if count < 3 or count > 7:
        raise DomainValidationError("Simulated node count must be between 3 and 7")

    existing = list(db.execute(select(SimulatedNode).order_by(SimulatedNode.id.asc())).scalars().all())
    if existing and len(existing) == count:
        return existing

    # Reset or resize deterministically
    for node in existing:
        db.delete(node)
    db.flush()

    created: list[SimulatedNode] = []
    for node_id, service_name, delay_ms in DEFAULT_NODE_DEFS[:count]:
        node = SimulatedNode(
            id=node_id,
            service_name=service_name,
            accepted_key_version=1,
            revoked_state_json=json.dumps({"actor": {}, "device": {}, "session": {}, "key": {}}),
            last_sequence=0,
            health="HEALTHY",
            delay_ms=delay_ms,
            fault_state="NONE",
        )
        db.add(node)
        created.append(node)
    db.commit()
    for node in created:
        db.refresh(node)
    return created


def ensure_default_nodes(db: Session) -> list[SimulatedNode]:
    """Ensure at least 3 simulated nodes are present."""
    existing = list(db.execute(select(SimulatedNode).order_by(SimulatedNode.id.asc())).scalars().all())
    if len(existing) >= 3:
        return existing
    return configure_simulated_nodes(db, count=3)


def list_simulated_nodes(db: Session) -> list[SimulatedNode]:
    ensure_default_nodes(db)
    return list(db.execute(select(SimulatedNode).order_by(SimulatedNode.id.asc())).scalars().all())


def simulate_node_partition(db: Session, node_id: str) -> SimulatedNode:
    ensure_default_nodes(db)
    node = db.get(SimulatedNode, node_id)
    if node is None:
        raise DomainNotFoundError(f"Simulated node '{node_id}' not found")
    node.health = "UNREACHABLE"
    node.fault_state = "PARTITIONED"
    db.commit()
    db.refresh(node)
    return node


def simulate_node_latency(db: Session, node_id: str, delay_ms: int) -> SimulatedNode:
    ensure_default_nodes(db)
    if delay_ms < 0 or delay_ms > 5000:
        raise DomainValidationError("delay_ms must be between 0 and 5000")
    node = db.get(SimulatedNode, node_id)
    if node is None:
        raise DomainNotFoundError(f"Simulated node '{node_id}' not found")
    node.delay_ms = delay_ms
    db.commit()
    db.refresh(node)
    return node


def simulate_node_recover(db: Session, node_id: str) -> SimulatedNode:
    ensure_default_nodes(db)
    node = db.get(SimulatedNode, node_id)
    if node is None:
        raise DomainNotFoundError(f"Simulated node '{node_id}' not found")
    node.health = "HEALTHY"
    node.fault_state = "NONE"
    db.commit()
    db.refresh(node)
    return node


def _load_revoked_map(node: SimulatedNode) -> dict[str, dict[str, int]]:
    data = json.loads(node.revoked_state_json or "{}")
    for key in ("actor", "device", "session", "key"):
        data.setdefault(key, {})
    return data


def propagate_revocation_to_nodes(
    db: Session,
    *,
    subject_type: str,
    subject_id: str,
    epoch: int,
    operation_id: str | None = None,
) -> dict[str, object]:
    """
    Propagate a durable revocation tombstone to all simulated nodes.
    - Monotonic & idempotent: stale epochs (< existing) are ignored.
    - Unreachable/partitioned nodes record NOT_CONVERGED and never report success prematurely.
    """
    nodes = ensure_default_nodes(db)
    op_id = operation_id or str(uuid.uuid4())
    t0_ns = time.perf_counter_ns()
    now = datetime.now(timezone.utc)

    acks: list[dict[str, object]] = []
    converged_count = 0
    per_node_delays_ms: dict[str, int] = {}

    for node in nodes:
        if node.health == "UNREACHABLE" or node.fault_state == "PARTITIONED":
            ack = NodeAcknowledgement(
                operation_id=op_id,
                node_id=node.id,
                sequence=node.last_sequence,
                ack_at=None,
                enforced_at=None,
                delay_ms=0,
                result="NOT_CONVERGED",
            )
            db.add(ack)
            acks.append({"node_id": node.id, "result": "NOT_CONVERGED", "delay_ms": None})
            continue

        rev_map = _load_revoked_map(node)
        bucket = rev_map.setdefault(subject_type, {})
        existing_epoch = bucket.get(subject_id, 0)

        if epoch < existing_epoch:
            # Stale update rejected monotonically
            result = "STALE_IGNORED"
        elif epoch == existing_epoch and node.last_sequence >= epoch:
            # Idempotent duplicate
            result = "IDEMPOTENT_ACK"
        else:
            bucket[subject_id] = epoch
            node.revoked_state_json = json.dumps(rev_map, separators=(",", ":"))
            node.last_sequence = max(node.last_sequence, epoch)
            result = "ENFORCED"

        elapsed_ns = time.perf_counter_ns() - t0_ns
        measured_ms = max(1, node.delay_ms + int(elapsed_ns // 1_000_000))
        node.last_ack_at = now
        node.enforced_at = now
        converged_count += 1
        per_node_delays_ms[node.id] = measured_ms

        ack = NodeAcknowledgement(
            operation_id=op_id,
            node_id=node.id,
            sequence=node.last_sequence,
            ack_at=now,
            enforced_at=now,
            delay_ms=measured_ms,
            result=result,
        )
        db.add(ack)
        acks.append({"node_id": node.id, "result": result, "delay_ms": measured_ms})

    db.commit()
    total = len(nodes)
    all_converged = converged_count == total
    convergence_ms = max(per_node_delays_ms.values()) if (all_converged and per_node_delays_ms) else None

    return {
        "simulated": True,
        "operation_id": op_id,
        "status": "CONVERGED" if all_converged else "NOT_CONVERGED",
        "converged_nodes": converged_count,
        "total_nodes": total,
        "convergence_ms": convergence_ms,
        "per_node_delays_ms": per_node_delays_ms,
        "acks": acks,
    }


def stage_key_version_on_nodes(
    db: Session,
    *,
    key_version: int,
    operation_id: str,
) -> dict[str, object]:
    """Stage/commit a key version across reachable simulated nodes."""
    nodes = ensure_default_nodes(db)
    now = datetime.now(timezone.utc)
    t0_ns = time.perf_counter_ns()

    converged_count = 0
    acks: list[dict[str, object]] = []
    for node in nodes:
        if node.health == "UNREACHABLE" or node.fault_state == "PARTITIONED":
            db.add(
                NodeAcknowledgement(
                    operation_id=operation_id,
                    node_id=node.id,
                    sequence=node.last_sequence,
                    result="NOT_CONVERGED",
                    delay_ms=0,
                )
            )
            acks.append({"node_id": node.id, "result": "NOT_CONVERGED"})
            continue

        if key_version > node.accepted_key_version:
            node.accepted_key_version = key_version
        measured_ms = max(1, node.delay_ms + int((time.perf_counter_ns() - t0_ns) // 1_000_000))
        node.last_ack_at = now
        node.enforced_at = now
        converged_count += 1
        db.add(
            NodeAcknowledgement(
                operation_id=operation_id,
                node_id=node.id,
                sequence=node.last_sequence,
                ack_at=now,
                enforced_at=now,
                delay_ms=measured_ms,
                result="ENFORCED",
            )
        )
        acks.append({"node_id": node.id, "result": "ENFORCED", "delay_ms": measured_ms})

    db.commit()
    return {
        "simulated": True,
        "status": "CONVERGED" if converged_count == len(nodes) else "NOT_CONVERGED",
        "converged_nodes": converged_count,
        "total_nodes": len(nodes),
        "acks": acks,
    }


def reconcile_nodes(db: Session) -> dict[str, object]:
    """Reconcile all healthy simulated nodes with central RevocationTombstones."""
    nodes = ensure_default_nodes(db)
    tombstones = list(db.execute(select(RevocationTombstone)).scalars().all())
    op_id = f"reconcile-{uuid.uuid4()}"
    now = datetime.now(timezone.utc)

    converged = 0
    for node in nodes:
        if node.health == "UNREACHABLE" or node.fault_state == "PARTITIONED":
            continue
        rev_map = _load_revoked_map(node)
        for ts in tombstones:
            bucket = rev_map.setdefault(ts.subject_type, {})
            if ts.epoch > bucket.get(ts.subject_id, 0):
                bucket[ts.subject_id] = ts.epoch
            node.last_sequence = max(node.last_sequence, ts.epoch)
        node.revoked_state_json = json.dumps(rev_map, separators=(",", ":"))
        node.last_ack_at = now
        node.enforced_at = now
        converged += 1
        db.add(
            NodeAcknowledgement(
                operation_id=op_id,
                node_id=node.id,
                sequence=node.last_sequence,
                ack_at=now,
                enforced_at=now,
                delay_ms=node.delay_ms,
                result="RECONCILED",
            )
        )
    db.commit()
    return {
        "simulated": True,
        "status": "CONVERGED" if converged == len(nodes) else "NOT_CONVERGED",
        "converged_nodes": converged,
        "total_nodes": len(nodes),
    }


def node_check_access(
    db: Session,
    *,
    node_id: str,
    actor_id: str,
    device_id: str,
    key_version: int,
) -> tuple[bool, str]:
    """Evaluate whether a specific simulated node permits a request (fail closed if partitioned)."""
    node = db.get(SimulatedNode, node_id)
    if node is None:
        return False, "NODE_NOT_FOUND"
    if node.health == "UNREACHABLE" or node.fault_state == "PARTITIONED":
        return False, "NODE_PARTITIONED_FAIL_CLOSED"
    rev_map = _load_revoked_map(node)
    if actor_id in rev_map.get("actor", {}):
        return False, "NODE_ACTOR_REVOKED"
    if device_id in rev_map.get("device", {}):
        return False, "NODE_DEVICE_REVOKED"
    if key_version < node.accepted_key_version:
        return False, "NODE_KEY_VERSION_CUTOFF"
    return True, "NODE_ALLOW"


def compute_convergence_metrics(db: Session) -> dict[str, object]:
    """Compute actual p50, p95, p99, max convergence delays from recorded NodeAcknowledgements."""
    acks = list(
        db.execute(
            select(NodeAcknowledgement).where(NodeAcknowledgement.result != "NOT_CONVERGED")
        )
        .scalars()
        .all()
    )
    delays = sorted(a.delay_ms for a in acks if a.delay_ms > 0)
    if not delays:
        return {
            "sample_count": 0,
            "p50_ms": None,
            "p95_ms": None,
            "p99_ms": None,
            "max_ms": None,
        }

    def pct(p: float) -> float:
        idx = min(len(delays) - 1, max(0, math.ceil(p * len(delays)) - 1))
        return float(delays[idx])

    return {
        "sample_count": len(delays),
        "p50_ms": pct(0.50),
        "p95_ms": pct(0.95),
        "p99_ms": pct(0.99),
        "max_ms": float(delays[-1]),
    }


class SimulatedNodePropagationBoundary:
    """Stage 5 implementation of Stage 4's NodePropagationBoundary."""

    def __init__(self, db: Session, epoch: int = 1) -> None:
        self.db = db
        self.epoch = epoch

    def propagate_revocation(
        self, subject_type: str, subject_id: str, reason: str
    ) -> dict[str, object]:
        return propagate_revocation_to_nodes(
            self.db,
            subject_type=subject_type,
            subject_id=subject_id,
            epoch=self.epoch,
        )
