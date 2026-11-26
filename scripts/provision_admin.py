"""CLI tool to securely provision an initial Admin account offline (no hardcoded passwords)."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.app.db.session import SessionLocal
from backend.app.services.rbac_auth_service import provision_rbac_account


def main() -> None:
    parser = argparse.ArgumentParser(description="Provision a Q-SHIELD Admin/Employee/User account")
    parser.add_argument("--actor-id", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--role", default="Admin", choices=["User", "Employee", "Admin"])
    parser.add_argument("--label", default=None)
    args = parser.parse_args()

    with SessionLocal() as db:
        actor = provision_rbac_account(
            db,
            actor_id=args.actor_id,
            display_label=args.label or args.actor_id,
            email=args.email,
            role=args.role,
            password=args.password,
            device_id=f"dev-{args.actor_id}",
            operator_actor_id="cli-provision",
            correlation_id="cli-provision",
        )
        print(f"Provisioned {actor.role} account '{actor.id}' ({actor.email})")


if __name__ == "__main__":
    main()
