"""Administrative CLI operations for ASM SaaS."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from asm.db.models import Domain, Organization
from asm.db.session import get_session_factory

logger = logging.getLogger(__name__)


def move_domain(
    session: Session,
    domain_id: int,
    target_org_id: int,
) -> int:
    """Move a domain from the legacy quarantine organization into a target organization.

    Security & Safety Invariants:
    1. A domain can ONLY be moved if its current org has system_kind == 'legacy_quarantine'.
       Moving between ordinary customer orgs via this command is strictly forbidden (exit 1).
    2. The target organization must exist (exit 1).
    3. The target organization cannot already contain a domain with the same name (exit 1).
    """
    domain = session.get(Domain, domain_id)
    if not domain:
        sys.stderr.write(f"Error: Domain with ID {domain_id} does not exist.\n")
        return 1

    current_org = session.get(Organization, domain.org_id)
    if not current_org or current_org.system_kind != "legacy_quarantine":
        sys.stderr.write(
            f"Error: Domain {domain_id} ('{domain.name}') cannot be moved. "
            f"Current organization {domain.org_id} is not a legacy quarantine organization.\n"
        )
        return 1

    target_org = session.get(Organization, target_org_id)
    if not target_org:
        sys.stderr.write(f"Error: Target organization with ID {target_org_id} does not exist.\n")
        return 1

    conflict = session.scalar(
        select(Domain.id).where(
            Domain.org_id == target_org_id,
            Domain.name == domain.name,
            Domain.id != domain_id,
        )
    )
    if conflict:
        sys.stderr.write(
            f"Error: Target organization {target_org_id} already contains domain "
            f"'{domain.name}' (domain_id={conflict}).\n"
        )
        return 1

    old_org_id = domain.org_id
    domain.org_id = target_org_id
    session.commit()
    print(
        f"Successfully moved domain {domain_id} ('{domain.name}') from legacy quarantine "
        f"(org {old_org_id}) to organization {target_org_id} ('{target_org.name}')."
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build administrative CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="asm-admin",
        description="ASM SaaS Administrative Operations",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    move_parser = subparsers.add_parser(
        "move-domain",
        help="Move a domain from the legacy quarantine organization into a target organization",
    )
    move_parser.add_argument(
        "--domain-id",
        type=int,
        required=True,
        help="ID of the domain to move",
    )
    move_parser.add_argument(
        "--target-org-id",
        type=int,
        required=True,
        help="ID of the target customer organization",
    )

    return parser


def main(argv: Sequence[str] | None = None, session: Session | None = None) -> int:
    """Main admin CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    if session is not None:
        if args.command == "move-domain":
            return move_domain(session, args.domain_id, args.target_org_id)
    else:
        factory = get_session_factory()
        with factory() as sess:
            if args.command == "move-domain":
                return move_domain(sess, args.domain_id, args.target_org_id)

    return 0


if __name__ == "__main__":
    sys.exit(main())
