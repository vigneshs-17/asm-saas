"""Just-in-time (JIT) user upsert with 5-minute update throttling."""

import uuid

from sqlalchemy import func, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from asm.db.models import User


def upsert_user(session: Session, user_id: uuid.UUID, email: str) -> User:
    """Upsert user record just-in-time on authenticated request.

    Only updates last_seen_at when it is older than 5 minutes to avoid
    wasteful database write amplification on rapid consecutive requests.
    """
    stmt = insert(User).values(
        id=user_id,
        email=email,
        created_at=func.now(),
        last_seen_at=func.now(),
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=[User.id],
        set_={
            "email": stmt.excluded.email,
            "last_seen_at": func.now(),
        },
        where=(User.last_seen_at < func.now() - text("INTERVAL '5 minutes'")),
    )
    session.execute(stmt)
    user = session.get(User, user_id)
    if user is None:
        raise RuntimeError(f"User {user_id} not found after JIT upsert")
    session.refresh(user)
    return user

