"""Organization and membership management routes."""

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func, select

from asm.api.deps import CurrentUser, DbSession, require_org_role
from asm.api.schemas import (
    OrgCreate,
    OrgMemberAdd,
    OrgMemberRead,
    OrgMemberUpdate,
    OrgRead,
    OrgWithRoleRead,
)
from asm.audit import record_event
from asm.db.models import Membership, Organization, User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/orgs", tags=["Organizations"])


@router.post(
    "",
    response_model=OrgRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new organization",
    responses={
        201: {"description": "Organization created successfully"},
        401: {"description": "Authentication required"},
    },
)
def create_organization(
    payload: OrgCreate,
    current_user: CurrentUser,
    db: DbSession,
) -> OrgRead:
    """Create a new organization and assign creator as owner."""
    org = Organization(name=payload.name)
    db.add(org)
    db.flush()  # populate org.id

    membership = Membership(
        org_id=org.id,
        user_id=current_user.id,
        role="owner",
    )
    db.add(membership)

    record_event(
        db,
        org_id=org.id,
        actor_type="user",
        actor_user_id=current_user.id,
        action="org.created",
        target_type="org",
        target_id=str(org.id),
        metadata={"name": org.name},
    )

    db.commit()
    db.refresh(org)

    logger.info("User %s created organization %d (%s)", current_user.id, org.id, org.name)
    return OrgRead.model_validate(org)


@router.get(
    "",
    response_model=list[OrgWithRoleRead],
    summary="List organizations current user belongs to",
    responses={
        200: {"description": "List of user organizations with roles"},
        401: {"description": "Authentication required"},
    },
)
def list_my_organizations(
    current_user: CurrentUser,
    db: DbSession,
) -> list[OrgWithRoleRead]:
    """Retrieve all organizations where current user has an active membership."""
    query = (
        select(Organization.id, Organization.name, Organization.created_at, Membership.role)
        .join(Membership, Organization.id == Membership.org_id)
        .where(Membership.user_id == current_user.id)
        .order_by(Organization.id.asc())
    )
    results = db.execute(query).all()
    return [
        OrgWithRoleRead(
            id=row.id,
            name=row.name,
            role=row.role,
            created_at=row.created_at,
        )
        for row in results
    ]


@router.get(
    "/{org_id}/members",
    response_model=list[OrgMemberRead],
    summary="List organization members",
    responses={
        200: {"description": "List of organization members"},
        401: {"description": "Authentication required"},
        404: {"description": "Organization not found (or non-member)"},
    },
)
def list_organization_members(
    org_id: int,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("viewer"))],
    db: DbSession,
) -> list[OrgMemberRead]:
    """List members of an organization. Accessible to any member (viewer, admin, owner)."""
    query = (
        select(Membership.user_id, User.email, Membership.role, Membership.created_at)
        .join(User, Membership.user_id == User.id)
        .where(Membership.org_id == org_id)
        .order_by(Membership.created_at.asc())
    )
    rows = db.execute(query).all()
    return [
        OrgMemberRead(
            user_id=row.user_id,
            email=row.email,
            role=row.role,
            created_at=row.created_at,
        )
        for row in rows
    ]


@router.post(
    "/{org_id}/members",
    response_model=OrgMemberRead,
    status_code=status.HTTP_201_CREATED,
    summary="Add a member to an organization",
    responses={
        201: {"description": "Member added successfully"},
        401: {"description": "Authentication required"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Organization not found (or non-member), or user not found"},
        409: {"description": "User already a member"},
    },
)
def add_organization_member(
    org_id: int,
    payload: OrgMemberAdd,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("admin"))],
    db: DbSession,
) -> OrgMemberRead:
    """Add a member to an organization by email.

    - Target user must have logged into the platform at least once.
    - Admins can add viewers or admins. Only owners can appoint owners.
    """
    _, caller_membership = auth_context

    if caller_membership.role != "owner" and payload.role == "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only owners can appoint other owners",
        )

    target_user = db.execute(
        select(User).where(User.email == payload.email)
    ).scalar_one_or_none()
    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User with this email has not logged in to the platform yet",
        )

    existing = db.execute(
        select(Membership).where(
            Membership.org_id == org_id,
            Membership.user_id == target_user.id,
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User is already a member of this organization",
        )

    membership = Membership(
        org_id=org_id,
        user_id=target_user.id,
        role=payload.role,
    )
    db.add(membership)
    db.flush()

    record_event(
        db,
        org_id=org_id,
        actor_type="user",
        actor_user_id=caller_membership.user_id,
        action="membership.added",
        target_type="membership",
        target_id=str(membership.id),
        metadata={"user_id": str(target_user.id), "role": payload.role},
    )

    db.commit()
    db.refresh(membership)

    logger.info("Added user %s to org %d with role %s", target_user.id, org_id, payload.role)
    return OrgMemberRead(
        user_id=membership.user_id,
        email=target_user.email,
        role=membership.role,
        created_at=membership.created_at,
    )


@router.patch(
    "/{org_id}/members/{user_id}",
    response_model=OrgMemberRead,
    summary="Update organization member role",
    responses={
        200: {"description": "Member role updated"},
        401: {"description": "Authentication required"},
        403: {"description": "Only owners can update member roles"},
        404: {"description": "Organization not found (or non-member), or member not found"},
        422: {"description": "Cannot demote the last owner"},
    },
)
def update_member_role(
    org_id: int,
    user_id: uuid.UUID,
    payload: OrgMemberUpdate,
    auth_context: Annotated[tuple[Organization, Membership], Depends(require_org_role("owner"))],
    db: DbSession,
) -> OrgMemberRead:
    """Update a member's role. Restricted to owners. Enforces last-owner invariant."""
    _, caller_membership = auth_context

    target_member = db.execute(
        select(Membership).where(
            Membership.org_id == org_id,
            Membership.user_id == user_id,
        )
    ).scalar_one_or_none()
    if target_member is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Member not found in organization",
        )

    if target_member.role == "owner" and payload.role != "owner":
        # Lock organization row to prevent concurrent last-owner race
        lock_stmt = select(Organization).where(Organization.id == org_id).with_for_update()
        db.execute(lock_stmt).scalar_one()

        remaining_owners = db.scalar(
            select(func.count(Membership.id)).where(
                Membership.org_id == org_id,
                Membership.role == "owner",
                Membership.user_id != user_id,
            )
        )
        if (remaining_owners or 0) == 0:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Cannot demote the last owner of an organization",
            )

    old_role = target_member.role
    target_member.role = payload.role

    record_event(
        db,
        org_id=org_id,
        actor_type="user",
        actor_user_id=caller_membership.user_id,
        action="membership.role_changed",
        target_type="membership",
        target_id=str(target_member.id),
        metadata={
            "user_id": str(user_id),
            "old_role": old_role,
            "new_role": payload.role,
        },
    )

    db.commit()
    db.refresh(target_member)

    target_user = db.get(User, user_id)
    return OrgMemberRead(
        user_id=target_member.user_id,
        email=target_user.email if target_user else "",
        role=target_member.role,
        created_at=target_member.created_at,
    )


@router.delete(
    "/{org_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove a member from organization",
    responses={
        204: {"description": "Member removed"},
        401: {"description": "Authentication required"},
        403: {"description": "Only owners can remove other members"},
        404: {"description": "Organization not found (or non-member), or member not found"},
        422: {"description": "Cannot remove the last owner"},
    },
)
def remove_organization_member(
    org_id: int,
    user_id: uuid.UUID,
    current_user: CurrentUser,
    db: DbSession,
) -> Response:
    """Remove a member from organization.

    - Any member may remove themselves (self-removal).
    - Removing other members requires owner role.
    - Last-owner invariant is strictly enforced.
    """
    caller_membership = db.execute(
        select(Membership).where(
            Membership.org_id == org_id,
            Membership.user_id == current_user.id,
        )
    ).scalar_one_or_none()
    if caller_membership is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found",
        )

    # If removing someone else, caller must be owner
    if current_user.id != user_id and caller_membership.role != "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only owners can remove other members",
        )

    target_member = db.execute(
        select(Membership).where(
            Membership.org_id == org_id,
            Membership.user_id == user_id,
        )
    ).scalar_one_or_none()
    if target_member is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Member not found in organization",
        )

    if target_member.role == "owner":
        # Lock organization row to prevent concurrent last-owner race
        lock_stmt = select(Organization).where(Organization.id == org_id).with_for_update()
        db.execute(lock_stmt).scalar_one()

        remaining_owners = db.scalar(
            select(func.count(Membership.id)).where(
                Membership.org_id == org_id,
                Membership.role == "owner",
                Membership.user_id != user_id,
            )
        )
        if (remaining_owners or 0) == 0:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Cannot remove the last owner of an organization",
            )

    target_member_id = target_member.id
    target_member_role = target_member.role

    record_event(
        db,
        org_id=org_id,
        actor_type="user",
        actor_user_id=current_user.id,
        action="membership.removed",
        target_type="membership",
        target_id=str(target_member_id),
        metadata={"user_id": str(user_id), "role": target_member_role},
    )

    db.delete(target_member)
    db.commit()
    logger.info("Removed user %s from org %d", user_id, org_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
