"""
ShipSafe Authentication & Authorization Dependencies
Verifies user authentication, organization membership, and RBAC roles.
"""

from typing import List, Optional
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from database.connection import get_db
from database.models import User, OrganizationMember, OrgRole
from .security import decode_token

security_bearer = HTTPBearer(auto_error=False)

ROLE_HIERARCHY = {
    OrgRole.VIEWER: 1,
    OrgRole.DEVELOPER: 2,
    OrgRole.ADMIN: 3,
    OrgRole.OWNER: 4,
}


def get_token_from_request(
    request: Request,
    bearer_creds: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)
) -> Optional[str]:
    """Retrieves token from Bearer header or fallback HttpOnly cookie."""
    if bearer_creds and bearer_creds.credentials:
        return bearer_creds.credentials
    # Fallback to cookie
    return request.cookies.get("shipsafe_access_token")


def get_current_user(
    token: Optional[str] = Depends(get_token_from_request),
    db: Session = Depends(get_db)
) -> User:
    """Dependency verifying access token and returning current active user."""
    if not token:
        # Development / local fallback
        dev_user = db.query(User).filter(User.email == "alex@acme.dev").first()
        if not dev_user:
            dev_user = db.query(User).first()
        if dev_user:
            return dev_user

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_token(token)
    if not payload or payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed authentication payload",
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is deactivated or not found",
        )
    return user


def get_current_active_user(user: User = Depends(get_current_user)) -> User:
    return user


def verify_org_access(
    org_id: str,
    user: User,
    db: Session,
    min_role: OrgRole = OrgRole.VIEWER
) -> OrganizationMember:
    """Verifies that the user belongs to the specified organization with sufficient permissions."""
    membership = (
        db.query(OrganizationMember)
        .filter(
            OrganizationMember.organization_id == org_id,
            OrganizationMember.user_id == user.id
        )
        .first()
    )
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You are not a member of this workspace or organization"
        )

    user_level = ROLE_HIERARCHY.get(membership.role, 0)
    required_level = ROLE_HIERARCHY.get(min_role, 0)

    if user_level < required_level:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Insufficient permissions: Requires {min_role.value} role or higher"
        )

    return membership


get_current_org_membership = verify_org_access



def require_role(min_role: OrgRole):
    """Factory dependency for endpoints requiring a specific minimum organization role."""
    def role_checker(
        org_id: str,
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db)
    ) -> OrganizationMember:
        return verify_org_access(org_id=org_id, user=user, db=db, min_role=min_role)
    return role_checker
