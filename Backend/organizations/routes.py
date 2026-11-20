"""
ShipSafe Organization & Workspace Management Routes
Enforces strict organization-level data isolation and role-based access control.
"""

import uuid
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database.connection import get_db
from database.models import User, Organization, OrganizationMember, OrgRole, AuditLog, SecurityPolicy
from database.schemas import (
    OrganizationCreateRequest,
    OrganizationResponse,
    MemberAddRequest,
    MemberUpdateRequest,
    MemberResponse,
)
from auth.dependencies import get_current_user, verify_org_access
from auth.service import slugify

router = APIRouter()


@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
def create_organization(
    req: OrganizationCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Creates a new Organization workspace with the creator as OWNER."""
    base_slug = req.slug or slugify(f"{req.name}-{str(uuid.uuid4())[:6]}")
    existing_org = db.query(Organization).filter(Organization.slug == base_slug).first()
    if existing_org:
        base_slug = slugify(f"{req.name}-{str(uuid.uuid4())[:8]}")

    org = Organization(
        name=req.name.strip(),
        slug=base_slug
    )
    db.add(org)
    db.flush()

    # Add creator as OWNER
    member = OrganizationMember(
        organization_id=org.id,
        user_id=current_user.id,
        role=OrgRole.OWNER
    )
    db.add(member)

    # Initialize policy
    policy = SecurityPolicy(
        organization_id=org.id,
        fail_on_severity="HIGH",
        block_prs_on_critical=True,
        block_prs_on_high=True,
        enable_secret_entropy=True,
        entropy_threshold=4.4,
        enable_ast_injections=True,
        enable_xss_checks=True,
        enable_auth_checks=True,
        enable_dependency_audit=True,
        ignored_paths_json='[".git", "node_modules", "dist", "build", "venv"]'
    )
    db.add(policy)

    # Audit log
    db.add(AuditLog(
        organization_id=org.id,
        user_id=current_user.id,
        action="ORGANIZATION_CREATED",
        resource_type="ORGANIZATION",
        resource_id=org.id,
        details_json=f'{{"name": "{org.name}", "slug": "{org.slug}"}}'
    ))
    db.commit()
    db.refresh(org)

    return {
        "id": org.id,
        "name": org.name,
        "slug": org.slug,
        "role": OrgRole.OWNER.value,
        "created_at": org.created_at
    }


@router.get("", response_model=List[OrganizationResponse])
def list_organizations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Lists all organizations/workspaces the authenticated user belongs to."""
    memberships = (
        db.query(OrganizationMember)
        .filter(OrganizationMember.user_id == current_user.id)
        .all()
    )
    results = []
    for m in memberships:
        results.append({
            "id": m.organization.id,
            "name": m.organization.name,
            "slug": m.organization.slug,
            "role": m.role.value,
            "created_at": m.organization.created_at
        })
    return results


@router.get("/{org_id}", response_model=OrganizationResponse)
def get_organization(
    org_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieves organization details if the user is a valid member."""
    membership = verify_org_access(org_id=org_id, user=current_user, db=db, min_role=OrgRole.VIEWER)
    org = membership.organization
    return {
        "id": org.id,
        "name": org.name,
        "slug": org.slug,
        "role": membership.role.value,
        "created_at": org.created_at
    }


@router.get("/{org_id}/members", response_model=List[MemberResponse])
def list_members(
    org_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Lists all members of an organization."""
    verify_org_access(org_id=org_id, user=current_user, db=db, min_role=OrgRole.VIEWER)
    memberships = db.query(OrganizationMember).filter(OrganizationMember.organization_id == org_id).all()
    return [
        {
            "id": m.id,
            "user_id": m.user.id,
            "email": m.user.email,
            "full_name": m.user.full_name,
            "role": m.role.value,
            "joined_at": m.created_at
        }
        for m in memberships
    ]


@router.post("/{org_id}/members", response_model=MemberResponse, status_code=status.HTTP_201_CREATED)
def add_member(
    org_id: str,
    req: MemberAddRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Invites or adds a member to the organization (Requires ADMIN or OWNER)."""
    verify_org_access(org_id=org_id, user=current_user, db=db, min_role=OrgRole.ADMIN)

    target_user = db.query(User).filter(User.email == req.email.lower()).first()
    if not target_user:
        # Create an invited stub user account if not yet registered
        target_user = User(
            email=req.email.lower(),
            full_name=req.email.split("@")[0],
            hashed_password="INVITED_PENDING_ACTIVATION",
            is_active=True,
            is_verified=False
        )
        db.add(target_user)
        db.flush()

    existing_membership = db.query(OrganizationMember).filter(
        OrganizationMember.organization_id == org_id,
        OrganizationMember.user_id == target_user.id
    ).first()
    if existing_membership:
        raise HTTPException(status_code=400, detail="User is already a member of this organization")

    new_membership = OrganizationMember(
        organization_id=org_id,
        user_id=target_user.id,
        role=OrgRole(req.role)
    )
    db.add(new_membership)

    db.add(AuditLog(
        organization_id=org_id,
        user_id=current_user.id,
        action="MEMBER_ADDED",
        resource_type="ORGANIZATION_MEMBER",
        resource_id=new_membership.id,
        details_json=f'{{"added_email": "{target_user.email}", "role": "{req.role}"}}'
    ))
    db.commit()
    db.refresh(new_membership)

    return {
        "id": new_membership.id,
        "user_id": target_user.id,
        "email": target_user.email,
        "full_name": target_user.full_name,
        "role": new_membership.role.value,
        "joined_at": new_membership.created_at
    }


@router.patch("/{org_id}/members/{user_id}", response_model=MemberResponse)
def update_member_role(
    org_id: str,
    user_id: str,
    req: MemberUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Updates a member's role (Requires ADMIN or OWNER)."""
    current_mem = verify_org_access(org_id=org_id, user=current_user, db=db, min_role=OrgRole.ADMIN)

    target_mem = db.query(OrganizationMember).filter(
        OrganizationMember.organization_id == org_id,
        OrganizationMember.user_id == user_id
    ).first()
    if not target_mem:
        raise HTTPException(status_code=404, detail="Member not found in this organization")

    # Only OWNER can promote or alter another OWNER
    if target_mem.role == OrgRole.OWNER and current_mem.role != OrgRole.OWNER:
        raise HTTPException(status_code=403, detail="Only Organization Owners can modify another Owner's role")

    target_mem.role = OrgRole(req.role)
    db.add(AuditLog(
        organization_id=org_id,
        user_id=current_user.id,
        action="MEMBER_ROLE_UPDATED",
        resource_type="ORGANIZATION_MEMBER",
        resource_id=target_mem.id,
        details_json=f'{{"user_id": "{user_id}", "new_role": "{req.role}"}}'
    ))
    db.commit()
    db.refresh(target_mem)

    return {
        "id": target_mem.id,
        "user_id": target_mem.user.id,
        "email": target_mem.user.email,
        "full_name": target_mem.user.full_name,
        "role": target_mem.role.value,
        "joined_at": target_mem.created_at
    }
