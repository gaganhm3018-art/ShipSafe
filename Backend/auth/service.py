"""
ShipSafe Authentication Service
Orchestrates registration, authentication, token rotation, and workspace provisioning.
"""

import uuid
import re
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from database.models import (
    User, 
    RefreshToken, 
    Organization, 
    OrganizationMember, 
    OrgRole, 
    SecurityPolicy, 
    AuditLog,
    PasswordReset,
    EmailVerification
)
from database.schemas import UserRegisterRequest, UserLoginRequest
from .security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    hash_token,
    decode_token,
)


def slugify(text: str) -> str:
    """Converts a name to a URL-friendly slug."""
    s = re.sub(r"[^\w\s-]", "", text).strip().lower()
    return re.sub(r"[-\s]+", "-", s) or "workspace"


class AuthService:
    @staticmethod
    def register_user(db: Session, req: UserRegisterRequest, ip_address: Optional[str] = None) -> Tuple[User, Organization, str, str]:
        if req.password != req.confirm_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password confirmation does not match password"
            )

        existing_user = db.query(User).filter(User.email == req.email.lower()).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="An account with this email address already exists"
            )

        # 1. Create User
        hashed_pw = hash_password(req.password)
        user = User(
            email=req.email.lower(),
            hashed_password=hashed_pw,
            full_name=req.full_name.strip(),
            is_active=True,
            is_verified=True,  # In dev/MVP, auto-verified; token workflow also supported
        )
        db.add(user)
        db.flush()

        # 2. Automatically provision initial personal workspace Organization
        workspace_name = f"{user.full_name}'s Workspace"
        base_slug = slugify(f"{user.full_name}-{str(uuid.uuid4())[:6]}")
        org = Organization(
            name=workspace_name,
            slug=base_slug
        )
        db.add(org)
        db.flush()

        # 3. Assign User as OWNER of this organization
        membership = OrganizationMember(
            organization_id=org.id,
            user_id=user.id,
            role=OrgRole.OWNER
        )
        db.add(membership)

        # 4. Provision default Security Policy for this organization
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

        # 5. Create Audit Log entry
        audit = AuditLog(
            organization_id=org.id,
            user_id=user.id,
            action="USER_REGISTERED",
            resource_type="USER",
            resource_id=user.id,
            details_json=f'{{"email": "{user.email}", "initial_workspace": "{org.name}"}}',
            ip_address=ip_address
        )
        db.add(audit)

        # 6. Generate Initial Token Pair
        access_token = create_access_token({
            "sub": user.id,
            "email": user.email,
            "org_id": org.id,
            "role": OrgRole.OWNER.value
        })
        refresh_token, expires_at = create_refresh_token(user.id)
        db_ref_token = RefreshToken(
            user_id=user.id,
            token_hash=hash_token(refresh_token),
            expires_at=expires_at,
            revoked=False
        )
        db.add(db_ref_token)

        db.commit()
        db.refresh(user)
        db.refresh(org)
        return user, org, access_token, refresh_token

    @staticmethod
    def authenticate_user(db: Session, req: UserLoginRequest, ip_address: Optional[str] = None) -> Tuple[User, Organization, str, str]:
        user = db.query(User).filter(User.email == req.email.lower()).first()
        if not user or not verify_password(req.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your account has been deactivated. Please contact an administrator."
            )

        # Find primary organization
        membership = db.query(OrganizationMember).filter(OrganizationMember.user_id == user.id).first()
        if not membership:
            # Create a workspace if none exists
            org = Organization(name=f"{user.full_name}'s Workspace", slug=slugify(f"{user.full_name}-{str(uuid.uuid4())[:6]}"))
            db.add(org)
            db.flush()
            membership = OrganizationMember(organization_id=org.id, user_id=user.id, role=OrgRole.OWNER)
            db.add(membership)
            db.commit()
            db.refresh(org)
        else:
            org = membership.organization

        access_token = create_access_token({
            "sub": user.id,
            "email": user.email,
            "org_id": org.id,
            "role": membership.role.value
        })
        refresh_token, expires_at = create_refresh_token(user.id)
        db_ref_token = RefreshToken(
            user_id=user.id,
            token_hash=hash_token(refresh_token),
            expires_at=expires_at,
            revoked=False
        )
        db.add(db_ref_token)

        # Audit log
        db.add(AuditLog(
            organization_id=org.id,
            user_id=user.id,
            action="USER_LOGIN",
            resource_type="USER",
            resource_id=user.id,
            details_json='{"status": "SUCCESS"}',
            ip_address=ip_address
        ))
        db.commit()
        return user, org, access_token, refresh_token

    @staticmethod
    def refresh_session(db: Session, refresh_token: str) -> Tuple[User, Organization, str, str]:
        payload = decode_token(refresh_token)
        if not payload or payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token"
            )

        t_hash = hash_token(refresh_token)
        stored_token = db.query(RefreshToken).filter(
            RefreshToken.token_hash == t_hash,
            RefreshToken.revoked == False
        ).first()

        if not stored_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has been revoked or expired"
            )

        now_utc = datetime.now(timezone.utc)
        stored_exp = stored_token.expires_at
        if stored_exp.tzinfo is None:
            stored_exp = stored_exp.replace(tzinfo=timezone.utc)

        if stored_exp < now_utc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has been revoked or expired"
            )



        user = db.query(User).filter(User.id == stored_token.user_id).first()
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account associated with this token is not active"
            )

        # Token Rotation: Revoke previous token
        stored_token.revoked = True

        membership = db.query(OrganizationMember).filter(OrganizationMember.user_id == user.id).first()
        org = membership.organization if membership else None
        org_id = org.id if org else None
        role_val = membership.role.value if membership else OrgRole.VIEWER.value

        new_access = create_access_token({
            "sub": user.id,
            "email": user.email,
            "org_id": org_id,
            "role": role_val
        })
        new_refresh, new_exp = create_refresh_token(user.id)
        db.add(RefreshToken(
            user_id=user.id,
            token_hash=hash_token(new_refresh),
            expires_at=new_exp,
            revoked=False
        ))
        db.commit()
        return user, org, new_access, new_refresh

    @staticmethod
    def revoke_token(db: Session, refresh_token: str) -> bool:
        t_hash = hash_token(refresh_token)
        stored_token = db.query(RefreshToken).filter(RefreshToken.token_hash == t_hash).first()
        if stored_token:
            stored_token.revoked = True
            stored_token.revoked_at = datetime.now(timezone.utc)
            db.commit()
            return True
        return False

    @staticmethod
    def revoke_all_user_sessions(db: Session, user_id: str):
        now_utc = datetime.now(timezone.utc)
        tokens = db.query(RefreshToken).filter(
            RefreshToken.user_id == user_id,
            RefreshToken.revoked == False
        ).all()
        for t in tokens:
            t.revoked = True
            t.revoked_at = now_utc
        db.commit()

    @staticmethod
    def initiate_password_reset(db: Session, email: str) -> Optional[str]:
        user = db.query(User).filter(User.email == email.lower()).first()
        if not user:
            return None

        # Invalidate previous unused reset tokens for this user
        prev_tokens = db.query(PasswordReset).filter(
            PasswordReset.user_id == user.id,
            PasswordReset.used_at == None
        ).all()
        now_utc = datetime.now(timezone.utc)
        for pt in prev_tokens:
            pt.used_at = now_utc

        raw_token = f"rst_{uuid.uuid4().hex}_{secrets.token_hex(16)}"
        token_entry = PasswordReset(
            user_id=user.id,
            token_hash=hash_token(raw_token),
            expires_at=now_utc + timedelta(hours=1)
        )
        db.add(token_entry)
        db.commit()
        return raw_token

    @staticmethod
    def complete_password_reset(db: Session, raw_token: str, new_password: str) -> User:
        t_hash = hash_token(raw_token)
        now_utc = datetime.now(timezone.utc)
        reset_record = db.query(PasswordReset).filter(
            PasswordReset.token_hash == t_hash,
            PasswordReset.used_at == None
        ).first()

        if not reset_record:
            # Fallback check for JWT-based reset token for backwards compatibility
            payload = decode_token(raw_token)
            if payload and payload.get("purpose") == "password_reset":
                user_id = payload.get("sub")
                user = db.query(User).filter(User.id == user_id).first()
                if user:
                    user.hashed_password = hash_password(new_password)
                    AuthService.revoke_all_user_sessions(db, user.id)
                    db.commit()
                    return user
            raise HTTPException(status_code=400, detail="Invalid or expired reset token")

        exp = reset_record.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < now_utc:
            raise HTTPException(status_code=400, detail="Reset token has expired")

        user = db.query(User).filter(User.id == reset_record.user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        reset_record.used_at = now_utc
        user.hashed_password = hash_password(new_password)
        # Revoke all existing sessions
        AuthService.revoke_all_user_sessions(db, user.id)
        db.commit()
        return user

    @staticmethod
    def initiate_email_verification(db: Session, user_id: str) -> str:
        now_utc = datetime.now(timezone.utc)
        raw_token = f"vrf_{uuid.uuid4().hex}_{secrets.token_hex(16)}"
        entry = EmailVerification(
            user_id=user_id,
            token_hash=hash_token(raw_token),
            expires_at=now_utc + timedelta(hours=24)
        )
        db.add(entry)
        db.commit()
        return raw_token

    @staticmethod
    def resend_email_verification(db: Session, email: str) -> Optional[str]:
        user = db.query(User).filter(User.email == email.lower()).first()
        if not user or user.is_verified:
            return None
        return AuthService.initiate_email_verification(db, user.id)

    @staticmethod
    def complete_email_verification(db: Session, raw_token: str) -> User:
        t_hash = hash_token(raw_token)
        now_utc = datetime.now(timezone.utc)
        record = db.query(EmailVerification).filter(
            EmailVerification.token_hash == t_hash,
            EmailVerification.verified_at == None
        ).first()

        if not record:
            payload = decode_token(raw_token)
            if payload:
                user_id = payload.get("sub")
                user = db.query(User).filter(User.id == user_id).first()
                if user:
                    user.is_verified = True
                    db.commit()
                    return user
            raise HTTPException(status_code=400, detail="Invalid or expired verification token")

        exp = record.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < now_utc:
            raise HTTPException(status_code=400, detail="Verification token has expired")

        user = db.query(User).filter(User.id == record.user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        record.verified_at = now_utc
        user.is_verified = True
        db.commit()
        return user
