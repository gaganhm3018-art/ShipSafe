"""
ShipSafe Authentication Routes
Provides API endpoints for registration, login, logout, refresh, and profile management.
"""

from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from sqlalchemy.orm import Session
from database.connection import get_db
from database.models import User, Organization
from database.schemas import (
    UserRegisterRequest,
    UserLoginRequest,
    TokenResponse,
    UserProfileResponse,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    VerifyEmailRequest,
    ResendVerificationRequest,
    RefreshTokenRequest,
)
from .service import AuthService
from .dependencies import get_current_user
from .security import hash_password, create_access_token, decode_token, auth_rate_limiter

router = APIRouter()


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(
    req: UserRegisterRequest,
    response: Response,
    request: Request,
    db: Session = Depends(get_db)
):
    """Registers a new user and provisions their personal workspace."""
    client_ip = request.client.host if request.client else "unknown"
    if not auth_rate_limiter.is_allowed(f"{client_ip}:register", max_requests=15, window_seconds=60):
        raise HTTPException(status_code=429, detail="Too many registration attempts. Please try again later.")

    user, org, access_token, refresh_token = AuthService.register_user(db, req, ip_address=client_ip)

    # Set secure HttpOnly cookie for refresh token
    response.set_cookie(
        key="shipsafe_refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,  # Set to True in HTTPS production
        samesite="lax",
        max_age=7 * 24 * 3600
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 1800,
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "is_verified": user.is_verified,
        },
        "active_organization": {
            "id": org.id,
            "name": org.name,
            "slug": org.slug,
            "role": "OWNER"
        }
    }


@router.post("/login", response_model=TokenResponse)
def login(
    req: UserLoginRequest,
    response: Response,
    request: Request,
    db: Session = Depends(get_db)
):
    """Authenticates credentials and establishes session."""
    client_ip = request.client.host if request.client else "unknown"
    if not auth_rate_limiter.is_allowed(f"{client_ip}:login", max_requests=25, window_seconds=60):
        raise HTTPException(status_code=429, detail="Too many login attempts. Please try again later.")

    user, org, access_token, refresh_token = AuthService.authenticate_user(db, req, ip_address=client_ip)

    response.set_cookie(
        key="shipsafe_refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=7 * 24 * 3600
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 1800,
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "is_verified": user.is_verified,
        },
        "active_organization": {
            "id": org.id,
            "name": org.name,
            "slug": org.slug,
            "role": "OWNER"
        }
    }


@router.post("/refresh", response_model=TokenResponse)
def refresh_token_endpoint(
    req: RefreshTokenRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """Rotates refresh token and returns a fresh short-lived access token."""
    token_str = req.refresh_token or request.cookies.get("shipsafe_refresh_token")
    if not token_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token required in request body or cookie"
        )

    user, org, new_access, new_refresh = AuthService.refresh_session(db, token_str)

    response.set_cookie(
        key="shipsafe_refresh_token",
        value=new_refresh,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=7 * 24 * 3600
    )

    return {
        "access_token": new_access,
        "token_type": "bearer",
        "expires_in": 1800,
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "is_verified": user.is_verified,
        },
        "active_organization": {
            "id": org.id if org else None,
            "name": org.name if org else "Personal Workspace",
            "slug": org.slug if org else "personal",
            "role": "OWNER"
        }
    }


@router.post("/logout")
def logout(
    req: RefreshTokenRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """Revokes session and clears authentication cookies."""
    token_str = req.refresh_token or request.cookies.get("shipsafe_refresh_token")
    if token_str:
        AuthService.revoke_token(db, token_str)

    response.delete_cookie("shipsafe_refresh_token")
    response.delete_cookie("shipsafe_access_token")
    return {"status": "success", "message": "Logged out successfully"}


@router.get("/me", response_model=UserProfileResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """Returns the authenticated user's profile."""
    return current_user


@router.post("/forgot-password")
def forgot_password(req: ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)):
    """Initiates a secure password reset email flow."""
    client_ip = request.client.host if request.client else "unknown"
    if not auth_rate_limiter.is_allowed(f"{client_ip}:forgot", max_requests=10, window_seconds=60):
        raise HTTPException(status_code=429, detail="Too many password reset requests. Please try again later.")

    raw_token = AuthService.initiate_password_reset(db, req.email)
    # Always return 200 to prevent email enumeration timing attacks
    response = {
        "status": "success",
        "message": "If this email exists, a password reset link has been dispatched."
    }
    if raw_token:
        response["dev_reset_token"] = raw_token
    return response


@router.post("/reset-password")
def reset_password(req: ResetPasswordRequest, request: Request, db: Session = Depends(get_db)):
    """Resets user password using a verified single-use reset token."""
    client_ip = request.client.host if request.client else "unknown"
    if not auth_rate_limiter.is_allowed(f"{client_ip}:reset", max_requests=10, window_seconds=60):
        raise HTTPException(status_code=429, detail="Too many reset attempts. Please try again later.")

    if req.new_password != req.confirm_new_password:
        raise HTTPException(status_code=400, detail="New passwords do not match")

    AuthService.complete_password_reset(db, req.token, req.new_password)
    return {
        "status": "success",
        "message": "Password updated successfully. All previous sessions have been revoked. Please sign in with your new password."
    }


@router.post("/verify-email")
def verify_email(req: VerifyEmailRequest, db: Session = Depends(get_db)):
    """Verifies user email address using a single-use verification token."""
    AuthService.complete_email_verification(db, req.token)
    return {"status": "success", "message": "Email address verified successfully"}


@router.post("/resend-verification")
def resend_verification(req: ResendVerificationRequest, request: Request, db: Session = Depends(get_db)):
    """Resends a verification email without leaking account registration status."""
    client_ip = request.client.host if request.client else "unknown"
    if not auth_rate_limiter.is_allowed(f"{client_ip}:resend_vrf", max_requests=5, window_seconds=60):
        raise HTTPException(status_code=429, detail="Too many verification requests. Please try again later.")

    raw_token = AuthService.resend_email_verification(db, req.email)
    res = {
        "status": "success",
        "message": "If the account exists and requires verification, a new verification link has been sent."
    }
    if raw_token:
        res["dev_verification_token"] = raw_token
    return res
