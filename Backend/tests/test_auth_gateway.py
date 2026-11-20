"""
ShipSafe Authentication Gateway Test Suite
Tests registration, login, rate limiting, password reset flows, session rotation, and email verification.
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.connection import Base, engine, SessionLocal
from database.models import User, RefreshToken, PasswordReset, EmailVerification
from database.schemas import (
    UserRegisterRequest,
    UserLoginRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    VerifyEmailRequest,
)
from auth.service import AuthService
from auth.security import verify_password, auth_rate_limiter, validate_password_strength
from fastapi import HTTPException


@pytest.fixture(scope="module")
def db():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    yield session
    session.close()


def test_password_strength_validator():
    weak = validate_password_strength("short")
    assert weak["label"] == "Weak"
    assert weak["valid"] is False

    fair = validate_password_strength("password123")
    assert fair["label"] in ["Fair", "Weak"]

    strong = validate_password_strength("SuperSecretPassword2026!#")
    assert strong["label"] == "Strong"
    assert strong["valid"] is True


def test_auth_gateway_registration_flow(db):
    req = UserRegisterRequest(
        full_name="Gateway Architect",
        email="gateway_test@shipsafe.dev",
        password="ValidPassword2026!#",
        confirm_password="ValidPassword2026!#"
    )
    user, org, access_token, refresh_token = AuthService.register_user(db, req)
    assert user.id is not None
    assert user.email == "gateway_test@shipsafe.dev"
    assert verify_password("ValidPassword2026!#", user.hashed_password)
    assert org.id is not None
    assert access_token is not None
    assert refresh_token is not None

    # Duplicate registration fails
    with pytest.raises(HTTPException) as exc:
        AuthService.register_user(db, req)
    assert exc.value.status_code == 400


def test_auth_gateway_login_and_token_rotation(db):
    login_req = UserLoginRequest(
        email="gateway_test@shipsafe.dev",
        password="ValidPassword2026!#"
    )
    user, org, access_tok, refresh_tok = AuthService.authenticate_user(db, login_req)
    assert user.email == "gateway_test@shipsafe.dev"
    assert access_tok is not None

    # Token rotation
    u2, o2, new_access, new_refresh = AuthService.refresh_session(db, refresh_tok)
    assert u2.id == user.id
    assert new_access is not None
    assert new_refresh != refresh_tok

    # Old refresh token is revoked
    with pytest.raises(HTTPException):
        AuthService.refresh_session(db, refresh_tok)


def test_auth_gateway_password_reset_revokes_sessions(db):
    # Request reset token
    raw_token = AuthService.initiate_password_reset(db, "gateway_test@shipsafe.dev")
    assert raw_token is not None
    assert raw_token.startswith("rst_")

    # Non-existent email returns None
    ghost_token = AuthService.initiate_password_reset(db, "nobody@nowhere.corp")
    assert ghost_token is None

    # Login to generate an active session
    _, _, _, active_refresh = AuthService.authenticate_user(
        db, 
        UserLoginRequest(email="gateway_test@shipsafe.dev", password="ValidPassword2026!#")
    )

    # Perform password reset
    updated_user = AuthService.complete_password_reset(db, raw_token, "NewPassword2026!#")
    assert updated_user.email == "gateway_test@shipsafe.dev"
    assert verify_password("NewPassword2026!#", updated_user.hashed_password)

    # Active session should now be revoked
    with pytest.raises(HTTPException):
        AuthService.refresh_session(db, active_refresh)

    # Re-using the same reset token must fail
    with pytest.raises(HTTPException):
        AuthService.complete_password_reset(db, raw_token, "AnotherPassword123!")


def test_auth_gateway_email_verification(db):
    user = db.query(User).filter(User.email == "gateway_test@shipsafe.dev").first()
    user.is_verified = False
    db.commit()

    vrf_token = AuthService.initiate_email_verification(db, user.id)
    assert vrf_token is not None

    verified_user = AuthService.complete_email_verification(db, vrf_token)
    assert verified_user.is_verified is True


def test_auth_gateway_rate_limiter():
    key = "test_client_ip:login"
    auth_rate_limiter.reset(key)

    for _ in range(5):
        assert auth_rate_limiter.is_allowed(key, max_requests=5, window_seconds=10) is True

    # 6th attempt should be blocked
    assert auth_rate_limiter.is_allowed(key, max_requests=5, window_seconds=10) is False
    auth_rate_limiter.reset(key)
