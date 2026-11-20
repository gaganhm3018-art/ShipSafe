"""
ShipSafe Comprehensive Test Suite
Tests authentication, organizations, RBAC, repository SAST, website DAST, SSRF protections, and analytics.
Directly exercises services and route logic without Starlette TestClient thread blocking portal.
"""

import pytest
import os
import sys

# Ensure backend directory is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.connection import Base, engine, SessionLocal
from database.models import User, Organization, OrganizationMember, OrgRole, SeverityEnum, FindingStatusEnum, Finding
from database.schemas import (
    UserRegisterRequest,
    UserLoginRequest,
    OrganizationCreateRequest,
    MemberAddRequest,
)
from auth.service import AuthService
from auth.dependencies import verify_org_access
from auth.security import verify_password, decode_token
from website_scanner.service import validate_and_resolve_url, SSRFValidationError
from analytics.service import AnalyticsService
from repositories.service import parse_github_url, generate_stable_fingerprint
from fastapi import HTTPException


@pytest.fixture(scope="module")
def db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    yield session
    session.close()



# ==============================================================================
# 1. AUTHENTICATION & WORKSPACE TESTS
# ==============================================================================

def test_user_registration_and_workspace_provisioning(db):
    req = UserRegisterRequest(
        full_name="Alex Lead",
        email="alex_lead_test@acme.dev",
        password="SuperPassword123!",
        confirm_password="SuperPassword123!"
    )
    user, org, access_token, refresh_token = AuthService.register_user(db, req)
    assert user.id is not None
    assert user.email == "alex_lead_test@acme.dev"
    assert verify_password("SuperPassword123!", user.hashed_password)
    assert org.id is not None
    assert "Alex Lead" in org.name

    # Verify membership
    mem = db.query(OrganizationMember).filter(
        OrganizationMember.organization_id == org.id,
        OrganizationMember.user_id == user.id
    ).first()
    assert mem is not None
    assert mem.role == OrgRole.OWNER

    # Duplicate registration must fail
    with pytest.raises(HTTPException) as exc:
        AuthService.register_user(db, req)
    assert exc.value.status_code == 400


def test_user_authentication_and_token_refresh(db):
    # Valid login
    login_req = UserLoginRequest(
        email="alex_lead_test@acme.dev",
        password="SuperPassword123!"
    )
    user, org, access_tok, refresh_tok = AuthService.authenticate_user(db, login_req)
    assert user.email == "alex_lead_test@acme.dev"
    assert access_tok is not None

    # Decode access token
    payload = decode_token(access_tok)
    assert payload["sub"] == user.id
    assert payload["type"] == "access"

    # Refresh session
    u2, o2, new_acc, new_ref = AuthService.refresh_session(db, refresh_tok)
    assert u2.id == user.id
    assert new_acc is not None

    # Old refresh token should now be revoked (Token Rotation)
    with pytest.raises(HTTPException):
        AuthService.refresh_session(db, refresh_tok)

    # Invalid password login
    bad_req = UserLoginRequest(
        email="alex_lead_test@acme.dev",
        password="IncorrectPassword!"
    )
    with pytest.raises(HTTPException) as exc:
        AuthService.authenticate_user(db, bad_req)
    assert exc.value.status_code == 401


# ==============================================================================
# 2. RBAC & ORGANIZATION DATA ISOLATION TESTS
# ==============================================================================

def test_organization_rbac_and_isolation(db):
    # Owner
    owner_req = UserRegisterRequest(
        full_name="Org Boss",
        email="boss_test@acme.dev",
        password="BossPassword123!",
        confirm_password="BossPassword123!"
    )
    owner, org, _, _ = AuthService.register_user(db, owner_req)

    # Outsider
    outsider_req = UserRegisterRequest(
        full_name="Outsider",
        email="outsider_test@evil.corp",
        password="OutsiderPassword123!",
        confirm_password="OutsiderPassword123!"
    )
    outsider, outsider_org, _, _ = AuthService.register_user(db, outsider_req)

    # Outsider trying to access Boss's org -> 403 Forbidden
    with pytest.raises(HTTPException) as exc:
        verify_org_access(org_id=org.id, user=outsider, db=db, min_role=OrgRole.VIEWER)
    assert exc.value.status_code == 403

    # Boss can access with OWNER role
    mem = verify_org_access(org_id=org.id, user=owner, db=db, min_role=OrgRole.OWNER)
    assert mem.role == OrgRole.OWNER


# ==============================================================================
# 3. WEBSITE DAST & STRICT SSRF DEFENSE TESTS
# ==============================================================================

def test_ssrf_protection_guards():
    # 1. Localhost rejection
    with pytest.raises(SSRFValidationError):
        validate_and_resolve_url("http://localhost:8080/admin")

    with pytest.raises(SSRFValidationError):
        validate_and_resolve_url("http://127.0.0.1:5432")

    # 2. Cloud metadata IP rejection (169.254.169.254)
    with pytest.raises(SSRFValidationError):
        validate_and_resolve_url("http://169.254.169.254/latest/meta-data/")

    # 3. Private IP subnet rejection (RFC 1918)
    with pytest.raises(SSRFValidationError):
        validate_and_resolve_url("http://192.168.1.1/")

    with pytest.raises(SSRFValidationError):
        validate_and_resolve_url("http://10.0.0.1/internal")

    # 4. Invalid protocols
    with pytest.raises(SSRFValidationError):
        validate_and_resolve_url("file:///etc/passwd")

    with pytest.raises(SSRFValidationError):
        validate_and_resolve_url("gopher://127.0.0.1:70")


# ==============================================================================
# 4. REPOSITORY URL VALIDATION & FINGERPRINTING
# ==============================================================================

def test_repository_url_parsing_and_fingerprints():
    # Valid GitHub URLs
    owner, repo = parse_github_url("https://github.com/facebook/react")
    assert owner == "facebook"
    assert repo == "react"

    owner2, repo2 = parse_github_url("https://github.com/fastapi/fastapi.git")
    assert owner2 == "fastapi"
    assert repo2 == "fastapi"

    # Invalid URLs
    with pytest.raises(ValueError):
        parse_github_url("https://gitlab.com/owner/repo")

    with pytest.raises(ValueError):
        parse_github_url("not-a-url")

    # Stable fingerprint consistency
    fp1 = generate_stable_fingerprint("INJ-001", "backend/app.py", 42, 'cursor.execute(f"SELECT * FROM users")')
    fp2 = generate_stable_fingerprint("INJ-001", "backend/app.py", 42, 'cursor.execute(f"SELECT * FROM users")  ')
    assert fp1 == fp2  # Normalized whitespace produces identical stable fingerprint


# ==============================================================================
# 5. SECURITY ANALYTICS & RECURRENCE TRACKING
# ==============================================================================

def test_analytics_calculations_and_recurrence(db):
    org = Organization(name="Analytics Test Org", slug="analytics-test-org")
    db.add(org)
    db.flush()

    # Seed mock finding
    f1 = Finding(
        id="TEST-FND-001",
        organization_id=org.id,
        fingerprint="fp-inj-001",
        rule_id="INJ-001",
        name="SQL Injection",
        type="SQL Injection",
        severity=SeverityEnum.CRITICAL,
        cwe="CWE-89",
        description="SQL injection in users endpoint",
        impact="Full compromise",
        remediation="Use parameterization",
        file_path="app.py",
        line_number=10,
        status=FindingStatusEnum.OPEN,
        occurrence_count=2
    )
    db.add(f1)
    db.commit()

    overview = AnalyticsService.get_overview(db, org.id, days=30)
    assert overview["critical_findings"] >= 1
    assert overview["gate_status"] == "BLOCKED_IN_CI"
    assert overview["security_score"] < 100

    recurring = AnalyticsService.get_recurring_mistakes(db, org.id)
    assert len(recurring) >= 1
    assert recurring[0]["rule_id"] == "INJ-001"
    assert "parameterized" in recurring[0]["action_item"].lower()
