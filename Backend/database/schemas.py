"""
ShipSafe Pydantic V2 Validation Schemas
Validates request bodies, parameters, and structured JSON responses.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field


# ==============================================================================
# AUTHENTICATION SCHEMAS
# ==============================================================================

class UserRegisterRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=255)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=256)
    confirm_password: Optional[str] = Field(None, min_length=8, max_length=256)
    organization_name: Optional[str] = None


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # in seconds
    user: Dict[str, Any]
    active_organization: Optional[Dict[str, Any]] = None


class UserProfileResponse(BaseModel):
    id: str
    email: str
    full_name: str
    is_active: bool
    is_verified: bool
    avatar_url: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8, max_length=256)
    confirm_new_password: str = Field(..., min_length=8, max_length=256)


class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: EmailStr


class RefreshTokenRequest(BaseModel):
    refresh_token: Optional[str] = None


# ==============================================================================
# ORGANIZATION & WORKSPACE SCHEMAS
# ==============================================================================

class OrganizationCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    slug: Optional[str] = None


class OrganizationResponse(BaseModel):
    id: str
    name: str
    slug: str
    role: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class MemberAddRequest(BaseModel):
    email: EmailStr
    role: str = Field("DEVELOPER", pattern="^(OWNER|ADMIN|DEVELOPER|VIEWER)$")


class MemberUpdateRequest(BaseModel):
    role: str = Field(..., pattern="^(OWNER|ADMIN|DEVELOPER|VIEWER)$")


class MemberResponse(BaseModel):
    id: str
    user_id: str
    email: str
    full_name: str
    role: str
    joined_at: datetime


# ==============================================================================
# REPOSITORY & SCAN SCHEMAS
# ==============================================================================

class RepositoryAnalyzeRequest(BaseModel):
    repository_url: str = Field(..., description="Public GitHub repository URL (e.g. https://github.com/owner/repo)")
    organization_id: Optional[str] = None
    branch: Optional[str] = "main"


class RepositoryResponse(BaseModel):
    id: str
    name: str
    url: str
    default_branch: str
    language: str
    total_scans: int = 0
    open_findings: int = 0
    last_scanned: Optional[datetime] = None

    class Config:
        from_attributes = True


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    target_name: str
    target_branch: str
    duration_ms: float
    files_scanned: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    policy_violation: Optional[str] = None
    created_at: datetime
    error_message: Optional[str] = None


# ==============================================================================
# WEBSITE DAST SCHEMAS
# ==============================================================================

class WebsiteAnalyzeRequest(BaseModel):
    url: str = Field(..., description="Target website URL (e.g. https://example.com)")
    organization_id: Optional[str] = None


class WebsiteFinding(BaseModel):
    id: str
    check_category: str
    name: str
    severity: str
    evidence: str
    explanation: str
    remediation: str
    timestamp: str


class WebsiteScanResponse(BaseModel):
    scan_id: str
    url: str
    status: str
    https_valid: bool
    tls_info: Dict[str, Any]
    headers_analyzed: Dict[str, Any]
    findings: List[WebsiteFinding]
    findings_count: int
    duration_ms: float
    created_at: datetime
    error_message: Optional[str] = None


# ==============================================================================
# SECURITY INTELLIGENCE & ANALYTICS SCHEMAS
# ==============================================================================

class SecurityTrendPoint(BaseModel):
    date: str
    discovered: int
    resolved: int
    critical: int
    high: int


class RecurringMistake(BaseModel):
    rule_id: str
    name: str
    type: str
    cwe: str
    count: int
    reopened_count: int
    affected_files: List[str]
    observation: str
    recommendation: str
    action_item: str


class AnalyticsOverviewResponse(BaseModel):
    total_scans: int
    open_findings_count: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    resolved_findings: int
    reopened_findings: int
    fix_rate_percentage: float
    avg_remediation_time_hours: float
    security_score: int  # 0 to 100
    gate_status: str  # SAFE_TO_SHIP vs BLOCKED_IN_CI
    time_range: str


class ActionableRecommendation(BaseModel):
    id: str
    title: str
    severity: str
    observation: str
    impact: str
    suggested_action: str
    affected_repositories: List[str]
