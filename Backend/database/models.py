"""
ShipSafe SQLAlchemy 2.0 ORM Models
Defines complete enterprise schema with organization-level data isolation.
"""

import enum
import uuid
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    ForeignKey,
    Text,
    Enum as SAEnum,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import relationship
from .connection import Base


def get_utc_now():
    return datetime.now(timezone.utc)


def generate_uuid():
    return str(uuid.uuid4())


class OrgRole(str, enum.Enum):
    OWNER = "OWNER"
    ADMIN = "ADMIN"
    DEVELOPER = "DEVELOPER"
    VIEWER = "VIEWER"


class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    WARNING = "WARNING"


class FindingStatusEnum(str, enum.Enum):
    OPEN = "OPEN"
    IN_REVIEW = "IN_REVIEW"
    REMEDIATED = "REMEDIATED"
    IGNORED = "IGNORED"


class SeverityEnum(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    avatar_url = Column(String(512), nullable=True)
    github_id = Column(String(100), nullable=True, unique=True)
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=get_utc_now, onupdate=get_utc_now, nullable=False)

    # Relationships
    memberships = relationship("OrganizationMember", back_populates="user", cascade="all, delete-orphan")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")
    password_resets = relationship("PasswordReset", back_populates="user", cascade="all, delete-orphan")
    email_verifications = relationship("EmailVerification", back_populates="user", cascade="all, delete-orphan")
    remediations = relationship("RemediationRecord", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(512), nullable=True)
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)

    user = relationship("User", back_populates="refresh_tokens")


class PasswordReset(Base):
    __tablename__ = "password_resets"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)

    user = relationship("User", back_populates="password_resets")


class EmailVerification(Base):
    __tablename__ = "email_verifications"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), unique=True, index=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)

    user = relationship("User", back_populates="email_verifications")


# Session alias for explicit session semantic references
SessionModel = RefreshToken


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=get_utc_now, onupdate=get_utc_now, nullable=False)

    # Relationships
    members = relationship("OrganizationMember", back_populates="organization", cascade="all, delete-orphan")
    projects = relationship("Project", back_populates="organization", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="organization", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="organization", cascade="all, delete-orphan")
    policies = relationship("SecurityPolicy", back_populates="organization", cascade="all, delete-orphan")
    integrations = relationship("Integration", back_populates="organization", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="organization", cascade="all, delete-orphan")
    website_scans = relationship("WebsiteScan", back_populates="organization", cascade="all, delete-orphan")


class OrganizationMember(Base):
    __tablename__ = "organization_members"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(SAEnum(OrgRole), default=OrgRole.DEVELOPER, nullable=False)
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)

    organization = relationship("Organization", back_populates="members")
    user = relationship("User", back_populates="memberships")

    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_org_user"),
    )


class Project(Base):
    __tablename__ = "projects"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=get_utc_now, onupdate=get_utc_now, nullable=False)

    organization = relationship("Organization", back_populates="projects")
    repositories = relationship("Repository", back_populates="project", cascade="all, delete-orphan")


class Repository(Base):
    __tablename__ = "repositories"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    url = Column(String(512), nullable=False)
    default_branch = Column(String(100), default="main", nullable=False)
    language = Column(String(50), default="Multi-language", nullable=False)
    is_private = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=get_utc_now, onupdate=get_utc_now, nullable=False)

    project = relationship("Project", back_populates="repositories")
    scans = relationship("Scan", back_populates="repository", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="repository", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(64), primary_key=True)  # e.g. SCAN-2026-001 or UUID
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    repository_id = Column(String(36), ForeignKey("repositories.id", ondelete="SET NULL"), nullable=True, index=True)
    scan_type = Column(String(50), default="SAST_LOCAL", nullable=False)  # SAST_LOCAL, SAST_GITHUB, DAST_WEBSITE
    target_name = Column(String(512), nullable=False)
    target_branch = Column(String(100), default="main", nullable=False)
    commit_hash = Column(String(64), nullable=True)
    trigger = Column(String(100), default="CLI Scan", nullable=False)
    status = Column(SAEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    duration_ms = Column(Float, default=0.0, nullable=False)
    files_scanned = Column(Integer, default=0, nullable=False)
    total_findings = Column(Integer, default=0, nullable=False)
    critical_count = Column(Integer, default=0, nullable=False)
    high_count = Column(Integer, default=0, nullable=False)
    medium_count = Column(Integer, default=0, nullable=False)
    low_count = Column(Integer, default=0, nullable=False)
    policy_violation = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)

    organization = relationship("Organization", back_populates="scans")
    repository = relationship("Repository", back_populates="scans")
    occurrences = relationship("FindingOccurrence", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    """
    Persistent Finding tracking a unique vulnerability instance via stable fingerprint.
    Survives across multiple scans of the same repo/file to track recurrence & remediation.
    """
    __tablename__ = "findings"

    id = Column(String(64), primary_key=True)  # SHP-{ruleId}-{hash}
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    repository_id = Column(String(36), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=True, index=True)
    fingerprint = Column(String(64), nullable=False, index=True)  # stable deduplication hash
    rule_id = Column(String(50), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    type = Column(String(100), nullable=False)
    severity = Column(SAEnum(SeverityEnum), nullable=False, index=True)
    cwe = Column(String(50), nullable=False)
    cwe_name = Column(String(255), nullable=True)
    cvss = Column(Float, nullable=True)
    description = Column(Text, nullable=False)
    why_dangerous = Column(Text, nullable=True)
    impact = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    file_path = Column(String(512), nullable=False)
    line_number = Column(Integer, nullable=False)
    language = Column(String(50), default="python", nullable=False)
    
    # Recurrence & Lifecycle tracking
    first_seen_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)
    last_seen_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)
    occurrence_count = Column(Integer, default=1, nullable=False)
    status = Column(SAEnum(FindingStatusEnum), default=FindingStatusEnum.OPEN, nullable=False, index=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    organization = relationship("Organization", back_populates="findings")
    repository = relationship("Repository", back_populates="findings")
    occurrences = relationship("FindingOccurrence", back_populates="finding", cascade="all, delete-orphan")
    remediations = relationship("RemediationRecord", back_populates="finding", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_org_repo_fingerprint", "organization_id", "repository_id", "fingerprint"),
    )


class FindingOccurrence(Base):
    """Specific snapshot of a finding occurrence during a particular scan."""
    __tablename__ = "finding_occurrences"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(64), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(String(64), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence = Column(Text, nullable=False)  # Always masked/safe
    snippet_json = Column(Text, nullable=False)  # Code context around line
    line_number = Column(Integer, nullable=False)
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)

    finding = relationship("Finding", back_populates="occurrences")
    scan = relationship("Scan", back_populates="occurrences")


class RemediationRecord(Base):
    __tablename__ = "remediation_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(64), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status = Column(String(50), default="APPLIED", nullable=False)  # REQUESTED, APPLIED, REJECTED
    patch_diff = Column(Text, nullable=False)
    commit_ref = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)

    finding = relationship("Finding", back_populates="remediations")
    user = relationship("User", back_populates="remediations")


class SecurityPolicy(Base):
    __tablename__ = "security_policies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    fail_on_severity = Column(String(20), default="HIGH", nullable=False)
    block_prs_on_critical = Column(Boolean, default=True, nullable=False)
    block_prs_on_high = Column(Boolean, default=True, nullable=False)
    enable_secret_entropy = Column(Boolean, default=True, nullable=False)
    entropy_threshold = Column(Float, default=4.4, nullable=False)
    enable_ast_injections = Column(Boolean, default=True, nullable=False)
    enable_xss_checks = Column(Boolean, default=True, nullable=False)
    enable_auth_checks = Column(Boolean, default=True, nullable=False)
    enable_dependency_audit = Column(Boolean, default=True, nullable=False)
    ignored_paths_json = Column(Text, default="[]", nullable=False)
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=get_utc_now, onupdate=get_utc_now, nullable=False)

    organization = relationship("Organization", back_populates="policies")


class Integration(Base):
    __tablename__ = "integrations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(String(50), nullable=False)  # GITHUB, GITLAB, SLACK, JIRA
    name = Column(String(255), nullable=False)
    config_json = Column(Text, default="{}", nullable=False)
    status = Column(String(50), default="ACTIVE", nullable=False)
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)

    organization = relationship("Organization", back_populates="integrations")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action = Column(String(100), nullable=False)
    resource_type = Column(String(100), nullable=False)
    resource_id = Column(String(100), nullable=True)
    details_json = Column(Text, default="{}", nullable=False)
    ip_address = Column(String(50), nullable=True)
    timestamp = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)

    organization = relationship("Organization", back_populates="audit_logs")
    user = relationship("User", back_populates="audit_logs")


class WebsiteScan(Base):
    __tablename__ = "website_scans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(String(512), nullable=False)
    status = Column(SAEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    https_valid = Column(Boolean, default=False, nullable=False)
    tls_info_json = Column(Text, default="{}", nullable=False)
    headers_analyzed_json = Column(Text, default="{}", nullable=False)
    findings_count = Column(Integer, default=0, nullable=False)
    findings_json = Column(Text, default="[]", nullable=False)
    duration_ms = Column(Float, default=0.0, nullable=False)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=get_utc_now, nullable=False)

    organization = relationship("Organization", back_populates="website_scans")
