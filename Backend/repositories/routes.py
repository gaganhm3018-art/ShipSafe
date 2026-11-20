"""
ShipSafe External GitHub Repository SAST Routes
Enforces organization data isolation and non-blocking asynchronous analysis.
"""

import time
import json
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from database.connection import get_db, SessionLocal
from database.models import User, OrganizationMember, OrgRole, Scan, ScanStatus, Repository, Finding, FindingOccurrence
from database.schemas import RepositoryAnalyzeRequest, RepositoryResponse, ScanStatusResponse
from auth.dependencies import get_current_user, verify_org_access
from .service import parse_github_url, RepositoryScannerService

router = APIRouter()


@router.post("/analyze", status_code=status.HTTP_202_ACCEPTED)
def analyze_github_repository(
    req: RepositoryAnalyzeRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Validates GitHub URL and kicks off an asynchronous SAST security scan
    in an isolated sandbox without executing untrusted code.
    """
    try:
        owner, repo_name = parse_github_url(req.repository_url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Determine organization
    org_id = req.organization_id
    if not org_id:
        membership = db.query(OrganizationMember).filter(OrganizationMember.user_id == current_user.id).first()
        if not membership:
            raise HTTPException(status_code=400, detail="User is not a member of any organization workspace")
        org_id = membership.organization_id
    else:
        verify_org_access(org_id=org_id, user=current_user, db=db, min_role=OrgRole.DEVELOPER)

    scan_id = f"SCAN-GH-{int(time.time())}"
    scan = Scan(
        id=scan_id,
        organization_id=org_id,
        scan_type="SAST_GITHUB",
        target_name=f"{owner}/{repo_name}",
        target_branch=req.branch or "main",
        trigger=f"GitHub SAST ({current_user.email})",
        status=ScanStatus.PENDING
    )
    db.add(scan)
    db.commit()

    # Dispatch to background task runner
    background_tasks.add_task(
        RepositoryScannerService.execute_repository_scan,
        scan_id=scan_id,
        repo_url=req.repository_url,
        branch=req.branch or "main",
        org_id=org_id,
        db_factory=SessionLocal
    )

    return {
        "status": "ACCEPTED",
        "message": f"Scan initiated for repository {owner}/{repo_name}",
        "scan_id": scan_id,
        "repository": f"{owner}/{repo_name}",
        "branch": req.branch or "main",
        "check_status_url": f"/api/scans/{scan_id}"
    }


@router.get("", response_model=List[RepositoryResponse])
def list_repositories(
    organization_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Lists all scanned repositories belonging to the organization."""
    if not organization_id:
        membership = db.query(OrganizationMember).filter(OrganizationMember.user_id == current_user.id).first()
        if not membership:
            return []
        organization_id = membership.organization_id
    else:
        verify_org_access(org_id=organization_id, user=current_user, db=db, min_role=OrgRole.VIEWER)

    repos = (
        db.query(Repository)
        .join(Repository.project)
        .filter(Repository.project.has(organization_id=organization_id))
        .all()
    )

    results = []
    for r in repos:
        total_scans = len(r.scans)
        open_findings = sum(1 for f in r.findings if f.status.value == "OPEN")
        last_scan = max([s.created_at for s in r.scans], default=None) if r.scans else None
        results.append({
            "id": r.id,
            "name": r.name,
            "url": r.url,
            "default_branch": r.default_branch,
            "language": r.language,
            "total_scans": total_scans,
            "open_findings": open_findings,
            "last_scanned": last_scan
        })
    return results


@router.get("/{repo_id}", response_model=RepositoryResponse)
def get_repository(
    repo_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieves repository metadata and health summary."""
    repo = db.query(Repository).filter(Repository.id == repo_id).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    verify_org_access(org_id=repo.project.organization_id, user=current_user, db=db, min_role=OrgRole.VIEWER)

    total_scans = len(repo.scans)
    open_findings = sum(1 for f in repo.findings if f.status.value == "OPEN")
    last_scan = max([s.created_at for s in repo.scans], default=None) if repo.scans else None

    return {
        "id": repo.id,
        "name": repo.name,
        "url": repo.url,
        "default_branch": repo.default_branch,
        "language": repo.language,
        "total_scans": total_scans,
        "open_findings": open_findings,
        "last_scanned": last_scan
    }


@router.get("/{repo_id}/scans")
def list_repository_scans(
    repo_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieves scan history for a specific repository."""
    repo = db.query(Repository).filter(Repository.id == repo_id).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    verify_org_access(org_id=repo.project.organization_id, user=current_user, db=db, min_role=OrgRole.VIEWER)
    scans = db.query(Scan).filter(Scan.repository_id == repo_id).order_by(Scan.created_at.desc()).all()

    return [
        {
            "id": s.id,
            "repository": s.target_name,
            "branch": s.target_branch,
            "commit": s.commit_hash or "latest",
            "timestamp": s.created_at.isoformat(),
            "status": s.status.value,
            "totalFindings": s.total_findings,
            "critical": s.critical_count,
            "high": s.high_count,
            "medium": s.medium_count,
            "low": s.low_count,
            "resolved": 0,
            "policyViolation": s.policy_violation,
            "trigger": s.trigger,
            "durationMs": s.duration_ms,
            "filesScanned": s.files_scanned
        }
        for s in scans
    ]
