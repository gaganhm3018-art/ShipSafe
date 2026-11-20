"""
ShipSafe Website DAST API Routes
Provides authorized passive security checks and reports with SSRF protection.
"""

import json
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database.connection import get_db
from database.models import User, OrganizationMember, OrgRole, WebsiteScan, ScanStatus
from database.schemas import WebsiteAnalyzeRequest, WebsiteScanResponse
from auth.dependencies import get_current_user, verify_org_access
from .service import WebsiteScannerService, SSRFValidationError

router = APIRouter()


@router.post("/analyze", response_model=WebsiteScanResponse)
def analyze_website(
    req: WebsiteAnalyzeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Executes non-invasive passive security audits against an authorized external website URL.
    Includes strict SSRF defenses: blocks localhost, RFC 1918 private IPs, cloud metadata, and DNS rebinding.
    """
    org_id = req.organization_id
    if not org_id:
        membership = db.query(OrganizationMember).filter(OrganizationMember.user_id == current_user.id).first()
        if not membership:
            raise HTTPException(status_code=400, detail="User has no workspace organization")
        org_id = membership.organization_id
    else:
        verify_org_access(org_id=org_id, user=current_user, db=db, min_role=OrgRole.DEVELOPER)

    try:
        results = WebsiteScannerService.run_passive_scan(req.url)
    except SSRFValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Passive analysis failed: {str(e)}"
        )

    # Persist WebsiteScan record
    scan_record = WebsiteScan(
        organization_id=org_id,
        url=results["url"],
        status=ScanStatus.COMPLETED,
        https_valid=results["https_valid"],
        tls_info_json=json.dumps(results["tls_info"]),
        headers_analyzed_json=json.dumps(results["headers_analyzed"]),
        findings_count=results["findings_count"],
        findings_json=json.dumps(results["findings"]),
        duration_ms=results["duration_ms"]
    )
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    return {
        "scan_id": scan_record.id,
        "url": scan_record.url,
        "status": scan_record.status.value,
        "https_valid": scan_record.https_valid,
        "tls_info": results["tls_info"],
        "headers_analyzed": results["headers_analyzed"],
        "findings": results["findings"],
        "findings_count": scan_record.findings_count,
        "duration_ms": scan_record.duration_ms,
        "created_at": scan_record.created_at,
        "error_message": None
    }


@router.get("/scans", response_model=List[Dict[str, Any]])
def list_website_scans(
    organization_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Lists historical website passive security scans."""
    if not organization_id:
        membership = db.query(OrganizationMember).filter(OrganizationMember.user_id == current_user.id).first()
        if not membership:
            return []
        organization_id = membership.organization_id
    else:
        verify_org_access(org_id=organization_id, user=current_user, db=db, min_role=OrgRole.VIEWER)

    scans = (
        db.query(WebsiteScan)
        .filter(WebsiteScan.organization_id == organization_id)
        .order_by(WebsiteScan.created_at.desc())
        .limit(50)
        .all()
    )

    return [
        {
            "id": s.id,
            "url": s.url,
            "status": s.status.value,
            "https_valid": s.https_valid,
            "findings_count": s.findings_count,
            "duration_ms": s.duration_ms,
            "created_at": s.created_at.isoformat()
        }
        for s in scans
    ]


@router.get("/scans/{scan_id}", response_model=WebsiteScanResponse)
def get_website_scan_details(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieves full details and findings for a specific website scan."""
    scan = db.query(WebsiteScan).filter(WebsiteScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Website scan not found")

    verify_org_access(org_id=scan.organization_id, user=current_user, db=db, min_role=OrgRole.VIEWER)

    return {
        "scan_id": scan.id,
        "url": scan.url,
        "status": scan.status.value,
        "https_valid": scan.https_valid,
        "tls_info": json.loads(scan.tls_info_json or "{}"),
        "headers_analyzed": json.loads(scan.headers_analyzed_json or "{}"),
        "findings": json.loads(scan.findings_json or "[]"),
        "findings_count": scan.findings_count,
        "duration_ms": scan.duration_ms,
        "created_at": scan.created_at,
        "error_message": scan.error_message
    }
