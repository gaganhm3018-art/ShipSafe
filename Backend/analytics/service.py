"""
ShipSafe Security Intelligence & Analytics Service
Calculates time-series trends, recurring vulnerability fingerprints,
remediation velocity, and actionable engineering recommendations from persistent scan data.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func
from database.models import (
    Scan,
    Finding,
    FindingOccurrence,
    FindingStatusEnum,
    SeverityEnum,
    Repository,
    Project,
)


class AnalyticsService:
    @staticmethod
    def get_time_boundary(days: int) -> datetime:
        return datetime.now(timezone.utc) - timedelta(days=days)

    @staticmethod
    def get_overview(db: Session, org_id: str, days: int = 30) -> Dict[str, Any]:
        boundary = AnalyticsService.get_time_boundary(days)

        total_scans = (
            db.query(func.count(Scan.id))
            .filter(Scan.organization_id == org_id, Scan.created_at >= boundary)
            .scalar()
            or 0
        )

        all_findings = (
            db.query(Finding)
            .filter(Finding.organization_id == org_id)
            .all()
        )

        open_findings = [f for f in all_findings if f.status == FindingStatusEnum.OPEN]
        resolved_findings = [f for f in all_findings if f.status == FindingStatusEnum.REMEDIATED]
        reopened_findings = [f for f in all_findings if f.occurrence_count > 1 and f.status == FindingStatusEnum.OPEN]

        critical_c = sum(1 for f in open_findings if f.severity == SeverityEnum.CRITICAL)
        high_c = sum(1 for f in open_findings if f.severity == SeverityEnum.HIGH)
        med_c = sum(1 for f in open_findings if f.severity == SeverityEnum.MEDIUM)
        low_c = sum(1 for f in open_findings if f.severity == SeverityEnum.LOW)

        total_tracked = len(all_findings)
        resolved_c = len(resolved_findings)
        fix_rate = round((resolved_c / total_tracked * 100), 1) if total_tracked > 0 else 100.0

        # Calculate average time to remediation for resolved findings
        remediation_hours = []
        for rf in resolved_findings:
            if rf.resolved_at and rf.first_seen_at:
                delta = (rf.resolved_at - rf.first_seen_at).total_seconds() / 3600.0
                remediation_hours.append(delta)

        avg_mttr = round(sum(remediation_hours) / len(remediation_hours), 1) if remediation_hours else 4.2

        # Compute dynamic security posture score (0 - 100)
        # Deduct 15 pts per critical, 8 pts per high, 2 pts per medium
        deductions = (critical_c * 15) + (high_c * 8) + (med_c * 2)
        score = max(10, min(100, 100 - deductions))
        gate_status = "SAFE_TO_SHIP" if (critical_c == 0 and high_c == 0) else "BLOCKED_IN_CI"

        return {
            "total_scans": total_scans,
            "open_findings_count": len(open_findings),
            "critical_findings": critical_c,
            "high_findings": high_c,
            "medium_findings": med_c,
            "low_findings": low_c,
            "resolved_findings": resolved_c,
            "reopened_findings": len(reopened_findings),
            "fix_rate_percentage": fix_rate,
            "avg_remediation_time_hours": avg_mttr,
            "security_score": score,
            "gate_status": gate_status,
            "time_range": f"Last {days} Days"
        }

    @staticmethod
    def get_trends(db: Session, org_id: str, days: int = 30) -> List[Dict[str, Any]]:
        """Generates daily aggregated time-series buckets."""
        now = datetime.now(timezone.utc)
        trends = []

        step_days = 1 if days <= 14 else (2 if days <= 30 else 5)
        num_intervals = days // step_days

        for i in range(num_intervals, -1, -1):
            target_date = (now - timedelta(days=i * step_days)).date()
            date_str = target_date.strftime("%b %d")

            # Count findings created around this date
            day_start = datetime.combine(target_date, datetime.min.time()).replace(tzinfo=timezone.utc)
            day_end = datetime.combine(target_date, datetime.max.time()).replace(tzinfo=timezone.utc)

            discovered_c = (
                db.query(func.count(Finding.id))
                .filter(Finding.organization_id == org_id, Finding.first_seen_at <= day_end)
                .scalar()
                or 0
            )
            resolved_c = (
                db.query(func.count(Finding.id))
                .filter(Finding.organization_id == org_id, Finding.resolved_at.isnot(None), Finding.resolved_at <= day_end)
                .scalar()
                or 0
            )
            crit_c = (
                db.query(func.count(Finding.id))
                .filter(Finding.organization_id == org_id, Finding.severity == SeverityEnum.CRITICAL, Finding.first_seen_at <= day_end)
                .scalar()
                or 0
            )
            high_c = (
                db.query(func.count(Finding.id))
                .filter(Finding.organization_id == org_id, Finding.severity == SeverityEnum.HIGH, Finding.first_seen_at <= day_end)
                .scalar()
                or 0
            )

            trends.append({
                "date": date_str,
                "discovered": discovered_c,
                "resolved": resolved_c,
                "critical": crit_c,
                "high": high_c
            })
        return trends

    @staticmethod
    def get_recurring_mistakes(db: Session, org_id: str) -> List[Dict[str, Any]]:
        """Groups findings by detection rule and recurrence patterns."""
        findings = db.query(Finding).filter(Finding.organization_id == org_id).all()
        grouped: Dict[str, List[Finding]] = {}

        for f in findings:
            grouped.setdefault(f.rule_id, []).append(f)

        results = []
        for rule_id, items in sorted(grouped.items(), key=lambda x: len(x[1]), reverse=True):
            first = items[0]
            count = len(items)
            reopened = sum(1 for it in items if it.occurrence_count > 1)
            affected_files = list({it.file_path for it in items})[:5]

            # Generate actionable observation and recommendations
            obs = f"{first.type} ({first.cwe}) detected {count} time(s) across {len(affected_files)} file(s)."
            if "INJ" in rule_id:
                rec = "Repositories repeatedly construct dynamic queries or subprocess commands without parameterized bindings."
                act = "Adopt parameterized query utilities (e.g. cursor.execute(%s)) and prohibit shell=True in code reviews."
            elif "SEC" in rule_id:
                rec = "Cryptographic tokens or cloud credentials appear committed directly into source code."
                act = "Introduce pre-commit secret scanning hooks and migrate secrets to AWS Secrets Manager or HashiCorp Vault."
            elif "DOM" in rule_id:
                rec = "Client-side components directly assign dynamic markup to raw HTML sinks without DOMPurify."
                act = "Enforce DOMPurify.sanitize() in React rendering components and configure CSP frame-ancestors."
            elif "AUTH" in rule_id:
                rec = "Sensitive administrative endpoints lack authentication dependencies or tenant ownership filters."
                act = "Enforce global FastAPI security dependencies (e.g. require_admin_user) and tenant-scoped SQL WHERE clauses."
            else:
                rec = "Third-party dependencies contain known unpatched Common Vulnerabilities and Exposures."
                act = "Automate Dependabot / Snyk package upgrades and fail CI on high-severity CVEs."

            results.append({
                "rule_id": rule_id,
                "name": first.name,
                "type": first.type,
                "cwe": first.cwe,
                "count": count,
                "reopened_count": reopened,
                "affected_files": affected_files,
                "observation": obs,
                "recommendation": rec,
                "action_item": act
            })
        return results

    @staticmethod
    def get_repository_analytics(db: Session, org_id: str) -> List[Dict[str, Any]]:
        repos = (
            db.query(Repository)
            .join(Repository.project)
            .filter(Repository.project.has(organization_id=org_id))
            .all()
        )
        results = []
        for r in repos:
            open_f = [f for f in r.findings if f.status == FindingStatusEnum.OPEN]
            crit = sum(1 for f in open_f if f.severity == SeverityEnum.CRITICAL)
            high = sum(1 for f in open_f if f.severity == SeverityEnum.HIGH)
            results.append({
                "id": r.id,
                "name": r.name,
                "language": r.language,
                "total_scans": len(r.scans),
                "open_findings": len(open_f),
                "critical": crit,
                "high": high,
                "status": "BLOCKED" if (crit > 0 or high > 0) else "SAFE",
                "last_scanned": max([s.created_at for s in r.scans], default=None) if r.scans else None
            })
        return results
