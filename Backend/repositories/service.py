"""
ShipSafe GitHub Repository SAST Service
Securely downloads external public repositories into sandboxed temporary directories,
runs the deterministic SecurityScannerEngine without executing untrusted code,
and persists scan results with stable vulnerability fingerprinting.
"""

import os
import re
import time
import subprocess
import tempfile
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from database.models import (
    Scan,
    ScanStatus,
    Repository,
    Project,
    Finding,
    FindingOccurrence,
    FindingStatusEnum,
    SeverityEnum,
    Organization,
)
from Scanner.engine import SecurityScannerEngine, ALL_EXTS

GITHUB_URL_REGEX = re.compile(
    r"^https?://(?:www\.)?github\.com/([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+?)(?:\.git)?/?$"
)


def parse_github_url(url: str) -> Tuple[str, str]:
    """Validates and parses a GitHub repository URL into (owner, repo_name)."""
    clean_url = url.strip()
    match = GITHUB_URL_REGEX.match(clean_url)
    if not match:
        raise ValueError(f"Invalid GitHub URL format: '{url}'. Expected format: https://github.com/owner/repository")
    owner, repo = match.groups()
    return owner, repo


def generate_stable_fingerprint(rule_id: str, file_path: str, line_no: int, snippet_target_line: str) -> str:
    """
    Generates a deterministic, stable fingerprint that tracks findings across successive scans.
    Normalized to avoid breaking across whitespace differences.
    """
    clean_code = re.sub(r"\s+", " ", snippet_target_line.strip())
    raw = f"{rule_id}:{file_path.lower()}:{clean_code}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class RepositoryScannerService:
    @staticmethod
    def execute_repository_scan(
        scan_id: str,
        repo_url: str,
        branch: str,
        org_id: str,
        db_factory
    ):
        """
        Runs asynchronously in a background worker:
        Clones repository safely (isolated sandbox), runs SecurityScannerEngine, and stores records.
        """
        db: Session = db_factory()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            db.close()
            return

        scan.status = ScanStatus.RUNNING
        db.commit()

        start_time = time.time()
        owner, repo_name = parse_github_url(repo_url)

        with tempfile.TemporaryDirectory(prefix="shipsafe_sast_") as temp_dir:
            temp_path = Path(temp_dir)
            clone_target = temp_path / "repo"

            try:
                # 1. Clone shallowly without executing any scripts or hooks
                # git clone --depth 1 --config core.hooksPath=/dev/null -b branch repo_url target
                env = os.environ.copy()
                env["GIT_TERMINAL_PROMPT"] = "0"  # Never hang for interactive prompt

                clone_cmd = [
                    "git", "clone",
                    "--depth", "1",
                    "--config", "core.hooksPath=/dev/null",
                    "-b", branch,
                    repo_url,
                    str(clone_target)
                ]

                # Fallback to default branch if specific branch fails
                proc = subprocess.run(
                    clone_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=90,
                    env=env,
                    text=True
                )
                if proc.returncode != 0:
                    # Retry without branch arg (defaults to default branch)
                    clone_cmd = [
                        "git", "clone",
                        "--depth", "1",
                        "--config", "core.hooksPath=/dev/null",
                        repo_url,
                        str(clone_target)
                    ]
                    proc = subprocess.run(
                        clone_cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=90,
                        env=env,
                        text=True
                    )
                    if proc.returncode != 0:
                        raise RuntimeError(f"Git clone failed: {proc.stderr.strip() or 'Unknown git error'}")

                # 2. Identify or create persistent Repository entity in DB
                repo_entity = (
                    db.query(Repository)
                    .join(Project)
                    .filter(
                        Project.organization_id == org_id,
                        Repository.url == repo_url
                    )
                    .first()
                )
                if not repo_entity:
                    # Find default project for this org
                    project = db.query(Project).filter(Project.organization_id == org_id).first()
                    if not project:
                        project = Project(organization_id=org_id, name="External GitHub Projects")
                        db.add(project)
                        db.flush()

                    repo_entity = Repository(
                        project_id=project.id,
                        name=f"{owner}/{repo_name}",
                        url=repo_url,
                        default_branch=branch,
                        language="Multi-language"
                    )
                    db.add(repo_entity)
                    db.flush()

                scan.repository_id = repo_entity.id

                # 3. Deterministic code scan using existing SecurityScannerEngine
                scanner = SecurityScannerEngine(workspace_path=str(clone_target))
                all_findings: List[Dict[str, Any]] = []
                files_scanned = 0
                detected_languages = set()

                excluded_dirs = {".git", "node_modules", "vendor", "dist", "build", "venv", ".venv"}

                for dirpath, dirnames, filenames in os.walk(clone_target):
                    dirnames[:] = [d for d in dirnames if d not in excluded_dirs and not d.startswith(".")]

                    for fname in filenames:
                        ext = Path(fname).suffix.lower()
                        if ext in ALL_EXTS or fname.lower() in {"requirements.txt", "package.json", "dockerfile"}:
                            f_path = Path(dirpath) / fname
                            try:
                                content = f_path.read_text(encoding="utf-8", errors="ignore")
                                rel_path = str(f_path.relative_to(clone_target)).replace("\\", "/")
                                file_findings = scanner.scan_file_content(rel_path, content)
                                all_findings.extend(file_findings)
                                files_scanned += 1

                                if ext in {".py"}:
                                    detected_languages.add("Python")
                                elif ext in {".js", ".jsx", ".ts", ".tsx"}:
                                    detected_languages.add("TypeScript/JavaScript")
                            except Exception:
                                continue

                duration_ms = round((time.time() - start_time) * 1000, 2)

                # Update repository detected language
                if detected_languages:
                    repo_entity.language = "/".join(sorted(detected_languages))

                # 4. Fingerprint & Persist Findings with Recurrence Tracking
                critical_c = 0
                high_c = 0
                med_c = 0
                low_c = 0

                current_scan_finding_ids = set()

                for f in all_findings:
                    sev = f.get("severity", "MEDIUM")
                    if sev == "CRITICAL":
                        critical_c += 1
                    elif sev == "HIGH":
                        high_c += 1
                    elif sev == "MEDIUM":
                        med_c += 1
                    else:
                        low_c += 1

                    # Compute stable fingerprint
                    target_line_text = ""
                    snippet = f.get("snippet", {})
                    for line_item in snippet.get("lines", []):
                        if line_item.get("isTarget"):
                            target_line_text = line_item.get("code", "")
                            break

                    fingerprint = generate_stable_fingerprint(
                        rule_id=f["ruleId"],
                        file_path=f["file"],
                        line_no=f["line"],
                        snippet_target_line=target_line_text
                    )

                    # Look up existing finding in this organization & repository
                    existing_finding = (
                        db.query(Finding)
                        .filter(
                            Finding.organization_id == org_id,
                            Finding.repository_id == repo_entity.id,
                            Finding.fingerprint == fingerprint
                        )
                        .first()
                    )

                    now = datetime.now(timezone.utc)

                    if existing_finding:
                        # Finding reappeared in this scan!
                        existing_finding.occurrence_count += 1
                        existing_finding.last_seen_at = now
                        if existing_finding.status == FindingStatusEnum.REMEDIATED:
                            # Reopened vulnerability!
                            existing_finding.status = FindingStatusEnum.OPEN
                            existing_finding.resolved_at = None
                        target_finding_id = existing_finding.id
                    else:
                        # New unique finding
                        target_finding_id = f["id"]
                        new_finding = Finding(
                            id=target_finding_id,
                            organization_id=org_id,
                            repository_id=repo_entity.id,
                            fingerprint=fingerprint,
                            rule_id=f["ruleId"],
                            name=f["name"],
                            type=f["type"],
                            severity=SeverityEnum(f["severity"]),
                            cwe=f.get("cwe", "CWE-General"),
                            cwe_name=f.get("name"),
                            cvss=9.0 if f["severity"] == "CRITICAL" else (7.5 if f["severity"] == "HIGH" else 5.0),
                            description=f["description"],
                            why_dangerous=f.get("impact"),
                            impact=f["impact"],
                            remediation=f["remediation"],
                            file_path=f["file"],
                            line_number=f["line"],
                            language=f.get("language", "python"),
                            first_seen_at=now,
                            last_seen_at=now,
                            occurrence_count=1,
                            status=FindingStatusEnum.OPEN
                        )
                        db.add(new_finding)
                        db.flush()

                    current_scan_finding_ids.add(target_finding_id)

                    # Create Occurrence snapshot for this scan
                    import json
                    occurrence = FindingOccurrence(
                        finding_id=target_finding_id,
                        scan_id=scan.id,
                        evidence=f.get("evidence", ""),
                        snippet_json=json.dumps(f.get("snippet", {})),
                        line_number=f["line"]
                    )
                    db.add(occurrence)

                # Check if previous findings in this repo are now resolved
                previous_open_findings = (
                    db.query(Finding)
                    .filter(
                        Finding.organization_id == org_id,
                        Finding.repository_id == repo_entity.id,
                        Finding.status == FindingStatusEnum.OPEN
                    )
                    .all()
                )
                for prev_f in previous_open_findings:
                    if prev_f.id not in current_scan_finding_ids:
                        # Finding is no longer present in target file -> mark resolved!
                        prev_f.status = FindingStatusEnum.REMEDIATED
                        prev_f.resolved_at = datetime.now(timezone.utc)

                # 5. Finalize Scan Record
                scan.status = ScanStatus.COMPLETED if (critical_c == 0 and high_c == 0) else ScanStatus.FAILED
                scan.duration_ms = duration_ms
                scan.files_scanned = files_scanned
                scan.total_findings = len(all_findings)
                scan.critical_count = critical_c
                scan.high_count = high_c
                scan.medium_count = med_c
                scan.low_count = low_c

                if critical_c > 0 or high_c > 0:
                    scan.policy_violation = f"Blocked: {critical_c} CRITICAL, {high_c} HIGH findings violate security gate (fail-on: high)"

                db.commit()

            except Exception as e:
                db.rollback()
                scan.status = ScanStatus.FAILED
                scan.error_message = str(e)
                db.commit()
            finally:
                db.close()
