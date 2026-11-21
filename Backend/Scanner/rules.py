"""
ShipSafe - Deterministic Security Detection Rules Engine
Covers Python and JavaScript/TypeScript codebases.
"""

import re
import math
from pathlib import Path
from typing import List, Dict, Any, Optional

# ==============================================================================
# 1. SECRET DETECTION & HIGH ENTROPY
# ==============================================================================

SECRET_RULES = [
    {
        "id": "SEC-001",
        "name": "AWS Access Key",
        "pattern": r"\b(AKIA[0-9A-Z]{16})\b",
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "type": "Hardcoded Secret",
        "description": "Exposed AWS Access Key ID found in source code.",
        "impact": "Full compromise of AWS cloud infrastructure, data exfiltration, unauthorized resource provisioning.",
        "remediation": "Revoke the access key in AWS IAM immediately. Use AWS Secrets Manager, IAM roles, or environment variables."
    },
    {
        "id": "SEC-002",
        "name": "OpenAI / Anthropic API Key",
        "pattern": r"\b(sk-[A-Za-z0-9_-]{24,})\b",
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "type": "Hardcoded Secret",
        "description": "Exposed LLM provider API key detected in code.",
        "impact": "Account takeover, API quota draining, unauthorized access to fine-tuned models and prompts.",
        "remediation": "Rotate API key in provider console. Load key via os.environ.get('OPENAI_API_KEY') or .env file excluded from git."
    },
    {
        "id": "SEC-003",
        "name": "GitHub Personal Access Token",
        "pattern": r"\b(gh[pousr]_[A-Za-z0-9_]{36,})\b",
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "type": "Hardcoded Secret",
        "description": "GitHub Personal Access Token or OAuth secret committed.",
        "impact": "Unauthorized repository write access, malicious release injection, supply chain compromise.",
        "remediation": "Revoke token immediately in GitHub Settings > Developer Settings. Use GitHub Actions Secrets or SSH deploy keys."
    },
    {
        "id": "SEC-004",
        "name": "Private Cryptographic Key",
        "pattern": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "severity": "CRITICAL",
        "cwe": "CWE-312",
        "type": "Hardcoded Secret",
        "description": "Unencrypted private RSA/EC/SSH cryptographic key found.",
        "impact": "Attacker can decrypt TLS traffic, spoof server identity, or access SSH bastion hosts.",
        "remediation": "Store private keys in a Hardware Security Module (HSM), HashiCorp Vault, or cloud KMS. Remove from git history."
    },
    {
        "id": "SEC-005",
        "name": "Database Connection String / Password",
        "pattern": r"""(?i)(?:postgres|mysql|mongodb(?:\+srv)?):\/\/[a-zA-Z0-9_\-]+:([a-zA-Z0-9_@#$%^&*!\-]+)@[a-zA-Z0-9_\.\-]+""",
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "type": "Hardcoded Secret",
        "description": "Database connection URI contains hardcoded authentication credentials.",
        "impact": "Direct database compromise, customer PII data leak, ransomware exposure.",
        "remediation": "Inject DATABASE_URL via deployment environment variables. Use mutual TLS or IAM database authentication."
    },
    {
        "id": "SEC-006",
        "name": "JWT Secret or Signing Key",
        "pattern": r"""(?i)(?:jwt_secret|jwt_key|secret_key|session_secret)\s*[:=]\s*['"]([A-Za-z0-9_\-!@#$%^&*]{8,})['"]""",
        "severity": "HIGH",
        "cwe": "CWE-798",
        "type": "Hardcoded Secret",
        "description": "Static JWT signing key or session secret hardcoded in source.",
        "impact": "Attackers can forge arbitrary JWT authentication tokens and impersonate any user or admin.",
        "remediation": "Generate cryptographically secure 256-bit keys and supply them through secrets management."
    }
]

# ==============================================================================
# 2. INJECTION DETECTIONS (SQL, COMMAND, NOSQL)
# ==============================================================================

INJECTION_RULES = [
    {
        "id": "INJ-001",
        "name": "SQL Injection via String Concatenation / F-Strings (Python)",
        "pattern": r"""(?i)(?:execute|cursor\.execute|raw|select)\s*\(\s*(?:f['"][^'"]*\{|['"][^'"]*%s.*%|['"][^'"]*\s*\+\s*[a-zA-Z_])""",
        "lang": ["python"],
        "severity": "CRITICAL",
        "cwe": "CWE-89",
        "type": "SQL Injection",
        "description": "Dynamic SQL query formed via f-string or string concatenation without parameterization.",
        "impact": "Arbitrary SQL execution, data alteration, authentication bypass, database takeover.",
        "remediation": "Use parameterized queries (e.g. cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))) or ORM query builders."
    },
    {
        "id": "INJ-002",
        "name": "SQL Injection via Template Literals (JS/TS)",
        "pattern": r"""(?i)(?:query|execute|db\.raw|prisma\.\$queryRawUnsafe)\s*\(\s*`[^`]*\$\{.*?\}[^`]*`""",
        "lang": ["javascript", "typescript"],
        "severity": "CRITICAL",
        "cwe": "CWE-89",
        "type": "SQL Injection",
        "description": "Unescaped template literal interpolation passed directly to SQL executor.",
        "impact": "Second-order SQL injection, privilege escalation, confidential records exfiltration.",
        "remediation": "Use parameterized queries ($1, $2) or tagged template literals such as prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`."
    },
    {
        "id": "INJ-003",
        "name": "Command Injection via subprocess shell=True (Python)",
        "pattern": r"""subprocess\.(?:Popen|call|run|check_output)\s*\(.*shell\s*=\s*True.*\)""",
        "lang": ["python"],
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "type": "Command Injection",
        "description": "Spawning shell process with shell=True and unsanitized command string.",
        "impact": "Remote Code Execution (RCE) on host operating system with process permissions.",
        "remediation": "Set shell=False and pass arguments as a structured list: subprocess.run(['ls', '-la'], check=True)."
    },
    {
        "id": "INJ-004",
        "name": "OS Command Injection via child_process.exec (JS/TS)",
        "pattern": r"""(?:child_process|cp)\.exec\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|['"][^'"]*['"]\s*\+\s*[a-zA-Z_])""",
        "lang": ["javascript", "typescript"],
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "type": "Command Injection",
        "description": "Unsanitized user-controlled string passed into child_process.exec().",
        "impact": "Host OS takeover, container escape, reverse shell initiation.",
        "remediation": "Use execFile or spawn with argument array: execFile('/usr/bin/tool', [userParam], callback)."
    }
]

# ==============================================================================
# 3. UNSAFE CODE EXECUTION & DOM MANIPULATION
# ==============================================================================

UNSAFE_EXEC_RULES = [
    {
        "id": "EXEC-001",
        "name": "Unsafe Dynamic Code Evaluation (eval / Function constructor)",
        "pattern": r"""\b(?:eval|Function)\s*\([^)]*[\$\+a-zA-Z_][^)]*\)""",
        "lang": ["javascript", "typescript", "python"],
        "severity": "HIGH",
        "cwe": "CWE-95",
        "type": "Unsafe Code Execution",
        "description": "Dynamic execution of code strings allows arbitrary payload evaluation.",
        "impact": "Arbitrary code execution within process scope, bypass of sandbox boundaries.",
        "remediation": "Replace eval() with structured parsers like JSON.parse(), math expression evaluators, or static dispatch maps."
    },
    {
        "id": "EXEC-002",
        "name": "Unsafe Deserialization via pickle / yaml.load (Python)",
        "pattern": r"""(?:pickle\.loads|yaml\.load\s*\([^)]*Loader\s*=\s*(?:yaml\.)?Loader)""",
        "lang": ["python"],
        "severity": "CRITICAL",
        "cwe": "CWE-502",
        "type": "Unsafe Code Execution",
        "description": "Untrusted pickle deserialization or unsafe PyYAML loader.",
        "impact": "Remote Code Execution via gadget chains upon deserialization.",
        "remediation": "Use safe serializers like json.loads() or yaml.safe_load(). Never deserialize untrusted pickle streams."
    },
    {
        "id": "DOM-001",
        "name": "Cross-Site Scripting via dangerouslySetInnerHTML (React)",
        "pattern": r"""dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!.*DOMPurify)[a-zA-Z0-9_\.]+""",
        "lang": ["javascript", "typescript"],
        "severity": "HIGH",
        "cwe": "CWE-79",
        "type": "DOM Manipulation (XSS)",
        "description": "Raw unescaped HTML injected into React DOM without DOMPurify sanitization.",
        "impact": "Stored or reflected Cross-Site Scripting (XSS), session hijacking, CSRF token theft.",
        "remediation": "Sanitize HTML using DOMPurify.sanitize(content) before assigning to __html, or render safe React elements."
    },
    {
        "id": "DOM-002",
        "name": "Direct DOM Injection via innerHTML / outerHTML",
        "pattern": r"""\.(?:innerHTML|outerHTML)\s*=\s*(?!.*(?:encodeURI|sanitize|escape))[a-zA-Z0-9_\.]+""",
        "lang": ["javascript", "typescript"],
        "severity": "HIGH",
        "cwe": "CWE-79",
        "type": "DOM Manipulation (XSS)",
        "description": "Direct assignment to innerHTML with unsanitized dynamic data.",
        "impact": "Client-side code injection, unauthorized browser actions, cookie harvesting.",
        "remediation": "Use element.textContent or element.innerText instead of innerHTML."
    }
]

# ==============================================================================
# 4. MISSING AUTHENTICATION & AUTHORIZATION CHECKS
# ==============================================================================

AUTH_RULES = [
    {
        "id": "AUTH-001",
        "name": "Unprotected Sensitive API Route (FastAPI / Express)",
        "pattern": r"""(?i)@(app|router)\.(post|delete|put|patch)\s*\(\s*['"]/(?:api/)?(?:admin|billing|users/delete|internal).*['"]\s*\)(?![\s\S]{1,120}(?:Depends|authenticate|requireAuth|checkRole))""",
        "lang": ["python", "javascript", "typescript"],
        "severity": "HIGH",
        "cwe": "CWE-306",
        "type": "Missing Authentication",
        "description": "Administrative or state-changing endpoint defined without security dependencies or auth middleware.",
        "impact": "Unauthenticated attackers can invoke privileged operations, delete data, or change user roles.",
        "remediation": "Add authentication guard or dependency: dependencies=[Depends(require_admin_user)]."
    },
    {
        "id": "AUTH-002",
        "name": "Missing Tenant / IDOR Authorization Check",
        "pattern": r"""(?i)def\s+[a-zA-Z_]+\s*\([^)]*user_id[^)]*\):[\s\S]{1,180}SELECT.*WHERE\s+id\s*=\s*user_id(?!.*AND\s+organization_id)""",
        "lang": ["python"],
        "severity": "HIGH",
        "cwe": "CWE-639",
        "type": "Broken Object Level Authorization (BOLA)",
        "description": "Direct object reference without validating organization tenancy or session ownership.",
        "impact": "Insecure Direct Object Reference (IDOR): Users can view or modify records belonging to other tenants.",
        "remediation": "Always filter database lookups with the authenticated tenant ID from request context: WHERE id = user_id AND org_id = current_user.org_id."
    },
    {
        "id": "AUTH-003",
        "name": "CORS Misconfiguration with Wildcard Origin & Credentials",
        "pattern": r"""allow_origins\s*=\s*\[['"]\*['"]\].*allow_credentials\s*=\s*True""",
        "lang": ["python", "javascript", "typescript"],
        "severity": "MEDIUM",
        "cwe": "CWE-942",
        "type": "Insecure CORS Policy",
        "description": "Access-Control-Allow-Origin wildcard configured together with Allow-Credentials.",
        "impact": "Cross-origin attackers can read sensitive authenticated session responses via victim browsers.",
        "remediation": "Specify explicit allowed trusted origins (e.g. ['https://app.example.com']) rather than '*' when credentials are true."
    }
]

# ==============================================================================
# 5. OUTDATED DEPENDENCIES WITH KNOWN VULNERABILITIES (CVE)
# ==============================================================================

KNOWN_VULNERABLE_DEPENDENCIES = [
    {
        "package": "requests",
        "ecosystem": "PyPI",
        "vulnerable_below": "2.31.0",
        "cve": "CVE-2023-32681",
        "severity": "MEDIUM",
        "cwe": "CWE-200",
        "description": "Information disclosure vulnerability in Requests library where Proxy-Authorization headers leak across redirects.",
        "fixed_in": "2.32.0"
    },
    {
        "package": "cryptography",
        "ecosystem": "PyPI",
        "vulnerable_below": "41.0.6",
        "cve": "CVE-2023-49083",
        "severity": "HIGH",
        "cwe": "CWE-400",
        "description": "Denial of service via NULL pointer dereference in PKCS7 parsing.",
        "fixed_in": "42.0.0"
    },
    {
        "package": "axios",
        "ecosystem": "npm",
        "vulnerable_below": "1.7.4",
        "cve": "CVE-2024-39338",
        "severity": "HIGH",
        "cwe": "CWE-918",
        "description": "Server-Side Request Forgery (SSRF) bypass when parsing relative target URLs.",
        "fixed_in": "1.7.7"
    },
    {
        "package": "jsonwebtoken",
        "ecosystem": "npm",
        "vulnerable_below": "9.0.0",
        "cve": "CVE-2022-23529",
        "severity": "CRITICAL",
        "cwe": "CWE-94",
        "description": "Remote Code Execution via insecure secretOrPublicKey parameter handling.",
        "fixed_in": "9.0.2"
    },
    {
        "package": "express",
        "ecosystem": "npm",
        "vulnerable_below": "4.19.2",
        "cve": "CVE-2024-29041",
        "severity": "MEDIUM",
        "cwe": "CWE-601",
        "description": "Open redirect vulnerability when handling untrusted URLs in res.location().",
        "fixed_in": "4.21.0"
    }
]
