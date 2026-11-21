"""
ShipSafe Core Scanner Engine
Performs multi-stage deterministic code auditing for Python & JavaScript/TypeScript.
"""

import os
import re
import math
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from .rules import (
    SECRET_RULES,
    INJECTION_RULES,
    UNSAFE_EXEC_RULES,
    AUTH_RULES,
    KNOWN_VULNERABLE_DEPENDENCIES
)

# Supported extensions
PYTHON_EXTS = {".py", ".pyw"}
JS_TS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
CONFIG_EXTS = {".json", ".env", ".yaml", ".yml", ".toml", ".ini", ".conf"}
ALL_EXTS = PYTHON_EXTS | JS_TS_EXTS | CONFIG_EXTS

def calculate_entropy(value: str) -> float:
    """Shannon entropy calculation for high randomness string detection."""
    if not value or len(value) < 16:
        return 0.0
    entropy = 0.0
    for char in set(value):
        prob = value.count(char) / len(value)
        entropy -= prob * math.log2(prob)
    return entropy

def mask_sensitive_token(token: str) -> str:
    """Mask credentials preserving prefix/suffix for technical verification."""
    clean = token.strip().strip("'\"")
    if len(clean) <= 6:
        return "******"
    if len(clean) <= 12:
        return clean[:2] + ("*" * (len(clean) - 4)) + clean[-2:]
    return clean[:4] + ("*" * (len(clean) - 8)) + clean[-4:]

def generate_finding_id(rule_id: str, file_path: str, line_no: int) -> str:
    """Deterministic unique finding ID."""
    raw = f"{rule_id}:{file_path}:{line_no}"
    hashed = hashlib.sha256(raw.encode()).hexdigest()[:8].upper()
    return f"SHP-{rule_id}-{hashed}"

def get_code_snippet(lines: List[str], target_line: int, context: int = 3) -> Dict[str, Any]:
    """Extract code context around the target line (1-indexed)."""
    start = max(1, target_line - context)
    end = min(len(lines), target_line + context)
    
    snippet_lines = []
    for idx in range(start, end + 1):
        snippet_lines.append({
            "line": idx,
            "code": lines[idx - 1],
            "isTarget": (idx == target_line)
        })
    
    return {
        "startLine": start,
        "endLine": end,
        "targetLine": target_line,
        "lines": snippet_lines,
        "raw": "\n".join(lines[start - 1:end])
    }

class SecurityScannerEngine:
    def __init__(self, workspace_path: Optional[str] = None):
        self.workspace = Path(workspace_path) if workspace_path else Path.cwd()

    def scan_file_content(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        findings = []
        p = Path(file_path)
        ext = p.suffix.lower()
        lines = content.splitlines()

        is_python = ext in PYTHON_EXTS
        is_jsts = ext in JS_TS_EXTS

        # 1. Secret Scanning
        for line_idx, line in enumerate(lines, start=1):
            # Check deterministic secret patterns
            for rule in SECRET_RULES:
                for match in re.finditer(rule["pattern"], line):
                    token = match.group(0)
                    masked = mask_sensitive_token(token)
                    masked_line = line.replace(token, masked)
                    f_id = generate_finding_id(rule["id"], str(p), line_idx)

                    findings.append({
                        "id": f_id,
                        "ruleId": rule["id"],
                        "name": rule["name"],
                        "type": rule["type"],
                        "severity": rule["severity"],
                        "file": str(p).replace("\\", "/"),
                        "line": line_idx,
                        "cwe": rule["cwe"],
                        "description": rule["description"],
                        "impact": rule["impact"],
                        "remediation": rule["remediation"],
                        "evidence": masked,
                        "status": "OPEN",
                        "detectedAt": "2026-11-20T20:10:00Z",
                        "language": "python" if is_python else ("typescript" if ext in {".ts", ".tsx"} else "javascript"),
                        "snippet": get_code_snippet(lines, line_idx)
                    })

            # Check High Entropy strings
            if len(line) < 300: # skip minified blobs
                potential_tokens = re.findall(r"[A-Za-z0-9_\-+=/]{24,}", line)
                for tok in potential_tokens:
                    ent = calculate_entropy(tok)
                    # Heuristic threshold for API keys & secrets
                    if ent >= 4.4 and not any(kw in tok.lower() for kw in ["sha256", "data:image", "commit", "bundle"]):
                        f_id = generate_finding_id("SEC-ENTROPY", str(p), line_idx)
                        masked = mask_sensitive_token(tok)
                        findings.append({
                            "id": f_id,
                            "ruleId": "SEC-ENTROPY",
                            "name": "High-Entropy Secret Candidate",
                            "type": "Hardcoded Secret",
                            "severity": "HIGH",
                            "file": str(p).replace("\\", "/"),
                            "line": line_idx,
                            "cwe": "CWE-798",
                            "description": f"Found high-entropy token (entropy: {ent:.2f}) indicating an unclassified private credential.",
                            "impact": "Exposure of sensitive operational key, API token, or cryptographic secret.",
                            "remediation": "Extract the token into an environment variable and rotate the value.",
                            "evidence": masked,
                            "status": "OPEN",
                            "detectedAt": "2026-11-20T20:10:00Z",
                            "language": "python" if is_python else "javascript",
                            "snippet": get_code_snippet(lines, line_idx)
                        })

        # 2. Injections (SQL, Command)
        for rule in INJECTION_RULES:
            rule_langs = rule.get("lang", [])
            matches_lang = (is_python and "python" in rule_langs) or (is_jsts and any(l in rule_langs for l in ["javascript", "typescript"]))
            if not matches_lang:
                continue

            for line_idx, line in enumerate(lines, start=1):
                if re.search(rule["pattern"], line):
                    f_id = generate_finding_id(rule["id"], str(p), line_idx)
                    findings.append({
                        "id": f_id,
                        "ruleId": rule["id"],
                        "name": rule["name"],
                        "type": rule["type"],
                        "severity": rule["severity"],
                        "file": str(p).replace("\\", "/"),
                        "line": line_idx,
                        "cwe": rule["cwe"],
                        "description": rule["description"],
                        "impact": rule["impact"],
                        "remediation": rule["remediation"],
                        "evidence": line.strip(),
                        "status": "OPEN",
                        "detectedAt": "2026-11-20T20:10:00Z",
                        "language": "python" if is_python else ("typescript" if ext in {".ts", ".tsx"} else "javascript"),
                        "snippet": get_code_snippet(lines, line_idx)
                    })

        # 3. Unsafe Code Execution & DOM Manipulation
        for rule in UNSAFE_EXEC_RULES:
            rule_langs = rule.get("lang", [])
            matches_lang = (is_python and "python" in rule_langs) or (is_jsts and any(l in rule_langs for l in ["javascript", "typescript"]))
            if not matches_lang:
                continue

            for line_idx, line in enumerate(lines, start=1):
                if re.search(rule["pattern"], line):
                    f_id = generate_finding_id(rule["id"], str(p), line_idx)
                    findings.append({
                        "id": f_id,
                        "ruleId": rule["id"],
                        "name": rule["name"],
                        "type": rule["type"],
                        "severity": rule["severity"],
                        "file": str(p).replace("\\", "/"),
                        "line": line_idx,
                        "cwe": rule["cwe"],
                        "description": rule["description"],
                        "impact": rule["impact"],
                        "remediation": rule["remediation"],
                        "evidence": line.strip(),
                        "status": "OPEN",
                        "detectedAt": "2026-11-20T20:10:00Z",
                        "language": "python" if is_python else ("typescript" if ext in {".ts", ".tsx"} else "javascript"),
                        "snippet": get_code_snippet(lines, line_idx)
                    })

        # 4. Authentication & Authorization Checks
        for rule in AUTH_RULES:
            rule_langs = rule.get("lang", [])
            matches_lang = (is_python and "python" in rule_langs) or (is_jsts and any(l in rule_langs for l in ["javascript", "typescript"]))
            if not matches_lang:
                continue

            for line_idx, line in enumerate(lines, start=1):
                if re.search(rule["pattern"], line):
                    f_id = generate_finding_id(rule["id"], str(p), line_idx)
                    findings.append({
                        "id": f_id,
                        "ruleId": rule["id"],
                        "name": rule["name"],
                        "type": rule["type"],
                        "severity": rule["severity"],
                        "file": str(p).replace("\\", "/"),
                        "line": line_idx,
                        "cwe": rule["cwe"],
                        "description": rule["description"],
                        "impact": rule["impact"],
                        "remediation": rule["remediation"],
                        "evidence": line.strip(),
                        "status": "OPEN",
                        "detectedAt": "2026-11-20T20:10:00Z",
                        "language": "python" if is_python else ("typescript" if ext in {".ts", ".tsx"} else "javascript"),
                        "snippet": get_code_snippet(lines, line_idx)
                    })

        # 5. Dependency File Auditing (requirements.txt / package.json)
        if p.name.lower() in {"requirements.txt", "package.json", "Pipfile"}:
            for dep in KNOWN_VULNERABLE_DEPENDENCIES:
                if (p.name.lower() == "requirements.txt" and dep["ecosystem"] == "PyPI") or \
                   (p.name.lower() == "package.json" and dep["ecosystem"] == "npm"):
                    for line_idx, line in enumerate(lines, start=1):
                        if dep["package"] in line.lower():
                            f_id = generate_finding_id(dep["cve"], str(p), line_idx)
                            findings.append({
                                "id": f_id,
                                "ruleId": dep["cve"],
                                "name": f"Vulnerable Dependency: {dep['package']} ({dep['cve']})",
                                "type": "Vulnerable Dependency",
                                "severity": dep["severity"],
                                "file": str(p).replace("\\", "/"),
                                "line": line_idx,
                                "cwe": dep["cwe"],
                                "description": dep["description"],
                                "impact": f"Known public vulnerability ({dep['cve']}) in dependency allows potential exploitation.",
                                "remediation": f"Upgrade {dep['package']} to version {dep['fixed_in']} or higher in {p.name}.",
                                "evidence": line.strip(),
                                "status": "OPEN",
                                "detectedAt": "2026-11-20T20:10:00Z",
                                "language": "manifest",
                                "snippet": get_code_snippet(lines, line_idx)
                            })

        return findings
