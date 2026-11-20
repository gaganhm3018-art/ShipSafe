"""
ShipSafe Passive Website Security Scanner (DAST)
Implements non-invasive passive checks (HTTPS, TLS/SSL, Security Headers, Cookie Attributes, Sensitive Exposure)
with strict Server-Side Request Forgery (SSRF) and DNS re-validation protections.
"""

import socket
import ssl
import ipaddress
import urllib.parse
import http.client
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple, Optional
import requests

ALLOWED_PORTS = {80, 443, 8080, 8443}
MAX_RESPONSE_BYTES = 512 * 1024  # 512 KB
CONNECT_TIMEOUT_SEC = 5.0
READ_TIMEOUT_SEC = 8.0


class SSRFValidationError(ValueError):
    """Raised when a URL targets a disallowed or private internal network resource."""
    pass


def validate_and_resolve_url(raw_url: str) -> Tuple[str, str, int, str]:
    """
    Validates URL scheme, port, and resolves hostname against DNS.
    Strictly forbids private IP ranges, link-local metadata, loopback, and reserved addresses.
    Returns: (normalized_url, hostname, port, resolved_ip)
    """
    parsed = urllib.parse.urlsplit(raw_url.strip())

    if parsed.scheme.lower() not in {"http", "https"}:
        raise SSRFValidationError(f"Invalid URL protocol '{parsed.scheme}'. Only http and https are permitted.")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFValidationError("Target URL must specify a valid hostname.")

    # Check for localhost literal
    if hostname.lower() in {"localhost", "localhost.localdomain", "127.0.0.1", "::1"}:
        raise SSRFValidationError("Targeting localhost or loopback domains is strictly prohibited.")

    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise SSRFValidationError(f"Port {port} is not permitted. Only standard web ports (80, 443, 8080, 8443) are allowed.")

    # DNS Resolution
    try:
        addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SSRFValidationError(f"DNS resolution failed for hostname '{hostname}': {e}")

    if not addr_info:
        raise SSRFValidationError(f"Could not resolve any IP address for hostname '{hostname}'.")

    # Extract all resolved IP addresses and ensure NONE are private or metadata addresses
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise SSRFValidationError(f"Invalid resolved IP address: {ip_str}")

        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            raise SSRFValidationError(
                f"Resolved IP {ip_str} for domain '{hostname}' belongs to an internal, loopback, or cloud-metadata address. Access blocked for SSRF prevention."
            )

    primary_ip = addr_info[0][4][0]
    normalized_url = urllib.parse.urlunsplit((parsed.scheme, f"{hostname}:{port}" if parsed.port else hostname, parsed.path or "/", parsed.query, ""))
    return normalized_url, hostname, port, primary_ip


def inspect_ssl_certificate(hostname: str, port: int) -> Dict[str, Any]:
    """Inspects TLS/SSL certificate validity, expiry, and issuer."""
    context = ssl.create_default_context()
    context.timeout = CONNECT_TIMEOUT_SEC
    try:
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT_SEC) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                cipher = ssock.cipher()

        not_after_str = cert.get("notAfter", "")
        # Format: May 26 23:59:59 2026 GMT
        expires_dt = None
        days_left = None
        if not_after_str:
            try:
                expires_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (expires_dt - datetime.now(timezone.utc)).days
            except Exception:
                pass

        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        subject_dict = dict(x[0] for x in cert.get("subject", []))

        return {
            "valid": True,
            "tlsVersion": version,
            "cipher": cipher[0] if cipher else None,
            "issuer": issuer_dict.get("organizationName", issuer_dict.get("commonName", "Unknown")),
            "commonName": subject_dict.get("commonName", hostname),
            "expiresAt": expires_dt.isoformat() if expires_dt else not_after_str,
            "daysRemaining": days_left
        }
    except Exception as e:
        return {
            "valid": False,
            "error": str(e)
        }


class WebsiteScannerService:
    @staticmethod
    def run_passive_scan(target_url: str) -> Dict[str, Any]:
        """
        Executes non-invasive passive security audits against an authorized external website.
        """
        start_time = datetime.now(timezone.utc)

        # 1. SSRF Validation & DNS check
        norm_url, hostname, port, ip_str = validate_and_resolve_url(target_url)

        findings: List[Dict[str, Any]] = []
        is_https = norm_url.startswith("https://")

        # 2. TLS/SSL Inspection (if HTTPS)
        tls_info = {}
        if is_https:
            tls_info = inspect_ssl_certificate(hostname, port)
            if not tls_info.get("valid"):
                findings.append({
                    "id": f"WEB-TLS-INVALID-{int(datetime.now().timestamp())}",
                    "check_category": "TLS/SSL Configuration",
                    "name": "Invalid or Untrusted TLS/SSL Certificate",
                    "severity": "CRITICAL",
                    "evidence": f"Failed SSL handshake: {tls_info.get('error')}",
                    "explanation": "The server presented an untrusted, expired, or self-signed SSL/TLS certificate. Browsers will display security warnings, and user communications are vulnerable to Man-In-The-Middle (MITM) attacks.",
                    "remediation": "Deploy a valid, unexpired certificate issued by a trusted Certificate Authority (e.g., Let's Encrypt, DigiCert, AWS ACM).",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            elif tls_info.get("daysRemaining") is not None and tls_info["daysRemaining"] < 15:
                findings.append({
                    "id": f"WEB-TLS-EXPIRING-{int(datetime.now().timestamp())}",
                    "check_category": "TLS/SSL Configuration",
                    "name": "TLS/SSL Certificate Expiring Soon",
                    "severity": "HIGH",
                    "evidence": f"Certificate expires in {tls_info['daysRemaining']} days ({tls_info['expiresAt']})",
                    "explanation": "The active TLS certificate is nearing its expiration date. If not renewed, public users and API clients will be unable to connect.",
                    "remediation": "Trigger automated certificate renewal immediately via ACME/certbot or your cloud certificate manager.",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
        else:
            findings.append({
                "id": f"WEB-NO-HTTPS-{int(datetime.now().timestamp())}",
                "check_category": "Transport Security",
                "name": "Cleartext HTTP Transport (No HTTPS)",
                "severity": "CRITICAL",
                "evidence": f"Target endpoint served via unencrypted {norm_url}",
                "explanation": "Traffic is transmitted in unencrypted plaintext. Eavesdroppers on the network can view session cookies, credentials, and customer data.",
                "remediation": "Enable HTTPS with an automated TLS certificate and enforce HTTP-to-HTTPS 301 redirects.",
                "timestamp": datetime.now(timezone.utc).isoformat()
            })

        # 3. HTTP Request with Strict Safe Session
        headers_found = {}
        try:
            # Revalidate redirects safely
            session = requests.Session()
            session.max_redirects = 3

            req = session.get(
                norm_url,
                timeout=(CONNECT_TIMEOUT_SEC, READ_TIMEOUT_SEC),
                stream=True,
                headers={"User-Agent": "ShipSafe-Security-Audit/2.4 (+https://github.com/gaganhm3018-art/ShipSafe)"},
                allow_redirects=True,
                verify=True
            )

            # Re-verify final URL to prevent open redirect SSRF
            final_url = req.url
            validate_and_resolve_url(final_url)

            # Read bounded body
            content = req.raw.read(MAX_RESPONSE_BYTES)
            headers_found = dict(req.headers)

            # Check Missing Security Headers
            required_headers = [
                {
                    "key": "Content-Security-Policy",
                    "severity": "HIGH",
                    "cwe": "CWE-1021",
                    "description": "Content-Security-Policy (CSP) is missing.",
                    "remediation": "Define a robust Content-Security-Policy header restricting script-src, object-src, and frame-ancestors to prevent XSS."
                },
                {
                    "key": "Strict-Transport-Security",
                    "severity": "HIGH",
                    "cwe": "CWE-319",
                    "description": "HTTP Strict-Transport-Security (HSTS) header is missing.",
                    "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to enforce secure browser connections."
                },
                {
                    "key": "X-Content-Type-Options",
                    "severity": "MEDIUM",
                    "cwe": "CWE-79",
                    "description": "X-Content-Type-Options: nosniff header is missing.",
                    "remediation": "Add 'X-Content-Type-Options: nosniff' to prevent browsers from MIME-sniffing away from the declared content-type."
                },
                {
                    "key": "Referrer-Policy",
                    "severity": "LOW",
                    "cwe": "CWE-200",
                    "description": "Referrer-Policy header is missing or overly permissive.",
                    "remediation": "Configure 'Referrer-Policy: strict-origin-when-cross-origin' to protect sensitive URL tokens."
                },
                {
                    "key": "X-Frame-Options",
                    "severity": "MEDIUM",
                    "cwe": "CWE-1021",
                    "description": "X-Frame-Options or CSP frame-ancestors is missing.",
                    "remediation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent Clickjacking."
                }
            ]

            lower_headers = {k.lower(): (k, v) for k, v in headers_found.items()}

            for h in required_headers:
                if h["key"].lower() not in lower_headers:
                    findings.append({
                        "id": f"WEB-HDR-{h['key'].upper()}-{int(datetime.now().timestamp())}",
                        "check_category": "HTTP Security Headers",
                        "name": f"Missing {h['key']} Header",
                        "severity": h["severity"],
                        "evidence": f"Header '{h['key']}' not returned by server response",
                        "explanation": h["description"],
                        "remediation": h["remediation"],
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })

            # Check Cookie Attributes
            for cookie in session.cookies:
                c_name = cookie.name
                if not cookie.secure and is_https:
                    findings.append({
                        "id": f"WEB-CK-SECURE-{c_name}-{int(datetime.now().timestamp())}",
                        "check_category": "Cookie Security",
                        "name": f"Cookie '{c_name}' Missing 'Secure' Attribute",
                        "severity": "HIGH",
                        "evidence": f"Set-Cookie: {c_name} missing Secure flag",
                        "explanation": "Cookies without the 'Secure' flag can be transmitted across unencrypted HTTP channels during connection downgrade attacks.",
                        "remediation": "Add the 'Secure' directive to all Set-Cookie response headers.",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                if not cookie.has_nonstandard_attr("HttpOnly") and not cookie.has_nonstandard_attr("httponly"):
                    findings.append({
                        "id": f"WEB-CK-HTTPONLY-{c_name}-{int(datetime.now().timestamp())}",
                        "check_category": "Cookie Security",
                        "name": f"Cookie '{c_name}' Missing 'HttpOnly' Attribute",
                        "severity": "MEDIUM",
                        "evidence": f"Set-Cookie: {c_name} missing HttpOnly flag",
                        "explanation": "Cookies without HttpOnly can be accessed by client-side JavaScript via document.cookie, magnifying the impact of any XSS vulnerability.",
                        "remediation": "Set the HttpOnly flag on session tokens and sensitive state cookies.",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })

        except requests.exceptions.SSLError as e:
            findings.append({
                "id": f"WEB-SSL-ERR-{int(datetime.now().timestamp())}",
                "check_category": "TLS/SSL Configuration",
                "name": "SSL Handshake / Certificate Verification Failure",
                "severity": "CRITICAL",
                "evidence": str(e),
                "explanation": "Client failed SSL handshake verification.",
                "remediation": "Install a valid intermediate and root SSL certificate chain.",
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
        except requests.exceptions.RequestException as e:
            # Connection error or timeout
            pass

        # 4. Non-invasive sensitive file exposure check (HEAD requests only)
        sensitive_probes = [
            ("/.env", "Environment Variables File", "CRITICAL"),
            ("/.git/HEAD", "Exposed Git Repository Metadata", "CRITICAL"),
            ("/server-status", "Apache / Nginx Server Status Console", "HIGH"),
        ]

        base_parsed = urllib.parse.urlsplit(norm_url)
        for path_suffix, probe_name, probe_sev in sensitive_probes:
            probe_url = urllib.parse.urlunsplit((base_parsed.scheme, base_parsed.netloc, path_suffix, "", ""))
            try:
                probe_res = requests.head(
                    probe_url,
                    timeout=3.0,
                    headers={"User-Agent": "ShipSafe-Security-Audit/2.4"},
                    allow_redirects=False
                )
                if probe_res.status_code == 200:
                    findings.append({
                        "id": f"WEB-EXP-{path_suffix.replace('/', '').replace('.', '')}-{int(datetime.now().timestamp())}",
                        "check_category": "Public Exposure",
                        "name": f"Publicly Exposed {probe_name}",
                        "severity": probe_sev,
                        "evidence": f"HTTP HEAD {probe_url} returned 200 OK",
                        "explanation": f"The sensitive endpoint '{path_suffix}' is publicly accessible over the web without authentication.",
                        "remediation": f"Block access to '{path_suffix}' in your web server / reverse proxy configuration (e.g. Nginx 'location ~ /\\.' deny all).",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
            except Exception:
                continue

        duration_ms = round((datetime.now(timezone.utc) - start_time).total_seconds() * 1000, 2)

        return {
            "url": norm_url,
            "https_valid": is_https and tls_info.get("valid", False),
            "tls_info": tls_info,
            "headers_analyzed": headers_found,
            "findings": findings,
            "findings_count": len(findings),
            "duration_ms": duration_ms
        }
