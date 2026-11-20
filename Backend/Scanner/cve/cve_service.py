"""
ShipSafe - Real-Time CVE Intelligence Service
Orchestrates dependency discovery, batch querying to OSV.dev, vulnerability evaluation,
and normalized finding aggregation with TTL caching.
"""

import time
import logging
from dataclasses import asdict
from typing import List, Dict, Any, Optional
from pathlib import Path

from .dependency_parser import DependencyParser, ParsedDependency
from .osv_client import OSVClient
from .vulnerability_matcher import VulnerabilityMatcher, MatchResult

logger = logging.getLogger("ShipSafe.CVE.Service")

CACHE_TTL_SECONDS = 900  # 15 minutes cache

class CVEService:
    """
    Central service for scanning dependencies against real-time CVE advisories.
    """

    def __init__(self, workspace_root: Optional[str] = None):
        self.workspace_root = Path(workspace_root).resolve() if workspace_root else Path.cwd().resolve()
        self.parser = DependencyParser(str(self.workspace_root))
        self.client = OSVClient()
        self.matcher = VulnerabilityMatcher()
        
        # In-memory cache
        self._cached_result: Optional[Dict[str, Any]] = None
        self._cache_timestamp: float = 0.0

    async def scan_project(
        self,
        target_path: Optional[str] = None,
        force_refresh: bool = False
    ) -> Dict[str, Any]:
        """
        Executes a real-time CVE intelligence scan on the repository or specified target path.
        """
        now = time.time()
        # Return cache if still valid and not forcing refresh
        if not force_refresh and self._cached_result and (now - self._cache_timestamp < CACHE_TTL_SECONDS):
            cached_copy = dict(self._cached_result)
            cached_copy["isCached"] = True
            cached_copy["cacheAgeSeconds"] = round(now - self._cache_timestamp, 1)
            return cached_copy

        start_time = time.time()
        
        # 1. Parse dependencies from all supported manifests and lockfiles
        parsed_deps: List[ParsedDependency] = self.parser.parse_all(target_path)
        logger.info(f"Discovered {len(parsed_deps)} dependencies across supported files.")

        if not parsed_deps:
            empty_result = {
                "scanId": f"CVE-{int(now)}",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "durationMs": round((time.time() - start_time) * 1000, 2),
                "status": "PASSED",
                "isCached": False,
                "summary": {
                    "totalDependencies": 0,
                    "vulnerableDependencies": 0,
                    "safeDependencies": 0,
                    "unknownDependencies": 0,
                    "totalVulnerabilities": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0
                },
                "dependencies": [],
                "findings": [],
                "ecosystemsFound": []
            }
            self._cached_result = empty_result
            self._cache_timestamp = now
            return empty_result

        # 2. Query OSV in batch
        queries = [
            {
                "name": dep.name,
                "version": dep.version,
                "ecosystem": dep.ecosystem
            }
            for dep in parsed_deps
        ]

        osv_responses = await self.client.query_batch(queries)

        # 3. Match vulnerabilities & normalize findings
        findings: List[Dict[str, Any]] = []
        dep_risk_summary: List[Dict[str, Any]] = []
        
        crit_count = 0
        high_count = 0
        med_count = 0
        low_count = 0
        vulnerable_deps_set = set()
        safe_deps_set = set()
        unknown_deps_set = set()
        seen_finding_keys = set()
        ecosystems_seen = set()

        for dep, resp in zip(parsed_deps, osv_responses):
            ecosystems_seen.add(dep.ecosystem)
            api_status = resp.get("status", "SUCCESS")
            vulns = resp.get("vulns", [])
            dep_key = f"{dep.ecosystem}:{dep.name.lower()}@{dep.version}"

            if api_status == "UNAVAILABLE":
                unknown_deps_set.add(dep_key)
                dep_risk_summary.append({
                    "name": dep.name,
                    "version": dep.version,
                    "ecosystem": dep.ecosystem,
                    "manifestFile": dep.manifest_file,
                    "isDirect": dep.is_direct,
                    "isExactVersion": dep.is_exact_version,
                    "status": "UNKNOWN",
                    "vulnerabilityCount": 0,
                    "highestSeverity": None
                })
                continue

            matched_for_dep: List[MatchResult] = []
            for vuln in vulns:
                match = self.matcher.match_vulnerability(
                    package_name=dep.name,
                    installed_version=dep.version,
                    ecosystem=dep.ecosystem,
                    osv_vuln=vuln
                )
                if match.is_affected:
                    matched_for_dep.append(match)

            if matched_for_dep:
                vulnerable_deps_set.add(dep_key)
                # Determine highest severity for this dependency
                sev_ranks = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                highest_sev = max(matched_for_dep, key=lambda m: sev_ranks.get(m.severity, 0)).severity

                dep_risk_summary.append({
                    "name": dep.name,
                    "version": dep.version,
                    "ecosystem": dep.ecosystem,
                    "manifestFile": dep.manifest_file,
                    "isDirect": dep.is_direct,
                    "isExactVersion": dep.is_exact_version,
                    "status": "VULNERABLE",
                    "vulnerabilityCount": len(matched_for_dep),
                    "highestSeverity": highest_sev
                })

                for m in matched_for_dep:
                    f_key = (dep.name.lower(), dep.version, m.vulnerability_id)
                    if f_key in seen_finding_keys:
                        continue
                    seen_finding_keys.add(f_key)

                    if m.severity == "CRITICAL": crit_count += 1
                    elif m.severity == "HIGH": high_count += 1
                    elif m.severity == "MEDIUM": med_count += 1
                    elif m.severity == "LOW": low_count += 1

                    findings.append({
                        "id": f"SHP-CVE-{m.vulnerability_id}-{dep.name.lower()}",
                        "vulnerabilityId": m.vulnerability_id,
                        "cveId": m.cve_id,
                        "ghsaId": m.ghsa_id,
                        "packageName": dep.name,
                        "installedVersion": dep.version,
                        "ecosystem": dep.ecosystem,
                        "manifestFile": dep.manifest_file,
                        "isDirect": dep.is_direct,
                        "isExactVersion": dep.is_exact_version,
                        "severity": m.severity,
                        "cvssScore": m.cvss_score,
                        "cvssVector": m.cvss_vector,
                        "summary": m.summary,
                        "details": m.details,
                        "affectedRange": m.affected_range,
                        "fixedVersion": m.fixed_version,
                        "references": m.references,
                        "status": "VULNERABLE",
                        "detectedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    })
            else:
                if dep.version and dep.version != "unknown":
                    safe_deps_set.add(dep_key)
                    status_str = "SAFE"
                else:
                    unknown_deps_set.add(dep_key)
                    status_str = "UNKNOWN"

                dep_risk_summary.append({
                    "name": dep.name,
                    "version": dep.version,
                    "ecosystem": dep.ecosystem,
                    "manifestFile": dep.manifest_file,
                    "isDirect": dep.is_direct,
                    "isExactVersion": dep.is_exact_version,
                    "status": status_str,
                    "vulnerabilityCount": 0,
                    "highestSeverity": None
                })

        duration_ms = round((time.time() - start_time) * 1000, 2)
        overall_status = "FAILED" if (crit_count > 0 or high_count > 0) else ("WARNING" if med_count > 0 else "PASSED")

        result = {
            "scanId": f"CVE-{int(now)}",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "durationMs": duration_ms,
            "status": overall_status,
            "isCached": False,
            "summary": {
                "totalDependencies": len(parsed_deps),
                "vulnerableDependencies": len(vulnerable_deps_set),
                "safeDependencies": len(safe_deps_set),
                "unknownDependencies": len(unknown_deps_set),
                "totalVulnerabilities": len(findings),
                "critical": crit_count,
                "high": high_count,
                "medium": med_count,
                "low": low_count
            },
            "dependencies": dep_risk_summary,
            "findings": findings,
            "ecosystemsFound": list(ecosystems_seen)
        }

        self._cached_result = result
        self._cache_timestamp = now
        return result

    def get_cached_findings(self) -> Optional[Dict[str, Any]]:
        """Returns the in-memory cached scan result or None."""
        if not self._cached_result:
            return None
        now = time.time()
        res = dict(self._cached_result)
        res["isCached"] = True
        res["cacheAgeSeconds"] = round(now - self._cache_timestamp, 1)
        return res

    def get_vulnerability_detail(self, vulnerability_id: str) -> Optional[Dict[str, Any]]:
        """
        Looks up a specific vulnerability finding by its vulnerabilityId or internal id.
        """
        if not self._cached_result:
            return None
        findings = self._cached_result.get("findings", [])
        for f in findings:
            if f["vulnerabilityId"] == vulnerability_id or f["id"] == vulnerability_id:
                return f
            if f.get("cveId") == vulnerability_id or f.get("ghsaId") == vulnerability_id:
                return f
        return None
