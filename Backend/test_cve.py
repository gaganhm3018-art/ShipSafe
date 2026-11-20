"""
ShipSafe - Real-Time CVE Intelligence Automated Test Suite
Validates all 14 required vulnerability scanning and dependency parsing test cases
using mocked deterministic OSV.dev responses.
"""

import sys
import os
import unittest
import asyncio
import tempfile
import json
from pathlib import Path
from unittest.mock import patch, AsyncMock

# Add Backend to python path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from Scanner.cve.dependency_parser import DependencyParser, ParsedDependency
from Scanner.cve.osv_client import OSVClient
from Scanner.cve.vulnerability_matcher import VulnerabilityMatcher
from Scanner.cve.cve_service import CVEService

# Sample Mock OSV Responses
MOCK_REQUESTS_VULN_OSV = {
    "vulns": [
        {
            "id": "GHSA-j8r2-6x86-q33q",
            "aliases": ["CVE-2023-32681"],
            "summary": "Requests vulnerable to unintended leak of Proxy-Authorization header",
            "details": "In Requests versions prior to 2.31.0, Proxy-Authorization headers leak across redirects.",
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
                }
            ],
            "affected": [
                {
                    "package": {
                        "name": "requests",
                        "ecosystem": "PyPI"
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "2.31.0"}
                            ]
                        }
                    ],
                    "database_specific": {"severity": "MEDIUM"}
                }
            ],
            "references": [
                {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-j8r2-6x86-q33q"},
                {"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-32681"}
            ]
        }
    ]
}

class TestCVEIntelligence(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name)
        self.parser = DependencyParser(str(self.workspace))
        self.matcher = VulnerabilityMatcher()

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. A package with a known vulnerability
    def test_01_known_vulnerability_detected(self):
        match = self.matcher.match_vulnerability(
            package_name="requests",
            installed_version="2.30.0",
            ecosystem="PyPI",
            osv_vuln=MOCK_REQUESTS_VULN_OSV["vulns"][0]
        )
        self.assertTrue(match.is_affected)
        self.assertEqual(match.status, "VULNERABLE")
        self.assertEqual(match.cve_id, "CVE-2023-32681")
        self.assertEqual(match.fixed_version, "2.31.0")

    # 2. A package with no matching known vulnerability
    def test_02_safe_package_with_no_vulnerabilities(self):
        match = self.matcher.match_vulnerability(
            package_name="clean-pkg",
            installed_version="1.0.0",
            ecosystem="PyPI",
            osv_vuln={}
        )
        self.assertFalse(match.is_affected)
        self.assertEqual(match.status, "SAFE")

    # 3. A fixed package version
    def test_03_fixed_package_version_evaluated_as_safe(self):
        match = self.matcher.match_vulnerability(
            package_name="requests",
            installed_version="2.31.0",  # Exact fixed version
            ecosystem="PyPI",
            osv_vuln=MOCK_REQUESTS_VULN_OSV["vulns"][0]
        )
        self.assertFalse(match.is_affected)
        self.assertEqual(match.status, "SAFE")

    # 4. An unknown package or unpinned version
    def test_04_unknown_version_handling(self):
        match = self.matcher.match_vulnerability(
            package_name="unknown-lib",
            installed_version="unknown",
            ecosystem="PyPI",
            osv_vuln=MOCK_REQUESTS_VULN_OSV["vulns"][0]
        )
        self.assertFalse(match.is_affected)
        self.assertEqual(match.status, "UNKNOWN")

    # 5. Invalid dependency file
    def test_05_invalid_dependency_file_handled_safely(self):
        bad_json = self.workspace / "package-lock.json"
        bad_json.write_text("{ unquoted_bad_json: 123,, ", encoding="utf-8")
        deps = self.parser.parse_package_lock_json(bad_json)
        self.assertEqual(deps, [])  # Should gracefully catch error and return empty

    # 6. Missing dependency file
    def test_06_missing_dependency_file_handled(self):
        nonexistent = self.workspace / "does_not_exist.lock"
        deps = self.parser.parse_poetry_lock(nonexistent)
        self.assertEqual(deps, [])

    # 7. OSV API timeout
    def test_07_osv_api_timeout_non_blocking(self):
        async def run_test():
            client = OSVClient(timeout=0.01, max_retries=1)
            with patch("httpx.AsyncClient.post", side_effect=asyncio.TimeoutError("Connection timed out")):
                res = await client.query_package_vulnerabilities("requests", "2.30.0", "PyPI")
                self.assertEqual(res["status"], "UNAVAILABLE")
                self.assertEqual(res["vulns"], [])
        asyncio.run(run_test())

    # 8. OSV API unavailable
    def test_08_osv_api_unavailable_handled(self):
        async def run_test():
            client = OSVClient(timeout=1.0, max_retries=1)
            mock_resp = AsyncMock()
            mock_resp.status_code = 503
            with patch("httpx.AsyncClient.post", return_value=mock_resp):
                res = await client.query_package_vulnerabilities("requests", "2.30.0", "PyPI")
                self.assertEqual(res["status"], "UNAVAILABLE")
        asyncio.run(run_test())

    # 9. Multiple dependencies batch query
    def test_09_multiple_dependencies_batch_query(self):
        async def run_test():
            client = OSVClient()
            mock_batch_data = {
                "results": [
                    {"vulns": MOCK_REQUESTS_VULN_OSV["vulns"]},
                    {"vulns": []}
                ]
            }
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_resp.json = lambda: mock_batch_data

            queries = [
                {"name": "requests", "version": "2.30.0", "ecosystem": "PyPI"},
                {"name": "fastapi", "version": "0.110.0", "ecosystem": "PyPI"}
            ]

            with patch("httpx.AsyncClient.post", return_value=mock_resp):
                results = await client.query_batch(queries)
                self.assertEqual(len(results), 2)
                self.assertEqual(results[0]["package"], "requests")
                self.assertEqual(len(results[0]["vulns"]), 1)
                self.assertEqual(results[1]["package"], "fastapi")
                self.assertEqual(len(results[1]["vulns"]), 0)
        asyncio.run(run_test())

    # 10. Duplicate vulnerability records deduplication
    def test_10_duplicate_vulnerabilities_deduplicated(self):
        async def run_test():
            req_file = self.workspace / "requirements.txt"
            req_file.write_text("requests==2.30.0\nrequests==2.30.0\n", encoding="utf-8")

            service = CVEService(str(self.workspace))
            
            mock_batch = [{"status": "SUCCESS", "package": "requests", "version": "2.30.0", "ecosystem": "PyPI", "vulns": MOCK_REQUESTS_VULN_OSV["vulns"]}]
            with patch.object(service.client, "query_batch", return_value=mock_batch):
                scan_res = await service.scan_project(str(self.workspace), force_refresh=True)
                self.assertEqual(len(scan_res["findings"]), 1)
        asyncio.run(run_test())

    # 11. Python dependencies parsing (requirements.txt, poetry.lock, Pipfile.lock)
    def test_11_python_dependencies_parsing(self):
        req_file = self.workspace / "requirements.txt"
        req_file.write_text("urllib3==1.26.5\nclick>=8.0.0\n# comment line\n", encoding="utf-8")
        deps = self.parser.parse_requirements_txt(req_file)
        self.assertEqual(len(deps), 2)
        self.assertEqual(deps[0].name, "urllib3")
        self.assertEqual(deps[0].version, "1.26.5")
        self.assertTrue(deps[0].is_exact_version)
        self.assertEqual(deps[1].name, "click")
        self.assertFalse(deps[1].is_exact_version)

        pipfile = self.workspace / "Pipfile.lock"
        pipfile.write_text(json.dumps({
            "default": {"flask": {"version": "==2.2.0"}},
            "develop": {"pytest": {"version": "==7.1.0"}}
        }), encoding="utf-8")
        p_deps = self.parser.parse_pipfile_lock(pipfile)
        self.assertEqual(len(p_deps), 2)
        self.assertTrue(any(d.name == "flask" and d.version == "2.2.0" for d in p_deps))

    # 12. JavaScript dependencies parsing (package.json, package-lock.json, yarn.lock)
    def test_12_javascript_dependencies_parsing(self):
        pkg_json = self.workspace / "package.json"
        pkg_json.write_text(json.dumps({
            "dependencies": {"axios": "^1.6.0"},
            "devDependencies": {"typescript": "^5.0.0"}
        }), encoding="utf-8")
        deps = self.parser.parse_package_json(pkg_json)
        self.assertEqual(len(deps), 2)
        self.assertTrue(any(d.name == "axios" for d in deps))

        yarn_lock = self.workspace / "yarn.lock"
        yarn_lock.write_text('"lodash@^4.17.20":\n  version "4.17.21"\n', encoding="utf-8")
        y_deps = self.parser.parse_yarn_lock(yarn_lock)
        self.assertEqual(len(y_deps), 1)
        self.assertEqual(y_deps[0].name, "lodash")
        self.assertEqual(y_deps[0].version, "4.17.21")

    # 13. Direct dependencies
    def test_13_direct_dependencies_marked_correctly(self):
        req_file = self.workspace / "requirements.txt"
        req_file.write_text("gunicorn==20.1.0\n", encoding="utf-8")
        deps = self.parser.parse_requirements_txt(req_file)
        self.assertEqual(len(deps), 1)
        self.assertTrue(deps[0].is_direct)

    # 14. Transitive dependencies from lockfiles
    def test_14_transitive_dependencies_from_lockfile(self):
        lock_file = self.workspace / "package-lock.json"
        lock_file.write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root-app"},
                "node_modules/express": {"version": "4.18.2"},
                "node_modules/express/node_modules/debug": {"version": "2.6.9"}  # Transitive nested
            }
        }), encoding="utf-8")
        deps = self.parser.parse_package_lock_json(lock_file)
        self.assertEqual(len(deps), 2)
        direct_pkg = next(d for d in deps if d.name == "express")
        transitive_pkg = next(d for d in deps if d.name == "debug")
        self.assertTrue(direct_pkg.is_direct)
        self.assertFalse(transitive_pkg.is_direct)


if __name__ == "__main__":
    unittest.main()
