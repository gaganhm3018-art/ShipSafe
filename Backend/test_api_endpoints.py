"""
ShipSafe - Integration Test for all Backend API Endpoints
Verifies both existing and new CVE endpoints without regressions.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_endpoints():
    print("Testing existing endpoints...")
    # 1. Health
    h_res = client.get("/api/health")
    assert h_res.status_code == 200, f"Health failed: {h_res.status_code}"
    print(" - /api/health: OK", h_res.json()["service"])

    # 2. Scans
    s_res = client.get("/api/scans")
    assert s_res.status_code == 200, f"Scans failed: {s_res.status_code}"
    print(" - /api/scans: OK, count:", len(s_res.json()["scans"]))

    # 3. Snippet scan
    snip_res = client.post("/api/scan/snippet", json={
        "filename": "test.py",
        "content": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
    })
    assert snip_res.status_code == 200, f"Snippet failed: {snip_res.status_code}"
    assert snip_res.json()["total"] > 0
    print(" - /api/scan/snippet: OK, findings:", snip_res.json()["total"])

    # 4. Remediation
    rem_res = client.get("/api/remediation/INJ-001")
    assert rem_res.status_code == 200, f"Remediation failed: {rem_res.status_code}"
    print(" - /api/remediation/INJ-001: OK")

    print("\nTesting new CVE endpoints...")
    # 5. CVE Scan
    cve_scan_res = client.post("/api/cve/scan", json={"target_path": "."})
    assert cve_scan_res.status_code == 200, f"CVE scan failed: {cve_scan_res.status_code}"
    scan_data = cve_scan_res.json()
    assert "summary" in scan_data
    assert "dependencies" in scan_data
    print(" - POST /api/cve/scan: OK, dependencies found:", scan_data["summary"]["totalDependencies"])

    # 6. CVE Findings (cached)
    cve_find_res = client.get("/api/cve/findings")
    assert cve_find_res.status_code == 200, f"CVE findings failed: {cve_find_res.status_code}"
    print(" - GET /api/cve/findings: OK, cached:", cve_find_res.json().get("isCached"))

    # 7. CVE Refresh
    cve_ref_res = client.post("/api/cve/refresh", json={"target_path": "."})
    assert cve_ref_res.status_code == 200, f"CVE refresh failed: {cve_ref_res.status_code}"
    print(" - POST /api/cve/refresh: OK")

    # 8. CVE Detail (if any findings exist, or 404 test)
    not_found_res = client.get("/api/cve/CVE-NONEXISTENT-9999")
    assert not_found_res.status_code == 404
    print(" - GET /api/cve/{id} (404 check): OK")

    if scan_data.get("findings"):
        first_vuln = scan_data["findings"][0]["vulnerabilityId"]
        detail_res = client.get(f"/api/cve/{first_vuln}")
        assert detail_res.status_code == 200
        print(f" - GET /api/cve/{first_vuln}: OK")

    print("\n>>> ALL 8 API ENDPOINT INTEGRATION TESTS PASSED SUCCESSFULLY! <<<")

if __name__ == "__main__":
    test_endpoints()
