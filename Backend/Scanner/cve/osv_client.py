"""
ShipSafe - OSV.dev API Client Module
Asynchronous client for querying the official Google OSV.dev vulnerability database.
Supports individual queries, batch queries, retry handling with exponential backoff,
timeout controls, and non-blocking failure semantics.
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
import httpx

logger = logging.getLogger("ShipSafe.CVE.OSVClient")

OSV_QUERY_ENDPOINT = "https://api.osv.dev/v1/query"
OSV_BATCH_ENDPOINT = "https://api.osv.dev/v1/querybatch"
DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_RETRIES = 3
INITIAL_BACKOFF_SECONDS = 0.5

class OSVClient:
    """
    Communicates with OSV API using HTTPX async client.
    Never raises uncaught exceptions that would crash the main scanner.
    """

    def __init__(self, timeout: float = DEFAULT_TIMEOUT_SECONDS, max_retries: int = MAX_RETRIES):
        self.timeout = timeout
        self.max_retries = max_retries
        self.headers = {
            "User-Agent": "ShipSafe-AppSec-Engine/2.4 (https://github.com/ShipSafe)",
            "Accept": "application/json"
        }

    async def query_package_vulnerabilities(
        self,
        package_name: str,
        version: str,
        ecosystem: str
    ) -> Dict[str, Any]:
        """
        Queries OSV for a single package version.
        Returns:
            {
                "status": "SUCCESS" | "UNAVAILABLE" | "NOT_FOUND",
                "package": package_name,
                "version": version,
                "ecosystem": ecosystem,
                "vulns": List[Dict]
            }
        """
        payload: Dict[str, Any] = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            }
        }
        if version and version != "unknown":
            payload["version"] = version

        retries = 0
        backoff = INITIAL_BACKOFF_SECONDS

        while retries <= self.max_retries:
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.post(
                        OSV_QUERY_ENDPOINT,
                        json=payload,
                        headers=self.headers
                    )

                    if response.status_code == 200:
                        data = response.json()
                        vulns = data.get("vulns", [])
                        return {
                            "status": "SUCCESS",
                            "package": package_name,
                            "version": version,
                            "ecosystem": ecosystem,
                            "vulns": vulns
                        }
                    elif response.status_code == 429:
                        # Rate limited: wait and retry
                        retries += 1
                        logger.warning(f"OSV Rate limit hit (429) for {package_name}. Backing off {backoff}s...")
                        await asyncio.sleep(backoff)
                        backoff *= 2
                        continue
                    elif response.status_code >= 500:
                        # Server error: retry
                        retries += 1
                        logger.warning(f"OSV Server error ({response.status_code}) for {package_name}. Attempt {retries}/{self.max_retries}")
                        await asyncio.sleep(backoff)
                        backoff *= 2
                        continue
                    else:
                        # Client error (400, 404, etc.)
                        return {
                            "status": "NOT_FOUND" if response.status_code == 404 else "SUCCESS",
                            "package": package_name,
                            "version": version,
                            "ecosystem": ecosystem,
                            "vulns": []
                        }

            except (httpx.TimeoutException, httpx.RequestError) as exc:
                retries += 1
                if retries <= self.max_retries:
                    logger.info(f"OSV connection issue: {exc}. Retrying in {backoff}s...")
                    await asyncio.sleep(backoff)
                    backoff *= 2
                else:
                    logger.error(f"OSV service unreachable after {self.max_retries} attempts for {package_name}: {exc}")
                    return {
                        "status": "UNAVAILABLE",
                        "package": package_name,
                        "version": version,
                        "ecosystem": ecosystem,
                        "vulns": [],
                        "error": str(exc)
                    }
            except Exception as exc:
                logger.error(f"Unexpected error while querying OSV for {package_name}: {exc}")
                return {
                    "status": "UNAVAILABLE",
                    "package": package_name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "vulns": [],
                    "error": str(exc)
                }

        return {
            "status": "UNAVAILABLE",
            "package": package_name,
            "version": version,
            "ecosystem": ecosystem,
            "vulns": [],
            "error": "Max retries exceeded"
        }

    async def query_batch(
        self,
        queries: List[Dict[str, str]]
    ) -> List[Dict[str, Any]]:
        """
        Batch query OSV for multiple packages:
        queries = [{"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"}, ...]
        Returns a list of result objects matching the order of input queries.
        Falls back to concurrent single queries if batch fails or endpoint is unavailable.
        """
        if not queries:
            return []

        # OSV batch endpoint payload structure
        batch_payload = {
            "queries": [
                {
                    "package": {
                        "name": q["name"],
                        "ecosystem": q["ecosystem"]
                    },
                    **({"version": q["version"]} if q.get("version") and q["version"] != "unknown" else {})
                }
                for q in queries
            ]
        }

        retries = 0
        backoff = INITIAL_BACKOFF_SECONDS

        while retries <= self.max_retries:
            try:
                async with httpx.AsyncClient(timeout=self.timeout + 5.0) as client:
                    response = await client.post(
                        OSV_BATCH_ENDPOINT,
                        json=batch_payload,
                        headers=self.headers
                    )

                    if response.status_code == 200:
                        data = response.json()
                        results_data = data.get("results", [])
                        
                        out = []
                        for i, res in enumerate(results_data):
                            q = queries[i] if i < len(queries) else {}
                            out.append({
                                "status": "SUCCESS",
                                "package": q.get("name", "unknown"),
                                "version": q.get("version", "unknown"),
                                "ecosystem": q.get("ecosystem", "unknown"),
                                "vulns": res.get("vulns", [])
                            })
                        return out

                    elif response.status_code == 429 or response.status_code >= 500:
                        retries += 1
                        await asyncio.sleep(backoff)
                        backoff *= 2
                        continue
                    else:
                        break

            except (httpx.TimeoutException, httpx.RequestError) as exc:
                retries += 1
                if retries <= self.max_retries:
                    await asyncio.sleep(backoff)
                    backoff *= 2
                else:
                    logger.warning(f"OSV batch query failed ({exc}), falling back to concurrent single queries.")
                    break
            except Exception as exc:
                logger.warning(f"Unexpected error in OSV batch query: {exc}, falling back to single queries.")
                break

        # Fallback to bounded concurrent individual queries
        semaphore = asyncio.Semaphore(10)
        async def _query_with_sem(q):
            async with semaphore:
                return await self.query_package_vulnerabilities(
                    package_name=q["name"],
                    version=q.get("version", ""),
                    ecosystem=q.get("ecosystem", "PyPI")
                )

        tasks = [_query_with_sem(q) for q in queries]
        return await asyncio.gather(*tasks)
