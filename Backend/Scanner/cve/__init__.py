"""
ShipSafe - Real-Time CVE Intelligence Package
Integrates official OSV.dev vulnerability database with developer lockfiles and manifests.
"""

from .osv_client import OSVClient
from .dependency_parser import DependencyParser, ParsedDependency
from .vulnerability_matcher import VulnerabilityMatcher, MatchResult
from .cve_service import CVEService

__all__ = [
    "OSVClient",
    "DependencyParser",
    "ParsedDependency",
    "VulnerabilityMatcher",
    "MatchResult",
    "CVEService"
]
