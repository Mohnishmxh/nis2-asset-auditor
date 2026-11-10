"""Canonical data models for the NIS2 Internal Asset & CVE Compliance Auditor."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ScopeValidationResult:
    """Result of validating an audit target against RFC 1918 / loopback policy."""

    valid: bool
    normalized_targets: List[str] = field(default_factory=list)
    host_count: int = 0
    network_classes: List[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CveFinding:
    """Normalized NIST NVD v2.0 CVE entry enriched with CVSS and CWE metadata."""

    id: str
    score: Optional[float] = None
    severity: str = "UNKNOWN"
    cvss_version: str = "3.1"
    vector: str = ""
    cwe_ids: List[str] = field(default_factory=list)
    published: str = ""
    last_modified: str = ""
    references: List[str] = field(default_factory=list)
    summary: str = ""
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Asset:
    """Discovered internal network service and its vulnerability enrichment."""

    host: str
    port: int
    protocol: str = "tcp"
    service: str = "unknown"
    product: str = ""
    version: str = ""
    cpe: str = ""
    extrainfo: str = ""
    hostname: str = ""
    banner: str = ""
    encrypted: bool = False
    exposure: str = "loopback"
    cves: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    nvd_status: str = "pending"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
