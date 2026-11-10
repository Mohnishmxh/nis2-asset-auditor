"""Rate-limited, cached NIST NVD API v2.0 vulnerability enrichment client."""

from __future__ import annotations

import os
import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

from src.storage import AuditStorage

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_RATE_LOCK = threading.Lock()
_LAST_REQUEST_TS = 0.0

_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def _rate_limit_wait(has_api_key: bool) -> None:
    """Enforce NIST NVD rolling rate limits without unnecessary trailing sleeps."""
    global _LAST_REQUEST_TS
    min_interval = 0.65 if has_api_key else 6.1
    with _RATE_LOCK:
        now = time.monotonic()
        elapsed = now - _LAST_REQUEST_TS
        if _LAST_REQUEST_TS > 0 and elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        _LAST_REQUEST_TS = time.monotonic()


def _normalize_version_token(version: str) -> str:
    """Extract the clean primary version number from verbose Nmap banner versions."""
    raw = (version or "").strip()
    if not raw:
        return ""
    # e.g., "8.9p1 Ubuntu 3ubuntu0.6" -> "8.9p1"
    first_token = raw.split()[0]
    return re.sub(r"[^A-Za-z0-9._+-]", "", first_token)


def _normalize_product_token(product: str) -> str:
    raw = (product or "").strip()
    if raw.lower() == "apache httpd":
        return "Apache HTTP Server"
    return raw


def _is_usable_cpe_for_query(cpe: str) -> bool:
    """Return True if a CPE 2.3 string contains a specific vendor, product, and version."""
    if not cpe or not cpe.startswith("cpe:2.3:"):
        return False
    parts = cpe.split(":")
    if len(parts) < 6:
        return False
    vendor, product, version = parts[3], parts[4], parts[5]
    return all(x and x not in ("*", "-") for x in (vendor, product, version))


def _extract_cvss(metrics: Dict[str, Any]) -> Tuple[Optional[float], str, str, str]:
    """Safely extract CVSS score, severity, version, and vector across v3.1, v3.0, and v2."""
    for key, ver_label in (
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(key) or []
        if not entries or not isinstance(entries, list):
            continue
        first = entries[0] if isinstance(entries[0], dict) else {}
        cvss_data = first.get("cvssData") or {}
        score = cvss_data.get("baseScore")
        severity = (
            cvss_data.get("baseSeverity")
            or first.get("baseSeverity")
            or _severity_from_score(score)
        )
        vector = cvss_data.get("vectorString", "")
        return (
            float(score) if isinstance(score, (int, float)) else None,
            str(severity).upper(),
            ver_label,
            vector,
        )
    return None, "UNKNOWN", "N/A", ""


def _severity_from_score(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _extract_cwes(cve: Dict[str, Any]) -> List[str]:
    cwes: List[str] = []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            val = desc.get("value", "")
            if val.startswith("CWE-") and val not in cwes:
                cwes.append(val)
    return cwes[:4]


def _parse_nvd_response(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    cves: List[Dict[str, Any]] = []
    for item in data.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        cve_id = cve.get("id", "UNKNOWN")

        descriptions = cve.get("descriptions") or []
        desc = next(
            (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
            "No description available.",
        )
        clean_desc = " ".join(desc.split())
        summary = (clean_desc[:157] + "...") if len(clean_desc) > 160 else clean_desc

        score, severity, cvss_ver, vector = _extract_cvss(cve.get("metrics") or {})
        refs = [
            r.get("url", "")
            for r in (cve.get("references") or [])
            if isinstance(r, dict) and r.get("url")
        ][:3]

        cves.append({
            "id": cve_id,
            "score": score if score is not None else "N/A",
            "severity": severity,
            "cvss_version": cvss_ver,
            "vector": vector,
            "cwe_ids": _extract_cwes(cve),
            "published": (cve.get("published") or "")[:10],
            "last_modified": (cve.get("lastModified") or "")[:10],
            "references": refs,
            "summary": summary,
            "description": clean_desc,
        })

    cves.sort(
        key=lambda c: (
            _SEV_ORDER.get(c["severity"], 0),
            float(c["score"]) if isinstance(c["score"], (int, float)) else -1.0,
        ),
        reverse=True,
    )
    return cves


def _perform_nvd_request(
    params: Dict[str, Any],
    api_key: Optional[str],
    timeout: int = 12,
    retries: int = 2,
) -> Tuple[Optional[Dict[str, Any]], str]:
    """Execute an NVD API GET request with rate limiting and retry/backoff."""
    headers = {
        "User-Agent": "NIS2-Internal-Asset-Auditor/2.0 (EU Compliance Utility)",
    }
    if api_key:
        headers["apiKey"] = api_key

    for attempt in range(retries + 1):
        _rate_limit_wait(bool(api_key))
        try:
            response = requests.get(
                NVD_API_URL, params=params, headers=headers, timeout=timeout
            )
            if response.status_code == 200:
                return response.json(), "ok"
            if response.status_code in (429, 502, 503, 504):
                if attempt < retries:
                    retry_after = response.headers.get("Retry-After")
                    wait_s = float(retry_after) if retry_after and retry_after.isdigit() else (2.5 * (attempt + 1))
                    time.sleep(min(wait_s, 10.0))
                    continue
                return None, "rate_limited" if response.status_code == 429 else "error"
            return None, f"http_{response.status_code}"
        except requests.RequestException:
            if attempt < retries:
                time.sleep(1.5 * (attempt + 1))
                continue
            return None, "offline_error"
    return None, "error"


def fetch_cves_with_status(
    product: str,
    version: str,
    max_results: int = 5,
    cpe: str = "",
    api_key: Optional[str] = None,
    use_cache: bool = True,
    storage: Optional[AuditStorage] = None,
) -> Tuple[List[Dict[str, Any]], str]:
    """
    Query NIST NVD API v2.0 for known CVEs matching a service CPE or product/version.
    Returns (cve_list, status_code).
    """
    clean_product = _normalize_product_token(product)
    clean_version = _normalize_version_token(version)
    if not clean_product or not clean_version:
        return [], "no_version"

    effective_key = api_key or os.getenv("NVD_API_KEY") or None
    cache_key = f"{cpe.lower()}|{clean_product.lower()}|{clean_version.lower()}|{max_results}"

    store = storage
    if use_cache and store is None:
        try:
            store = AuditStorage()
        except Exception:
            store = None

    if use_cache and store is not None:
        cached = store.get_cached_nvd(cache_key)
        if cached is not None:
            return cached["cves"], "cached"

    cves: List[Dict[str, Any]] = []
    status = "ok"

    # Prefer precise CPE 2.3 lookup when available, fall back to keywordSearch
    if _is_usable_cpe_for_query(cpe):
        payload, status = _perform_nvd_request(
            {"cpeName": cpe, "resultsPerPage": max_results}, effective_key
        )
        if payload is not None:
            cves = _parse_nvd_response(payload)

    if not cves and status in ("ok", "http_404"):
        query = f"{clean_product} {clean_version}"
        payload, status = _perform_nvd_request(
            {"keywordSearch": query, "resultsPerPage": max_results}, effective_key
        )
        if payload is not None:
            cves = _parse_nvd_response(payload)

    if use_cache and store is not None and status == "ok":
        try:
            store.set_cached_nvd(cache_key, status, cves)
        except Exception:
            pass

    return cves, status


def fetch_cves_for_service(
    product: str,
    version: str,
    max_results: int = 5,
    cpe: str = "",
    api_key: Optional[str] = None,
    use_cache: bool = True,
) -> List[Dict[str, Any]]:
    """Query NIST NVD API v2.0 for known CVEs matching a product and version."""
    cves, _ = fetch_cves_with_status(
        product=product,
        version=version,
        max_results=max_results,
        cpe=cpe,
        api_key=api_key,
        use_cache=use_cache,
    )
    return cves
