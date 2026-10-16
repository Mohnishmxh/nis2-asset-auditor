import time
import requests
from typing import List, Dict

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_cves_for_service(product: str, version: str, max_results: int = 3) -> List[Dict]:
    """Queries NIST NVD API v2.0 for known CVEs matching a product and version."""
    if not product or not version:
        return []

    query = f"{product} {version}"
    params = {
        "keywordSearch": query,
        "resultsPerPage": max_results
    }
    headers = {
        "User-Agent": "NIS2-Internal-Asset-Auditor/1.0 (Portfolio Compliance Tool)"
    }

    try:
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=12)
        if response.status_code == 200:
            data = response.json()
            cves = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "UNKNOWN")

                # Extract English description
                descriptions = cve.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description available.")

                # Extract CVSS v3.1 Score and Severity if available
                metrics = cve.get("metrics", {})
                cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                score = cvss_v31.get("baseScore", "N/A")
                severity = cvss_v31.get("baseSeverity", "UNKNOWN")

                cves.append({
                    "id": cve_id,
                    "score": score,
                    "severity": severity,
                    "summary": desc[:140].replace("\n", " ") + "..."
                })
            # Respect NVD public API rate limit (5 requests per rolling 30s window)
            time.sleep(6.0)
            return cves
    except requests.RequestException as exc:
        print(f"[!] Warning: Could not reach NVD API ({exc})")

    return []