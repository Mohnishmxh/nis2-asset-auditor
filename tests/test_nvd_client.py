"""Unit tests for NIST NVD v2.0 client parsing, fallback, and caching."""

from unittest.mock import MagicMock, patch

from src.nvd_client import _extract_cvss, fetch_cves_with_status
from src.storage import AuditStorage


def test_extract_cvss_handles_empty_lists_and_v30_v2_fallbacks():
    # Empty cvssMetricV31 list used to raise IndexError in v1
    assert _extract_cvss({"cvssMetricV31": []}) == (None, "UNKNOWN", "N/A", "")

    score, sev, ver, vec = _extract_cvss({
        "cvssMetricV31": [],
        "cvssMetricV30": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.0/AV:N"}}],
    })
    assert (score, sev, ver, vec) == (7.5, "HIGH", "3.0", "CVSS:3.0/AV:N")

    score2, sev2, ver2, _ = _extract_cvss({
        "cvssMetricV2": [{"baseSeverity": "MEDIUM", "cvssData": {"baseScore": 5.0}}]
    })
    assert (score2, sev2, ver2) == (5.0, "MEDIUM", "2.0")


def test_nvd_client_uses_cpe_and_sqlite_cache(tmp_path):
    store = AuditStorage(db_path=tmp_path / "test.db")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-42013",
                    "published": "2021-10-07T00:00:00.000",
                    "lastModified": "2024-11-21T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Apache path traversal RCE."}],
                    "weaknesses": [{"description": [{"value": "CWE-22"}]}],
                    "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                }
                            }
                        ]
                    },
                }
            }
        ]
    }

    with patch("src.nvd_client.requests.get", return_value=mock_resp) as mock_get:
        cves1, status1 = fetch_cves_with_status(
            product="Apache httpd",
            version="2.4.49",
            cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            storage=store,
            api_key="dummy-key",
        )
        assert status1 == "ok"
        assert len(cves1) == 1
        assert cves1[0]["id"] == "CVE-2021-42013"
        assert cves1[0]["cwe_ids"] == ["CWE-22"]
        assert mock_get.call_count == 1
        assert "cpeName" in mock_get.call_args.kwargs["params"]

        # Second call should hit SQLite cache without invoking requests.get again
        cves2, status2 = fetch_cves_with_status(
            product="Apache httpd",
            version="2.4.49",
            cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            storage=store,
            api_key="dummy-key",
        )
        assert status2 == "cached"
        assert cves2 == cves1
        assert mock_get.call_count == 1
