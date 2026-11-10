"""End-to-end audit orchestration pipeline shared by CLI and FastAPI server."""

from __future__ import annotations

import datetime
import time
import uuid
from typing import Any, Dict, List, Optional

from src.compliance import evaluate_nis2_compliance
from src.nvd_client import fetch_cves_with_status
from src.scanner import SCAN_PROFILES, ProgressCallback, discover_services_with_meta, validate_scope_details
from src.scenarios import get_scenario_assets
from src.storage import AuditStorage


def run_audit_pipeline(
    target: str = "127.0.0.1",
    ports: str = "22,80,443,8000,8080",
    profile: str = "custom",
    mode: str = "live",
    scenario_id: Optional[str] = None,
    max_cves: int = 5,
    api_key: Optional[str] = None,
    use_cache: bool = True,
    storage: Optional[AuditStorage] = None,
    save_history: bool = True,
    on_progress: Optional[ProgressCallback] = None,
) -> Dict[str, Any]:
    """
    Execute a full NIS2 internal audit (live or simulated) and return the canonical report dict.
    """
    started = time.perf_counter()
    audit_id = f"audit-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    store = storage or AuditStorage()

    resolved_ports = ports
    if profile in SCAN_PROFILES and (not ports or ports == "22,80,443,8000,8080"):
        resolved_ports = SCAN_PROFILES[profile]["ports"]

    if mode == "simulation" or scenario_id:
        sid = scenario_id or "mittelstand_office"
        if on_progress:
            on_progress("scope", f"Loading NIS2 simulation scenario '{sid}'...", 15)
        scenario = get_scenario_assets(sid)
        target = scenario["target"]
        resolved_ports = scenario["ports"]
        scope = validate_scope_details(target)
        assets: List[Dict[str, Any]] = scenario["assets"]
        engine_used = "simulation"
        if on_progress:
            on_progress("discovery", f"Loaded {len(assets)} simulated internal service(s)", 45)
            on_progress("enrichment", "Correlating pre-indexed NIST NVD CVE advisories...", 70)
    else:
        scope = validate_scope_details(target)
        if not scope.valid:
            raise PermissionError(scope.reason)

        assets, engine_used = discover_services_with_meta(
            target=target, ports=resolved_ports, on_progress=on_progress
        )

        total_assets = len(assets)
        if total_assets == 0 and on_progress:
            on_progress("enrichment", "No open ports detected; skipping NVD lookup.", 75)

        for idx, asset in enumerate(assets, start=1):
            pct = 45 + int((idx / max(1, total_assets)) * 35)
            if asset.get("product") and asset.get("version"):
                if on_progress:
                    on_progress(
                        "enrichment",
                        f"Querying NIST NVD v2.0 for {asset['product']} {asset['version']} ({idx}/{total_assets})...",
                        pct,
                    )
                cves, status = fetch_cves_with_status(
                    product=asset["product"],
                    version=asset["version"],
                    max_results=max_cves,
                    cpe=asset.get("cpe", ""),
                    api_key=api_key,
                    use_cache=use_cache,
                    storage=store,
                )
                asset["cves"] = cves
                asset["nvd_status"] = status
            else:
                asset["cves"] = []
                asset["nvd_status"] = "no_version"

    if on_progress:
        on_progress("compliance", "Evaluating EU NIS2 Article 21(2) posture & calculating risk scores...", 90)

    compliance = evaluate_nis2_compliance(assets)
    duration_ms = int((time.perf_counter() - started) * 1000)

    report: Dict[str, Any] = {
        "id": audit_id,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "target": target,
        "ports": resolved_ports,
        "profile": profile,
        "mode": "simulation" if (mode == "simulation" or scenario_id) else "live",
        "scenario_id": scenario_id,
        "scanner_engine": engine_used,
        "duration_ms": duration_ms,
        "scope_summary": scope.to_dict(),
        "assets": assets,
        "compliance": compliance,
        "mitigated_ids": [],
    }

    if save_history:
        store.save_audit(report)

    if on_progress:
        on_progress("complete", "NIS2 compliance audit complete.", 100)

    return report
