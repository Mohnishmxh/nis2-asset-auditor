"""Unit tests for EU NIS2 compliance evaluation, counterfactual mitigation math, and exporters."""

import csv
import io
import json

from src.compliance import evaluate_nis2_compliance
from src.reporter import (
    render_csv_report,
    render_html_report,
    render_json_report,
    render_markdown_report,
)
from src.scenarios import get_scenario_assets


def test_hardened_vs_vulnerable_compliance_scoring():
    hardened = get_scenario_assets("hardened_dmz")["assets"]
    vulnerable = get_scenario_assets("mittelstand_office")["assets"]

    comp_hard = evaluate_nis2_compliance(hardened)
    comp_vuln = evaluate_nis2_compliance(vulnerable)

    assert comp_hard["score"] >= 90.0
    assert comp_hard["grade"] == "A"
    assert comp_vuln["score"] < 55.0
    assert comp_vuln["total_cves"] >= 4
    assert comp_vuln["severity_counts"]["CRITICAL"] >= 1


def test_counterfactual_mitigation_score_delta_consistency():
    assets = get_scenario_assets("mittelstand_office")["assets"]
    base = evaluate_nis2_compliance(assets)
    first_action = base["remediations"][0]
    expected_new_score = round(base["score"] + first_action["impact_points"], 1)

    after = evaluate_nis2_compliance(assets, mitigated_ids=[first_action["id"]])
    assert after["score"] == expected_new_score
    toggled = next(r for r in after["remediations"] if r["id"] == first_action["id"])
    assert toggled["mitigated"] is True


def test_multi_format_report_exports_and_markdown_pipe_escaping():
    assets = get_scenario_assets("dev_workstation")["assets"]
    assets[0]["cves"][0]["summary"] = "Pipe | character inside summary"
    comp = evaluate_nis2_compliance(assets)
    report = {
        "id": "audit-test-01",
        "timestamp": "2026-11-10 11:00 UTC",
        "target": "127.0.0.1",
        "ports": "22,2375,5432,8000",
        "mode": "simulation",
        "scanner_engine": "simulation",
        "assets": assets,
        "compliance": comp,
    }

    md = render_markdown_report(report)
    assert "Pipe \\| character inside summary" in md
    assert "EU NIS2 Directive" in md

    parsed_json = json.loads(render_json_report(report))
    assert parsed_json["id"] == "audit-test-01"

    csv_rows = list(csv.DictReader(io.StringIO(render_csv_report(report))))
    assert len(csv_rows) == len(assets)

    html_out = render_html_report(report)
    assert "<!DOCTYPE html>" in html_out
    assert "CVE-2024-21626" in html_out
