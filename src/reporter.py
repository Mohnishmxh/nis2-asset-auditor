"""Multi-format NIS2 compliance report exporters (Markdown, JSON, CSV, HTML)."""

from __future__ import annotations

import csv
import datetime
import html
import io
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.compliance import evaluate_nis2_compliance


def _escape_md_cell(text: str) -> str:
    return (text or "").replace("|", "\\|").replace("\n", " ").strip()


def render_markdown_report(report: Dict[str, Any]) -> str:
    """Render an enriched audit report dictionary into a NIS2 Markdown compliance dossier."""
    target = report.get("target", "unknown")
    timestamp = report.get("timestamp") or datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )
    assets = report.get("assets", [])
    compliance = report.get("compliance") or evaluate_nis2_compliance(assets)
    sev = compliance.get("severity_counts", {})

    lines: List[str] = [
        "# EU NIS2 Automated Asset & Vulnerability Compliance Report",
        "",
        f"- **Audit ID:** `{report.get('id', 'cli-run')}`",
        f"- **Audit Timestamp:** {timestamp}",
        f"- **Audited Scope:** `{target}` (Verified RFC 1918 / Loopback)",
        f"- **Scan Mode / Engine:** `{report.get('mode', 'live')}` / `{report.get('scanner_engine', 'nmap')}`",
        "- **Regulatory Mapping:** EU NIS2 Directive (Directive (EU) 2022/2555) — Article 21(2)",
        (
            f"- **NIS2 Posture Score:** **{compliance['score']}/100 (Grade {compliance['grade']} — "
            f"{compliance['posture']})**"
        ),
        (
            f"- **Summary:** {len(assets)} active service(s) discovered | "
            f"{compliance['total_cves']} unique CVE(s) mapped "
            f"(Critical: {sev.get('CRITICAL', 0)}, High: {sev.get('HIGH', 0)}, "
            f"Medium: {sev.get('MEDIUM', 0)}, Low: {sev.get('LOW', 0)})"
        ),
        "",
        f"> **NIS2 Advisory:** {compliance.get('nis2_reporting_alert', '')}",
        "",
        "---",
        "",
        "## 1. NIS2 Article 21(2) Control Matrix",
        "",
        "| Control | Pillar | Status | Score | Key Evidence |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]

    for ctrl in compliance.get("controls", []):
        evidence = "; ".join(ctrl.get("evidence", [])[:2])
        lines.append(
            f"| `{ctrl['article']}` | {_escape_md_cell(ctrl['title'])} | **{ctrl['status']}** | "
            f"{ctrl['score']}/{ctrl['max_score']} | {_escape_md_cell(evidence)} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 2. Discovered Asset & CVE Matrix",
        "",
        "| Host | Port | Service | Transport | Identified Version | Risk | Mapped CVEs (CVSS) |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ])

    for asset in assets:
        version_str = f"{asset.get('product', '')} {asset.get('version', '')}".strip() or "Unidentified Banner"
        transport = "TLS/Encrypted" if asset.get("encrypted") else "Cleartext"
        cves = asset.get("cves", [])
        if cves:
            cve_lines = [
                f"**{c['id']}** (`{c.get('severity', 'UNKNOWN')}` - {c.get('score', 'N/A')}): "
                f"{_escape_md_cell(c.get('summary', ''))}"
                for c in cves
            ]
            cve_cell = "<br>".join(cve_lines)
        else:
            cve_cell = "No known CVEs matched"

        lines.append(
            f"| `{asset['host']}` | `{asset['port']}/{asset.get('protocol', 'tcp')}` | "
            f"{_escape_md_cell(asset.get('service', 'unknown'))} | {transport} | "
            f"{_escape_md_cell(version_str)} | {asset.get('risk_score', 0)}/100 | {cve_cell} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 3. Prioritized NIS2 Remediation Playbook",
        "",
    ])

    remediations = compliance.get("remediations", [])
    if not remediations:
        lines.append("No active remediation items required. Maintain scheduled continuous compliance scanning.")
    else:
        for idx, rem in enumerate(remediations, start=1):
            state = "MITIGATED" if rem.get("mitigated") else rem.get("priority", "MEDIUM")
            lines.append(
                f"{idx}. **[{state}] {rem['title']}** (`{rem['nis2_article']}`, "
                f"Impact: +{rem.get('impact_points', 0)} pts, Effort: {rem.get('effort', 'MEDIUM')})"
            )
            lines.append(f"   - Affected: {', '.join(rem.get('affected_assets', []))}")
            lines.append(f"   - Rationale: {rem.get('rationale', '')}")

    lines.append("")
    return "\n".join(lines)


def render_json_report(report: Dict[str, Any]) -> str:
    """Serialize the audit report as formatted JSON."""
    return json.dumps(report, indent=2)


def render_csv_report(report: Dict[str, Any]) -> str:
    """Render flattened asset and CVE rows as CSV."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "host",
        "hostname",
        "port",
        "protocol",
        "service",
        "product",
        "version",
        "cpe",
        "encrypted",
        "exposure",
        "asset_risk_score",
        "cve_id",
        "cve_severity",
        "cvss_score",
        "cwe_ids",
        "cve_summary",
    ])
    for asset in report.get("assets", []):
        cves = asset.get("cves") or [None]
        for cve in cves:
            writer.writerow([
                asset.get("host", ""),
                asset.get("hostname", ""),
                asset.get("port", ""),
                asset.get("protocol", "tcp"),
                asset.get("service", ""),
                asset.get("product", ""),
                asset.get("version", ""),
                asset.get("cpe", ""),
                asset.get("encrypted", False),
                asset.get("exposure", ""),
                asset.get("risk_score", 0),
                cve.get("id", "") if cve else "",
                cve.get("severity", "") if cve else "",
                cve.get("score", "") if cve else "",
                ";".join(cve.get("cwe_ids", [])) if cve else "",
                cve.get("summary", "") if cve else "",
            ])
    return buf.getvalue()


def render_html_report(report: Dict[str, Any]) -> str:
    """Render a self-contained, print/PDF-ready HTML executive compliance dossier."""
    compliance = report.get("compliance") or evaluate_nis2_compliance(report.get("assets", []))
    assets = report.get("assets", [])
    sev = compliance.get("severity_counts", {})

    def esc(val: Any) -> str:
        return html.escape(str(val or ""))

    ctrl_rows = []
    for c in compliance.get("controls", []):
        badge_cls = "pass" if c["status"] == "PASS" else "warn" if c["status"] == "WARN" else "fail"
        ctrl_rows.append(
            f"<tr><td><code>{esc(c['article'])}</code></td><td><strong>{esc(c['title'])}</strong></td>"
            f"<td><span class='badge {badge_cls}'>{esc(c['status'])}</span></td>"
            f"<td>{esc(c['score'])}/{esc(c['max_score'])}</td>"
            f"<td>{esc('; '.join(c.get('evidence', [])[:2]))}</td></tr>"
        )

    asset_rows = []
    for a in assets:
        ver = f"{a.get('product', '')} {a.get('version', '')}".strip() or "Unidentified Banner"
        cve_items = [
            f"<div><strong>{esc(cv['id'])}</strong> "
            f"<span class='badge {esc(cv.get('severity', 'unknown')).lower()}'>{esc(cv.get('severity', 'UNKNOWN'))} ({esc(cv.get('score', 'N/A'))})</span>"
            f"<div class='muted'>{esc(cv.get('summary', ''))}</div></div>"
            for cv in a.get("cves", [])
        ]
        asset_rows.append(
            f"<tr><td><code>{esc(a['host'])}</code></td><td><code>{esc(a['port'])}/{esc(a.get('protocol', 'tcp'))}</code></td>"
            f"<td>{esc(a.get('service', ''))}</td><td>{'TLS' if a.get('encrypted') else 'Cleartext'}</td>"
            f"<td>{esc(ver)}</td><td>{esc(a.get('risk_score', 0))}/100</td>"
            f"<td>{''.join(cve_items) if cve_items else '<span class=muted>None matched</span>'}</td></tr>"
        )

    rem_items = []
    for r in compliance.get("remediations", []):
        rem_items.append(
            f"<div class='card'><strong>[{esc(r.get('priority'))}] {esc(r.get('title'))}</strong> "
            f"<span class='muted'>({esc(r.get('nis2_article'))} | +{esc(r.get('impact_points'))} pts)</span>"
            f"<p>{esc(r.get('rationale'))}</p>"
            f"<pre>{esc(r.get('commands'))}</pre></div>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>NIS2 Compliance Report — {esc(report.get('target'))}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #0f172a; margin: 36px auto; max-width: 1080px; padding: 0 24px; line-height: 1.5; }}
  h1, h2 {{ color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; }}
  .meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 12px; margin: 20px 0; }}
  .kpi {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; }}
  .kpi .label {{ font-size: 12px; text-transform: uppercase; color: #64748b; letter-spacing: 0.04em; }}
  .kpi .val {{ font-size: 24px; font-weight: 700; margin-top: 4px; }}
  .alert {{ background: #eff6ff; border-left: 4px solid #2563eb; padding: 12px 16px; border-radius: 4px; margin: 16px 0; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 13px; }}
  th, td {{ border: 1px solid #e2e8f0; padding: 10px; text-align: left; vertical-align: top; }}
  th {{ background: #f1f5f9; font-weight: 600; }}
  code {{ background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-size: 12px; }}
  pre {{ background: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; }}
  .pass {{ background: #dcfce7; color: #166534; }}
  .warn {{ background: #fef9c3; color: #854d0e; }}
  .fail, .critical {{ background: #fee2e2; color: #991b1b; }}
  .high {{ background: #ffedd5; color: #9a3412; }}
  .medium {{ background: #fef3c7; color: #92400e; }}
  .low {{ background: #e0f2fe; color: #075985; }}
  .card {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; margin: 12px 0; }}
  .muted {{ color: #64748b; font-size: 12px; }}
</style>
</head>
<body>
  <h1>EU NIS2 Asset &amp; Vulnerability Compliance Report</h1>
  <p class="muted">Audit ID: <code>{esc(report.get('id'))}</code> | Timestamp: {esc(report.get('timestamp'))} | Scope: <code>{esc(report.get('target'))}</code></p>
  <div class="meta">
    <div class="kpi"><div class="label">NIS2 Posture Score</div><div class="val">{esc(compliance['score'])}/100 (Grade {esc(compliance['grade'])})</div></div>
    <div class="kpi"><div class="label">Active Services</div><div class="val">{len(assets)}</div></div>
    <div class="kpi"><div class="label">Unique CVEs</div><div class="val">{esc(compliance['total_cves'])}</div></div>
    <div class="kpi"><div class="label">Critical / High</div><div class="val">{esc(sev.get('CRITICAL', 0))} / {esc(sev.get('HIGH', 0))}</div></div>
  </div>
  <div class="alert"><strong>Regulatory Advisory:</strong> {esc(compliance.get('nis2_reporting_alert'))}</div>
  <h2>1. NIS2 Article 21(2) Control Matrix</h2>
  <table><thead><tr><th>Article</th><th>Control</th><th>Status</th><th>Score</th><th>Evidence</th></tr></thead><tbody>{''.join(ctrl_rows)}</tbody></table>
  <h2>2. Discovered Asset &amp; CVE Matrix</h2>
  <table><thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Transport</th><th>Version</th><th>Risk</th><th>Mapped CVEs</th></tr></thead><tbody>{''.join(asset_rows)}</tbody></table>
  <h2>3. Prioritized Remediation Playbook</h2>
  {''.join(rem_items) if rem_items else '<p>No active remediation actions required.</p>'}
</body>
</html>"""


def write_report_file(report: Dict[str, Any], filepath: str, fmt: str = "md") -> Path:
    """Write an audit report to disk in md, json, csv, or html format."""
    out_path = Path(filepath)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fmt_lower = fmt.lower()
    if fmt_lower in ("md", "markdown"):
        content = render_markdown_report(report)
    elif fmt_lower == "json":
        content = render_json_report(report)
    elif fmt_lower == "csv":
        content = render_csv_report(report)
    elif fmt_lower == "html":
        content = render_html_report(report)
    else:
        raise ValueError(f"Unsupported report format: '{fmt}'.")

    out_path.write_text(content, encoding="utf-8")
    return out_path


def generate_markdown_report(
    target: str,
    enriched_assets: List[Dict[str, Any]],
    filepath: str,
    report_meta: Optional[Dict[str, Any]] = None,
) -> None:
    """Writes an executive-ready Markdown compliance report mapped to EU NIS2."""
    compliance = evaluate_nis2_compliance(enriched_assets)
    report: Dict[str, Any] = {
        "id": (report_meta or {}).get("id", "cli-audit"),
        "timestamp": (report_meta or {}).get("timestamp")
        or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "target": target,
        "mode": (report_meta or {}).get("mode", "live"),
        "scanner_engine": (report_meta or {}).get("scanner_engine", "nmap"),
        "assets": enriched_assets,
        "compliance": compliance,
    }
    write_report_file(report, filepath, fmt="md")
