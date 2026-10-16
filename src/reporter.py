import datetime
from typing import List, Dict

def generate_markdown_report(target: str, enriched_assets: List[Dict], filepath: str) -> None:
    """Writes an executive-ready Markdown compliance report mapped to EU NIS2."""
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_cves = sum(len(a.get("cves", [])) for a in enriched_assets)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("# Automated Asset & Vulnerability Compliance Report\n\n")
        f.write(f"- **Audit Timestamp:** {timestamp}\n")
        f.write(f"- **Audited Scope:** `{target}` (Verified RFC 1918 / Loopback)\n")
        f.write("- **Regulatory Mapping:** EU NIS2 Directive — Article 21(2)(e) (Vulnerability Handling & Disclosure)\n")
        f.write(f"- **Summary:** {len(enriched_assets)} active service(s) discovered | {total_cves} potential CVE(s) mapped\n\n")
        f.write("---\n\n")
        f.write("## 1. Discovered Asset & CVE Matrix\n\n")
        f.write("| Host | Port | Service | Identified Version | Mapped CVEs (CVSS v3.1) |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- |\n")

        for asset in enriched_assets:
            version_str = f"{asset['product']} {asset['version']}".strip() or "Unidentified Banner"
            cves = asset.get("cves", [])

            if cves:
                cve_lines = [
                    f"**{c['id']}** (`{c['severity']}` - {c['score']}): {c['summary']}"
                    for c in cves
                ]
                cve_cell = "<br>".join(cve_lines)
            else:
                cve_cell = "No exact version CVEs matched"

            f.write(
                f"| `{asset['host']}` | `{asset['port']}/{asset['protocol']}` | "
                f"{asset['service']} | {version_str} | {cve_cell} |\n"
            )

        f.write("\n---\n\n")
        f.write("## 2. Recommended Remediation Workflow\n\n")
        f.write("1. **Patch Management:** Prioritize services flagged with `CRITICAL` or `HIGH` CVSS v3.1 scores.\n")
        f.write("2. **Attack Surface Reduction:** Disable unnecessary open ports or restrict access via host firewall (`ufw`/`iptables`).\n")
        f.write("3. **Banner Hardening:** Suppress verbose version banners (e.g., `ServerTokens Prod` in Apache / `server_tokens off` in Nginx) to impede automated recon.\n")