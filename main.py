import argparse
import sys
from src.scanner import discover_services
from src.nvd_client import fetch_cves_for_service
from src.reporter import generate_markdown_report

def main():
    parser = argparse.ArgumentParser(
        description="NIS2 Internal Asset & CVE Compliance Auditor"
    )
    parser.add_argument(
        "-t", "--target",
        default="127.0.0.1",
        help="Target private IP or subnet (default: 127.0.0.1)"
    )
    parser.add_argument(
        "-p", "--ports",
        default="22,80,443,8000,8080",
        help="Comma-separated ports or range to audit (default: 22,80,443,8000,8080)"
    )
    parser.add_argument(
        "-o", "--output",
        default="reports/sample_audit_report.md",
        help="Output Markdown report path"
    )
    args = parser.parse_args()

    print(f"[*] Starting NIS2 compliance audit on target: {args.target} (Ports: {args.ports})")
    try:
        assets = discover_services(args.target, args.ports)
    except PermissionError as err:
        print(f"[!] {err}")
        sys.exit(1)

    print(f"[*] Discovered {len(assets)} active service(s). Querying NIST NVD API v2.0...")
    for asset in assets:
        if asset["product"] and asset["version"]:
            print(f"    -> Auditing {asset['product']} {asset['version']} on port {asset['port']}...")
            asset["cves"] = fetch_cves_for_service(asset["product"], asset["version"])
        else:
            asset["cves"] = []

    generate_markdown_report(args.target, assets, args.output)
    print(f"[+] Audit complete! Compliance report written to: {args.output}")

if __name__ == "__main__":
    main()