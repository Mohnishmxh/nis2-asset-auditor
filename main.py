"""CLI and Server Entrypoint for the NIS2 Internal Asset & CVE Compliance Auditor."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

import uvicorn

from src.auditor import run_audit_pipeline
from src.reporter import write_report_file
from src.scanner import SCAN_PROFILES
from src.scenarios import SIMULATION_SCENARIOS


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="NIS2 Internal Asset & CVE Compliance Auditor"
    )
    parser.add_argument(
        "-t",
        "--target",
        default="127.0.0.1",
        help="Target private IP, CIDR subnet, or 'localhost' (default: 127.0.0.1)",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default="22,80,443,8000,8080",
        help="Comma-separated ports or range to audit (default: 22,80,443,8000,8080)",
    )
    parser.add_argument(
        "--profile",
        choices=["custom", *SCAN_PROFILES.keys()],
        default="custom",
        help="Named port scan profile",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="reports/sample_audit_report.md",
        help="Output report path (default: reports/sample_audit_report.md)",
    )
    parser.add_argument(
        "--format",
        choices=["md", "json", "csv", "html", "all"],
        default="md",
        help="Report output format (default: md)",
    )
    parser.add_argument(
        "--demo",
        nargs="?",
        const="mittelstand_office",
        choices=list(SIMULATION_SCENARIOS.keys()),
        help="Run an offline NIS2 demo simulation scenario instead of live scanning",
    )
    parser.add_argument(
        "--max-cves",
        type=int,
        default=5,
        help="Max CVEs fetched per discovered service (default: 5)",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="Optional NIST NVD API key (or set NVD_API_KEY env var)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Bypass local SQLite NVD response cache",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="Start the FastAPI web dashboard & REST API server",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Web server bind address when using --serve or 'serve' (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Web server port when using --serve or 'serve' (default: 8000)",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    raw_args = list(sys.argv[1:] if argv is None else argv)

    # Support friendly `python main.py serve --port 8000` subcommand style
    if raw_args and raw_args[0] == "serve":
        raw_args = ["--serve", *raw_args[1:]]

    parser = _build_parser()
    args = parser.parse_args(raw_args)

    if args.serve:
        print(f"[*] Starting NIS2 Smart Console at http://{args.host}:{args.port}")
        uvicorn.run("src.server:app", host=args.host, port=args.port, reload=False)
        return

    mode = "simulation" if args.demo else "live"
    print(
        f"[*] Starting NIS2 compliance audit (mode={mode}, target={args.target}, profile={args.profile})"
    )

    try:
        report = run_audit_pipeline(
            target=args.target,
            ports=args.ports,
            profile=args.profile,
            mode=mode,
            scenario_id=args.demo,
            max_cves=args.max_cves,
            api_key=args.api_key,
            use_cache=not args.no_cache,
            save_history=True,
            on_progress=lambda stage, msg, pct: print(f"    [{pct:3d}%] {stage}: {msg}"),
        )
    except (PermissionError, ValueError) as err:
        print(f"[!] {err}")
        sys.exit(1)

    out_path = Path(args.output)
    if args.format == "all":
        stem = out_path.with_suffix("")
        for fmt in ("md", "json", "csv", "html"):
            written = write_report_file(report, f"{stem}.{fmt}", fmt=fmt)
            print(f"[+] Wrote {fmt.upper()} report: {written}")
    else:
        written = write_report_file(report, str(out_path), fmt=args.format)
        print(f"[+] Wrote {args.format.upper()} report: {written}")

    comp = report["compliance"]
    print(
        f"[+] Audit complete! Score: {comp['score']}/100 (Grade {comp['grade']} — {comp['posture']}) | "
        f"Services: {len(report['assets'])} | CVEs: {comp['total_cves']}"
    )


if __name__ == "__main__":
    main()
