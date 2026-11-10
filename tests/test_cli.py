"""CLI tests for backward-compatible flags, named profiles, and demo output."""

import json
from pathlib import Path

from main import main


def test_cli_demo_all_formats(tmp_path, monkeypatch):
    monkeypatch.setenv("NIS2_DB_PATH", str(tmp_path / "cli_test.db"))
    out_base = tmp_path / "out_report.md"

    main([
        "--demo",
        "mittelstand_office",
        "--format",
        "all",
        "-o",
        str(out_base),
    ])

    for ext in ("md", "json", "csv", "html"):
        p = Path(tmp_path / f"out_report.{ext}")
        assert p.exists(), f"Missing exported file: {p}"
        assert p.stat().st_size > 100

    parsed = json.loads((tmp_path / "out_report.json").read_text(encoding="utf-8"))
    assert parsed["mode"] == "simulation"
    assert parsed["compliance"]["total_cves"] >= 4
