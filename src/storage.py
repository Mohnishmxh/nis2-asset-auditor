"""SQLite persistence for audit history, NVD response caching, and remediation state."""

from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, List, Optional

DEFAULT_DB_PATH = "data/nis2_auditor.db"


def get_db_path() -> Path:
    """Resolve the active SQLite database path from environment or default."""
    return Path(os.getenv("NIS2_DB_PATH", DEFAULT_DB_PATH))


class AuditStorage:
    """Lightweight SQLite store for audit history, NVD cache, and mitigation tracking."""

    def __init__(self, db_path: Optional[str | Path] = None) -> None:
        self.db_path = Path(db_path) if db_path is not None else get_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS audits (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    target TEXT NOT NULL,
                    ports TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    scanner_engine TEXT NOT NULL,
                    compliance_score REAL NOT NULL,
                    grade TEXT NOT NULL,
                    asset_count INTEGER NOT NULL,
                    cve_count INTEGER NOT NULL,
                    critical_count INTEGER NOT NULL,
                    high_count INTEGER NOT NULL,
                    report_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_audits_created_at
                    ON audits(created_at DESC);

                CREATE TABLE IF NOT EXISTS nvd_cache (
                    cache_key TEXT PRIMARY KEY,
                    fetched_at REAL NOT NULL,
                    status TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS mitigations (
                    audit_id TEXT NOT NULL,
                    action_id TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (audit_id, action_id)
                );
                """
            )

    def save_audit(self, report: Dict[str, Any]) -> None:
        compliance = report.get("compliance", {})
        sev = compliance.get("severity_counts", {})
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO audits (
                    id, created_at, target, ports, profile, mode, scanner_engine,
                    compliance_score, grade, asset_count, cve_count,
                    critical_count, high_count, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report["id"],
                    report["timestamp"],
                    report["target"],
                    report["ports"],
                    report.get("profile", "custom"),
                    report.get("mode", "live"),
                    report.get("scanner_engine", "nmap"),
                    float(compliance.get("score", 0.0)),
                    str(compliance.get("grade", "F")),
                    len(report.get("assets", [])),
                    int(compliance.get("total_cves", 0)),
                    int(sev.get("CRITICAL", 0)),
                    int(sev.get("HIGH", 0)),
                    json.dumps(report),
                ),
            )

    def list_audits(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, created_at, target, ports, profile, mode, scanner_engine,
                       compliance_score, grade, asset_count, cve_count,
                       critical_count, high_count
                FROM audits
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_audit(self, audit_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT report_json FROM audits WHERE id = ?", (audit_id,)
            ).fetchone()
        if not row:
            return None
        return json.loads(row["report_json"])

    def delete_audit(self, audit_id: str) -> bool:
        with self._connect() as conn:
            conn.execute("DELETE FROM mitigations WHERE audit_id = ?", (audit_id,))
            cur = conn.execute("DELETE FROM audits WHERE id = ?", (audit_id,))
            return cur.rowcount > 0

    def get_mitigations(self, audit_id: str) -> List[str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT action_id FROM mitigations WHERE audit_id = ?", (audit_id,)
            ).fetchall()
        return [r["action_id"] for r in rows]

    def set_mitigation(self, audit_id: str, action_id: str, mitigated: bool) -> List[str]:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._connect() as conn:
            if mitigated:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO mitigations (audit_id, action_id, updated_at)
                    VALUES (?, ?, ?)
                    """,
                    (audit_id, action_id, now),
                )
            else:
                conn.execute(
                    "DELETE FROM mitigations WHERE audit_id = ? AND action_id = ?",
                    (audit_id, action_id),
                )
        return self.get_mitigations(audit_id)

    def get_cached_nvd(
        self, cache_key: str, ttl_seconds: int = 86400
    ) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT fetched_at, status, payload_json FROM nvd_cache WHERE cache_key = ?",
                (cache_key,),
            ).fetchone()
        if not row:
            return None
        if (time.time() - float(row["fetched_at"])) > ttl_seconds:
            return None
        return {
            "status": row["status"],
            "cves": json.loads(row["payload_json"]),
        }

    def set_cached_nvd(
        self, cache_key: str, status: str, cves: List[Dict[str, Any]]
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO nvd_cache (cache_key, fetched_at, status, payload_json)
                VALUES (?, ?, ?, ?)
                """,
                (cache_key, time.time(), status, json.dumps(cves)),
            )

    def clear_nvd_cache(self) -> int:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM nvd_cache")
            return cur.rowcount

    def get_cache_stats(self) -> Dict[str, Any]:
        with self._connect() as conn:
            cache_row = conn.execute("SELECT COUNT(*) AS cnt FROM nvd_cache").fetchone()
            audit_row = conn.execute("SELECT COUNT(*) AS cnt FROM audits").fetchone()
        return {
            "cached_queries": int(cache_row["cnt"]) if cache_row else 0,
            "stored_audits": int(audit_row["cnt"]) if audit_row else 0,
            "db_path": str(self.db_path),
        }
