"""FastAPI web server & REST/SSE API for the NIS2 Smart Compliance Console."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import shutil
import threading
import time
from typing import Any, Dict, List, Optional
import uuid

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src.assistant import answer_compliance_question
from src.auditor import run_audit_pipeline
from src.compliance import evaluate_nis2_compliance
from src.reporter import (
    render_csv_report,
    render_html_report,
    render_json_report,
    render_markdown_report,
)
from src.scanner import SCAN_PROFILES, validate_ports_spec, validate_scope_details
from src.scenarios import list_scenarios
from src.storage import AuditStorage


class ScopeCheckRequest(BaseModel):
    target: str = Field(..., description="Target private IP, CIDR subnet, or 'localhost'")


class RunAuditRequest(BaseModel):
    target: str = Field(default="127.0.0.1")
    ports: str = Field(default="22,80,443,8000,8080")
    profile: str = Field(default="custom")
    mode: str = Field(default="live", description="'live' or 'simulation'")
    scenario_id: Optional[str] = Field(default=None)
    max_cves: int = Field(default=5, ge=1, le=20)
    use_cache: bool = Field(default=True)
    api_key: Optional[str] = Field(default=None)
    sync: bool = Field(default=False)


class MitigationUpdateRequest(BaseModel):
    action_id: str
    mitigated: bool


class AskAssistantRequest(BaseModel):
    question: str


class JobManager:
    """Thread-safe tracker for asynchronous scan jobs and progress events."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: Dict[str, Dict[str, Any]] = {}

    def create(self) -> str:
        job_id = f"job-{uuid.uuid4().hex[:10]}"
        with self._lock:
            self._jobs[job_id] = {
                "job_id": job_id,
                "status": "queued",
                "stage": "init",
                "message": "Initializing NIS2 audit pipeline...",
                "progress": 5,
                "events": [
                    {
                        "stage": "init",
                        "message": "Initializing NIS2 audit pipeline...",
                        "progress": 5,
                        "ts": time.time(),
                    }
                ],
                "audit_id": None,
                "report": None,
                "error": None,
            }
        return job_id

    def push_event(self, job_id: str, stage: str, message: str, progress: int) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["status"] = "running"
            job["stage"] = stage
            job["message"] = message
            job["progress"] = progress
            job["events"].append({
                "stage": stage,
                "message": message,
                "progress": progress,
                "ts": time.time(),
            })

    def complete(self, job_id: str, report: Dict[str, Any]) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["status"] = "completed"
            job["stage"] = "complete"
            job["progress"] = 100
            job["message"] = "Audit complete."
            job["audit_id"] = report["id"]
            job["report"] = report

    def fail(self, job_id: str, error_msg: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["status"] = "failed"
            job["stage"] = "error"
            job["message"] = error_msg
            job["error"] = error_msg
            job["events"].append({
                "stage": "error",
                "message": error_msg,
                "progress": job["progress"],
                "ts": time.time(),
            })

    def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            copy_job = dict(job)
            copy_job["events"] = list(job["events"])
            return copy_job


def _detect_nmap() -> bool:
    if shutil.which("nmap"):
        return True
    win_candidates = (
        Path("C:/Program Files (x86)/Nmap/nmap.exe"),
        Path("C:/Program Files/Nmap/nmap.exe"),
    )
    return any(p.exists() for p in win_candidates)


def _apply_mitigations_to_report(
    report: Dict[str, Any], mitigated_ids: List[str]
) -> Dict[str, Any]:
    updated = dict(report)
    updated["mitigated_ids"] = mitigated_ids
    updated["compliance"] = evaluate_nis2_compliance(
        updated.get("assets", []), mitigated_ids=mitigated_ids
    )
    return updated


def create_app(db_path: Optional[str | Path] = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="NIS2 Asset Auditor API",
        description="EU NIS2 Article 21(2) Internal Network Asset & CVE Compliance Platform",
        version="2.0.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    storage = AuditStorage(db_path=db_path)
    jobs = JobManager()
    frontend_dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"

    @app.get("/api/health")
    def health() -> Dict[str, Any]:
        stats = storage.get_cache_stats()
        return {
            "status": "ok",
            "version": "2.0.0",
            "nmap_available": _detect_nmap(),
            "nvd_api_key_configured": bool(os.getenv("NVD_API_KEY")),
            "frontend_built": frontend_dist.exists(),
            "storage": stats,
        }

    @app.get("/api/profiles")
    def get_profiles() -> Dict[str, Any]:
        return {
            "profiles": list(SCAN_PROFILES.values()),
            "scenarios": list_scenarios(),
        }

    @app.post("/api/validate-scope")
    def validate_scope(req: ScopeCheckRequest) -> Dict[str, Any]:
        return validate_scope_details(req.target).to_dict()

    @app.post("/api/audits/run")
    def start_audit(req: RunAuditRequest) -> Dict[str, Any]:
        if req.mode != "simulation" and not req.scenario_id:
            scope = validate_scope_details(req.target)
            if not scope.valid:
                raise HTTPException(status_code=403, detail=scope.reason)
            if req.profile not in SCAN_PROFILES or req.ports != "22,80,443,8000,8080":
                try:
                    validate_ports_spec(req.ports)
                except ValueError as exc:
                    raise HTTPException(status_code=400, detail=str(exc)) from exc

        job_id = jobs.create()

        def _worker() -> None:
            try:
                report = run_audit_pipeline(
                    target=req.target,
                    ports=req.ports,
                    profile=req.profile,
                    mode=req.mode,
                    scenario_id=req.scenario_id,
                    max_cves=req.max_cves,
                    api_key=req.api_key or None,
                    use_cache=req.use_cache,
                    storage=storage,
                    save_history=True,
                    on_progress=lambda stage, msg, pct: jobs.push_event(job_id, stage, msg, pct),
                )
                jobs.complete(job_id, report)
            except PermissionError as exc:
                jobs.fail(job_id, str(exc))
            except Exception as exc:
                jobs.fail(job_id, f"Audit execution failed: {exc}")

        if req.sync:
            _worker()
            job = jobs.get(job_id)
            if job and job["status"] == "failed":
                raise HTTPException(status_code=400, detail=job["error"])
            return job or {"job_id": job_id, "status": "completed"}

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()
        return {"job_id": job_id, "status": "running"}

    @app.get("/api/audits/jobs/{job_id}")
    def get_job_status(job_id: str) -> Dict[str, Any]:
        job = jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Audit job not found.")
        return job

    @app.get("/api/audits/jobs/{job_id}/stream")
    async def stream_job_progress(job_id: str) -> StreamingResponse:
        if not jobs.get(job_id):
            raise HTTPException(status_code=404, detail="Audit job not found.")

        async def event_generator():
            last_idx = 0
            while True:
                job = jobs.get(job_id)
                if not job:
                    break
                events = job.get("events", [])
                while last_idx < len(events):
                    yield f"data: {json.dumps(events[last_idx])}\n\n"
                    last_idx += 1
                if job["status"] in ("completed", "failed"):
                    final_payload = {
                        "stage": job["status"],
                        "progress": job["progress"],
                        "message": job["message"],
                        "audit_id": job.get("audit_id"),
                        "error": job.get("error"),
                        "done": True,
                    }
                    yield f"data: {json.dumps(final_payload)}\n\n"
                    break
                await asyncio.sleep(0.2)

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    @app.get("/api/audits")
    def list_audits(limit: int = Query(default=50, ge=1, le=200)) -> Dict[str, Any]:
        return {"audits": storage.list_audits(limit=limit)}

    @app.get("/api/audits/{audit_id}")
    def get_audit(audit_id: str) -> Dict[str, Any]:
        report = storage.get_audit(audit_id)
        if not report:
            raise HTTPException(status_code=404, detail="Audit report not found.")
        mitigated_ids = storage.get_mitigations(audit_id)
        return _apply_mitigations_to_report(report, mitigated_ids)

    @app.delete("/api/audits/{audit_id}")
    def delete_audit(audit_id: str) -> Dict[str, Any]:
        deleted = storage.delete_audit(audit_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Audit report not found.")
        return {"deleted": True, "id": audit_id}

    @app.post("/api/audits/{audit_id}/mitigations")
    def toggle_mitigation(audit_id: str, req: MitigationUpdateRequest) -> Dict[str, Any]:
        report = storage.get_audit(audit_id)
        if not report:
            raise HTTPException(status_code=404, detail="Audit report not found.")
        mitigated_ids = storage.set_mitigation(audit_id, req.action_id, req.mitigated)
        return _apply_mitigations_to_report(report, mitigated_ids)

    @app.get("/api/audits/{audit_id}/compare/{other_id}")
    def compare_audits(audit_id: str, other_id: str) -> Dict[str, Any]:
        base = storage.get_audit(audit_id)
        other = storage.get_audit(other_id)
        if not base or not other:
            raise HTTPException(status_code=404, detail="One or both audit IDs were not found.")

        base_rep = _apply_mitigations_to_report(base, storage.get_mitigations(audit_id))
        other_rep = _apply_mitigations_to_report(other, storage.get_mitigations(other_id))

        base_ports = {f"{a['host']}:{a['port']}" for a in base_rep.get("assets", [])}
        other_ports = {f"{a['host']}:{a['port']}" for a in other_rep.get("assets", [])}

        base_cves = {
            c["id"] for a in base_rep.get("assets", []) for c in (a.get("cves") or [])
        }
        other_cves = {
            c["id"] for a in other_rep.get("assets", []) for c in (a.get("cves") or [])
        }

        return {
            "baseline_id": audit_id,
            "comparison_id": other_id,
            "baseline_score": base_rep["compliance"]["score"],
            "comparison_score": other_rep["compliance"]["score"],
            "score_delta": round(
                other_rep["compliance"]["score"] - base_rep["compliance"]["score"], 1
            ),
            "new_services": sorted(other_ports - base_ports),
            "removed_services": sorted(base_ports - other_ports),
            "new_cves": sorted(other_cves - base_cves),
            "resolved_cves": sorted(base_cves - other_cves),
        }

    @app.post("/api/audits/{audit_id}/ask")
    def ask_assistant(audit_id: str, req: AskAssistantRequest) -> Dict[str, Any]:
        report = storage.get_audit(audit_id)
        if not report:
            raise HTTPException(status_code=404, detail="Audit report not found.")
        hydrated = _apply_mitigations_to_report(report, storage.get_mitigations(audit_id))
        return answer_compliance_question(hydrated, req.question)

    @app.get("/api/audits/{audit_id}/export")
    def export_audit(
        audit_id: str,
        format: str = Query(default="md", pattern="^(md|markdown|json|csv|html)$"),
    ) -> Response:
        report = storage.get_audit(audit_id)
        if not report:
            raise HTTPException(status_code=404, detail="Audit report not found.")
        hydrated = _apply_mitigations_to_report(report, storage.get_mitigations(audit_id))

        fmt = format.lower()
        if fmt in ("md", "markdown"):
            body = render_markdown_report(hydrated)
            media = "text/markdown; charset=utf-8"
            ext = "md"
        elif fmt == "json":
            body = render_json_report(hydrated)
            media = "application/json; charset=utf-8"
            ext = "json"
        elif fmt == "csv":
            body = render_csv_report(hydrated)
            media = "text/csv; charset=utf-8"
            ext = "csv"
        else:
            body = render_html_report(hydrated)
            media = "text/html; charset=utf-8"
            ext = "html"

        return Response(
            content=body,
            media_type=media,
            headers={
                "Content-Disposition": f'attachment; filename="{audit_id}.{ext}"',
            },
        )

    @app.delete("/api/cache")
    def clear_cache() -> Dict[str, Any]:
        removed = storage.clear_nvd_cache()
        return {"cleared_entries": removed}

    if (frontend_dist / "assets").exists():
        app.mount(
            "/assets",
            StaticFiles(directory=str(frontend_dist / "assets")),
            name="frontend-assets",
        )

    @app.get("/{full_path:path}")
    def serve_spa(full_path: str):
        if full_path.startswith("api/"):
            return JSONResponse(status_code=404, content={"detail": "API endpoint not found."})
        candidate = frontend_dist / full_path
        if full_path and candidate.is_file():
            return FileResponse(str(candidate))
        index_file = frontend_dist / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file))
        return JSONResponse(
            status_code=200,
            content={
                "message": "NIS2 Asset Auditor API is running. Build frontend/dist or run Vite dev server for the web UI.",
                "docs": "/docs",
            },
        )

    return app


app = create_app()
