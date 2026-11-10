"""Integration tests for FastAPI endpoints, scope guardrails, mitigation simulator, and exports."""

from fastapi.testclient import TestClient

from src.server import create_app


def _make_client(tmp_path):
    app = create_app(db_path=tmp_path / "api_test.db")
    return TestClient(app)


def test_health_profiles_and_scope_validation(tmp_path):
    client = _make_client(tmp_path)

    r_health = client.get("/api/health")
    assert r_health.status_code == 200
    assert r_health.json()["status"] == "ok"

    r_prof = client.get("/api/profiles")
    assert r_prof.status_code == 200
    assert len(r_prof.json()["profiles"]) >= 4
    assert len(r_prof.json()["scenarios"]) >= 3

    r_ok = client.post("/api/validate-scope", json={"target": "192.168.10.0/24"})
    assert r_ok.status_code == 200
    assert r_ok.json()["valid"] is True

    r_bad = client.post("/api/validate-scope", json={"target": "8.8.8.8"})
    assert r_bad.status_code == 200
    assert r_bad.json()["valid"] is False

    # Direct scan attempt on public IP must return HTTP 403
    r_blocked = client.post(
        "/api/audits/run",
        json={"target": "8.8.8.8", "ports": "80", "mode": "live"},
    )
    assert r_blocked.status_code == 403


def test_audit_lifecycle_mitigation_compare_ask_and_exports(tmp_path):
    client = _make_client(tmp_path)

    run1 = client.post(
        "/api/audits/run",
        json={"mode": "simulation", "scenario_id": "mittelstand_office", "sync": True},
    )
    assert run1.status_code == 200
    report1 = run1.json()["report"]
    id1 = report1["id"]

    run2 = client.post(
        "/api/audits/run",
        json={"mode": "simulation", "scenario_id": "hardened_dmz", "sync": True},
    )
    assert run2.status_code == 200
    id2 = run2.json()["report"]["id"]

    # History list
    hist = client.get("/api/audits").json()["audits"]
    assert len(hist) == 2

    # Mitigation toggle raises score and persists on subsequent GET
    action_id = report1["compliance"]["remediations"][0]["id"]
    toggled = client.post(
        f"/api/audits/{id1}/mitigations",
        json={"action_id": action_id, "mitigated": True},
    )
    assert toggled.status_code == 200
    assert toggled.json()["compliance"]["score"] > report1["compliance"]["score"]

    fetched = client.get(f"/api/audits/{id1}").json()
    assert action_id in fetched["mitigated_ids"]

    # Compare audits
    cmp_res = client.get(f"/api/audits/{id1}/compare/{id2}")
    assert cmp_res.status_code == 200
    assert cmp_res.json()["score_delta"] > 0

    # Ask compliance assistant
    ask_res = client.post(
        f"/api/audits/{id1}/ask",
        json={"question": "What should I patch first?"},
    )
    assert ask_res.status_code == 200
    assert "NIS2" in ask_res.json()["answer"] or "score" in ask_res.json()["answer"]

    # Export formats
    for fmt in ("md", "json", "csv", "html"):
        exp = client.get(f"/api/audits/{id1}/export?format={fmt}")
        assert exp.status_code == 200
        assert len(exp.text) > 50

    # Delete audit
    del_res = client.delete(f"/api/audits/{id1}")
    assert del_res.status_code == 200
    assert client.get(f"/api/audits/{id1}").status_code == 404


def test_built_frontend_spa_is_served(tmp_path):
    client = _make_client(tmp_path)
    root_res = client.get("/")
    assert root_res.status_code == 200
    assert "NIS2 Asset Auditor" in root_res.text
    assert "/assets/" in root_res.text


def test_async_job_and_sse_stream(tmp_path):
    client = _make_client(tmp_path)
    start_res = client.post(
        "/api/audits/run",
        json={"mode": "simulation", "scenario_id": "dev_workstation", "sync": False},
    )
    assert start_res.status_code == 200
    job_id = start_res.json()["job_id"]

    with client.stream("GET", f"/api/audits/jobs/{job_id}/stream") as stream:
        assert stream.status_code == 200
        body = "".join(stream.iter_text())
    assert '"done": true' in body

    job_res = client.get(f"/api/audits/jobs/{job_id}")
    assert job_res.status_code == 200
    assert job_res.json()["status"] == "completed"
    assert job_res.json()["audit_id"] is not None


