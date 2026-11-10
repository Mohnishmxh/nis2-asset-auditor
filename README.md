# NIS2 Internal Asset & CVE Compliance Auditor

An automated, containerized vulnerability lifecycle platform written in Python & React. This tool combines guarded internal network discovery with **NIST National Vulnerability Database (NVD) API v2.0** enrichment, an **EU NIS2 Article 21(2) Compliance Engine**, multi-format reporting, and a smart web console acting as the face of the project.

---

## 🌍 Problem Statement & Real-World Impact

Under **Article 21(2) of the EU NIS2 Directive (Directive (EU) 2022/2555)**, essential and important entities must maintain continuous security across network and information systems—covering vulnerability handling (`21(2)(e)`), risk analysis (`21(2)(a)`), cryptography in transit (`21(2)(h)`), supply chain hygiene (`21(2)(d)`), and access segmentation (`21(2)(i)`).

While large enterprises rely on costly proprietary scanners, Small and Medium-sized Enterprises (*Mittelstand*) often lack automated visibility into their internal attack surface. This platform delivers an auditable, zero-cost pipeline:

1. **Guarded Internal Discovery:** Discovers active services and version banners via Nmap `-sV` (with a pure-Python socket banner fallback), enforcing strict **RFC 1918 / Loopback / ULA** scope guardrails (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `::1`, `fc00::/7`) and safe host-count limits.
2. **Smart NIST NVD v2.0 Enrichment:** Queries CPE 2.3 identifiers first with normalized keyword fallback, handles CVSS v3.1 / v3.0 / v2.0 safely, respects NVD rate limits (and `NVD_API_KEY`), and caches results locally in SQLite.
3. **EU NIS2 Article 21(2) Scoring & "What-If" Simulator:** Calculates a transparent `0–100` posture score (`Grade A–F`), flags cleartext/high-risk ports, computes Article 23 escalation readiness, and lets engineers simulate remediations interactively.
4. **Multi-Format Audit Evidence:** Exports reports in **Markdown (`.md`)**, **HTML (`.html`)**, **JSON (`.json`)**, and **CSV (`.csv`)**.
5. **Smart Web Console (`frontend/` + FastAPI):** Provides real-time SSE scan streaming, live RFC 1918 guardrail feedback, asset/CVE inspection drawers, drift comparison across stored audits, copy-pasteable hardening snippets, and a deterministic Compliance Q&A Analyst.

---

## 🏗️ Architecture

```text
nis2-asset-auditor/
├── src/
│   ├── models.py        # Canonical typed audit, asset, CVE & scope models
│   ├── scanner.py       # RFC 1918 guardrails, Nmap discovery & socket fallback
│   ├── nvd_client.py    # Rate-limited, CPE-aware NIST NVD v2.0 client
│   ├── compliance.py    # EU NIS2 Art. 21(2) scoring & what-if simulator
│   ├── scenarios.py     # Offline benchmark & demo scenarios
│   ├── storage.py       # SQLite persistence (audits, NVD cache, mitigations)
│   ├── reporter.py      # Markdown, JSON, CSV & HTML report exporters
│   ├── assistant.py     # Deterministic compliance Q&A analyst
│   ├── auditor.py       # Shared audit orchestration pipeline
│   └── server.py        # FastAPI REST + SSE API & SPA static server
├── frontend/            # React + TypeScript + Tailwind CSS Smart Console
├── tests/               # Pytest unit & FastAPI integration test suite
├── reports/
├── main.py              # CLI & server entrypoint
├── Dockerfile           # Multi-stage Node + Python/Nmap container build
├── requirements.txt
└── requirements-dev.txt
```

---

## 🚀 Quick Start

### 1. Local Setup (Python + Built Web UI)
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1   # Linux/macOS: source venv/bin/activate
python -m pip install -r requirements.txt
```

*(Optional if developing the frontend)*:
```bash
npm --prefix frontend install
npm --prefix frontend run build
```

### 2. Launch the Smart Frontend Web Console
```bash
python main.py serve --host 127.0.0.1 --port 8000
```
Open **http://127.0.0.1:8000** in your browser.
- Interactive Swagger API docs are also available at **http://127.0.0.1:8000/docs**.
- For frontend hot-reload during UI development, run `npm --prefix frontend run dev` alongside the backend.

### 3. CLI Execution (Backwards-Compatible + New Flags)
```bash
# Live internal audit (Markdown)
python main.py -t 127.0.0.1 -p 22,80,443,8000 -o reports/sample_audit_report.md

# Named profile + export all formats (md, json, csv, html)
python main.py -t 127.0.0.1 --profile web --format all -o reports/web_audit

# Instant offline NIS2 benchmark demo
python main.py --demo mittelstand_office --format md -o reports/demo_audit.md
```

*(Optional)* Set `NVD_API_KEY` in your environment for faster NVD rate limits (50 req / 30s instead of 5 req / 30s).

### 4. Docker Execution
```bash
docker build -t nis2-auditor:2.0 .
# Run the Smart Web Console:
docker run --rm -p 8000:8000 --network host nis2-auditor:2.0
# Or run a one-shot CLI audit:
docker run --rm --network host nis2-auditor:2.0 -t 127.0.0.1 -p 8000
```

---

## 🧪 Running Tests
```bash
python -m pip install -r requirements-dev.txt
python -m pytest -v
```
