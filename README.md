# NIS2 Internal Asset & CVE Compliance Auditor

An automated, containerized vulnerability lifecycle utility written in Python. This tool combines local network service discovery with real-time **NIST National Vulnerability Database (NVD) API v2.0** enrichment to generate Markdown compliance reports mapped to the **EU NIS2 Directive**.

---

## 🌍 Problem Statement & Real-World Impact

Under **Article 21(2)(e) of the EU NIS2 Directive (Directive (EU) 2022/2555)**, essential and important entities are legally required to maintain continuous security in network and information systems, including proactive vulnerability handling and disclosure. 

While large enterprises rely on costly proprietary scanners, Small and Medium-sized Enterprises (the *Mittelstand*) often lack automated visibility into their internal attack surface. This project bridges that gap by providing a zero-cost, lightweight, and auditable pipeline that:
1. **Automates Asset Inventory:** Identifies active services and version banners across local subnets.
2. **Enforces Scope Safety:** Implements strict RFC 1918 private-network and loopback validation in code (`ipaddress`), preventing accidental scanning of unauthorized external IP ranges.
3. **Quantifies Risk:** Queries the NIST NVD REST API v2.0 to map discovered service versions against known CVEs and **CVSS v3.1** severity scores.
4. **Generates Audit Evidence:** Outputs timestamped Markdown reports ready for engineering remediation and regulatory review.

---

## 🏗️ Architecture

nis2-asset-auditor/
├── src/
│   ├── scanner.py       # RFC 1918 scope guardrail & Nmap service discovery
│   ├── nvd_client.py    # Rate-limited NIST NVD API v2.0 REST client
│   └── reporter.py      # NIS2-mapped Markdown compliance generator
├── reports/
│   └── sample_audit_report.md
├── main.py              # CLI Entrypoint (argparse)
├── Dockerfile           # Slim Debian/Python container definition
└── requirements.txt

---

## 🚀 Quick Start

### Local Execution
1. Clone the repository and create a virtual environment:
python -m venv venv
source venv/bin/activate  # Windows PowerShell: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt

2. Run an internal compliance audit:
python main.py -t 127.0.0.1 -p 22,80,443,8000 -o reports/sample_audit_report.md

### Docker Execution
docker build -t nis2-auditor:1.0 .
docker run --rm --network host nis2-auditor:1.0 -t 127.0.0.1 -p 8000

---

## 📄 Sample Output
See [`reports/sample_audit_report.md`](reports/sample_audit_report.md) for an example of a generated compliance matrix.

