"""EU NIS2 Directive (2022/2555) Article 21(2) compliance evaluation and scoring engine."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

CLEARTEXT_PORTS = {21, 23, 80, 110, 143, 3000, 5000, 8000, 8080, 8888, 9000}
CLEARTEXT_SERVICES = {"http", "ftp", "telnet", "pop3", "imap", "http-proxy"}
HIGH_RISK_EXPOSED_PORTS = {
    23: ("Telnet", "Cleartext remote administration protocol transmits credentials in plain text."),
    21: ("FTP", "Unencrypted file transfer service exposes credentials and payload traffic."),
    2375: ("Unencrypted Docker Daemon", "Exposing Docker API on TCP 2375 grants unauthenticated root-equivalent host control."),
    6379: ("Redis", "In-memory cache commonly deployed without authentication or TLS."),
    27017: ("MongoDB", "Document database exposed on network interface; risk of unauthenticated data access."),
    9200: ("Elasticsearch", "Search cluster API exposed without enforced transport security."),
    11211: ("Memcached", "Unauthenticated memory cache susceptible to data leakage and amplification."),
    445: ("SMB", "File sharing service requires strict internal segmentation and SMBv1 removal."),
    5900: ("VNC", "Remote desktop protocol often lacks strong authentication or encryption."),
}
ADMIN_PORTS = {22, 3389, 5900}
DATABASE_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017}

_LEGACY_PATTERNS = (
    ("simplehttpserver", "Development HTTP server detected; unsuitable for production NIS2 environments."),
    ("apache httpd 2.4.49", "Apache HTTP Server 2.4.49 contains critical path-traversal / RCE vulnerabilities."),
    ("vsftpd 2.3.4", "vsFTPd 2.3.4 is notoriously compromised / end-of-life."),
    ("openssh 7.", "Legacy OpenSSH 7.x series lacks modern hardening defaults and is near/past support."),
    ("php/5", "End-of-life PHP 5 runtime receives zero upstream security patches."),
    ("php/7", "End-of-life PHP 7 runtime is unsupported for security updates."),
)


def _grade_from_score(score: float) -> Tuple[str, str]:
    if score >= 90:
        return "A", "Compliant"
    if score >= 75:
        return "B", "Substantially Compliant"
    if score >= 60:
        return "C", "Needs Remediation"
    if score >= 40:
        return "D", "Non-Compliant — Action Required"
    return "F", "Critical Non-Compliance"


def _asset_label(asset: Dict[str, Any]) -> str:
    return f"{asset['host']}:{asset['port']} ({asset.get('service', 'unknown')})"


def _compute_asset_risk_score(asset: Dict[str, Any], active_cve_ids: Set[str]) -> float:
    score = 0.0
    for cve in asset.get("cves") or []:
        if cve["id"] not in active_cve_ids:
            continue
        sev = cve.get("severity", "UNKNOWN")
        if sev == "CRITICAL":
            score += 35.0
        elif sev == "HIGH":
            score += 20.0
        elif sev == "MEDIUM":
            score += 8.0
        elif sev == "LOW":
            score += 3.0

    port = int(asset.get("port", 0))
    if port in HIGH_RISK_EXPOSED_PORTS:
        score += 22.0
    if not asset.get("encrypted", False) and (
        port in CLEARTEXT_PORTS or asset.get("service") in CLEARTEXT_SERVICES
    ):
        score += 12.0
    if asset.get("exposure") != "loopback" and port in ADMIN_PORTS | DATABASE_PORTS:
        score += 10.0

    return round(min(100.0, score), 1)


def _build_cve_remediation(cve: Dict[str, Any], affected: List[str]) -> Dict[str, Any]:
    sev = cve.get("severity", "UNKNOWN")
    score_val = cve.get("score", "N/A")
    cve_id = cve["id"]
    sla = "24h Emergency Patch" if sev == "CRITICAL" else "72h Priority Patch" if sev == "HIGH" else "30d Maintenance Window"
    return {
        "id": f"rem-cve-{cve_id.lower()}",
        "title": f"Remediate {cve_id} ({sev}, CVSS {score_val}) — {sla}",
        "priority": sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM",
        "nis2_article": "Art. 21(2)(e)",
        "pillar_id": "ART21_2E",
        "effort": "MEDIUM",
        "affected_assets": affected,
        "rationale": cve.get("summary") or "Known vulnerability mapped via NIST NVD v2.0.",
        "commands": (
            f"# Verify package version and apply vendor security update for {cve_id}\n"
            "sudo apt-get update && sudo apt-get upgrade -y\n"
            "# If patch is temporarily unavailable, restrict network access:\n"
            "# sudo ufw deny from any to any port <SERVICE_PORT> proto tcp"
        ),
        "cve_id": cve_id,
    }


def _collect_findings_and_actions(
    assets: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, float]]:
    """Build deterministic compliance deductions and remediation actions from discovered assets."""
    actions_by_id: Dict[str, Dict[str, Any]] = {}
    penalties: List[Tuple[str, str, float, str]] = []
    # Tuple: (action_id, pillar_id, raw_points, evidence_line)

    # 1. CVE findings (Art. 21(2)(e))
    cve_assets: Dict[str, Tuple[Dict[str, Any], List[str]]] = {}
    for asset in assets:
        label = _asset_label(asset)
        for cve in asset.get("cves") or []:
            cid = cve["id"]
            if cid not in cve_assets:
                cve_assets[cid] = (cve, [label])
            elif label not in cve_assets[cid][1]:
                cve_assets[cid][1].append(label)

    for cid, (cve, affected) in cve_assets.items():
        sev = cve.get("severity", "UNKNOWN")
        pts = 12.0 if sev == "CRITICAL" else 6.0 if sev == "HIGH" else 2.5 if sev == "MEDIUM" else 1.0
        action = _build_cve_remediation(cve, affected)
        actions_by_id[action["id"]] = action
        penalties.append((
            action["id"],
            "ART21_2E",
            pts,
            f"{cid} ({sev}, CVSS {cve.get('score', 'N/A')}) on {', '.join(affected)}",
        ))

    # 2. High-risk exposed services (Art. 21(2)(a))
    for asset in assets:
        port = int(asset.get("port", 0))
        label = _asset_label(asset)
        if port in HIGH_RISK_EXPOSED_PORTS:
            svc_label, reason = HIGH_RISK_EXPOSED_PORTS[port]
            aid = f"rem-highrisk-{port}"
            if aid not in actions_by_id:
                cmd = (
                    "sudo systemctl disable --now telnet.socket"
                    if port == 23
                    else f"sudo ufw delete allow {port}/tcp && sudo ufw deny {port}/tcp"
                )
                if port == 2375:
                    cmd = "# Disable unencrypted Docker TCP socket and enforce TLS (2376) or Unix socket only\nsudo systemctl edit docker.service"
                elif port == 6379:
                    cmd = "# Bind Redis to localhost and enforce ACL password in /etc/redis/redis.conf\nbind 127.0.0.1 ::1\nrequirepass <STRONG_RANDOM_SECRET>"
                actions_by_id[aid] = {
                    "id": aid,
                    "title": f"Isolate or Disable High-Risk {svc_label} Service (Port {port})",
                    "priority": "CRITICAL" if port in (23, 2375) else "HIGH",
                    "nis2_article": "Art. 21(2)(a)",
                    "pillar_id": "ART21_2A",
                    "effort": "LOW",
                    "affected_assets": [label],
                    "rationale": reason,
                    "commands": cmd,
                }
            elif label not in actions_by_id[aid]["affected_assets"]:
                actions_by_id[aid]["affected_assets"].append(label)

            pts = 10.0 if port in (23, 2375) else 6.0
            penalties.append((aid, "ART21_2A", pts, f"{label}: {reason}"))

    # 3. Cleartext transport protocols (Art. 21(2)(h))
    cleartext_assets = [
        a for a in assets
        if not a.get("encrypted", False)
        and (int(a.get("port", 0)) in CLEARTEXT_PORTS or a.get("service") in CLEARTEXT_SERVICES)
    ]
    if cleartext_assets:
        affected_clear = [_asset_label(a) for a in cleartext_assets]
        aid = "rem-enforce-tls-transport"
        actions_by_id[aid] = {
            "id": aid,
            "title": "Enforce TLS 1.3 Encryption in Transit Across Cleartext Endpoints",
            "priority": "HIGH",
            "nis2_article": "Art. 21(2)(h)",
            "pillar_id": "ART21_2H",
            "effort": "MEDIUM",
            "affected_assets": affected_clear,
            "rationale": "Cleartext protocols expose credentials, tokens, and operational telemetry to internal sniffing or MITM.",
            "commands": (
                "# Nginx HTTPS redirect & TLS 1.3 enforcement\n"
                "server {\n"
                "    listen 80;\n"
                "    return 301 https://$host$request_uri;\n"
                "}\n"
                "ssl_protocols TLSv1.2 TLSv1.3;"
            ),
        }
        for asset in cleartext_assets:
            penalties.append((
                aid,
                "ART21_2H",
                5.0,
                f"{_asset_label(asset)} transmits traffic without TLS encryption",
            ))

    # 4. Non-loopback database / cache exposure (Art. 21(2)(h) + Art. 21(2)(i))
    exposed_dbs = [
        a for a in assets
        if int(a.get("port", 0)) in DATABASE_PORTS and a.get("exposure") != "loopback"
    ]
    if exposed_dbs:
        aid = "rem-segment-databases"
        actions_by_id[aid] = {
            "id": aid,
            "title": "Restrict Database & Cache Interfaces to Loopback or Isolated VLAN",
            "priority": "HIGH",
            "nis2_article": "Art. 21(2)(i)",
            "pillar_id": "ART21_2I",
            "effort": "LOW",
            "affected_assets": [_asset_label(a) for a in exposed_dbs],
            "rationale": "Database ports bound to non-loopback internal LAN interfaces increase lateral movement risk.",
            "commands": (
                "# Allow database access strictly from trusted app subnet\n"
                "sudo ufw allow from 10.0.10.0/24 to any port 5432 proto tcp\n"
                "sudo ufw deny 5432/tcp"
            ),
        }
        for asset in exposed_dbs:
            penalties.append((
                aid,
                "ART21_2I",
                4.0,
                f"{_asset_label(asset)} reachable on non-loopback interface",
            ))

    # 5. Software lifecycle & banner hygiene (Art. 21(2)(d))
    verbose_assets = [
        a for a in assets if (a.get("product") and a.get("version"))
    ]
    for asset in assets:
        ver_str = f"{asset.get('product', '')} {asset.get('version', '')}".strip().lower()
        for pat, msg in _LEGACY_PATTERNS:
            if pat in ver_str:
                aid = f"rem-upgrade-{pat.replace(' ', '-').replace('/', '-')}"
                label = _asset_label(asset)
                if aid not in actions_by_id:
                    actions_by_id[aid] = {
                        "id": aid,
                        "title": f"Replace / Upgrade Legacy Software ({asset.get('product')} {asset.get('version')})",
                        "priority": "HIGH",
                        "nis2_article": "Art. 21(2)(d)",
                        "pillar_id": "ART21_2D",
                        "effort": "MEDIUM",
                        "affected_assets": [label],
                        "rationale": msg,
                        "commands": "# Pin maintained LTS container/package release and remove development servers from internal LAN",
                    }
                elif label not in actions_by_id[aid]["affected_assets"]:
                    actions_by_id[aid]["affected_assets"].append(label)
                penalties.append((aid, "ART21_2D", 6.0, f"{label}: {msg}"))

    if verbose_assets:
        aid = "rem-harden-banners"
        actions_by_id[aid] = {
            "id": aid,
            "title": "Suppress Verbose Service Version Banners",
            "priority": "LOW",
            "nis2_article": "Art. 21(2)(d)",
            "pillar_id": "ART21_2D",
            "effort": "LOW",
            "affected_assets": [_asset_label(a) for a in verbose_assets],
            "rationale": "Explicit product and version strings accelerate automated reconnaissance for known exploits.",
            "commands": (
                "# Apache: ServerTokens Prod & ServerSignature Off\n"
                "# Nginx:  server_tokens off;\n"
                "# OpenSSH (/etc/ssh/sshd_config): DebianBanner no"
            ),
        }
        penalties.append((
            aid,
            "ART21_2D",
            min(4.0, 1.0 * len(verbose_assets)),
            f"{len(verbose_assets)} service(s) disclose detailed product/version banners",
        ))

    # 6. Broad admin port exposure on LAN (Art. 21(2)(i))
    lan_admin = [
        a for a in assets
        if int(a.get("port", 0)) in ADMIN_PORTS and a.get("exposure") != "loopback"
    ]
    if lan_admin:
        aid = "rem-restrict-admin-access"
        actions_by_id[aid] = {
            "id": aid,
            "title": "Enforce Bastion / MFA Segmentation on Remote Admin Ports",
            "priority": "MEDIUM",
            "nis2_article": "Art. 21(2)(i)",
            "pillar_id": "ART21_2I",
            "effort": "MEDIUM",
            "affected_assets": [_asset_label(a) for a in lan_admin],
            "rationale": "Administrative interfaces (SSH/RDP/VNC) exposed across internal subnets require jump-host/MFA controls under NIS2 Art. 21(2)(i)-(j).",
            "commands": (
                "# Restrict SSH to management jump host & disable password login\n"
                "PasswordAuthentication no\n"
                "AllowUsers ops-admin@10.0.0.0/24"
            ),
        }
        penalties.append((
            aid,
            "ART21_2I",
            min(5.0, 2.5 * len(lan_admin)),
            f"{len(lan_admin)} remote admin interface(s) exposed on non-loopback subnet",
        ))

    return list(actions_by_id.values()), {
        "_penalties": penalties,  # type: ignore[dict-item]
    }


def _score_pillars(
    penalties: List[Tuple[str, str, float, str]],
    mitigated_ids: Set[str],
) -> Tuple[List[Dict[str, Any]], float]:
    pillar_defs = [
        ("ART21_2E", "Art. 21(2)(e)", "Vulnerability Handling & Disclosure", 35.0,
         "Continuous vulnerability identification, CVSS risk triage, and timely patch remediation."),
        ("ART21_2A", "Art. 21(2)(a)", "Risk Analysis & System Security Policies", 20.0,
         "Elimination of unauthenticated, legacy, or high-risk administrative exposure."),
        ("ART21_2H", "Art. 21(2)(h)", "Cryptography & Encryption in Transit", 20.0,
         "Mandatory encryption protocols protecting internal network traffic and credentials."),
        ("ART21_2D", "Art. 21(2)(d)", "Supply Chain & Software Lifecycle", 15.0,
         "Active software lifecycle governance, patching unsupported runtimes, and banner minimization."),
        ("ART21_2I", "Art. 21(2)(i)/(j)", "Access Control & Segmentation", 10.0,
         "Least-privilege network segmentation for databases and administrative endpoints."),
    ]

    controls: List[Dict[str, Any]] = []
    total_score = 0.0

    for pid, article, title, max_pts, desc in pillar_defs:
        active_p = [p for p in penalties if p[1] == pid and p[0] not in mitigated_ids]
        deduction = min(max_pts, sum(p[2] for p in active_p))
        earned = round(max(0.0, max_pts - deduction), 1)
        total_score += earned
        ratio = earned / max_pts if max_pts else 1.0
        status = "PASS" if ratio >= 0.85 else "WARN" if ratio >= 0.55 else "FAIL"
        controls.append({
            "id": pid,
            "article": article,
            "title": title,
            "description": desc,
            "status": status,
            "score": earned,
            "max_score": max_pts,
            "evidence": [p[3] for p in active_p] or ["No active violations detected under this control."],
        })

    return controls, round(total_score, 1)


def evaluate_nis2_compliance(
    assets: List[Dict[str, Any]],
    mitigated_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Evaluate discovered assets and CVE findings against EU NIS2 Directive Article 21(2).
    Supports interactive 'what-if' scoring when `mitigated_ids` are supplied.
    """
    mitigated_set = set(mitigated_ids or [])
    actions, meta = _collect_findings_and_actions(assets)
    penalties: List[Tuple[str, str, float, str]] = meta["_penalties"]  # type: ignore[assignment]

    controls, current_score = _score_pillars(penalties, mitigated_set)
    _, baseline_score = _score_pillars(penalties, set())
    grade, posture = _grade_from_score(current_score)

    # Calculate per-action impact score precisely via counterfactual simulation
    for action in actions:
        aid = action["id"]
        is_mitigated = aid in mitigated_set
        action["mitigated"] = is_mitigated
        if is_mitigated:
            _, score_without = _score_pillars(penalties, mitigated_set - {aid})
            action["impact_points"] = round(max(0.0, current_score - score_without), 1)
        else:
            _, score_with = _score_pillars(penalties, mitigated_set | {aid})
            action["impact_points"] = round(max(0.0, score_with - current_score), 1)

    prio_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    actions.sort(
        key=lambda a: (
            not a["mitigated"],
            prio_rank.get(a["priority"], 0),
            a["impact_points"],
        ),
        reverse=True,
    )

    # Active CVEs (filtering out mitigated CVE actions)
    active_cve_ids: Set[str] = set()
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    seen_cves: Set[str] = set()

    for asset in assets:
        for cve in asset.get("cves") or []:
            cid = cve["id"]
            if f"rem-cve-{cid.lower()}" in mitigated_set:
                continue
            active_cve_ids.add(cid)
            if cid not in seen_cves:
                seen_cves.add(cid)
                sev = cve.get("severity", "UNKNOWN")
                if sev not in severity_counts:
                    sev = "UNKNOWN"
                severity_counts[sev] += 1

    for asset in assets:
        asset["risk_score"] = _compute_asset_risk_score(asset, active_cve_ids)

    encrypted_count = sum(1 for a in assets if a.get("encrypted"))
    cleartext_count = len(assets) - encrypted_count
    critical_high = severity_counts["CRITICAL"] + severity_counts["HIGH"]

    if severity_counts["CRITICAL"] > 0:
        reporting_alert = (
            "NIS2 Art. 23 Readiness Alert: CRITICAL vulnerabilities detected. "
            "If actively exploited on essential infrastructure, early warning to CSIRT/competent authority is required within 24 hours."
        )
    elif severity_counts["HIGH"] > 0:
        reporting_alert = (
            "Elevated Exposure: HIGH severity CVEs require prioritized patching within 72 hours under Art. 21(2)(e)."
        )
    else:
        reporting_alert = (
            "No Critical/High CVEs currently active. Maintain routine monitoring and documented patch cadence."
        )

    return {
        "score": current_score,
        "baseline_score": baseline_score,
        "grade": grade,
        "posture": posture,
        "controls": controls,
        "remediations": actions,
        "severity_counts": severity_counts,
        "encrypted_count": encrypted_count,
        "cleartext_count": cleartext_count,
        "total_cves": len(seen_cves),
        "critical_high_cves": critical_high,
        "nis2_reporting_alert": reporting_alert,
    }
