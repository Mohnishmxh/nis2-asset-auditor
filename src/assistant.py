"""Deterministic local NIS2 compliance assistant for interactive audit Q&A."""

from __future__ import annotations

from typing import Any, Dict, List


def answer_compliance_question(report: Dict[str, Any], question: str) -> Dict[str, Any]:
    """Answer natural-language audit queries directly from the active compliance report."""
    q = (question or "").strip().lower()
    assets: List[Dict[str, Any]] = report.get("assets", [])
    compliance: Dict[str, Any] = report.get("compliance", {})
    remediations: List[Dict[str, Any]] = compliance.get("remediations", [])
    controls: List[Dict[str, Any]] = compliance.get("controls", [])

    if not q:
        return {
            "answer": "Ask a question about CVEs, encryption posture, NIS2 Article 21(2) controls, or top remediation priorities.",
            "highlights": [],
            "suggested_actions": [],
        }

    # 1. Patch / priority / Grade A questions
    if any(k in q for k in ("first", "patch", "priorit", "grade a", "improve", "score", "fix")):
        pending = [r for r in remediations if not r.get("mitigated")]
        top = pending[:3]
        if not top:
            return {
                "answer": f"Your environment currently scores {compliance.get('score')}/100 (Grade {compliance.get('grade')}) with zero open remediation items.",
                "highlights": ["All tracked controls are compliant."],
                "suggested_actions": [],
            }
        gain = round(sum(float(r.get("impact_points", 0)) for r in top), 1)
        projected = round(min(100.0, float(compliance.get("score", 0)) + gain), 1)
        lines = [
            f"Addressing the top {len(top)} open action(s) boosts your NIS2 score from {compliance.get('score')} to ~{projected}/100:"
        ]
        for idx, item in enumerate(top, start=1):
            lines.append(
                f"{idx}. [{item['priority']}] {item['title']} (+{item['impact_points']} pts, {item['nis2_article']})"
            )
        return {
            "answer": "\n".join(lines),
            "highlights": [r["title"] for r in top],
            "suggested_actions": [r["id"] for r in top],
        }

    # 2. Encryption / cleartext / TLS questions
    if any(k in q for k in ("encrypt", "tls", "ssl", "cleartext", "plain", "21(2)(h)")):
        cleartext = [a for a in assets if not a.get("encrypted")]
        if not cleartext:
            return {
                "answer": "All discovered services enforce encrypted transport (TLS/SSH), satisfying NIS2 Article 21(2)(h).",
                "highlights": [],
                "suggested_actions": [],
            }
        labels = [f"{a['host']}:{a['port']} ({a.get('service')})" for a in cleartext]
        return {
            "answer": (
                f"{len(cleartext)} service(s) communicate without transport encryption, impacting NIS2 Article 21(2)(h): "
                + ", ".join(labels)
            ),
            "highlights": labels,
            "suggested_actions": [r["id"] for r in remediations if r.get("nis2_article") == "Art. 21(2)(h)"],
        }

    # 3. Critical / high CVE questions
    if any(k in q for k in ("cve", "vuln", "critical", "high", "exploit")):
        found = []
        for a in assets:
            for c in a.get("cves") or []:
                found.append((a, c))
        if not found:
            return {
                "answer": "No known CVEs were mapped to the discovered service versions.",
                "highlights": [],
                "suggested_actions": [],
            }
        crit_high = [(a, c) for a, c in found if c.get("severity") in ("CRITICAL", "HIGH")]
        target_list = crit_high or found
        highlights = [
            f"{c['id']} ({c.get('severity')} {c.get('score')}) on {a['host']}:{a['port']} ({a.get('product')} {a.get('version')})"
            for a, c in target_list[:6]
        ]
        return {
            "answer": (
                f"Detected {len(found)} CVE mapping(s) across {len(assets)} service(s) "
                f"({len(crit_high)} Critical/High). Under NIS2 Art. 21(2)(e) and Art. 23, Critical flaws require immediate 24h triage."
            ),
            "highlights": highlights,
            "suggested_actions": [r["id"] for r in remediations if r.get("cve_id")][:4],
        }

    # 4. Database / exposed internal assets
    if any(k in q for k in ("database", "db", "redis", "postgres", "mysql", "mongo", "docker")):
        matches = [
            a for a in assets
            if a.get("port") in {1433, 1521, 2375, 2376, 3306, 5432, 6379, 9200, 11211, 27017}
        ]
        if not matches:
            return {
                "answer": "No exposed database, cache, or container API ports were found in this audit.",
                "highlights": [],
                "suggested_actions": [],
            }
        labels = [f"{a['host']}:{a['port']} ({a.get('service')}, {a.get('exposure')})" for a in matches]
        return {
            "answer": f"Found {len(matches)} data-store/container endpoint(s): {', '.join(labels)}. Ensure strict subnet ACLs and authentication.",
            "highlights": labels,
            "suggested_actions": [
                r["id"] for r in remediations
                if r.get("id") in {"rem-segment-databases", "rem-highrisk-6379", "rem-highrisk-2375", "rem-highrisk-27017"}
            ],
        }

    # 5. Failing controls / NIS2 overview
    failing = [c for c in controls if c.get("status") != "PASS"]
    return {
        "answer": (
            f"Current NIS2 score is {compliance.get('score')}/100 (Grade {compliance.get('grade')} — {compliance.get('posture')}). "
            f"{len(failing)} of {len(controls)} Article 21(2) pillars have active findings."
        ),
        "highlights": [f"{c['article']} ({c['status']}): {c['title']}" for c in failing],
        "suggested_actions": [r["id"] for r in remediations if not r.get("mitigated")][:3],
    }
