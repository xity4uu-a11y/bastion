from __future__ import annotations

from typing import Any

from app.models import Finding


_SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note",
    "unrated": "warning",
}


def build_sarif_report(findings: list[Finding], project_name: str = "Bastion Target") -> dict[str, Any]:
    rules_map: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in findings:
        rule_id = f"BASTION-G{f.gate_number}-{f.detector_or_class or f.source_engine}".replace(" ", "_").upper()
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": f.detector_or_class or f.title,
                "shortDescription": {"text": f.title[:200]},
                "fullDescription": {"text": f.description or f.title},
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_SARIF_LEVEL.get(f.severity, "warning"),
                },
                "properties": {
                    "engine": f.source_engine,
                    "gate": f.gate_number,
                    "tags": ["security", f.source_engine, f"gate-{f.gate_number}"],
                },
            }

        region = {"startLine": max(1, int(f.line_number or 1))}
        result_entry: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SEVERITY_TO_SARIF_LEVEL.get(f.severity, "warning"),
            "message": {
                "text": (
                    f"[{f.verdict.upper()}] {f.title} — {f.description}"
                    if f.description
                    else f"[{f.verdict.upper()}] {f.title}"
                )
            },
            "partialFingerprints": {"primaryLocationLineHash": f.fingerprint},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": (f.file_path or "unknown").replace("\\", "/")},
                        "region": region,
                    }
                }
            ],
            "properties": {
                "findingId": f.id,
                "runId": f.run_id,
                "gateNumber": f.gate_number,
                "sourceEngine": f.source_engine,
                "verdict": f.verdict,
                "severity": f.severity,
                "verified": f.verified,
                "resolved": f.resolved,
                "hunterAgentId": f.hunter_agent_id,
                "verifierAgentId": f.verifier_agent_id,
                "remediation": f.remediation,
            },
        }
        if f.resolved:
            result_entry["suppressions"] = [
                {
                    "kind": "inSource",
                    "status": "accepted",
                    "justification": f.resolution_note or "Marked resolved in Bastion Triage",
                }
            ]
        results.append(result_entry)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Bastion Release Gate",
                        "informationUri": "https://github.com/bastion-devsecops/bastion",
                        "version": "1.0.0",
                        "rules": list(rules_map.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {"projectName": project_name},
                    }
                ],
                "results": results,
            }
        ],
    }
