from __future__ import annotations
import hashlib
import re
from typing import Any

SEVERITY_WEIGHT = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def family_key(value: str) -> str:
    text = re.sub(r"[^a-z0-9]+", "_", (value or "unknown").lower()).strip("_")
    aliases = {
        "brute_force": ("brute", "credential", "password", "login_attempt"),
        "sql_injection": ("sql", "injection"),
        "reconnaissance_scanning": ("scan", "recon", "probing", "enumerat"),
        "directory_traversal": ("traversal", "path_traversal", "file_inclusion"),
        "unauthorized_access": ("unauthorized", "access_denied", "privilege"),
        "rate_abuse": ("rate", "dos", "flood", "request_spike"),
    }
    for canonical, words in aliases.items():
        if any(word in text for word in words):
            return canonical
    return text


def merge_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for source in findings:
        item = dict(source)
        family = family_key(str(item.get("attack_type", "unknown")))
        entity = str(item.get("ip_or_identifier", "unknown")).strip().lower()
        target = str(item.get("target", "")).strip().lower()
        # Reconnaissance/injection campaigns often touch several paths; keep them
        # together by source entity. Preserve targets for identity/access findings.
        grouping_target = "" if family in {"reconnaissance_scanning", "sql_injection", "directory_traversal", "rate_abuse"} else target
        key = (family, entity, grouping_target)
        if key not in grouped:
            item["attack_type"] = item.get("attack_type") or family
            item["evidence"] = list(item.get("evidence", []))
            grouped[key] = item
            continue
        existing = grouped[key]
        if SEVERITY_WEIGHT.get(item.get("severity", "Low"), 1) > SEVERITY_WEIGHT.get(existing.get("severity", "Low"), 1):
            existing["severity"] = item["severity"]
        evidence_by_line = {e.get("line_number"): e for e in existing.get("evidence", []) if e.get("line_number")}
        for evidence in item.get("evidence", []):
            number = evidence.get("line_number")
            if number and number not in evidence_by_line:
                evidence_by_line[number] = evidence
        existing["evidence"] = [evidence_by_line[n] for n in sorted(evidence_by_line)]
        if len(item.get("reason", "")) > len(existing.get("reason", "")):
            existing["reason"] = item["reason"]
        if item.get("suggested_action") and item["suggested_action"] not in existing.get("suggested_action", ""):
            existing["suggested_action"] = (existing.get("suggested_action", "") + " " + item["suggested_action"]).strip()[:1000]
        existing["confidence"] = max(float(existing.get("confidence", 0.5)), float(item.get("confidence", 0.5)))
    result = list(grouped.values())
    result.sort(key=lambda x: (-(SEVERITY_WEIGHT.get(x.get("severity", "Low"), 1)), x.get("attack_type", ""), x.get("ip_or_identifier", "")))
    for item in result:
        stable = "|".join([family_key(item.get("attack_type", "")), item.get("ip_or_identifier", ""), item.get("target", "")])
        item["_key"] = hashlib.sha256(stable.encode("utf-8")).hexdigest()[:20]
    return result
