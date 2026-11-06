from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote

SQL_PATTERN = re.compile(
    r"(?i)(\bunion\s+select\b|\bor\s+['\"% ]?1['\"% ]?\s*=\s*['\"% ]?1|"
    r"\bselect\b.{0,80}\bfrom\b|\bsleep\s*\(|\bbenchmark\s*\(|;\s*--)"
)
SENSITIVE_PROBES = (
    "/.env", "/.git", "/wp-admin", "/phpmyadmin", "/actuator",
    "/server-status", "/backup", "/config",
)


def decode_path(value: str) -> str:
    result = value or ""
    for _ in range(3):
        decoded = unquote(result)
        if decoded == result:
            break
        result = decoded
    return result


def event_path(record: dict[str, Any]) -> str:
    return str(record.get("path", ""))


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _status(row: dict[str, Any]) -> int | None:
    try:
        return int(row.get("status"))
    except (TypeError, ValueError):
        return None


def _is_login(row: dict[str, Any], path: str) -> bool:
    method = str(row.get("method", "")).upper()
    is_login_path = "/login" in path.lower()
    # Some valid logs omit the HTTP method. A 401 on a login endpoint is still
    # an authentication failure; a GET /login 200 remains only a page view.
    return (
        row.get("auth_result") in {"invalid_password", "success"}
        or (is_login_path and (method == "POST" or _status(row) == 401))
    )


def _is_auth_failure(row: dict[str, Any]) -> bool:
    return _status(row) == 401 or row.get("auth_result") == "invalid_password"


def _is_auth_success(row: dict[str, Any], path: str) -> bool:
    return (
        row.get("auth_result") == "success"
        or (
            str(row.get("method", "")).upper() == "POST"
            and "/login" in path.lower()
            and _status(row) in {200, 201}
        )
    )


def _has_traversal(path: str) -> bool:
    lowered = path.lower()
    return (
        "../" in lowered
        or "..\\" in lowered
        or re.search(r"(?:^|/)\.\.(?:/|\\)", lowered) is not None
    )



def _is_sensitive_probe(path: str) -> bool:
    """Match known sensitive path names, not unrelated longer prefixes."""
    candidate = (path or "").split("?", 1)[0].lower().rstrip("/")
    for probe in SENSITIVE_PROBES:
        if candidate == probe:
            return True
        if candidate.startswith(probe + "/"):
            return True
        if candidate.startswith(probe + "."):
            return True
    return False


def _model_family(attack_type: str) -> str:
    value = (attack_type or "").lower()
    if "sql" in value or "injection" in value:
        return "sql_injection"
    if "traversal" in value or "path" in value and "file" in value:
        return "directory_traversal"
    if any(word in value for word in ("brute", "password", "credential", "login")):
        return "brute_force"
    if any(word in value for word in ("rate", "flood", "request spike", "dos")):
        return "rate_abuse"
    if any(word in value for word in ("scan", "recon", "probe", "enumerat")):
        return "reconnaissance_scanning"
    if "unauthorized" in value or "access denied" in value:
        return "unauthorized_access"
    return "unknown"


def _model_line_supports(family: str, row: dict[str, Any], path_value: str) -> bool:
    status = _status(row)

    if family == "sql_injection":
        return SQL_PATTERN.search(path_value) is not None

    if family == "directory_traversal":
        return _has_traversal(path_value)

    if family == "brute_force":
        return _is_login(row, path_value) and (
            _is_auth_failure(row) or _is_auth_success(row, path_value)
        )

    if family == "rate_abuse":
        return status == 429 or _safe_int(row.get("requests_in_window")) >= 100

    if family == "reconnaissance_scanning":
        return _is_sensitive_probe(path_value)

    if family == "unauthorized_access":
        rule = str(row.get("security_rule", "")).lower()
        return status in {401, 403} and (
            "access_denied" in rule
            or "unauthorized" in rule
            or row.get("auth_result") == "invalid_password"
        )

    return False


def corroborate_model_findings(
    path: Path,
    proposals: list[dict[str, Any]],
    source_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Let local-model proposals corroborate findings only against source rows.

    No model-created IP, line number, or detail is trusted. Each cited line is
    re-read from the original JSONL file, checked for identity and attack-family
    support, and rendered using fields from that source record.
    """
    if not proposals:
        return source_findings

    requested_lines: set[int] = set()
    for proposal in proposals:
        if not isinstance(proposal, dict):
            continue
        for evidence in proposal.get("evidence", []) or []:
            if isinstance(evidence, dict):
                try:
                    requested_lines.add(int(evidence.get("line_number")))
                except (TypeError, ValueError):
                    pass

    if not requested_lines:
        return source_findings

    source_rows: dict[int, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8", errors="replace") as source:
        for line_number, raw in enumerate(source, start=1):
            if line_number not in requested_lines or not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                source_rows[line_number] = row

    # Index source-grounded findings by family and IP.
    trusted: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in source_findings:
        family = _model_family(str(finding.get("attack_type", "")))
        ip = str(finding.get("ip_or_identifier", "")).strip()
        if family != "unknown" and ip:
            trusted[(family, ip)] = finding

    for proposal in proposals:
        if not isinstance(proposal, dict):
            continue

        family = _model_family(str(proposal.get("attack_type", "")))
        if family == "unknown":
            continue

        identifier = str(proposal.get("ip_or_identifier", "")).strip()
        if not identifier:
            continue

        verified_by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for evidence in proposal.get("evidence", []) or []:
            if not isinstance(evidence, dict):
                continue

            try:
                line_number = int(evidence.get("line_number"))
            except (TypeError, ValueError):
                continue

            row = source_rows.get(line_number)
            if not row:
                continue

            row_ip = str(row.get("client_ip", "")).strip()
            row_user = str(row.get("username", "")).strip()

            # The model may identify either the source IP or an account name.
            if identifier not in {row_ip, row_user}:
                continue

            path_value = decode_path(event_path(row))
            if not _model_line_supports(family, row, path_value):
                continue

            detail = (
                f"{str(row.get('method', '')).upper()} "
                f"{str(row.get('path', ''))[:100]} "
                f"returned HTTP {_status(row)}"
            )
            if row.get("auth_result"):
                detail += f" (auth_result={row.get('auth_result')})"

            verified_by_ip[row_ip].append({
                "line_number": line_number,
                "detail": detail[:300],
            })

        for verified_ip, evidence_items in verified_by_ip.items():
            # Require at least two distinct source events before counting an AI review
            # as corroboration. One matching line is not enough to validate a pattern.
            evidence_by_line = {item["line_number"]: item for item in evidence_items}
            evidence_items = list(evidence_by_line.values())
            if len(evidence_items) < 2:
                continue

            cited_rows = [source_rows[item["line_number"]] for item in evidence_items]
            if family == "brute_force":
                has_failure = any(_is_auth_failure(row) for row in cited_rows)
                has_success = any(
                    _is_auth_success(row, decode_path(event_path(row)))
                    for row in cited_rows
                )
                if not (has_failure and has_success):
                    continue
            elif family == "reconnaissance_scanning":
                cited_paths = {
                    str(row.get("path", "")).split("?", 1)[0].lower()
                    for row in cited_rows
                }
                if len(cited_paths) < 2:
                    continue

            # Only attach proposals to an independently source-grounded finding.
            existing = trusted.get((family, verified_ip))

            if existing is None:
                # Explicit access-denied security events are the only model-
                # proposed category permitted without another aggregate rule.
                if family != "unauthorized_access":
                    continue

                rule = " ".join(
                    str(source_rows[e["line_number"]].get("security_rule", "")).lower()
                    for e in evidence_items
                )
                if "access_denied" not in rule and "unauthorized" not in rule:
                    continue

                existing = _finding(
                    "Unauthorized access attempt",
                    "Medium",
                    verified_ip,
                    str(proposal.get("target", ""))[:120],
                    evidence_items[:2],
                    "Original log records explicitly mark an unauthorized or access-denied request.",
                    "Review the denied request and confirm the endpoint is protected by authorization checks.",
                    confidence=0.7,
                )
                source_findings.append(existing)
                trusted[(family, verified_ip)] = existing

            # Mark model corroboration without replacing source-derived
            # severity, reason, or suggested action.
            existing["ai_corroborated_by_local_model"] = True
            try:
                confidence = float(proposal.get("confidence", 0.0))
                if confidence > 1 and confidence <= 100:
                    confidence /= 100
            except (TypeError, ValueError):
                confidence = 0.0

            existing["ai_confidence"] = max(
                float(existing.get("ai_confidence", 0.0)),
                min(1.0, max(0.0, confidence)),
            )

            lines = set(existing.get("ai_reviewed_line_numbers", []))
            lines.update(item["line_number"] for item in evidence_items)
            existing["ai_reviewed_line_numbers"] = sorted(lines)[:12]

    return source_findings

def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
    except (TypeError, ValueError):
        return None


def _dedupe_key(row: dict[str, Any], line_number: int | None = None) -> str:
    event_id = row.get("event_id")
    if event_id:
        return f"event:{event_id}"

    # The sample contains a duplicate record with the same request_id/event_id.
    # Include identifying request fields so reused IDs do not collapse distinct
    # events when their method/path/status/time differ.
    fields = [
        row.get("request_id"), row.get("client_ip"), row.get("time"),
        row.get("method"), row.get("path"), row.get("status"),
        row.get("username"), row.get("auth_result"),
    ]
    if row.get("request_id"):
        return "request:" + json.dumps(fields, separators=(",", ":"), default=str)

    # Without a unique event/request ID, preserve each original source line.
    if line_number is not None:
        return f"line:{line_number}"

    stable = {
        key: row.get(key)
        for key in (
            "time", "client_ip", "method", "path", "status",
            "username", "auth_result", "message", "event_id",
        )
    }
    return "sha:" + sha256(
        json.dumps(stable, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _evidence(event: dict[str, Any], detail: str) -> dict[str, Any]:
    return {"line_number": event["line"], "detail": detail}


def _finding(
    attack_type: str,
    severity: str,
    ip: str,
    target: str,
    evidence: list[dict[str, Any]],
    reason: str,
    action: str,
    confidence: float = 0.92,
) -> dict[str, Any]:
    # Stable key, based on detector category + source + target.
    stable = "|".join((attack_type.lower(), ip, target.lower()))
    return {
        "_key": sha256(stable.encode("utf-8")).hexdigest()[:20],
        "attack_type": attack_type,
        "severity": severity,
        "ip_or_identifier": ip,
        "target": target,
        "evidence": evidence,
        "reason": reason,
        "suggested_action": action,
        "confidence": confidence,
    }


def candidate_signals(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Small deterministic hints for tests/optional model context; not report output."""
    auth: dict[tuple[str, str], list[int]] = defaultdict(list)
    sql: dict[str, list[int]] = defaultdict(list)
    traversal: dict[str, list[int]] = defaultdict(list)
    rate: dict[str, list[int]] = defaultdict(list)

    for item in records:
        row = item.get("record", {})
        if not isinstance(row, dict):
            continue
        line = int(item["line_number"])
        ip = str(row.get("client_ip", "unknown"))
        path = decode_path(event_path(row))
        user = str(row.get("username", "unknown"))
        if _is_login(row, path) and _is_auth_failure(row):
            auth[(ip, user)].append(line)
        if SQL_PATTERN.search(path):
            sql[ip].append(line)
        if _has_traversal(path):
            traversal[ip].append(line)
        if _status(row) == 429:
            rate[ip].append(line)

    hints: list[dict[str, Any]] = []
    for (ip, user), lines in auth.items():
        if len(lines) >= 2:
            hints.append({"type": "repeated_auth_failures", "entity": ip, "account": user, "line_numbers": lines[:8]})
    for ip, lines in sql.items():
        # Keep the current canonical type plus the legacy detector label used
        # by older integrations/tests. Both point to the same source events.
        hints.append({"type": "sql_injection_attempt", "entity": ip, "line_numbers": lines[:8]})
        hints.append({"type": "SQL-like_payload", "entity": ip, "line_numbers": lines[:8]})
    for ip, lines in traversal.items():
        hints.append({"type": "path_traversal_attempt", "entity": ip, "line_numbers": lines[:8]})
    for ip, lines in rate.items():
        if len(lines) >= 2:
            hints.append({"type": "rate_limit_responses", "entity": ip, "line_numbers": lines[:8]})
    return hints[:12]


class HistoryTracker:
    """Small carry-forward state for model awareness across chunk boundaries."""

    def __init__(self) -> None:
        self.auth: dict[tuple[str, str], dict[str, Any]] = {}
        self.sql: dict[str, dict[str, Any]] = {}
        self.traversal: dict[str, dict[str, Any]] = {}
        self.rate: dict[str, dict[str, Any]] = {}
        self.seen_line_numbers: set[int] = set()

    def update(self, records: list[dict[str, Any]]) -> None:
        for item in records:
            line = int(item["line_number"])
            self.seen_line_numbers.add(line)
            row = item.get("record", {})
            if not isinstance(row, dict):
                continue
            ip = str(row.get("client_ip", "unknown"))
            user = str(row.get("username", "unknown"))
            path = decode_path(event_path(row))

            if _is_login(row, path):
                state = self.auth.setdefault((ip, user), {"failed": 0, "successful": 0, "lines": []})
                if _is_auth_failure(row):
                    state["failed"] += 1
                if _is_auth_success(row, path):
                    state["successful"] += 1
                state["lines"] = (state["lines"] + [line])[-6:]

            if SQL_PATTERN.search(path):
                state = self.sql.setdefault(ip, {"count": 0, "lines": []})
                state["count"] += 1
                state["lines"] = (state["lines"] + [line])[-4:]

            if _has_traversal(path):
                state = self.traversal.setdefault(ip, {"count": 0, "lines": []})
                state["count"] += 1
                state["lines"] = (state["lines"] + [line])[-4:]

            if _status(row) == 429:
                state = self.rate.setdefault(ip, {"count": 0, "lines": []})
                state["count"] += 1
                state["lines"] = (state["lines"] + [line])[-4:]

    def as_prompt_context(self) -> str:
        auth = [
            {"ip": ip, "user": user, **data}
            for (ip, user), data in self.auth.items()
            if data["failed"] or data["successful"]
        ]
        auth.sort(key=lambda x: x["failed"], reverse=True)
        sql = [{"ip": ip, **data} for ip, data in self.sql.items()]
        traversal = [{"ip": ip, **data} for ip, data in self.traversal.items()]
        rate = [{"ip": ip, **data} for ip, data in self.rate.items()]
        payload = {
            "auth": auth[:2],
            "sql": sql[:2],
            "traversal": traversal[:2],
            "rate": rate[:2],
            # Explicit semantic labels make cross-chunk state easy for both
            # the model prompt and integrations/tests to interpret.
            "prior_authentication_facts": auth[:2],
            "prior_sql_injection_facts": sql[:2],
            "prior_path_traversal_facts": traversal[:2],
            "prior_directory_traversal_facts": traversal[:2],
            "prior_rate_limit_facts": rate[:2],
        }
        # The caller applies MAX_HISTORY_CHARS before sending this to the model.
        return json.dumps(payload, separators=(",", ":"))[:1200]


def detect_file_findings(path: Path) -> list[dict[str, Any]]:
    """Source-grounded detections over the complete file, including cross-chunk events.

    Model output is not trusted as evidence. Every finding and evidence detail here
    is constructed from the original log fields, with duplicate events removed.
    """
    auth: dict[tuple[str, str], dict[str, list[dict[str, Any]]]] = defaultdict(lambda: {"failed": [], "successful": []})
    sql: dict[str, list[dict[str, Any]]] = defaultdict(list)
    traversal: dict[str, list[dict[str, Any]]] = defaultdict(list)
    probes: dict[str, list[dict[str, Any]]] = defaultdict(list)
    rate: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen: set[str] = set()

    with path.open("r", encoding="utf-8", errors="replace") as source:
        for line_number, raw in enumerate(source, start=1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue

            ip = str(row.get("client_ip", "")).strip()
            if not ip:
                continue

            dedupe = _dedupe_key(row, line_number)
            if dedupe in seen:
                continue
            seen.add(dedupe)

            path_value = decode_path(event_path(row))
            event = {
                "line": line_number,
                "row": row,
                "ip": ip,
                "path": path_value,
                "status": _status(row),
                "time": _parse_time(row.get("time")),
            }

            username = str(row.get("username", "unknown")).strip() or "unknown"
            if _is_login(row, path_value):
                if _is_auth_failure(row):
                    auth[(ip, username)]["failed"].append(event)
                elif _is_auth_success(row, path_value):
                    auth[(ip, username)]["successful"].append(event)

            if SQL_PATTERN.search(path_value):
                sql[ip].append(event)

            if _has_traversal(path_value):
                traversal[ip].append(event)

            if _is_sensitive_probe(path_value):
                probes[ip].append(event)

            if event["status"] == 429:
                rate[ip].append(event)

    findings: list[dict[str, Any]] = []

    # Authentication: a single failure followed by a success is not brute force.
    for (ip, username), group in auth.items():
        failures = group["failed"]
        successes = group["successful"]
        if not failures:
            continue
        last_failure_line = max(x["line"] for x in failures)
        later_successes = [x for x in successes if x["line"] > last_failure_line]
        if len(failures) < 5 and not (len(failures) >= 2 and later_successes):
            continue
        selected_failures = failures[:3] + failures[-3:]
        evidence_by_line: dict[int, dict[str, Any]] = {}
        for event in selected_failures:
            status = event["status"]
            evidence_by_line[event["line"]] = _evidence(
                event,
                f"Failed login for account '{username}' (HTTP {status}; auth_result={event['row'].get('auth_result', 'not_recorded')}).",
            )
        for event in later_successes[:2]:
            evidence_by_line[event["line"]] = _evidence(
                event,
                f"Successful POST login for account '{username}' (HTTP {event['status']}; auth_result={event['row'].get('auth_result', 'not_recorded')}).",
            )
        strong_guessing_signal = len(failures) >= 5 and bool(later_successes)
        severity = "High" if strong_guessing_signal else "Medium"
        if strong_guessing_signal:
            attack_type = "Repeated password guessing followed by successful authentication"
        elif later_successes:
            attack_type = "Repeated authentication failures followed by successful login"
        else:
            attack_type = "Repeated failed authentication attempts"
        reason = (
            f"{len(failures)} distinct failed login attempts were recorded for the same account and source IP. "
            + ("A later successful authentication from the same IP/account is recorded; investigate possible account compromise."
               if later_successes else "No subsequent successful login for this IP/account is present in the log.")
        )
        action = (
            "Review the successful session, revoke it if unauthorized, reset the account credentials, and inspect follow-on activity."
            if later_successes else
            "Apply authentication rate limits, MFA, and account protections; investigate the source IP and preserve authentication logs."
        )
        findings.append(_finding(
            attack_type, severity, ip, username,
            [evidence_by_line[n] for n in sorted(evidence_by_line)],
            reason, action,
        ))

    # SQL injection attempts. HTTP 400/403 indicates rejection, not exploitation.
    for ip, events in sql.items():
        if not events:
            continue
        selected = events[:3] + events[-2:]
        evidence = [
            _evidence(
                event,
                f"SQL-like payload appears in request path '{event['row'].get('path', '')[:120]}' (HTTP {event['status']}).",
            )
            for event in {x["line"]: x for x in selected}.values()
        ]
        any_success = any(x["status"] is not None and 200 <= x["status"] < 300 for x in events)
        findings.append(_finding(
            "SQL injection attempts",
            "High" if any_success else "Medium",
            ip,
            "HTTP query parameters",
            evidence,
            f"{len(events)} distinct request(s) contain SQL-injection syntax. "
            + ("At least one request returned 2xx; verify whether input reached a database query."
               if any_success else "The recorded responses do not show successful exploitation; the attempts appear rejected or unsuccessful."),
            "Use parameterized queries and strict input validation; review database audit logs. Treat these as attempts, not confirmed data access.",
        ))

    # Path traversal attempts, correlated across all chunks by source IP.
    for ip, events in traversal.items():
        if not events:
            continue
        selected = events[:3] + events[-2:]
        evidence = [
            _evidence(
                event,
                f"Traversal sequence appears in request path '{event['row'].get('path', '')[:120]}' (HTTP {event['status']}).",
            )
            for event in {x["line"]: x for x in selected}.values()
        ]
        any_success = any(x["status"] is not None and 200 <= x["status"] < 300 for x in events)
        findings.append(_finding(
            "Directory traversal attempts",
            "High" if any_success else "Medium",
            ip,
            "File endpoint",
            evidence,
            f"{len(events)} distinct request(s) contain encoded or plain directory-traversal sequences. "
            + ("A 2xx response was recorded and needs immediate investigation."
               if any_success else "The observed responses are denied; there is no evidence of file disclosure in these records."),
            "Reject traversal sequences after canonical URL decoding, constrain file access to an allowlisted directory, and review access logs.",
        ))

    # Sensitive endpoint discovery is reconnaissance, not brute force.
    for ip, events in probes.items():
        if len(events) < 4:
            continue
        times = [x["time"] for x in events if x["time"] is not None]
        rapid = False
        if len(times) >= 2:
            rapid = (max(times) - min(times)).total_seconds() <= 600
        if not rapid and len(events) < 6:
            continue
        selected = events[:5]
        evidence = [
            _evidence(
                event,
                f"Sensitive endpoint probe '{event['row'].get('path', '')[:100]}' returned HTTP {event['status']}.",
            )
            for event in selected
        ]
        findings.append(_finding(
            "Sensitive endpoint reconnaissance",
            "Medium",
            ip,
            "Common administrative/configuration endpoints",
            evidence,
            f"{len(events)} distinct requests probed sensitive paths such as environment, repository, admin, or backup endpoints. "
            "Responses are errors/denials in the supplied records; successful access is not established.",
            "Keep sensitive files outside the web root, deny access to administrative paths, and review this source for further probing.",
        ))

    # Rate limiting: correctly classified as high-rate request behavior, not brute force.
    for ip, events in rate.items():
        if len(events) < 5:
            continue
        peak = max(
            [_safe_int(x["row"].get("requests_in_window", 0)) for x in events]
            or [0]
        )
        window_values = [_safe_int(x["row"].get("window_seconds", 0)) for x in events]
        window = min((x for x in window_values if x > 0), default=0)
        selected = events[:5]
        evidence = []
        for event in selected:
            row = event["row"]
            count = row.get("requests_in_window")
            win = row.get("window_seconds")
            detail = f"HTTP 429 rate-limit response."
            if count is not None and win is not None:
                detail += f" Server recorded {count} requests in {win} seconds."
            evidence.append(_evidence(event, detail))
        findings.append(_finding(
            "High request-rate activity (rate limited)",
            "Medium",
            ip,
            "Rate-limited API endpoint",
            evidence,
            f"{len(events)} HTTP 429 responses were recorded; the highest reported window count was {peak} request(s) in {window or 'an unspecified'} second(s). "
            "The rate limiter responded, so the log supports abusive/high-rate traffic but not service compromise.",
            "Review rate-limit thresholds and request patterns, consider temporary throttling for this source, and monitor service availability.",
        ))

    findings.sort(key=lambda x: ({"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(x["severity"], 4), x["attack_type"], x["ip_or_identifier"]))
    return findings
