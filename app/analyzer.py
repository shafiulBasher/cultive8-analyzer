from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

from .chunker import iter_chunks
from .config import MAX_OUTPUT_TOKENS, MAX_PROMPT_TOKENS, SAFETY_TOKENS
from .database import (
    get_job,
    save_chunk,
    save_findings,
    update_job,
)
from .model_client import LocalModelClient, LocalModelError
from .prompts import build_analysis_messages, build_candidate_review_messages
from .schemas import AnalysisResult, Finding
from .signals import (
    HistoryTracker,
    detect_file_findings,
    corroborate_model_findings,
)

ANALYSIS_LOCK = asyncio.Lock()


def parse_json_response(raw: str) -> dict[str, Any]:
    """Parse one complete JSON object; truncated output is rejected."""
    text = (raw or "").strip()

    if text.startswith("```"):
        text = text.removeprefix("```json").removeprefix("```")
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3]
        text = text.strip()

    value = json.loads(text)

    if not isinstance(value, dict):
        raise ValueError("Model response must be a JSON object")

    if not isinstance(value.get("findings", []), list):
        raise ValueError("Model JSON 'findings' must be an array")

    return value


def validate_result(
    payload: dict[str, Any],
    allowed_line_numbers: set[int],
) -> AnalysisResult:
    """Validate model structure and discard evidence outside supplied history."""
    raw_findings = payload.get("findings", [])

    if not isinstance(raw_findings, list):
        raw_findings = []

    valid = []

    for raw in raw_findings:
        if not isinstance(raw, dict):
            continue

        try:
            finding = Finding.model_validate(raw)
        except Exception:
            continue

        finding.evidence = [
            evidence
            for evidence in finding.evidence
            if evidence.line_number in allowed_line_numbers
        ]

        if finding.evidence:
            valid.append(finding)

    return AnalysisResult(
        findings=valid,
        summary=str(payload.get("summary", ""))[:200],
        carry_forward=str(payload.get("carry_forward", ""))[:200],
    )


async def request_with_retry(
    model: LocalModelClient,
    messages: list[dict[str, str]],
) -> str:
    last_error: Exception | None = None

    for attempt in range(2):
        try:
            return await model.chat_json(
                messages,
                max_tokens=MAX_OUTPUT_TOKENS,
            )
        except LocalModelError as exc:
            last_error = exc
            if attempt == 0:
                await asyncio.sleep(0.6)

    raise LocalModelError(
        str(last_error or "Local model request failed")
    )


async def count_lines(path: Path) -> int:
    def _count() -> int:
        with path.open("r", encoding="utf-8", errors="replace") as source:
            return sum(1 for _ in source)

    return await asyncio.to_thread(_count)


def read_candidate_records(path: Path, candidate: dict[str, Any]) -> list[dict[str, Any]]:
    """Read exact original JSONL rows cited by one source-derived candidate."""
    wanted = {
        int(item["line_number"])
        for item in candidate.get("evidence", [])
        if isinstance(item, dict) and item.get("line_number") is not None
    }
    if not wanted:
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as source:
        for line_number, raw in enumerate(source, start=1):
            if line_number not in wanted or not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append({"line_number": line_number, "record": row})
    return rows


def trim_review_records(records: list[dict[str, Any]], candidate: dict[str, Any]) -> list[dict[str, Any]]:
    """Keep representative evidence if a candidate-review prompt approaches the budget."""
    if len(records) <= 4:
        return records
    attack = str(candidate.get("attack_type", "")).lower()
    if "password" in attack or "authentication" in attack:
        # Preserve a failed attempt and a later success when available.
        first = records[0]
        successful = next((r for r in reversed(records) if r["record"].get("auth_result") == "success"), None)
        middle = records[len(records) // 2]
        selected = [first, middle]
        if successful:
            selected.append(successful)
        return selected
    return [records[0], records[1], records[-2], records[-1]]


async def analyze_job(job_id: str) -> None:
    # One model request at a time, protecting CPU/RAM limits.
    async with ANALYSIS_LOCK:
        job = get_job(job_id)
        if not job:
            return

        path = Path(job["file_path"])
        model = LocalModelClient()

        if not await model.health():
            update_job(
                job_id,
                status="failed",
                phase="model_unavailable",
                error=(
                    "Local model server is not running. Local llama.cpp server is unavailable. "
                    "Start the model server and submit the log again."
                ),
            )
            return

        update_job(job_id, status="processing", phase="tokenizing", error=None)

        try:
            total_lines = await count_lines(path)

            # Independent source scan is a safety net and evidence verifier.
            source_findings = await asyncio.to_thread(
                detect_file_findings,
                path,
            )
            save_findings(job_id, source_findings)

            tracker = HistoryTracker()
            model_proposals: list[dict[str, Any]] = []
            model_summaries: list[str] = []
            chunk_errors: list[str] = []

            processed = 0
            succeeded = 0
            failed = 0
            total_model_ms = 0
            chunk_model_proposals = 0

            async for chunk in iter_chunks(
                path,
                model,
                tracker.as_prompt_context,
            ):
                update_job(
                    job_id,
                    phase=f"analyzing_chunk_{chunk.index}",
                )

                messages = build_analysis_messages(
                    tracker.as_prompt_context(),
                    chunk.records,
                )

                prompt_tokens = chunk.prompt_tokens

                # Prompt tokens + reserved generation + safety must fit 2,048.
                if (
                    prompt_tokens
                    + MAX_OUTPUT_TOKENS
                    + SAFETY_TOKENS
                    > 2048
                ):
                    raise ValueError(
                        f"Chunk {chunk.index} exceeds the 2,048-token budget."
                    )

                started = time.perf_counter()

                try:
                    raw = await request_with_retry(model, messages)
                    payload = parse_json_response(raw)

                    allowed_lines = set(tracker.seen_line_numbers)
                    allowed_lines.update(
                        int(item["line_number"])
                        for item in chunk.records
                    )

                    parsed = validate_result(payload, allowed_lines)

                    elapsed = int(
                        (time.perf_counter() - started) * 1000
                    )
                    total_model_ms += elapsed

                    chunk_proposals = [
                        finding.model_dump()
                        for finding in parsed.findings
                    ]
                    model_proposals.extend(chunk_proposals)
                    chunk_model_proposals += len(chunk_proposals)

                    if parsed.summary:
                        model_summaries.append(parsed.summary[:160])

                    succeeded += 1

                    save_chunk(
                        job_id,
                        chunk.index,
                        chunk.start_line,
                        chunk.end_line,
                        "completed",
                        prompt_tokens,
                        elapsed,
                        response={
                            "model_summary": parsed.summary[:200],
                            "model_proposals": len(chunk_proposals),
                        },
                    )

                except Exception as exc:
                    elapsed = int(
                        (time.perf_counter() - started) * 1000
                    )
                    total_model_ms += elapsed
                    failed += 1

                    message = str(exc)[:400]
                    chunk_errors.append(
                        f"Chunk {chunk.index}: {message}"
                    )

                    save_chunk(
                        job_id,
                        chunk.index,
                        chunk.start_line,
                        chunk.end_line,
                        "failed",
                        prompt_tokens,
                        elapsed,
                        error=message,
                    )

                # Persist source-backed findings after every chunk, regardless
                # of whether the model succeeded.
                save_findings(job_id, source_findings)

                tracker.update(chunk.records)
                processed += 1

                update_job(
                    job_id,
                    processed_chunks=processed,
                )

            # Stage 03: ask the local model to independently adjudicate each
            # source-derived candidate. This focused review is important for small
            # local models that may miss rare attacks while scanning every chunk.
            update_job(job_id, phase="correlating")
            candidate_review_results: list[dict[str, Any]] = []
            candidate_review_proposals: list[dict[str, Any]] = []
            candidate_review_succeeded = 0
            candidate_review_failed = 0

            for candidate_index, candidate in enumerate(source_findings, start=1):
                update_job(
                    job_id,
                    phase=f"reviewing_candidate_{candidate_index}_of_{len(source_findings)}",
                )
                rows = await asyncio.to_thread(read_candidate_records, path, candidate)
                if not rows:
                    candidate_review_failed += 1
                    candidate_review_results.append({
                        "attack_type": candidate.get("attack_type", "Unknown"),
                        "ip_or_identifier": candidate.get("ip_or_identifier", ""),
                        "status": "not_reviewed_no_source_rows",
                        "source_evidence_lines": [],
                    })
                    continue

                messages = build_candidate_review_messages(candidate, rows)
                try:
                    prompt_tokens = await model.count_messages(messages)
                    if prompt_tokens + MAX_OUTPUT_TOKENS + SAFETY_TOKENS > 2048:
                        rows = trim_review_records(rows, candidate)
                        messages = build_candidate_review_messages(candidate, rows)
                        prompt_tokens = await model.count_messages(messages)
                    if prompt_tokens + MAX_OUTPUT_TOKENS + SAFETY_TOKENS > 2048:
                        raise ValueError("Candidate-review prompt exceeds the 2,048-token budget.")

                    started = time.perf_counter()
                    raw = await request_with_retry(model, messages)
                    payload = parse_json_response(raw)
                    allowed_lines = {int(item["line_number"]) for item in rows}
                    parsed = validate_result(payload, allowed_lines)
                    elapsed = int((time.perf_counter() - started) * 1000)
                    total_model_ms += elapsed
                    proposals = [finding.model_dump() for finding in parsed.findings]
                    candidate_review_proposals.extend(proposals)
                    model_proposals.extend(proposals)
                    candidate_review_succeeded += 1
                    candidate_review_results.append({
                        "attack_type": candidate.get("attack_type", "Unknown"),
                        "ip_or_identifier": candidate.get("ip_or_identifier", ""),
                        "status": "proposal_returned" if proposals else "no_model_confirmation",
                        "proposal_count": len(proposals),
                        "prompt_tokens": prompt_tokens,
                        "source_evidence_lines": [int(item["line_number"]) for item in candidate.get("evidence", []) if isinstance(item, dict) and item.get("line_number") is not None],
                    })
                except Exception as exc:
                    candidate_review_failed += 1
                    candidate_review_results.append({
                        "attack_type": candidate.get("attack_type", "Unknown"),
                        "ip_or_identifier": candidate.get("ip_or_identifier", ""),
                        "status": "review_error",
                        "error": str(exc)[:240],
                        "source_evidence_lines": [int(item["line_number"]) for item in candidate.get("evidence", []) if isinstance(item, dict) and item.get("line_number") is not None],
                    })

            # A proposal is counted as corroboration only after its entity, attack
            # family, and at least two exact source events pass source validation.
            final_findings = await asyncio.to_thread(
                corroborate_model_findings,
                path,
                model_proposals,
                source_findings,
            )

            save_findings(job_id, final_findings)

            # Distinguish a model response from a successfully source-validated
            # corroboration in the report shown to the user.
            for review in candidate_review_results:
                cited_candidate_lines = set(review.get("source_evidence_lines", []))
                entity = str(review.get("ip_or_identifier", ""))
                corroborated = any(
                    item.get("ai_corroborated_by_local_model")
                    and str(item.get("ip_or_identifier", "")) == entity
                    and len(cited_candidate_lines.intersection(set(item.get("ai_reviewed_line_numbers", [])))) >= 2
                    for item in final_findings
                )
                if corroborated:
                    review["status"] = "ai_corroborated"
                elif review.get("status") == "proposal_returned":
                    review["status"] = "proposal_not_source_validated"

            ai_corroborated = sum(
                1
                for finding in final_findings
                if finding.get("ai_corroborated_by_local_model")
            )

            # Stage 04: build report.
            update_job(job_id, phase="generating_report")

            report = {
                "summary": (
                    f"Reviewed {total_lines} source lines in {processed} "
                    f"sequential model chunk(s); retained {len(source_findings)} source-rule candidate(s) "
                    f"and AI-corroborated {ai_corroborated} finding(s)."
                ),
                "total_lines": total_lines,
                "chunks_processed": processed,
                "chunks_succeeded": succeeded,
                "chunks_failed": failed,
                "rule_based_findings": len(source_findings),
                "model_proposals": len(model_proposals),
                "chunk_model_proposals": chunk_model_proposals,
                "candidate_review_proposals": len(candidate_review_proposals),
                "candidate_review_attempted": len(source_findings),
                "candidate_review_succeeded": candidate_review_succeeded,
                "candidate_review_failed": candidate_review_failed,
                "candidate_review_results": candidate_review_results,
                "ai_corroborated_findings": ai_corroborated,
                "rule_only_findings": len(final_findings) - ai_corroborated,
                "findings": [
                    {
                        key: value
                        for key, value in item.items()
                        if key != "_key"
                    }
                    for item in final_findings
                ],
                "chunk_errors": chunk_errors,
                "model_summaries": model_summaries[:8],
                "model": "ggml-org/Qwen3.5-0.8B-GGUF:Q4_0",
                "analysis_method": (
                    "A deterministic source scan creates evidence-backed candidate alerts. "
                    "The local model analyzes every token-bounded chunk and then independently "
                    "reviews each candidate. An alert is marked AI-corroborated only when the "
                    "model cites at least two distinct original records matching the same "
                    "source entity and attack family. Uncorroborated source findings remain "
                    "visible and are labeled as rule-only findings."
                ),
                "token_budget": {
                    "context_limit": 2048,
                    "max_output": MAX_OUTPUT_TOKENS,
                    "safety_reserve": SAFETY_TOKENS,
                    "max_prompt": MAX_PROMPT_TOKENS,
                },
                "model_time_ms": total_model_ms,
            }

            status = (
                "completed_with_errors"
                if failed or candidate_review_failed
                else "completed"
            )

            update_job(
                job_id,
                status=status,
                phase="complete",
                findings_count=len(final_findings),
                report_json=report,
                error=(
                    "; ".join(
                        part for part in [
                            f"{failed} chunk(s) failed" if failed else "",
                            f"{candidate_review_failed} candidate AI review(s) failed" if candidate_review_failed else "",
                        ] if part
                    ) + ". Source-validated findings were retained."
                    if failed or candidate_review_failed
                    else None
                ),
            )

        except Exception as exc:
            update_job(
                job_id,
                status="failed",
                phase="analysis_error",
                error=str(exc)[:1500],
            )
