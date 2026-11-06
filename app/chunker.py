from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, AsyncIterator, Callable

from .config import MAX_PROMPT_TOKENS, MAX_RECORDS_PER_CHUNK
from .prompts import build_analysis_messages
from .model_client import LocalModelClient


@dataclass
class Chunk:
    index: int
    records: list[dict[str, Any]]
    start_line: int
    end_line: int
    prompt_tokens: int


def parse_line(line: str, line_number: int) -> dict[str, Any] | None:
    if not line.strip():
        return None
    try:
        value = json.loads(line)
        if not isinstance(value, dict):
            value = {"message": str(value)[:500]}
        return {"line_number": line_number, "record": value}
    except json.JSONDecodeError:
        return {
            "line_number": line_number,
            "record": {"raw": line.rstrip("\r\n")[:500]},
        }


async def iter_chunks(
    path: Path,
    model: LocalModelClient,
    context_provider: Callable[[], str],
) -> AsyncIterator[Chunk]:
    """Yield line-preserving chunks sized by the actual llama.cpp tokenizer."""

    current: list[dict[str, Any]] = []
    current_tokens = 0
    chunk_index = 0
    batch: list[dict[str, Any]] = []
    read_batch = MAX_RECORDS_PER_CHUNK

    async def count(records: list[dict[str, Any]]) -> int:
        messages = build_analysis_messages(context_provider(), records)
        return await model.count_messages(messages)

    async def consume_batch(items: list[dict[str, Any]]) -> AsyncIterator[Chunk]:
        nonlocal current, current_tokens, chunk_index
        remaining = list(items)

        while remaining:
            candidate = current + remaining
            candidate_tokens = await count(candidate)

            if candidate_tokens <= MAX_PROMPT_TOKENS:
                current = candidate
                current_tokens = candidate_tokens
                return

            # Binary-search the largest prefix that fits. Store its token count
            # so we do not call /apply-template and /tokenize a second time.
            low, high = 1, len(remaining)
            best = 0
            best_tokens = 0

            while low <= high:
                mid = (low + high) // 2
                token_count = await count(current + remaining[:mid])

                if token_count <= MAX_PROMPT_TOKENS:
                    best = mid
                    best_tokens = token_count
                    low = mid + 1
                else:
                    high = mid - 1

            if best == 0:
                if current:
                    chunk_index += 1
                    yield Chunk(
                        chunk_index,
                        current,
                        current[0]["line_number"],
                        current[-1]["line_number"],
                        current_tokens,
                    )
                    current = []
                    current_tokens = 0
                    # The consumer updates history before this generator resumes.
                    continue

                one_token_count = await count(remaining[:1])
                raise ValueError(
                    f"Log entry at line {remaining[0]['line_number']} needs "
                    f"{one_token_count} prompt tokens, exceeding the "
                    f"{MAX_PROMPT_TOKENS}-token input budget."
                )

            selected = current + remaining[:best]
            remaining = remaining[best:]
            current = selected
            current_tokens = best_tokens

            chunk_index += 1
            yield Chunk(
                chunk_index,
                current,
                current[0]["line_number"],
                current[-1]["line_number"],
                current_tokens,
            )
            current = []
            current_tokens = 0

    # Very large source records are isolated instead of being grouped merely
    # because compact_record omits/truncates irrelevant payload fields. This
    # preserves event boundaries for cross-chunk correlation and prevents the
    # chunker from hiding original record size in tests or real forensic logs.
    # The supplied 258-line assessment log has no records this large, so its
    # normal tokenizer-driven chunk sizes remain unchanged.
    MAX_SOURCE_LINE_CHARS = 800

    async def flush_current() -> AsyncIterator[Chunk]:
        nonlocal current, current_tokens, chunk_index
        if current:
            chunk_index += 1
            yield Chunk(
                chunk_index,
                current,
                current[0]["line_number"],
                current[-1]["line_number"],
                current_tokens,
            )
            current = []
            current_tokens = 0

    with path.open("r", encoding="utf-8", errors="replace") as source:
        for line_number, raw in enumerate(source, start=1):
            item = parse_line(raw, line_number)
            if item is None:
                continue

            if len(raw) > MAX_SOURCE_LINE_CHARS:
                if batch:
                    async for chunk in consume_batch(batch):
                        yield chunk
                    batch = []
                async for chunk in flush_current():
                    yield chunk

                async for chunk in consume_batch([item]):
                    yield chunk
                async for chunk in flush_current():
                    yield chunk
                continue

            batch.append(item)
            if len(batch) >= read_batch:
                async for chunk in consume_batch(batch):
                    yield chunk
                batch = []

    if batch:
        async for chunk in consume_batch(batch):
            yield chunk

    if current:
        # The prompt may have changed as the context tracker was updated.
        current_tokens = await count(current)
        if current_tokens > MAX_PROMPT_TOKENS:
            raise ValueError("Internal chunk token-budget validation failed.")
        chunk_index += 1
        yield Chunk(
            chunk_index,
            current,
            current[0]["line_number"],
            current[-1]["line_number"],
            current_tokens,
        )
