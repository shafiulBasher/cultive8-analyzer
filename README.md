# Cultive8 — Local AI Security Log Analyzer

A small, local-only web application for analyzing `.log` and `.txt` server logs with a downloaded GGUF language model. It uses FastAPI, SQLite and `llama.cpp`; log content is never sent to a cloud AI API.

## Features

- Upload `.log` or `.txt` files (25 MB upload limit).
- JSON Lines parsing with original source line numbers; unstructured text lines are retained as raw log data.
- Line-preserving chunking. Before a chunk is sent, the app formats the exact chat prompt with llama.cpp `/apply-template` and counts it with the selected model's `/tokenize` endpoint.
- 2,048-token call budget: prompt is capped at 1,632 tokens, generation at 320 tokens, and 96 tokens are reserved as a safety margin for every chunk and candidate-review call.
- Sequential inference (`asyncio.Lock`) to prevent concurrent model calls from competing for RAM.
- Schema-constrained JSON responses, per-finding validation, a safe retry for transient model-call failures, and preservation of source-rule findings if a model call fails.
- A full-file source detector creates evidence-backed candidate alerts; the local model analyzes all chunks and then reviews each candidate in a focused second pass. AI corroboration requires at least two distinct matching source records.
- SQLite persistence for jobs, chunk progress, and findings.
- Evidence line numbers, severity, entity/IP, reason, and suggested action in the final report.
- A local dashboard with progress and JSON export.

## Requirements

- Windows 10/11, macOS, or Linux.
- Python 3.11 recommended.
- `llama.cpp` with its server executable/CLI available as `llama`.
- Approximately 563 MB for the selected Q4_0 model download, plus runtime memory for the model, KV cache, backend and OS. Measure actual use on the assessment machine; the weight-file size alone is not the full RAM requirement.
- The assessment target is 4 GB total RAM, 2 CPU threads, and no GPU. The provided model command explicitly uses CPU (`-ngl 0`), two threads and one parallel slot.

## 1. Install llama.cpp

In a new PowerShell terminal:

```powershell
winget install llama.cpp
```

Open a new terminal afterwards and verify:

```powershell
llama --version
```

## 2. Download and start the local model

From the project root:

```powershell
.\scripts\start_model.ps1
```

The script starts:

- Model: `ggml-org/Qwen3.5-0.8B-GGUF`
- Quantization: `Q4_0` (563 MB file at the time this project was prepared)
- Context: 2,048 tokens
- CPU threads: 2
- Parallel requests: 1
- GPU layers: 0
- Reasoning mode: off (keeps the small output budget focused on JSON findings)
- Special-token escaping for input text (additional guard against model control-token injection from logs)
- Local server: `http://127.0.0.1:8080`

The first run needs internet access to download the model. After the model is cached, run llama.cpp with network disconnected to verify offline operation. Do not close this terminal while analyzing logs.

Check local model health in another terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:8080/health
```

It should return `status: ok` when the model is ready.

## 3. Start the web application

Open a second PowerShell terminal in the project root:

```powershell
.\scripts\start_app.ps1
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000).

The app checks the local model at `http://127.0.0.1:8080`. If it is offline, analysis stops with an actionable error and previously completed job data remains stored.

## 4. Use the application

1. Select or drop a `.log` / `.txt` file.
2. Click **Run security analysis**.
3. Watch the chunk count and status.
4. Watch live pipeline stages, successful/failed chunk counts, elapsed time, recent source-line ranges, and the final per-candidate AI review status. The dashboard starts clean on page load so a stale job is not silently restored.
5. Review the consolidated findings and any warnings about incomplete chunks or skipped correlation.
6. Export the final report as JSON.

The SQLite database and uploaded files are saved under `data/`. Remove that folder to clear local job data after preserving any report you need.

## Architecture

```text
Browser
  └── FastAPI upload / progress API
        ├── Upload validation + disk-backed file storage
        ├── Token-aware, line-preserving chunker
        │     └── llama.cpp /apply-template + /tokenize
        ├── Sequential local model calls
        │     └── llama.cpp /v1/chat/completions (JSON mode)
        ├── Pydantic validation of model output
        ├── Compact entity/event context across chunks
        ├── Focused AI review of source-rule candidates
        ├── Exact source-line, entity, and attack-family verification
        ├── Rule-only vs AI-corroborated report labels
        └── SQLite progress + final report
```

### Chunking method

Each non-empty source line is parsed as one JSON record when possible; otherwise it remains a raw text record. The chunker greedily appends whole records while the *complete, model-formatted prompt* stays at or below 1,632 tokens. The tokenizer is the tokenizer loaded by llama.cpp for the selected GGUF model. Original physical line numbers are attached before chunking and never renumbered. Each call reserves 320 output tokens and 96 safety tokens. The same budget check applies to the focused candidate-review calls. If one record alone exceeds the prompt budget, the job fails clearly rather than silently cutting or losing that record.

### Source detection and AI review

A deterministic detector scans the complete original file first. It identifies candidate patterns (for example repeated authentication failures, SQL-like request values, traversal sequences, sensitive endpoint probes, and repeated rate-limit responses), correlates events by source identity, and constructs evidence using original physical line numbers. These detector outputs are explicitly **source-rule candidates**, not AI-generated findings.

The local model then analyzes every token-bounded chunk sequentially with compact carry-forward context. After chunk processing, the model receives one focused review call per source-rule candidate, together with the exact original JSONL rows cited by the detector. It must independently accept or reject that candidate and cite at least two distinct source lines. The backend re-reads those lines and verifies the source IP, attack family, and event semantics. Only then is a finding labeled **AI CORROBORATED**. Source findings that the model does not corroborate remain visible as **SOURCE-RULED ONLY**; they are never silently discarded.

The report separates source-rule candidate count, chunk-model proposals, candidate-review proposals, AI-corroborated findings, and rule-only findings. This distinction prevents successful chunk processing from being misrepresented as successful AI threat discovery.

### Prompt-injection protection

Log entries are explicitly marked as untrusted data in the system prompt. The model is told not to follow instructions found in values such as `submitted_text`, URLs, user agents, or application messages. The analyzer does not execute log commands or shell content.

## Supplied assessment log: useful validation cases

The provided `Cultive8_Workspace_Agrigen_Server.log` was inspected as 258 valid JSONL records (94,398 bytes). Keep the source file local and upload it through the dashboard; it is intentionally not committed to this repository.

| Source lines | Pattern to validate | Important interpretation |
|---|---|---|
| 5, 13, 23, 35, 50, 65, 80, 94, 108, 123, 153, 189, 196, 198, 201 | Twelve failed `workspace.admin` logins from `203.0.113.44`, then a successful login and later 200 responses for admin/export paths | Correlate across chunks; distinguish evidence of authentication from proof of data theft. |
| 29, 30, 32, 222–223 | SQL-like query payloads from `203.0.113.72` | Lines 222–223 share the same event ID and should not become two independent incidents. |
| 54, 56, 58, 60, 62, 64, 67, 69, 99, 101, 102 | Sensitive-path probes and traversal/admin-path attempts from `203.0.113.90` | Most probes were rejected (403/404); describe them as attempted/probed, not successful exploitation. |
| 162–170 | Nine HTTP 429 responses from `203.0.113.155` within 1.6 seconds | Evaluate request-rate abuse using timing and response sequence. |
| 217 | A support-message field contains instruction-like text | It is untrusted log data and must not alter the analysis prompt. |
| 134–141 | Planned release followed by temporary 503 responses and successful health checks | This is an operational deployment pattern, not automatically an attack. |
| 238–239 | One failed login followed by success for `field.officer` from `198.51.100.96` | A single retry is not, by itself, proof of brute force or compromise. |

These are source-supported validation cases, not hardcoded IPs or line-number outputs. The source detector extracts candidates dynamically, and the local model receives all chunks plus focused source-record reviews. The report must cite original lines and clearly label whether the model corroborated each candidate.

## API

- `GET /api/health` — backend and local-model availability.
- `POST /api/analyze` — multipart upload; returns a job ID.
- `GET /api/jobs/{job_id}` — status, chunk progress, and current findings.
- `GET /api/jobs/{job_id}/report` — JSON report.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The included automated suite currently has 16 passing tests. The cross-chunk pipeline test uses a mock model to test orchestration and persistence; it does not stand in for a live Qwen inference run.

## Known limitations / unfinished work

- This is a practical assessment MVP, not a production SIEM. Its model output quality depends on a small 0.8B model; verify high-impact findings manually.
- The model may still reject a rule candidate or return no proposals. A 0.8B model is a constrained reviewer, not a production-grade autonomous threat detector. The report explicitly marks source-rule-only versus AI-corroborated findings.
- If one physical log entry by itself exceeds the usable prompt budget, the current behavior is to stop that job with the exact line number rather than fragment the entry.
- Per-job restart/resume is not implemented. Job status and completed chunks are persisted, but the background task does not automatically resume after a process restart.
- No multi-user authentication or remote deployment is provided. The app binds to localhost by default.
- RAM use is bounded operationally by a small quantized model, 2 CPU threads, one model slot, short context, and sequential jobs, but should be measured on the actual machine.
- The project tests use a mocked local model to test orchestration/cross-chunk behavior. Before submission, run the full sample log through the actual downloaded Qwen model on the assessment machine and inspect its results.
- A completed report can contain source-rule findings with zero AI corroborations. That means the model did not confirm those candidates; it must not be presented as AI-generated discovery or as a guarantee that the system is safe.


### Dashboard progress behavior

The pipeline indicator is driven by the backend job phase rather than a hard-coded active step. It advances through parsing/tokenizing, per-chunk model analysis, candidate AI review/correlation, and final report generation. The progress bar is intentionally indeterminate while streaming chunks because the tokenizer discovers chunk boundaries as it reads the file; it reaches 100% only when the job is terminal. The live panel shows attempted, successful, and failed chunk counts, elapsed time, and recent chunk line ranges. Failed chunks are surfaced as warnings and are never presented as a clean report.
