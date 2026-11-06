# AI_USAGE.md

## AI tools used

- ChatGPT (OpenAI, GPT-6) assisted with architecture design, code generation/review, debugging, test design, and documentation.
- The application uses the local `ggml-org/Qwen3.5-0.8B-GGUF:Q4_0` model through `llama.cpp`. No cloud AI API is called by the application.
- The supplied log is kept local and is uploaded only to the local FastAPI service.

## What the AI does

The application is a **hybrid source-rule + local-AI review system**. It does not claim that the small model independently discovered every final finding.

1. A deterministic source detector scans the complete JSONL file, deduplicates repeated events, correlates source IP/account behavior across the whole file, and creates evidence-backed candidate alerts. Its patterns and thresholds are general rules; IP addresses, line numbers, and event values are extracted dynamically from the uploaded source.
2. Qwen analyzes every sequential, token-bounded chunk and carries compact facts across chunk boundaries. This stage can propose additional findings, but proposals are not trusted as facts.
3. Qwen then receives one focused review call per source-rule candidate, together with the exact original source rows for that candidate. It is asked to accept or reject the hypothesis and cite at least two distinct lines.
4. The backend re-reads each cited line and checks that the source IP, attack family, and event semantics match. A candidate is marked `AI CORROBORATED` only after those checks pass. A rule finding not confirmed by the model remains visible as `SOURCE-RULED ONLY`.
5. The exported report exposes separate counts for rule-based findings, chunk model proposals, candidate-review proposals, AI-corroborated findings, and rule-only findings. A successful chunk call is not counted as an AI finding.

## Prompt and safety design

- Log content is untrusted data, never instructions. The prompts explicitly reject instructions embedded in log fields.
- HTTP 4xx/5xx responses alone do not establish an attack or successful exploitation.
- The model must cite exact line numbers from the supplied source rows. The backend verifies those lines again from the original file.
- Candidate review requires at least two distinct matching source records. For a password-guessing sequence followed by success, the cited records must include a failed and later successful login for the same IP/account.
- Model-generated severity, evidence wording, and recommended actions do not overwrite the source detector's validated report details.

## Token budget

Every model call uses the 2,048-token context limit. The application counts the formatted prompt using llama.cpp `/apply-template` and `/tokenize`.

| Budget item | Tokens |
|---|---:|
| Maximum prompt | 1,632 |
| Maximum generated output | 320 |
| Safety reserve | 96 |
| **Total** | **2,048** |

Chunk analysis and candidate-review calls are sequential. The application uses one model slot and two CPU threads; no GPU is required.

## Validation and known limits

- Automated tests in this patched source tree: 16 passing tests.
- The supplied assessment log contains 258 physical source records and is processed in 24 chunks on the target machine.
- On the first live Qwen run before the focused candidate-review stage was added, all 24 chunk requests succeeded but the model returned zero findings and zero corroborations. The five findings in that report came from the deterministic source detector.
- The candidate-review stage is designed to let Qwen independently adjudicate those rule candidates; its actual success count must be read from the next live report. Do not claim AI corroboration until `ai_corroborated_findings` is greater than zero and the corresponding findings are marked accordingly.
- A 0.8B quantized model can miss subtle attacks. Findings require human review before operational action. This MVP is not a production SIEM.
- The 4 GB memory target must be measured on the assessment machine under inference, not inferred from idle memory.

## AI-assisted development

ChatGPT was used to draft and refine the application code, security prompts, tests, and project documentation. The final source files and test results should be reviewed by the assessment candidate. The implementation and report must be described honestly as hybrid detection and AI review, not as fully autonomous AI threat detection.
