from __future__ import annotations

import httpx

from .config import MODEL_BASE_URL, MODEL_TIMEOUT_SECONDS


class LocalModelError(RuntimeError):
    """A request to the local model failed or was incomplete."""


# Keep the grammar intentionally simple; llama.cpp converts this JSON Schema
# into a constrained grammar during generation.
ANALYSIS_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "maxItems": 2,
            "items": {
                "type": "object",
                "properties": {
                    "attack_type": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": ["Low", "Medium", "High", "Critical"],
                    },
                    "ip_or_identifier": {"type": "string"},
                    "target": {"type": "string"},
                    "evidence": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": 2,
                        "items": {
                            "type": "object",
                            "properties": {
                                "line_number": {"type": "integer"},
                                "detail": {"type": "string"},
                            },
                            "required": ["line_number", "detail"],
                            "additionalProperties": False,
                        },
                    },
                    "reason": {"type": "string"},
                    "suggested_action": {"type": "string"},
                    "confidence": {"type": "number"},
                },
                "required": [
                    "attack_type",
                    "severity",
                    "ip_or_identifier",
                    "target",
                    "evidence",
                    "reason",
                    "suggested_action",
                    "confidence",
                ],
                "additionalProperties": False,
            },
        },
        "summary": {"type": "string"},
        "carry_forward": {"type": "string"},
    },
    "required": ["findings", "summary", "carry_forward"],
    "additionalProperties": False,
}


class LocalModelClient:
    """HTTP client for llama.cpp running locally; no cloud AI APIs."""

    def __init__(self, base_url: str = MODEL_BASE_URL):
        self.base_url = base_url.rstrip("/")
        self.timeout = httpx.Timeout(
            MODEL_TIMEOUT_SECONDS,
            connect=5.0,
        )

    async def health(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.base_url}/health")
                return response.status_code == 200
        except httpx.HTTPError:
            return False

    async def count_messages(self, messages: list[dict]) -> int:
        """Count the exact chat-template prompt using the model tokenizer."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                templated = await client.post(
                    f"{self.base_url}/apply-template",
                    json={"messages": messages},
                )
                templated.raise_for_status()

                prompt = templated.json().get("prompt")
                if not isinstance(prompt, str):
                    raise LocalModelError(
                        "llama.cpp /apply-template returned no prompt"
                    )

                counted = await client.post(
                    f"{self.base_url}/tokenize",
                    json={
                        "content": prompt,
                        "add_special": True,
                        "parse_special": True,
                    },
                )
                counted.raise_for_status()

                tokens = counted.json().get("tokens")
                if not isinstance(tokens, list):
                    raise LocalModelError(
                        "llama.cpp /tokenize returned no token list"
                    )

                return len(tokens)

            except LocalModelError:
                raise
            except httpx.HTTPError as exc:
                raise LocalModelError(
                    f"Local tokenizer request failed: {exc}"
                ) from exc
            except (ValueError, KeyError, TypeError) as exc:
                raise LocalModelError(
                    f"Unexpected tokenizer response: {exc}"
                ) from exc

    async def chat_json(
        self,
        messages: list[dict],
        max_tokens: int = 320,
    ) -> str:
        payload = {
            "model": "local-model",
            "messages": messages,
            "temperature": 0.0,
            "top_p": 0.9,
            "max_tokens": max_tokens,
            "stream": False,
            "response_format": {
                "type": "json_schema",
                "schema": ANALYSIS_JSON_SCHEMA,
            },
        }

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(
                    f"{self.base_url}/v1/chat/completions",
                    json=payload,
                )
                response.raise_for_status()

                body = response.json()
                choice = body["choices"][0]
                finish_reason = choice.get("finish_reason")

                if finish_reason == "length":
                    usage = body.get("usage", {})
                    used = usage.get("completion_tokens", "unknown")
                    raise LocalModelError(
                        "Model output was truncated at the output-token "
                        f"limit ({used} completion tokens)."
                    )

                if finish_reason not in (None, "stop"):
                    raise LocalModelError(
                        f"Model did not finish normally: {finish_reason}"
                    )

                message = choice["message"]
                content = message.get("content")

                # Do not concatenate reasoning_content into the JSON.
                if isinstance(content, list):
                    content = "".join(
                        part.get("text", "")
                        for part in content
                        if isinstance(part, dict)
                    )

                if not isinstance(content, str) or not content.strip():
                    raise LocalModelError(
                        "Local model returned an empty final message."
                    )

                return content

            except LocalModelError:
                raise
            except httpx.HTTPError as exc:
                raise LocalModelError(
                    f"Local model HTTP request failed: {exc}"
                ) from exc
            except (ValueError, KeyError, IndexError, TypeError) as exc:
                raise LocalModelError(
                    f"Unexpected local model response: {exc}"
                ) from exc
