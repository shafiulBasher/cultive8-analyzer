from __future__ import annotations

from typing import Literal, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["Low", "Medium", "High", "Critical"]


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="ignore")

    line_number: int = Field(ge=1)
    detail: str = Field(min_length=2, max_length=300)


class Finding(BaseModel):
    model_config = ConfigDict(extra="ignore")

    attack_type: str = Field(min_length=2, max_length=100)
    severity: Severity
    ip_or_identifier: str = Field(min_length=1, max_length=100)
    target: str = Field(default="", max_length=120)
    evidence: list[EvidenceItem] = Field(min_length=1, max_length=2)
    reason: str = Field(min_length=2, max_length=300)
    suggested_action: str = Field(min_length=2, max_length=300)
    confidence: float = Field(default=0.65, ge=0, le=1)

    @field_validator("confidence", mode="before")
    @classmethod
    def normalize_confidence(cls, value: Any) -> Any:
        # Small models sometimes return confidence as 0-100 instead of 0-1.
        if isinstance(value, (int, float)) and 1 < value <= 100:
            return value / 100
        return value

    @field_validator("evidence")
    @classmethod
    def unique_evidence_lines(
        cls,
        value: list[EvidenceItem],
    ) -> list[EvidenceItem]:
        seen: set[int] = set()
        result: list[EvidenceItem] = []

        for item in value:
            if item.line_number not in seen:
                result.append(item)
                seen.add(item.line_number)

        return result


class AnalysisResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    findings: list[Finding] = Field(default_factory=list, max_length=2)
    summary: str = Field(default="", max_length=200)
    carry_forward: str = Field(default="", max_length=200)
