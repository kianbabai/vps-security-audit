"""Typed data structures shared by every audit module."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


DEFAULT_RISK_SCORES: dict[Severity, int] = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 18,
    Severity.MEDIUM: 10,
    Severity.LOW: 4,
    Severity.INFO: 0,
}


@dataclass(slots=True)
class Finding:
    finding_id: str
    title: str
    severity: Severity
    category: str
    description: str
    evidence: str
    recommendation: str
    metadata: dict[str, Any] = field(default_factory=dict)
    risk_score: int | None = None
    confidence: int = 80
    reason: str = ""
    remediation_commands: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.risk_score is None:
            self.risk_score = DEFAULT_RISK_SCORES[self.severity]
        self.risk_score = max(0, min(100, int(self.risk_score)))
        self.confidence = max(0, min(100, int(self.confidence)))

    def to_dict(self) -> dict[str, Any]:
        item = asdict(self)
        item["severity"] = self.severity.value
        item["what_happened"] = self.description
        item["why_it_matters"] = self.reason or self.description
        item["how_to_fix"] = self.recommendation
        return item


@dataclass(slots=True)
class ModuleResult:
    name: str
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "data": self.data,
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": self.errors,
            "duration_ms": self.duration_ms,
        }


@dataclass(slots=True)
class AuditReport:
    scan_id: str
    generated_at: str
    hostname: str
    score: int
    risk_level: str
    module_results: list[ModuleResult]
    findings: list[Finding]
    changes: list[dict[str, Any]]
    previous_score: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def timestamp(cls) -> str:
        return datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "scan_id": self.scan_id,
            "generated_at": self.generated_at,
            "hostname": self.hostname,
            "score": self.score,
            "risk_level": self.risk_level,
            "previous_score": self.previous_score,
            "summary": severity_counts(self.findings),
            "changes": self.changes,
            "findings": [finding.to_dict() for finding in self.findings],
            "modules": [result.to_dict() for result in self.module_results],
            "metadata": self.metadata,
        }


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {severity.value: 0 for severity in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts
