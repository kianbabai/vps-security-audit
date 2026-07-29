"""Scoring and historical snapshot comparison."""

from __future__ import annotations

from typing import Any

from collections import defaultdict

from models import Finding


def calculate_score(findings: list[Finding]) -> tuple[int, str]:
    """Confidence-weighted scoring with diminishing returns per category.

    Repeated variants of the same problem should matter, but should not let a
    noisy collector dominate the entire host score.
    """
    categories: dict[str, list[float]] = defaultdict(list)
    for finding in findings:
        if finding.risk_score is None:
            continue
        categories[finding.category].append(finding.risk_score * finding.confidence / 100)

    penalty = 0.0
    for contributions in categories.values():
        ordered = sorted(contributions, reverse=True)
        if not ordered:
            continue
        category_penalty = ordered[0]
        if len(ordered) > 1:
            category_penalty += ordered[1] * 0.50
        if len(ordered) > 2:
            category_penalty += sum(ordered[2:]) * 0.25
        penalty += min(35.0, category_penalty)

    score = max(0, min(100, round(100 - penalty)))
    return score, risk_level(score)


def risk_level(score: int) -> str:
    if score < 40:
        return "CRITICAL"
    if score < 60:
        return "HIGH"
    if score < 80:
        return "MEDIUM"
    if score < 90:
        return "LOW"
    return "HEALTHY"


def compare_snapshots(previous: dict[str, Any] | None, current: dict[str, Any]) -> list[dict[str, Any]]:
    if not previous:
        return [{"type": "baseline", "severity": "info", "description": "Initial audit baseline created"}]
    old = previous.get("snapshot", {})
    changes: list[dict[str, Any]] = []
    _set_changes(changes, "users", old.get("users", []), current.get("users", []), "user")
    _set_changes(changes, "ports", old.get("ports", []), current.get("ports", []), "listening port")
    _set_changes(changes, "containers", old.get("containers", []), current.get("containers", []), "container")
    _set_changes(changes, "ssh_ips", old.get("ssh_ips", []), current.get("ssh_ips", []), "SSH source IP")
    _set_changes(changes, "persistence", old.get("persistence", []), current.get("persistence", []), "persistence item")

    old_hashes = old.get("file_hashes", {})
    new_hashes = current.get("file_hashes", {})
    for path in sorted(set(old_hashes) & set(new_hashes)):
        if old_hashes[path] != new_hashes[path]:
            changes.append(
                {
                    "type": "changed",
                    "category": "file_integrity",
                    "severity": "high",
                    "description": f"Tracked file changed: {path}",
                }
            )
    return changes


def _set_changes(
    changes: list[dict[str, Any]],
    category: str,
    old_values: list[Any],
    new_values: list[Any],
    label: str,
) -> None:
    old, new = {str(value) for value in old_values}, {str(value) for value in new_values}
    for value in sorted(new - old):
        changes.append(
            {
                "type": "added",
                "category": category,
                "severity": "medium",
                "description": f"New {label}: {value}",
            }
        )
    for value in sorted(old - new):
        changes.append(
            {
                "type": "removed",
                "category": category,
                "severity": "info",
                "description": f"Removed {label}: {value}",
            }
        )
