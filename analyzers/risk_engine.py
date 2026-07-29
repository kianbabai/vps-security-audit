"""Scoring and historical snapshot comparison."""

from __future__ import annotations

from typing import Any

from models import Finding, PENALTIES


def calculate_score(findings: list[Finding]) -> tuple[int, str]:
    score = max(0, 100 - sum(PENALTIES[finding.severity] for finding in findings))
    if score < 40:
        level = "CRITICAL"
    elif score < 70:
        level = "WARNING"
    else:
        level = "GOOD"
    return score, level


def compare_snapshots(previous: dict[str, Any] | None, current: dict[str, Any]) -> list[dict[str, Any]]:
    if not previous:
        return [{"type": "baseline", "severity": "info", "description": "Initial audit baseline created"}]
    old = previous.get("snapshot", {})
    changes: list[dict[str, Any]] = []
    _set_changes(changes, "users", old.get("users", []), current.get("users", []), "user")
    _set_changes(changes, "ports", old.get("ports", []), current.get("ports", []), "listening port")
    _set_changes(changes, "containers", old.get("containers", []), current.get("containers", []), "container")
    _set_changes(changes, "ssh_ips", old.get("ssh_ips", []), current.get("ssh_ips", []), "SSH source IP")

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

