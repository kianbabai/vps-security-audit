"""System and user scheduled-task inspection."""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path
from typing import Any

from audit_context import AuditContext
from models import Finding, ModuleResult, Severity


def audit(context: AuditContext) -> ModuleResult:
    config = context.config["cron"]
    findings: list[Finding] = []
    errors: list[str] = []
    jobs: list[dict[str, Any]] = []
    suspicious: list[str] = []
    patterns = [str(pattern).lower() for pattern in config["suspicious_patterns"]]
    for configured in config["paths"]:
        root = Path(configured)
        candidates = [root] if root.is_file() else _limited_files(root)
        for path in candidates:
            text, error = context.read_text(path, max_bytes=256 * 1024)
            if error:
                errors.append(f"Cannot read {path}: {error}")
                continue
            for number, raw in enumerate((text or "").splitlines(), 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                safe_line = _sanitize(line)
                entry = {"source": str(path), "line": number, "command": safe_line[:1000]}
                jobs.append(entry)
                if any(fnmatch.fnmatch(line.lower(), f"*{pattern}*") for pattern in patterns):
                    suspicious.append(f"{path}:{number}: {safe_line[:300]}")
    if suspicious:
        findings.append(
            Finding(
                "cron.suspicious_command",
                "Suspicious scheduled command pattern",
                Severity.HIGH,
                "cron",
                "Scheduled commands reference transient directories, download-and-execute patterns, or shell payload tools.",
                "\n".join(suspicious[:20]),
                "Validate each task owner and purpose; remove unauthorized jobs manually after investigation.",
            )
        )
    return ModuleResult("cron", {"jobs": jobs, "job_count": len(jobs)}, findings, errors)


def _limited_files(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    result: list[Path] = []
    try:
        for directory, names, files in os.walk(root):
            names[:] = names[:100]
            for filename in files[:1000]:
                path = Path(directory) / filename
                if path.is_file():
                    result.append(path)
                if len(result) >= 5000:
                    return result
    except OSError:
        return result
    return result


def _sanitize(line: str) -> str:
    """Redact common secret assignments before cron content enters a report."""
    value = re.sub(
        r"(?i)\b([A-Z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|PRIVATE_KEY)[A-Z0-9_]*)"
        r"\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s]+)",
        r"\1=[REDACTED]",
        line,
    )
    value = re.sub(
        r"(?i)(--?(?:password|passwd|token|secret|api[-_]?key|private[-_]?key))\s+\S+",
        r"\1 [REDACTED]",
        value,
    )
    value = re.sub(r"(?i)([?&](?:token|key|secret|password)=)[^&\s]+", r"\1[REDACTED]", value)
    return re.sub(r"(https?://[^:/\s]+:)[^@\s]+@", r"\1[REDACTED]@", value)
