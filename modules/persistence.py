"""Read-only persistence inventory for systemd and shell startup files."""

from __future__ import annotations

import glob
import re
from pathlib import Path
from typing import Any

from audit_context import AuditContext
from models import Finding, ModuleResult, Severity
from modules.cron import _sanitize

SUSPICIOUS_RE = re.compile(
    r"(?i)(?:curl|wget)\b[^\n|;]*(?:\||;)\s*(?:ba)?sh\b|"
    r"/(?:tmp|var/tmp|dev/shm)/|base64\s+(?:--decode|-d)|\bnc\s+.*\s-e\b|"
    r"\b(?:xmrig|minerd|kinsing|kdevtmpfsi)\b"
)


def audit(context: AuditContext) -> ModuleResult:
    findings: list[Finding] = []
    errors: list[str] = []
    enabled = _enabled_services(context, errors)
    services: list[dict[str, Any]] = []
    suspicious_entries: list[str] = []
    service_paths = sorted({Path(value) for value in glob.glob("/etc/systemd/system/**/*.service", recursive=True)})
    for path in service_paths[:1000]:
        text, error = context.read_text(path, max_bytes=512 * 1024)
        if error:
            errors.append(f"Cannot read {path}: {error}")
            continue
        commands = []
        for number, line in enumerate((text or "").splitlines(), 1):
            if line.strip().lower().startswith(("execstart=", "execstartpre=", "execstartpost=")):
                safe = _sanitize(line.strip())
                commands.append(safe)
                if SUSPICIOUS_RE.search(line):
                    suspicious_entries.append(f"{path}:{number}: {safe[:500]}")
        services.append(
            {
                "unit": path.name,
                "path": str(path),
                "enabled": path.name in enabled,
                "commands": commands,
            }
        )

    startup_files = _startup_files()
    startup_inventory: list[dict[str, Any]] = []
    for path in startup_files:
        text, error = context.read_text(path, max_bytes=512 * 1024)
        if error:
            errors.append(f"Cannot read {path}: {error}")
            continue
        suspicious_lines = []
        for number, line in enumerate((text or "").splitlines(), 1):
            if SUSPICIOUS_RE.search(line):
                safe = _sanitize(line.strip())
                suspicious_lines.append({"line": number, "command": safe[:500]})
                suspicious_entries.append(f"{path}:{number}: {safe[:500]}")
        startup_inventory.append({"path": str(path), "suspicious_lines": suspicious_lines})

    if suspicious_entries:
        findings.append(
            Finding(
                "persistence.suspicious_commands",
                "Suspicious persistence command detected",
                Severity.HIGH,
                "persistence",
                "A systemd unit or shell startup file contains download-and-execute, transient-path, encoding, or miner indicators.",
                "\n".join(suspicious_entries[:50]),
                "Validate ownership and deployment provenance. Preserve the file before removing unauthorized persistence manually.",
                risk_score=42,
                confidence=90,
                reason="Persistence combined with execution from writable paths or remote download pipelines is a strong compromise signal.",
                remediation_commands=[
                    "sudo systemctl cat <unit>",
                    "sudo systemctl status <unit> --no-pager",
                    "sudo journalctl -u <unit> --no-pager",
                ],
            )
        )
    context.snapshots["persistence"] = sorted(
        [f"service:{item['unit']}" for item in services if item["enabled"]]
        + [f"startup:{item['path']}" for item in startup_inventory if item["suspicious_lines"]]
    )
    return ModuleResult(
        "persistence",
        {
            "enabled_services": sorted(enabled),
            "custom_services": services,
            "startup_files": startup_inventory,
        },
        findings,
        errors,
    )


def _enabled_services(context: AuditContext, errors: list[str]) -> set[str]:
    result = context.run(
        ["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--no-pager"]
    )
    if not result.ok:
        errors.append(result.error or result.stderr.strip() or "Cannot list enabled systemd services")
        return set()
    return {line.split()[0] for line in result.stdout.splitlines() if line.split()}


def _startup_files() -> list[Path]:
    candidates = {
        Path("/etc/rc.local"),
        Path("/root/.bashrc"),
        Path("/root/.profile"),
        Path("/etc/profile"),
        *[Path(value) for value in glob.glob("/etc/profile.d/*.sh")],
        *[Path(value) for value in glob.glob("/home/*/.bashrc")],
        *[Path(value) for value in glob.glob("/home/*/.profile")],
    }
    return sorted((path for path in candidates if path.is_file()), key=str)

