"""Hash and permission monitoring for security-sensitive files."""

from __future__ import annotations

import glob
import hashlib
from pathlib import Path
from typing import Any

from audit_context import AuditContext
from models import Finding, ModuleResult, Severity


def audit(context: AuditContext) -> ModuleResult:
    config = context.config["filesystem"]
    findings: list[Finding] = []
    errors: list[str] = []
    paths = {Path(item) for item in config["tracked_paths"]}
    for pattern in config["tracked_globs"]:
        paths.update(Path(item) for item in glob.glob(pattern, recursive=True))
    hashes: dict[str, str] = {}
    files: list[dict[str, Any]] = []
    max_size = int(config["max_file_size_bytes"])
    sensitive_names = {"shadow", "sudoers", "wp-config.php"}
    for path in sorted(paths, key=str):
        if not path.is_file():
            continue
        try:
            stat = path.stat()
            mode = stat.st_mode & 0o777
            if stat.st_size > max_size:
                errors.append(f"Skipped oversized tracked file: {path}")
                continue
            digest = _sha256(path)
            hashes[str(path)] = digest
            files.append(
                {
                    "path": str(path),
                    "sha256": digest,
                    "size": stat.st_size,
                    "mode": oct(mode),
                    "owner_uid": stat.st_uid,
                    "modified_ns": stat.st_mtime_ns,
                }
            )
            if path.name in sensitive_names and mode & 0o007:
                findings.append(
                    Finding(
                        f"filesystem.world_accessible.{str(path).replace('/', '_')}",
                        "Sensitive file is accessible to all local users",
                        Severity.HIGH,
                        "filesystem",
                        "The tracked file may contain credentials or security policy.",
                        f"{path} mode {oct(mode)}",
                        "Restrict permissions and verify the required service account retains access.",
                    )
                )
        except (OSError, PermissionError) as exc:
            errors.append(f"Cannot hash {path}: {exc}")
    context.snapshots["file_hashes"] = hashes
    return ModuleResult("filesystem", {"tracked_files": files}, findings, errors)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
