"""Runtime context and safe, read-only command execution."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence


@dataclass(slots=True)
class CommandResult:
    command: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and self.error is None


@dataclass(slots=True)
class AuditContext:
    config: dict[str, Any]
    previous_scan: dict[str, Any] | None
    logger: logging.Logger
    snapshots: dict[str, Any] = field(default_factory=dict)

    def run(self, command: Sequence[str], timeout: int | None = None) -> CommandResult:
        """Run an argument-vector command without a shell or stdin."""
        argv = [str(part) for part in command]
        if not argv or shutil.which(argv[0]) is None:
            return CommandResult(argv, None, "", "", f"Command not available: {argv[0] if argv else '<empty>'}")
        limit = int(self.config["audit"]["max_output_bytes"])
        command_timeout = timeout or int(self.config["audit"]["command_timeout_seconds"])
        env = {
            "PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
            "LANG": "C",
            "LC_ALL": "C",
        }
        try:
            with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
                process = subprocess.Popen(
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    env=env,
                )
                timed_out = False
                try:
                    process.wait(timeout=command_timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    process.kill()
                    process.wait()
                stdout_file.seek(0)
                stderr_file.seek(0)
                stdout = stdout_file.read(limit).decode("utf-8", errors="replace")
                stderr = stderr_file.read(limit).decode("utf-8", errors="replace")
                return CommandResult(
                    argv,
                    process.returncode,
                    stdout,
                    stderr,
                    "Command timed out" if timed_out else None,
                )
        except OSError as exc:
            return CommandResult(argv, None, "", "", f"Command failed: {exc}")

    def read_text(self, path: Path, max_bytes: int | None = None) -> tuple[str | None, str | None]:
        limit = max_bytes or int(self.config["audit"]["max_output_bytes"])
        try:
            with path.open("rb") as handle:
                raw = handle.read(limit + 1)
            suffix = "\n[truncated]" if len(raw) > limit else ""
            return raw[:limit].decode("utf-8", errors="replace") + suffix, None
        except (OSError, PermissionError) as exc:
            return None, str(exc)

    def tail_lines(self, path: Path, max_lines: int) -> tuple[list[str], str | None]:
        """Read recent text lines with bounded memory, seeking from the file end."""
        limit = int(self.config["audit"]["max_output_bytes"])
        block_size = 64 * 1024
        try:
            with path.open("rb") as handle:
                handle.seek(0, os.SEEK_END)
                position = handle.tell()
                chunks: list[bytes] = []
                byte_count = 0
                newline_count = 0
                while position > 0 and byte_count < limit and newline_count <= max_lines:
                    size = min(block_size, position, limit - byte_count)
                    position -= size
                    handle.seek(position)
                    chunk = handle.read(size)
                    chunks.append(chunk)
                    byte_count += len(chunk)
                    newline_count += chunk.count(b"\n")
            text = b"".join(reversed(chunks)).decode("utf-8", errors="replace")
            return text.splitlines()[-max_lines:], None
        except (OSError, PermissionError) as exc:
            return [], str(exc)
