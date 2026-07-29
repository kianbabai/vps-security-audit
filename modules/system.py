"""Host operating-system and capacity inventory."""

from __future__ import annotations

import os
import platform
import shutil
import socket
import urllib.request
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from audit_context import AuditContext
from models import Finding, ModuleResult, Severity


def audit(context: AuditContext) -> ModuleResult:
    data: dict[str, Any] = {
        "hostname": socket.gethostname(),
        "os": _os_release(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "cpu": _cpu_info(),
        "memory": _memory_info(),
        "uptime_seconds": _uptime(),
        "disks": _disk_usage(),
    }
    findings: list[Finding] = []
    errors: list[str] = []
    config = context.config["system"]

    for disk in data["disks"]:
        percent = disk["percent_used"]
        if percent >= int(config["disk_critical_percent"]):
            severity = Severity.HIGH
        elif percent >= int(config["disk_warning_percent"]):
            severity = Severity.MEDIUM
        else:
            continue
        findings.append(
            Finding(
                f"system.disk_usage.{disk['mount'].replace('/', '_') or 'root'}",
                f"High disk usage on {disk['mount']}",
                severity,
                "system",
                "A nearly full filesystem can interrupt logging, updates, and container workloads.",
                f"{percent:.1f}% used ({disk['used_bytes']} of {disk['total_bytes']} bytes)",
                "Remove unneeded data after review or expand the filesystem capacity.",
            )
        )

    packages = _packages(context)
    data["installed_packages_count"] = len(packages)
    if context.config["audit"].get("include_package_list", False):
        data["installed_packages"] = packages

    if config.get("public_ip_lookup", False):
        try:
            request = urllib.request.Request(str(config["public_ip_url"]), headers={"User-Agent": "vps-security-audit/1"})
            with urllib.request.urlopen(request, timeout=5) as response:
                public_ip = response.read(128).decode("ascii", errors="replace").strip()
                data["public_ip"] = str(ip_address(public_ip))
        except Exception as exc:  # network failures must not abort an audit
            errors.append(f"Public IP lookup failed: {exc}")
    else:
        data["public_ip"] = None

    context.snapshots["hostname"] = data["hostname"]
    return ModuleResult("system", data, findings, errors)


def _os_release() -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                result[key.lower()] = value.strip().strip('"')
    except OSError:
        result["name"] = platform.system()
        result["pretty_name"] = platform.platform()
    return result


def _cpu_info() -> dict[str, Any]:
    model = platform.processor() or "unknown"
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace").splitlines():
            if line.lower().startswith("model name"):
                model = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    return {"model": model, "logical_cpus": os.cpu_count()}


def _memory_info() -> dict[str, int | float | None]:
    values: dict[str, int] = {}
    try:
        for line in Path("/proc/meminfo").read_text(encoding="ascii", errors="replace").splitlines():
            key, raw = line.split(":", 1)
            values[key] = int(raw.strip().split()[0]) * 1024
    except (OSError, ValueError):
        return {"total_bytes": None, "available_bytes": None, "percent_used": None}
    total, available = values.get("MemTotal", 0), values.get("MemAvailable", 0)
    percent = ((total - available) / total * 100) if total else None
    return {"total_bytes": total, "available_bytes": available, "percent_used": percent}


def _uptime() -> float | None:
    try:
        return float(Path("/proc/uptime").read_text(encoding="ascii").split()[0])
    except (OSError, ValueError, IndexError):
        return None


def _disk_usage() -> list[dict[str, Any]]:
    mounts = [Path("/")]
    for candidate in (Path("/var"), Path("/srv"), Path("/opt")):
        if candidate.exists() and os.path.ismount(candidate):
            mounts.append(candidate)
    result = []
    for mount in mounts:
        try:
            usage = shutil.disk_usage(mount)
            result.append(
                {
                    "mount": str(mount),
                    "total_bytes": usage.total,
                    "used_bytes": usage.used,
                    "free_bytes": usage.free,
                    "percent_used": usage.used / usage.total * 100 if usage.total else 0,
                }
            )
        except OSError:
            continue
    return result


def _packages(context: AuditContext) -> list[str]:
    result = context.run(["dpkg-query", "-W", "-f=${binary:Package}\\t${Version}\\n"])
    if result.ok:
        return [line for line in result.stdout.splitlines() if line]
    result = context.run(["rpm", "-qa"])
    return [line for line in result.stdout.splitlines() if line] if result.ok else []
