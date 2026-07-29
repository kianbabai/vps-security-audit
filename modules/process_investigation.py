"""Context-aware Linux process investigation and compromise signal analysis."""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from audit_context import AuditContext
from models import Finding, ModuleResult, Severity
from modules.cron import _sanitize

TRUSTED_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/usr/lib/")
TRANSIENT_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")
SECRET_RE = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|PRIVATE_KEY)[A-Z0-9_]*)"
    r"=([^\s]+)"
)


def audit(context: AuditContext) -> ModuleResult:
    config = context.config["process"]
    findings: list[Finding] = []
    errors: list[str] = []
    process_result = context.run(["ps", "-eo", "pid=,ppid=,user=,pcpu=,pmem=,lstart=,comm="])
    if not process_result.ok:
        errors.append(process_result.error or process_result.stderr.strip() or "Process list unavailable")
        return ModuleResult("process", {"investigations": []}, findings, errors)

    sockets = _process_sockets(context)
    names = {str(name).lower() for name in config["suspicious_process_names"]}
    cpu_threshold = float(config["high_cpu_percent"])
    investigations: list[dict[str, Any]] = []
    for line in process_result.stdout.splitlines():
        item = _parse_ps(line)
        if not item:
            continue
        pid = item["pid"]
        item["executable"] = _readlink(Path(f"/proc/{pid}/exe"))
        item["working_directory"] = _readlink(Path(f"/proc/{pid}/cwd"))
        item["command"] = _command(pid, item["name"])
        item["open_ports"] = sockets["listeners"].get(pid, [])
        item["network_connections"] = sockets["connections"].get(pid, [])
        item["parent_tree"] = _parent_tree(pid)
        item["systemd_unit"] = _systemd_unit(pid)

        clean_path = str(item["executable"] or "").removesuffix(" (deleted)")
        suspicious_path = clean_path.startswith(TRANSIENT_PREFIXES)
        hidden_path = _has_hidden_component(clean_path)
        deleted = str(item["executable"] or "").endswith(" (deleted)")
        known_name = item["name"].lower() in names
        public_listener = any(port["public"] and not port.get("expected", False) for port in item["open_ports"])
        high_cpu = item["cpu_percent"] >= cpu_threshold
        if not any((suspicious_path, hidden_path, deleted, known_name, public_listener, high_cpu)):
            continue

        package_owner = _package_owner(context, clean_path)
        item["package_owner"] = package_owner
        unit_path = Path("/etc/systemd/system") / str(item["systemd_unit"] or "")
        item["custom_systemd_service"] = bool(
            item["systemd_unit"]
            and unit_path.exists()
            and (not unit_path.is_symlink() or str(unit_path.resolve()).startswith("/etc/systemd/system/"))
        )
        assessment = _assess(item, suspicious_path, hidden_path, deleted, known_name, high_cpu)
        item.update(assessment)
        investigations.append(item)
        findings.append(_finding(item))

    investigations.sort(key=lambda item: (-item["risk_score"], item["pid"]))
    return ModuleResult(
        "process",
        {
            "investigated_processes": len(investigations),
            "investigations": investigations,
            "methodology": (
                "Candidates are contextualized using executable location, package ownership, parent tree, "
                "systemd ownership, user identity, public listeners, and active connections."
            ),
        },
        findings,
        errors,
    )


def _parse_ps(line: str) -> dict[str, Any] | None:
    parts = line.split(None, 10)
    if len(parts) < 11:
        return None
    try:
        return {
            "pid": int(parts[0]),
            "ppid": int(parts[1]),
            "user": parts[2],
            "cpu_percent": float(parts[3]),
            "memory_percent": float(parts[4]),
            "start_time": " ".join(parts[5:10]),
            "name": parts[10],
        }
    except ValueError:
        return None


def _process_sockets(context: AuditContext) -> dict[str, dict[int, list[dict[str, Any]]]]:
    listeners: dict[int, list[dict[str, Any]]] = defaultdict(list)
    connections: dict[int, list[dict[str, Any]]] = defaultdict(list)
    expected_ports = {int(value) for value in context.config["network"]["expected_public_ports"]}
    listening = context.run(["ss", "-H", "-lntup"])
    if listening.ok:
        for line in listening.stdout.splitlines():
            parts = line.split(None, 6)
            if len(parts) < 5:
                continue
            endpoint = parts[4]
            host, port = _endpoint(endpoint)
            for pid in _pids(line):
                listeners[pid].append(
                    {
                        "protocol": parts[0],
                        "address": host,
                        "port": port,
                        "public": host in {"0.0.0.0", "::", "*", "[::]"},
                        "expected": port in expected_ports if port is not None else False,
                    }
                )
    established = context.run(["ss", "-H", "-ntup", "state", "established"])
    if established.ok:
        for line in established.stdout.splitlines():
            parts = line.split(None, 6)
            if len(parts) < 5:
                continue
            local = parts[3] if len(parts) == 6 else parts[4]
            remote = parts[4] if len(parts) == 6 else parts[5]
            for pid in _pids(line):
                connections[pid].append({"local": local, "remote": remote, "protocol": parts[0]})
    return {"listeners": dict(listeners), "connections": dict(connections)}


def _pids(line: str) -> set[int]:
    return {int(value) for value in re.findall(r"pid=(\d+)", line)}


def _endpoint(value: str) -> tuple[str, int | None]:
    if value.startswith("[") and "]:" in value:
        host, raw_port = value.rsplit("]:", 1)
        host += "]"
    elif ":" in value:
        host, raw_port = value.rsplit(":", 1)
    else:
        return value, None
    try:
        return host, int(raw_port)
    except ValueError:
        return host, None


def _readlink(path: Path) -> str | None:
    try:
        return str(path.readlink())
    except OSError:
        return None


def _command(pid: int, fallback: str) -> str:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()[:8192]
        value = " ".join(part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part)
        return _sanitize(SECRET_RE.sub(r"\1=[REDACTED]", value)) or fallback
    except OSError:
        return fallback


def _parent_tree(pid: int, depth: int = 6) -> list[dict[str, Any]]:
    tree: list[dict[str, Any]] = []
    current = pid
    seen: set[int] = set()
    for _ in range(depth):
        status = _proc_status(current)
        parent = status.get("PPid")
        if not parent or parent in seen:
            break
        seen.add(parent)
        parent_status = _proc_status(parent)
        if not parent_status:
            break
        tree.append({"pid": parent, "name": parent_status.get("Name", "unknown")})
        if parent <= 1:
            break
        current = parent
    return tree


def _proc_status(pid: int) -> dict[str, Any]:
    try:
        result: dict[str, Any] = {}
        for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("Name:"):
                result["Name"] = line.split(":", 1)[1].strip()
            elif line.startswith("PPid:"):
                result["PPid"] = int(line.split(":", 1)[1].strip())
        return result
    except (OSError, ValueError):
        return {}


def _systemd_unit(pid: int) -> str | None:
    try:
        content = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    matches = re.findall(r"/([^/\s]+\.service)(?:/|$)", content, flags=re.MULTILINE)
    return matches[-1] if matches else None


def _package_owner(context: AuditContext, executable: str) -> str | None:
    if not executable or not executable.startswith("/"):
        return None
    result = context.run(["dpkg-query", "-S", executable], timeout=5)
    if result.ok and ":" in result.stdout:
        return result.stdout.split(":", 1)[0].strip()
    result = context.run(["rpm", "-qf", executable], timeout=5)
    return result.stdout.strip().splitlines()[0] if result.ok and result.stdout.strip() else None


def _has_hidden_component(path: str) -> bool:
    if not path.startswith("/"):
        return False
    return any(part.startswith(".") and part not in {".", ".."} for part in Path(path).parts)


def _assess(
    item: dict[str, Any],
    suspicious_path: bool,
    hidden_path: bool,
    deleted: bool,
    known_name: bool,
    high_cpu: bool,
) -> dict[str, Any]:
    compromise_score = 0
    exposure_score = 0
    increases: list[str] = []
    decreases: list[str] = []
    executable = str(item["executable"] or "")
    parent_is_systemd = any(node["pid"] == 1 or node["name"] == "systemd" for node in item["parent_tree"])

    def increase(points: int, reason: str, exposure: bool = False) -> None:
        nonlocal compromise_score, exposure_score
        if exposure:
            exposure_score += points
        else:
            compromise_score += points
        increases.append(reason)

    if known_name:
        increase(55, "process name matches a known miner or malware indicator")
    if suspicious_path:
        increase(40, "executable runs from a transient writable directory")
    if hidden_path:
        increase(20, "executable is stored under a hidden directory")
    if deleted:
        increase(8, "the running executable was deleted or replaced on disk")
    if high_cpu:
        increase(12, "CPU usage exceeds the configured investigation threshold")
    if item["network_connections"] and (known_name or suspicious_path or hidden_path or deleted):
        increase(15, "the candidate has an established network connection")
    public_ports = [
        value for value in item["open_ports"] if value["public"] and not value.get("expected", False)
    ]
    if public_ports:
        increase(25, "the process listens on a wildcard network address", exposure=True)
    if item["user"] == "root" and (compromise_score or exposure_score):
        increase(10, "the process runs as root", exposure=True)
    if not item["parent_tree"]:
        increase(8, "the parent process could not be established")
    if item["custom_systemd_service"]:
        increase(12, "the process is persisted by a custom systemd service")

    if executable.startswith(TRUSTED_PREFIXES):
        compromise_score -= 15
        decreases.append("executable is under a standard system binary directory")
    if item["package_owner"]:
        compromise_score -= 20
        decreases.append(f"binary is owned by installed package {item['package_owner']}")
    if parent_is_systemd:
        compromise_score -= 10
        decreases.append("the process descends from systemd")
    if item["systemd_unit"] and not item["custom_systemd_service"]:
        compromise_score -= 8
        decreases.append(f"process belongs to systemd unit {item['systemd_unit']}")

    risk = max(1, min(100, max(exposure_score, compromise_score)))
    if risk >= 70:
        severity = Severity.CRITICAL
    elif risk >= 45:
        severity = Severity.HIGH
    elif risk >= 20:
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW
    confidence = 55
    confidence += 10 if item["executable"] else 0
    confidence += 10 if item["parent_tree"] else 0
    confidence += 10 if item["package_owner"] else 0
    confidence += 10 if item["systemd_unit"] else 0
    confidence += 5 if item["open_ports"] or item["network_connections"] else 0
    return {
        "risk_score": risk,
        "severity": severity.value,
        "confidence": min(95, confidence),
        "risk_increases": increases,
        "risk_decreases": decreases,
        "reason": "; ".join(increases + decreases) or "insufficient evidence to establish elevated risk",
    }


def _finding(item: dict[str, Any]) -> Finding:
    ports = [f"{value['address']}:{value['port']}" for value in item["open_ports"]]
    deleted = str(item["executable"] or "").endswith(" (deleted)")
    title = "Deleted executable contextual analysis" if deleted else f"Process requires investigation: {item['name']}"
    evidence = (
        f"pid={item['pid']} ppid={item['ppid']} user={item['user']} command={item['command']} "
        f"executable={item['executable']} cwd={item['working_directory']} "
        f"ports={','.join(ports) or 'none'} package={item['package_owner'] or 'unresolved'} "
        f"systemd={item['systemd_unit'] or 'none'}"
    )
    recommendation = (
        "Validate the process against the service inventory. If unauthorized, preserve volatile evidence and "
        "investigate its binary, parent, persistence, credentials, and remote connections before containment."
    )
    return Finding(
        f"process.{item['pid']}",
        title,
        Severity(item["severity"]),
        "process",
        f"Contextual investigation of process {item['pid']} produced a risk score of {item['risk_score']}.",
        evidence,
        recommendation,
        {"pid": item["pid"], "assessment": item["reason"]},
        risk_score=item["risk_score"],
        confidence=item["confidence"],
        reason=item["reason"],
        remediation_commands=[
            f"sudo readlink -f /proc/{item['pid']}/exe",
            f"sudo cat /proc/{item['pid']}/status",
            f"sudo ss -ntup | grep 'pid={item['pid']},'",
        ],
    )
