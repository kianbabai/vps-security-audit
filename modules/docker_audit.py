"""Docker daemon, container, image, mount, and network-mode audit."""

from __future__ import annotations

import glob
import json
from pathlib import Path
from typing import Any

import yaml

from audit_context import AuditContext
from models import Finding, ModuleResult, Severity


def audit(context: AuditContext) -> ModuleResult:
    if not context.config["docker"].get("enabled", True):
        return ModuleResult("docker", {"enabled": False})
    findings: list[Finding] = []
    errors: list[str] = []
    compose_files, compose_findings = _compose_audit(context)
    findings.extend(compose_findings)
    socket = Path(context.config["docker"]["socket_path"])
    if socket.exists():
        try:
            mode = socket.stat().st_mode & 0o777
            if mode & 0o007:
                findings.append(
                    Finding(
                        "docker.world_accessible_socket",
                        "Docker socket is accessible to all local users",
                        Severity.CRITICAL,
                        "docker",
                        "Docker socket access is effectively root-equivalent.",
                        f"{socket} mode {oct(mode)}",
                        "Restrict socket ownership and permissions to trusted administrators.",
                    )
                )
        except OSError as exc:
            errors.append(f"Cannot stat Docker socket: {exc}")

    version = context.run(["docker", "version", "--format", "{{json .Server}}"])
    if not version.ok:
        errors.append(version.error or version.stderr.strip() or "Docker daemon is not accessible")
        return ModuleResult("docker", {"available": False, "compose_files": compose_files}, findings, errors)
    server = _json(version.stdout, {})
    listed = context.run(["docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}"])
    summaries = [_json(line, {}) for line in listed.stdout.splitlines() if line.strip()] if listed.ok else []
    containers: list[dict[str, Any]] = []
    for summary in summaries:
        container_id = summary.get("ID")
        if not container_id:
            continue
        inspected = context.run(["docker", "inspect", str(container_id)])
        values = _json(inspected.stdout, []) if inspected.ok else []
        if not values:
            errors.append(f"Cannot inspect container {container_id}")
            continue
        item = _container_record(values[0])
        containers.append(item)
        findings.extend(_container_findings(item))

    images_result = context.run(["docker", "images", "--no-trunc", "--format", "{{json .}}"])
    images = [_json(line, {}) for line in images_result.stdout.splitlines() if line.strip()] if images_result.ok else []
    mutable = [f"{image.get('Repository')}:{image.get('Tag')}" for image in images if image.get("Tag") == "latest"]
    if mutable:
        findings.append(
            Finding(
                "docker.mutable_image_tags",
                "Docker images use the mutable latest tag",
                Severity.LOW,
                "docker",
                "Mutable tags weaken deployment reproducibility and make version auditing ambiguous.",
                ", ".join(mutable[:20]),
                "Pin production images to an explicit version and preferably an image digest.",
            )
        )

    context.snapshots["containers"] = sorted(item["name"] for item in containers)
    return ModuleResult(
        "docker",
        {
            "available": True,
            "server": server,
            "containers": containers,
            "images": images,
            "compose_files": compose_files,
        },
        findings,
        errors,
    )


def _container_record(raw: dict[str, Any]) -> dict[str, Any]:
    config = raw.get("Config") or {}
    host = raw.get("HostConfig") or {}
    network = raw.get("NetworkSettings") or {}
    mounts = [
        {
            "source": mount.get("Source"),
            "destination": mount.get("Destination"),
            "read_only": not bool(mount.get("RW", False)),
            "type": mount.get("Type"),
        }
        for mount in raw.get("Mounts") or []
    ]
    ports: list[dict[str, Any]] = []
    for container_port, bindings in (network.get("Ports") or {}).items():
        for binding in bindings or []:
            ports.append(
                {
                    "container": container_port,
                    "host_ip": binding.get("HostIp"),
                    "host_port": binding.get("HostPort"),
                    "public": binding.get("HostIp") in {"0.0.0.0", "::", ""},
                }
            )
    return {
        "id": raw.get("Id", "")[:12],
        "name": str(raw.get("Name", "")).lstrip("/"),
        "image": config.get("Image"),
        "state": (raw.get("State") or {}).get("Status"),
        "user": config.get("User") or "root (default)",
        "privileged": bool(host.get("Privileged")),
        "network_mode": host.get("NetworkMode"),
        "pid_mode": host.get("PidMode"),
        "read_only_rootfs": bool(host.get("ReadonlyRootfs")),
        "cap_add": host.get("CapAdd") or [],
        "security_opt": host.get("SecurityOpt") or [],
        "mounts": mounts,
        "published_ports": ports,
    }


def _container_findings(item: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    name = item["name"] or item["id"]
    if item["privileged"]:
        findings.append(
            _finding(name, "privileged", "Privileged Docker container", Severity.CRITICAL,
                     "Privileged mode removes most container isolation.",
                     "Run with privileged=false and grant only individually required capabilities.",
                     risk_score=55, confidence=95)
        )
    if item["state"] == "running" and item["user"] in {"root (default)", "0", "root"}:
        findings.append(
            _finding(name, "root_user", "Container runs as root", Severity.MEDIUM,
                     f"Configured user: {item['user']}",
                     "Use a non-root USER in the image or set user in the deployment configuration.",
                     risk_score=12, confidence=90)
        )
    if item["network_mode"] == "host":
        findings.append(
            _finding(name, "host_network", "Container uses host networking", Severity.HIGH,
                     "NetworkMode=host", "Use a dedicated bridge network unless host networking is strictly required.",
                     risk_score=28, confidence=95)
        )
    if item["pid_mode"] == "host":
        findings.append(
            _finding(name, "host_pid", "Container shares the host PID namespace", Severity.HIGH,
                     "PidMode=host", "Remove host PID sharing unless it is essential and tightly controlled.",
                     risk_score=35, confidence=95)
        )
    dangerous = {"/", "/etc", "/boot", "/proc", "/sys", "/var/run", "/var/run/docker.sock"}
    for mount in item["mounts"]:
        source = str(mount["source"] or "")
        if not mount["read_only"] and any(source == path or source.startswith(path + "/") for path in dangerous):
            findings.append(
                _finding(name, f"dangerous_mount.{source}", "Sensitive host path mounted writable", Severity.HIGH,
                         f"{source} -> {mount['destination']} (read-write)",
                         "Remove the mount or make it read-only with the narrowest possible source path.",
                         risk_score=38, confidence=95)
            )
    if "ALL" in item["cap_add"]:
        findings.append(
            _finding(name, "all_capabilities", "Container adds all Linux capabilities", Severity.CRITICAL,
                     "CapAdd includes ALL", "Drop all capabilities and add back only those demonstrably required.",
                     risk_score=52, confidence=95)
        )
    for port in item["published_ports"]:
        if port["public"]:
            raw_port = str(port["container"]).split("/", 1)[0]
            database = raw_port in {"3306", "5432", "6379", "9200", "11211", "27017"}
            findings.append(
                _finding(
                    name,
                    f"public_port.{port['host_port']}",
                    "Database container is publicly published" if database else "Container publishes a port on all interfaces",
                    Severity.HIGH if database else Severity.LOW,
                    f"{port['host_ip']}:{port['host_port']} -> {port['container']}",
                    "Bind the database to an internal Docker network or loopback."
                    if database
                    else "Publish through Caddy or bind to loopback when direct public access is not required.",
                    risk_score=42 if database else 8,
                    confidence=95,
                )
            )
    return findings


def _finding(
    name: str,
    suffix: str,
    title: str,
    severity: Severity,
    evidence: str,
    recommendation: str,
    risk_score: int | None = None,
    confidence: int = 85,
) -> Finding:
    return Finding(
        f"docker.{name}.{suffix}".replace("/", "_"),
        f"{title}: {name}",
        severity,
        "docker",
        "The container configuration weakens workload or host isolation.",
        evidence,
        recommendation,
        {"container": name},
        risk_score=risk_score,
        confidence=confidence,
        reason="The container setting weakens isolation or exposes a workload beyond its intended trust boundary.",
    )


def _json(value: str, default: Any) -> Any:
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default


def _compose_audit(context: AuditContext) -> tuple[list[dict[str, Any]], list[Finding]]:
    records: list[dict[str, Any]] = []
    findings: list[Finding] = []
    candidates: set[str] = set()
    for pattern in context.config["docker"].get("compose_globs", []):
        candidates.update(glob.glob(str(pattern), recursive=True))
        if len(candidates) >= 200:
            break
    for value in sorted(candidates)[:200]:
        path = Path(value)
        text, error = context.read_text(path, max_bytes=1024 * 1024)
        if error or not text:
            continue
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError:
            continue
        services = document.get("services", {}) if isinstance(document, dict) else {}
        if not isinstance(services, dict):
            continue
        record = {"path": str(path), "services": []}
        for service_name, raw in services.items():
            service = raw if isinstance(raw, dict) else {}
            record["services"].append({"name": str(service_name), "image": service.get("image")})
            flags: list[tuple[str, Severity, str]] = []
            if service.get("privileged") is True:
                flags.append(("privileged=true", Severity.CRITICAL, "Remove privileged mode."))
            if service.get("network_mode") == "host":
                flags.append(("network_mode=host", Severity.HIGH, "Use an isolated bridge network."))
            if service.get("pid") == "host":
                flags.append(("pid=host", Severity.HIGH, "Remove host PID namespace sharing."))
            volumes = service.get("volumes") or []
            if any("/var/run/docker.sock:" in str(volume) and ":ro" not in str(volume) for volume in volumes):
                flags.append(("writable Docker socket mount", Severity.CRITICAL, "Remove Docker socket access."))
            for flag, severity, recommendation in flags:
                findings.append(
                    Finding(
                        f"docker.compose.{path.name}.{service_name}.{flag}".replace("/", "_").replace(" ", "_"),
                        f"Risky Compose setting: {service_name}",
                        severity,
                        "docker",
                        "A risky container setting exists in a discovered Compose definition.",
                        f"{path}: service={service_name}, {flag}",
                        recommendation,
                    )
                )
        records.append(record)
    return records, findings
