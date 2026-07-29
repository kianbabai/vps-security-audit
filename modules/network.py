"""Listening socket and active connection inventory."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from audit_context import AuditContext
from models import Finding, ModuleResult, Severity


def audit(context: AuditContext) -> ModuleResult:
    config = context.config["network"]
    findings: list[Finding] = []
    errors: list[str] = []
    sockets, source, collection_error = _collect_listeners(context)
    if collection_error:
        errors.append(collection_error)
    if not sockets:
        if not collection_error:
            errors.append("No listening sockets were returned")
        return ModuleResult("network", {"listening_ports": [], "active_connections": {}}, findings, errors)
    dangerous = {int(port) for port in config["dangerous_ports"]}
    expected = {int(port) for port in config["expected_public_ports"]}
    for item in sockets:
        if not item["public_access"] or item["port"] is None:
            continue
        port = item["port"]
        if port in dangerous:
            findings.append(
                Finding(
                    f"network.dangerous_port.{port}",
                    f"High-risk service port {port} is publicly bound",
                    Severity.HIGH,
                    "network",
                    "A commonly abused database, remote-control, or legacy service is bound to all interfaces.",
                    f"{item['protocol']} {item['local_address']} process={item['process'] or 'unknown'}",
                    "Bind the service to a private interface and restrict it with the firewall.",
                )
            )
        elif port not in expected:
            findings.append(
                Finding(
                    f"network.unexpected_public_port.{port}",
                    f"Unexpected public listening port {port}",
                    Severity.MEDIUM,
                    "network",
                    "The port is not in the configured expected public-port allowlist.",
                    f"{item['protocol']} {item['local_address']} process={item['process'] or 'unknown'}",
                    "Confirm the service is required and restrict its source networks or bind address.",
                )
            )

    active = context.run(["ss", "-H", "-ntup", "state", "established"])
    remote_counts: Counter[str] = Counter()
    if active.ok:
        for line in active.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5:
                remote_counts[_host_from_endpoint(parts[4])] += 1
    context.snapshots["ports"] = sorted(
        f"{item['protocol']}/{item['port']}" for item in sockets if item["port"] is not None
    )
    return ModuleResult(
        "network",
        {
            "listener_source": source,
            "listening_ports": sockets,
            "active_connections": dict(remote_counts.most_common(100)),
        },
        findings,
        errors,
    )


def _parse_socket(line: str) -> dict[str, Any] | None:
    parts = line.split(None, 6)
    if len(parts) < 5:
        return None
    protocol, state, local = parts[0], parts[1], parts[4]
    host, port = _split_endpoint(local)
    process_match = re.search(r'\(\("([^"]+)"', parts[6] if len(parts) > 6 else "")
    return {
        "protocol": protocol,
        "state": state,
        "local_address": local,
        "bind_address": host,
        "port": port,
        "public_access": host in {"0.0.0.0", "::", "*", "[::]"},
        "process": process_match.group(1) if process_match else None,
    }


def _collect_listeners(context: AuditContext) -> tuple[list[dict[str, Any]], str | None, str | None]:
    result = context.run(["ss", "-H", "-lntup"])
    if result.ok:
        return [item for line in result.stdout.splitlines() if (item := _parse_socket(line))], "ss", None
    netstat = context.run(["netstat", "-lntup"])
    if netstat.ok:
        values = [item for line in netstat.stdout.splitlines() if (item := _parse_netstat(line))]
        return values, "netstat", None
    lsof = context.run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])
    if lsof.ok:
        values = [item for line in lsof.stdout.splitlines() if (item := _parse_lsof(line))]
        return values, "lsof", None
    errors = [result.error or result.stderr.strip(), netstat.error or netstat.stderr.strip(), lsof.error or lsof.stderr.strip()]
    return [], None, "Unable to enumerate listening sockets: " + "; ".join(error for error in errors if error)


def _parse_netstat(line: str) -> dict[str, Any] | None:
    parts = line.split()
    if not parts or not parts[0].startswith(("tcp", "udp")) or len(parts) < 4:
        return None
    protocol = parts[0]
    local = parts[3]
    host, port = _split_endpoint(local)
    state = parts[5] if protocol.startswith("tcp") and len(parts) > 5 else "UNCONN"
    process_value = parts[-1] if "/" in parts[-1] else ""
    process = process_value.split("/", 1)[1] if process_value else None
    return {
        "protocol": protocol,
        "state": state,
        "local_address": local,
        "bind_address": host,
        "port": port,
        "public_access": host in {"0.0.0.0", "::", "*", "[::]"},
        "process": process,
    }


def _parse_lsof(line: str) -> dict[str, Any] | None:
    parts = line.split()
    if not parts or parts[0] == "COMMAND" or len(parts) < 9:
        return None
    endpoint = parts[-2] if parts[-1] == "(LISTEN)" else parts[-1]
    host, port = _split_endpoint(endpoint)
    return {
        "protocol": "tcp",
        "state": "LISTEN",
        "local_address": endpoint,
        "bind_address": host,
        "port": port,
        "public_access": host in {"0.0.0.0", "::", "*", "[::]"},
        "process": parts[0],
    }


def _split_endpoint(endpoint: str) -> tuple[str, int | None]:
    value = endpoint.strip()
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


def _host_from_endpoint(endpoint: str) -> str:
    return _split_endpoint(endpoint)[0]
