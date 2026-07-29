"""Nginx, Apache, and Caddy service and access-log analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from analyzers.suspicious_activity import parse_access_lines
from audit_context import AuditContext
from models import ModuleResult

SERVERS = {
    "nginx": ["/etc/nginx/nginx.conf"],
    "apache2": ["/etc/apache2/apache2.conf"],
    "httpd": ["/etc/httpd/conf/httpd.conf"],
    "caddy": ["/etc/caddy/Caddyfile", "/srv/proxy/Caddyfile"],
}


def audit(context: AuditContext) -> ModuleResult:
    config = context.config["web_server"]
    errors: list[str] = []
    servers: list[dict[str, Any]] = []
    for service, paths in SERVERS.items():
        status = context.run(["systemctl", "is-active", service], timeout=3)
        existing = [path for path in paths if Path(path).exists()]
        if status.stdout.strip() == "active" or existing:
            servers.append(
                {
                    "service": service,
                    "active": status.stdout.strip() == "active",
                    "configuration_paths": existing,
                }
            )

    limit = int(context.config["audit"]["max_log_lines"])
    lines: list[str] = []
    sources: list[str] = []
    for configured in config["access_log_paths"]:
        path = Path(configured)
        if not path.exists():
            continue
        recent, error = context.tail_lines(path, limit)
        if error:
            errors.append(f"Cannot read {path}: {error}")
            continue
        if recent:
            lines.extend(recent)
            sources.append(str(path))
    activity, findings = parse_access_lines(lines[-limit:], int(config["request_threshold_per_ip"]))
    return ModuleResult(
        "web",
        {"detected_servers": servers, "log_sources": sources, "access_log_analysis": activity},
        findings,
        errors,
    )

