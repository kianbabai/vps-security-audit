"""WordPress installation and attack-pattern audit."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from analyzers.suspicious_activity import parse_access_lines
from audit_context import AuditContext
from models import Finding, ModuleResult, Severity


def audit(context: AuditContext) -> ModuleResult:
    config = context.config["wordpress"]
    findings: list[Finding] = []
    errors: list[str] = []
    installations: list[dict[str, Any]] = []
    for configured in config["roots"]:
        root = Path(configured)
        wp_config = root / "wp-config.php"
        if not wp_config.exists():
            continue
        record: dict[str, Any] = {"root": str(root), "plugins": [], "themes": []}
        try:
            mode = wp_config.stat().st_mode & 0o777
            record["wp_config_mode"] = oct(mode)
            if mode & 0o007:
                findings.append(
                    Finding(
                        f"wordpress.config_world_readable.{str(root).replace('/', '_')}",
                        "WordPress configuration is accessible to all local users",
                        Severity.HIGH,
                        "wordpress",
                        "wp-config.php normally contains database credentials and authentication salts.",
                        f"{wp_config} mode {oct(mode)}",
                        "Restrict wp-config.php ownership and permissions while preserving web-server access.",
                    )
                )
            for kind in ("plugins", "themes"):
                folder = root / "wp-content" / kind
                if folder.is_dir():
                    record[kind] = sorted(child.name for child in folder.iterdir() if child.is_dir())[:500]
        except OSError as exc:
            errors.append(f"Cannot inspect {root}: {exc}")
        uploads = root / "wp-content" / "uploads"
        if uploads.is_dir():
            executable = _find_executable_uploads(uploads)
            if executable:
                findings.append(
                    Finding(
                        f"wordpress.executable_uploads.{str(root).replace('/', '_')}",
                        "Executable scripts found in WordPress uploads",
                        Severity.HIGH,
                        "wordpress",
                        "PHP-family files in uploads may indicate an unsafe server policy or compromise.",
                        ", ".join(executable[:20]),
                        "Validate the files, then block script execution in the uploads directory.",
                    )
                )
        installations.append(record)

    log_lines: list[str] = []
    limit = int(context.config["audit"]["max_log_lines"])
    for configured in config["access_log_paths"]:
        path = Path(configured)
        if not path.exists():
            continue
        recent, error = context.tail_lines(path, limit)
        if recent:
            log_lines.extend(recent)
        elif error:
            errors.append(f"Cannot read {path}: {error}")
    activity, _ = parse_access_lines(log_lines[-limit:], 2**31 - 1)
    threshold = int(config["login_attack_threshold"])
    login_attackers = {ip: count for ip, count in activity["wp_login_by_ip"].items() if count >= threshold}
    xmlrpc_attackers = {ip: count for ip, count in activity["xmlrpc_by_ip"].items() if count >= threshold}
    if login_attackers:
        findings.append(
            Finding(
                "wordpress.login_attack",
                "Repeated WordPress login requests detected",
                Severity.HIGH,
                "wordpress",
                "Sources exceeded the configured wp-login.php request threshold.",
                ", ".join(f"{ip}: {count}" for ip, count in login_attackers.items()),
                "Enable MFA, strong rate limits, and Cloudflare controls for the login endpoint.",
            )
        )
    if xmlrpc_attackers:
        findings.append(
            Finding(
                "wordpress.xmlrpc_abuse",
                "Possible WordPress XML-RPC abuse",
                Severity.HIGH,
                "wordpress",
                "Sources repeatedly requested xmlrpc.php.",
                ", ".join(f"{ip}: {count}" for ip, count in xmlrpc_attackers.items()),
                "Disable XML-RPC when unused or tightly rate-limit and filter the endpoint.",
            )
        )
    return ModuleResult(
        "wordpress",
        {"installations": installations, "access_log_analysis": activity},
        findings,
        errors,
    )


def _find_executable_uploads(root: Path) -> list[str]:
    matches: list[str] = []
    try:
        for directory, names, files in os.walk(root):
            names[:] = names[:1000]
            for filename in files:
                if Path(filename).suffix.lower() in {".php", ".phtml", ".phar", ".php5", ".php7", ".php8"}:
                    matches.append(str(Path(directory) / filename))
                    if len(matches) >= 100:
                        return matches
    except OSError:
        pass
    return matches
