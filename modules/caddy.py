"""Caddy configuration and access-log security audit."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from analyzers.suspicious_activity import parse_access_lines
from audit_context import AuditContext
from models import Finding, ModuleResult, Severity


def audit(context: AuditContext) -> ModuleResult:
    config = context.config["caddy"]
    findings: list[Finding] = []
    errors: list[str] = []
    configs: list[dict[str, Any]] = []
    for configured in config["config_paths"]:
        path = Path(configured)
        if not path.exists():
            continue
        text, error = context.read_text(path)
        if error:
            errors.append(f"Cannot read {path}: {error}")
            continue
        content = text or ""
        lower = content.lower()
        configs.append(
            {
                "path": str(path),
                "tls_configured": "tls " in lower or "https://" in lower,
                "security_headers_configured": any(
                    header in lower
                    for header in ("strict-transport-security", "content-security-policy", "x-content-type-options")
                ),
                "access_logging_configured": "\n\tlog" in lower or "\n log" in lower,
            }
        )
        if "admin 0.0.0.0:" in lower or "admin :2019" in lower:
            findings.append(
                Finding(
                    "caddy.public_admin_api",
                    "Caddy admin API may be publicly exposed",
                    Severity.CRITICAL,
                    "caddy",
                    "The Caddy admin listener appears to bind to all network interfaces.",
                    f"{path}: admin listener has a wildcard bind",
                    "Bind the admin API to loopback or disable it if configuration reloads are not required.",
                )
            )
        if config.get("cloudflare_expected", False) and "trusted_proxies" not in lower:
            findings.append(
                Finding(
                    "caddy.cloudflare_trusted_proxies_missing",
                    "Caddy trusted proxies are not configured for Cloudflare",
                    Severity.MEDIUM,
                    "caddy",
                    "Without a validated trusted-proxy policy, client IP attribution and attack analysis may be inaccurate.",
                    f"{path}: no trusted_proxies directive found",
                    "Configure current Cloudflare proxy ranges and strict client-IP parsing, then verify logs show real clients.",
                )
            )
        if "http://" in lower and "auto_https off" in lower:
            findings.append(
                Finding(
                    "caddy.https_disabled",
                    "Caddy automatic HTTPS appears disabled",
                    Severity.HIGH,
                    "caddy",
                    "A plaintext site address is combined with disabled automatic HTTPS.",
                    str(path),
                    "Serve public sites over HTTPS and retain HTTP-to-HTTPS redirects.",
                )
            )
        if not configs[-1]["security_headers_configured"]:
            findings.append(
                Finding(
                    "caddy.security_headers_missing",
                    "Common browser security headers not found in Caddy configuration",
                    Severity.LOW,
                    "caddy",
                    "No HSTS, CSP, or X-Content-Type-Options directive was detected by static analysis.",
                    str(path),
                    "Define suitable security headers after testing them against each application.",
                )
            )

    lines = _log_lines(context, config["access_log_paths"], errors)
    activity, activity_findings = parse_access_lines(lines, int(config["request_threshold_per_ip"]))
    activity["country_by_ip"] = _geoip_countries(
        activity["top_ips"], context.config.get("privacy", {}).get("geoip_database"), errors
    )
    findings.extend(activity_findings)
    if not configs:
        errors.append("No configured Caddyfile was found")
    return ModuleResult("caddy", {"configurations": configs, "access_log_analysis": activity}, findings, errors)


def _log_lines(context: AuditContext, paths: list[str], errors: list[str]) -> list[str]:
    limit = int(context.config["audit"]["max_log_lines"])
    lines: list[str] = []
    for configured in paths:
        path = Path(configured)
        if not path.exists():
            continue
        recent, error = context.tail_lines(path, limit)
        if recent:
            lines.extend(recent)
        elif error:
            errors.append(f"Cannot read {path}: {error}")
    return lines[-limit:]


def _geoip_countries(ips: dict[str, int], database: str | None, errors: list[str]) -> dict[str, str]:
    if not database:
        return {}
    path = Path(database)
    if not path.is_file():
        errors.append(f"Configured GeoIP database does not exist: {path}")
        return {}
    try:
        import geoip2.database

        countries: dict[str, str] = {}
        with geoip2.database.Reader(str(path)) as reader:
            for ip in ips:
                try:
                    response = reader.country(ip)
                    countries[ip] = response.country.iso_code or response.country.name or "unknown"
                except Exception:
                    continue
        return countries
    except (ImportError, OSError) as exc:
        errors.append(f"GeoIP enrichment unavailable: {exc}")
        return {}
