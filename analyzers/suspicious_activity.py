"""Web access-log parsing and suspicious request analysis."""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any, Iterable
from urllib.parse import urlsplit

from models import Finding, Severity

COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+]\s+"(?P<method>\S+)\s+(?P<uri>\S+)'
    r'\s+[^"]+"\s+(?P<status>\d{3})\s+\S+(?:\s+"[^"]*"\s+"(?P<ua>[^"]*)")?'
)
SUSPICIOUS_PATHS = (
    "/.env",
    "/.git/",
    "/wp-config.php",
    "/phpmyadmin",
    "/vendor/phpunit",
    "/cgi-bin/",
    "/actuator",
    "/server-status",
    "/etc/passwd",
)
SCANNER_UA = ("sqlmap", "nikto", "nmap", "masscan", "zgrab", "nuclei", "dirbuster")


def parse_access_lines(lines: Iterable[str], request_threshold: int) -> tuple[dict[str, Any], list[Finding]]:
    ips: Counter[str] = Counter()
    paths: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    scanners: Counter[str] = Counter()
    wp_login: Counter[str] = Counter()
    xmlrpc: Counter[str] = Counter()
    sql_injection: Counter[str] = Counter()
    path_traversal: Counter[str] = Counter()
    parsed = 0

    for line in lines:
        record = _parse_line(line)
        if not record:
            continue
        parsed += 1
        ip = record["ip"]
        uri = record["uri"].lower()
        ua = record["user_agent"].lower()
        path = urlsplit(uri).path
        ips[ip] += 1
        paths[path] += 1
        statuses[str(record["status"])] += 1
        if any(marker in path for marker in SUSPICIOUS_PATHS) or any(marker in ua for marker in SCANNER_UA):
            scanners[ip] += 1
        if "/wp-login.php" in path:
            wp_login[ip] += 1
        if "/xmlrpc.php" in path:
            xmlrpc[ip] += 1
        if any(marker in uri for marker in ("%27", "' or ", "union select", "sleep(", "benchmark(", "or 1=1")):
            sql_injection[ip] += 1
        if any(marker in uri for marker in ("../", "..%2f", "%2e%2e", "/etc/passwd", "/proc/self")):
            path_traversal[ip] += 1

    findings: list[Finding] = []
    noisy = {ip: count for ip, count in ips.items() if count >= request_threshold}
    if noisy:
        findings.append(
            Finding(
                "web.high_request_rate",
                "High request volume from individual clients",
                Severity.MEDIUM,
                "web",
                "Client request counts exceeded the configured per-scan threshold.",
                ", ".join(f"{ip}: {count}" for ip, count in Counter(noisy).most_common(20)),
                "Review the clients and tune Cloudflare rate limiting or bot controls where appropriate.",
                risk_score=8,
                confidence=60,
                reason="High volume can be abusive, but may also represent a legitimate crawler, proxy, or busy client.",
            )
        )
    if scanners:
        findings.append(
            Finding(
                "web.scanner_activity",
                "Web scanner or sensitive-path probing detected",
                Severity.MEDIUM,
                "web",
                "Requests matched known scanner user agents or commonly probed sensitive paths.",
                ", ".join(f"{ip}: {count}" for ip, count in scanners.most_common(20)),
                "Confirm the origin is not directly exposed and review Cloudflare/WAF rules and application logs.",
            )
        )
    if sql_injection:
        findings.append(
            Finding(
                "web.sql_injection_probing",
                "SQL injection probing detected",
                Severity.HIGH,
                "web",
                "Request URIs contained common SQL injection operators or timing-function payloads.",
                ", ".join(f"{ip}: {count}" for ip, count in sql_injection.most_common(20)),
                "Inspect application responses and database logs, validate parameterized queries, and tune WAF rules.",
                risk_score=28,
                confidence=85,
                reason="SQL injection probes can lead to data disclosure or remote code execution when an endpoint is vulnerable.",
            )
        )
    if path_traversal:
        findings.append(
            Finding(
                "web.path_traversal_probing",
                "Path traversal probing detected",
                Severity.HIGH,
                "web",
                "Requests attempted parent-directory traversal or access to sensitive operating-system paths.",
                ", ".join(f"{ip}: {count}" for ip, count in path_traversal.most_common(20)),
                "Review response codes and application logs, normalize paths, and block confirmed hostile patterns at the edge.",
                risk_score=26,
                confidence=90,
                reason="Successful traversal can expose credentials, configuration, and host files.",
            )
        )

    return {
        "parsed_requests": parsed,
        "top_ips": dict(ips.most_common(50)),
        "top_paths": dict(paths.most_common(50)),
        "status_codes": dict(statuses),
        "scanner_requests_by_ip": dict(scanners.most_common(50)),
        "wp_login_by_ip": dict(wp_login.most_common(50)),
        "xmlrpc_by_ip": dict(xmlrpc.most_common(50)),
        "sql_injection_by_ip": dict(sql_injection.most_common(50)),
        "path_traversal_by_ip": dict(path_traversal.most_common(50)),
    }, findings


def _parse_line(line: str) -> dict[str, Any] | None:
    try:
        value = json.loads(line)
        request = value.get("request", {})
        client_ip = request.get("client_ip") or request.get("remote_ip") or value.get("remote_ip")
        uri = request.get("uri") or value.get("uri")
        if client_ip and uri:
            user_agent = request.get("headers", {}).get("User-Agent", "")
            if isinstance(user_agent, list):
                user_agent = user_agent[0] if user_agent else ""
            return {
                "ip": str(client_ip),
                "uri": str(uri),
                "status": int(value.get("status", 0)),
                "user_agent": str(user_agent),
            }
    except (json.JSONDecodeError, TypeError, ValueError, IndexError):
        pass
    match = COMBINED_RE.search(line)
    if not match:
        return None
    return {
        "ip": match.group("ip"),
        "uri": match.group("uri"),
        "status": int(match.group("status")),
        "user_agent": match.group("ua") or "",
    }
