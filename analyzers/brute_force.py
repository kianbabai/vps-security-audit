"""Authentication log parsing and brute-force detection."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any, Iterable

from models import Finding, Severity

FAILED_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
SUCCESS_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
TIMESTAMP_RE = re.compile(r"^(?P<stamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})")


def analyze_auth_lines(
    lines: Iterable[str],
    failed_threshold: int,
    distributed_threshold: int,
    unusual_start: int,
    unusual_end: int,
) -> tuple[dict[str, Any], list[Finding]]:
    failures: Counter[str] = Counter()
    targeted_users: dict[str, Counter[str]] = defaultdict(Counter)
    invalid_users: Counter[str] = Counter()
    successes: list[dict[str, str]] = []
    unusual: list[dict[str, str]] = []

    for line in lines:
        failed = FAILED_RE.search(line) or INVALID_RE.search(line)
        if failed:
            ip, user = failed.group("ip"), failed.group("user")
            failures[ip] += 1
            targeted_users[ip][user] += 1
            if "Invalid user" in line or "invalid user" in line:
                invalid_users[user] += 1
            continue
        accepted = SUCCESS_RE.search(line)
        if accepted:
            item = {
                "user": accepted.group("user"),
                "ip": accepted.group("ip"),
                "date": _timestamp(line),
            }
            successes.append(item)
            hour = _hour(line)
            if hour is not None and _within_hour_window(hour, unusual_start, unusual_end):
                unusual.append(item)

    findings: list[Finding] = []
    offenders = {ip: count for ip, count in failures.items() if count >= failed_threshold}
    if offenders:
        top = sorted(offenders.items(), key=lambda pair: pair[1], reverse=True)[:20]
        findings.append(
            Finding(
                "ssh.brute_force",
                "Repeated SSH authentication failures detected",
                Severity.HIGH,
                "ssh",
                f"{len(offenders)} source IP(s) exceeded the configured failure threshold.",
                ", ".join(f"{ip}: {count}" for ip, count in top),
                "Restrict SSH exposure, require key authentication, and investigate the source addresses.",
                {"source_counts": dict(top)},
            )
        )
    if len(failures) >= distributed_threshold and sum(failures.values()) >= distributed_threshold:
        findings.append(
            Finding(
                "ssh.distributed_brute_force",
                "Distributed SSH password attack pattern",
                Severity.HIGH,
                "ssh",
                "Authentication failures came from many distinct source addresses.",
                f"{sum(failures.values())} failures from {len(failures)} IPs",
                "Place SSH behind a trusted network or VPN and use rate limiting at the network edge.",
            )
        )
    if unusual:
        findings.append(
            Finding(
                "ssh.unusual_login_time",
                "Successful SSH login at an unusual hour",
                Severity.MEDIUM,
                "ssh",
                "One or more successful logins occurred inside the configured unusual-hours window.",
                "; ".join(f"{x['user']} from {x['ip']} at {x['date']}" for x in unusual[-10:]),
                "Validate these logins against administrator activity and rotate credentials if unrecognized.",
            )
        )

    data = {
        "failed_by_ip": [
            {"ip": ip, "count": count, "usernames": dict(targeted_users[ip].most_common(10))}
            for ip, count in failures.most_common(100)
        ],
        "successful_logins": successes[-100:],
        "suspicious_usernames": dict(invalid_users.most_common(30)),
        "total_failures": sum(failures.values()),
        "distinct_failure_ips": len(failures),
    }
    return data, findings


def _timestamp(line: str) -> str:
    match = TIMESTAMP_RE.search(line)
    return match.group("stamp") if match else "unknown"


def _hour(line: str) -> int | None:
    match = TIMESTAMP_RE.search(line)
    if not match:
        return None
    try:
        return int(match.group("stamp").rsplit(" ", 1)[1].split(":", 1)[0])
    except (ValueError, IndexError):
        return None


def _within_hour_window(hour: int, start: int, end: int) -> bool:
    return start <= hour <= end if start <= end else hour >= start or hour <= end
