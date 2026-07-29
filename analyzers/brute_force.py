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
    success_after_failure_threshold: int = 5,
) -> tuple[dict[str, Any], list[Finding]]:
    failures: Counter[str] = Counter()
    targeted_users: dict[str, Counter[str]] = defaultdict(Counter)
    invalid_users: Counter[str] = Counter()
    successes: list[dict[str, str]] = []
    unusual: list[dict[str, str]] = []
    success_after_failures: list[dict[str, Any]] = []

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
            prior_failures = failures[item["ip"]]
            if prior_failures:
                success_after_failures.append({**item, "prior_failures": prior_failures})
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
                "Disable password authentication, restrict SSH exposure, enable Fail2ban or equivalent rate limiting, and investigate the source addresses.",
                {"source_counts": dict(top)},
                risk_score=32,
                confidence=95,
                reason="Repeated authentication failures above the configured threshold are strong evidence of an active password attack.",
                remediation_commands=[
                    "sudo sshd -T | grep -E 'passwordauthentication|permitrootlogin'",
                    "sudo fail2ban-client status sshd",
                ],
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
                Severity.LOW,
                "ssh",
                "One or more successful logins occurred inside the configured unusual-hours window.",
                "; ".join(f"{x['user']} from {x['ip']} at {x['date']}" for x in unusual[-10:]),
                "Validate these logins against administrator activity and rotate credentials if unrecognized.",
                risk_score=5,
                confidence=50,
                reason="Login time is a weak behavioral signal and is not suspicious without user or source context.",
            )
        )
    suspicious_successes = [
        item for item in success_after_failures if item["prior_failures"] >= success_after_failure_threshold
    ]
    if suspicious_successes:
        findings.append(
            Finding(
                "ssh.success_after_failures",
                "Successful SSH authentication followed earlier failures",
                Severity.HIGH,
                "ssh",
                "A source address that generated failed authentication attempts later logged in successfully.",
                "; ".join(
                    f"{x['user']} from {x['ip']} after {x['prior_failures']} failures"
                    for x in suspicious_successes[-20:]
                ),
                "Immediately validate the successful sessions and rotate affected credentials if any login is unrecognized.",
                risk_score=32,
                confidence=80,
                reason="A success following repeated failures can indicate a guessed password or stolen credential.",
            )
        )

    targeted_totals: Counter[str] = Counter()
    for values in targeted_users.values():
        targeted_totals.update(values)
    data = {
        "failed_by_ip": [
            {"ip": ip, "count": count, "usernames": dict(targeted_users[ip].most_common(10))}
            for ip, count in failures.most_common(100)
        ],
        "successful_logins": successes[-100:],
        "suspicious_usernames": dict(invalid_users.most_common(30)),
        "targeted_usernames": dict(targeted_totals.most_common(30)),
        "successful_after_failures": success_after_failures[-100:],
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
