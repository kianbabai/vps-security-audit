"""Local account and privilege inventory."""

from __future__ import annotations

from typing import Any
import glob
import re
from datetime import datetime, timedelta
from pathlib import Path

from audit_context import AuditContext
from models import Finding, ModuleResult, Severity

try:
    import pwd
except ImportError:  # non-POSIX development host
    pwd = None  # type: ignore[assignment]


def audit(context: AuditContext) -> ModuleResult:
    findings: list[Finding] = []
    errors: list[str] = []
    accounts: list[dict[str, Any]] = []
    if pwd is None:
        errors.append("POSIX account database is unavailable on this platform")
    else:
        try:
            for account in pwd.getpwall():
                interactive = account.pw_shell not in {
                    "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", ""
                }
                accounts.append(
                    {
                        "name": account.pw_name,
                        "uid": account.pw_uid,
                        "gid": account.pw_gid,
                        "home": account.pw_dir,
                        "shell": account.pw_shell,
                        "interactive": interactive,
                    }
                )
        except OSError as exc:
            errors.append(f"Cannot read account database: {exc}")

    uid_zero = [item["name"] for item in accounts if item["uid"] == 0]
    if set(uid_zero) - {"root"}:
        findings.append(
            Finding(
                "users.additional_uid_zero",
                "Additional UID 0 account detected",
                Severity.CRITICAL,
                "users",
                "Accounts other than root have unrestricted superuser identity.",
                ", ".join(uid_zero),
                "Validate and reassign non-root UID 0 accounts.",
            )
        )
    system_shells = [item["name"] for item in accounts if item["uid"] < 1000 and item["uid"] != 0 and item["interactive"]]
    if system_shells:
        findings.append(
            Finding(
                "users.system_interactive_shells",
                "System accounts have interactive shells",
                Severity.MEDIUM,
                "users",
                "Service accounts with login shells can expand the attack surface.",
                ", ".join(system_shells),
                "Confirm each account requires interactive login; assign nologin where it does not.",
            )
        )

    sudo_members = _group_members(context, "sudo") | _group_members(context, "wheel")
    sudo_principals = _sudoers_principals(context)
    password_status = _password_statuses(context, accounts)
    recent_users = _recently_created_users(context)
    login_activity = _login_activity(context, accounts)
    inactive_admins = sorted(
        name
        for name in sudo_members
        if login_activity.get(name, {}).get("status") in {"INACTIVE", "NEVER_LOGGED_IN"}
    )
    no_password = [
        name
        for name, status in password_status.items()
        if status.get("state") == "NO_PASSWORD"
        and any(account["name"] == name and account["interactive"] for account in accounts)
    ]
    if no_password:
        findings.append(
            Finding(
                "users.passwordless_accounts",
                "Interactive accounts without passwords",
                Severity.HIGH,
                "users",
                "One or more login-capable local accounts have no password set.",
                ", ".join(no_password),
                "Lock unused accounts or set strong credentials, then verify SSH and sudo access policy.",
                risk_score=35,
                confidence=95,
                reason="A passwordless interactive account can permit unintended local or remote authentication.",
                remediation_commands=[f"sudo passwd -l {name}" for name in no_password],
            )
        )
    if recent_users:
        findings.append(
            Finding(
                "users.recent_accounts",
                "Recently created local accounts",
                Severity.MEDIUM,
                "users",
                "Account-creation events were found in recent authentication evidence.",
                ", ".join(item["name"] for item in recent_users),
                "Validate each account against an approved administrator or deployment change.",
                risk_score=18,
                confidence=85,
                reason="Unexpected account creation is a common persistence and privilege-escalation technique.",
            )
        )
    if inactive_admins:
        findings.append(
            Finding(
                "users.inactive_administrators",
                "Inactive accounts retain administrative access",
                Severity.LOW,
                "users",
                "Administrative group members have no recent recorded login.",
                ", ".join(inactive_admins),
                "Confirm the accounts are still required and lock obsolete accounts after approval.",
                risk_score=8,
                confidence=70,
                reason="Dormant privileged accounts increase credential and persistence exposure.",
            )
        )
    current_names = sorted(item["name"] for item in accounts)
    context.snapshots["users"] = current_names
    return ModuleResult(
        "users",
        {
            "accounts": accounts,
            "uid_zero_accounts": uid_zero,
            "administrative_group_members": sorted(sudo_members),
            "sudoers_principals": sorted(sudo_principals),
            "password_status": password_status,
            "recently_created_users": recent_users,
            "login_activity": login_activity,
            "inactive_days_threshold": int(context.config.get("users", {}).get("inactive_days", 90)),
        },
        findings,
        errors,
    )


def _group_members(context: AuditContext, group: str) -> set[str]:
    result = context.run(["getent", "group", group])
    if not result.ok or not result.stdout.strip():
        return set()
    fields = result.stdout.strip().split(":")
    return set(fields[3].split(",")) if len(fields) > 3 and fields[3] else set()


def _password_statuses(context: AuditContext, accounts: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    statuses: dict[str, dict[str, str]] = {}
    for account in accounts:
        if not account["interactive"]:
            continue
        result = context.run(["passwd", "-S", account["name"]], timeout=3)
        if not result.ok:
            continue
        fields = result.stdout.split()
        if len(fields) < 2:
            continue
        code = fields[1].upper()
        state = "PASSWORD_SET" if code in {"P", "PS"} else "LOCKED" if code in {"L", "LK"} else "NO_PASSWORD"
        statuses[account["name"]] = {
            "state": state,
            "last_change": fields[2] if len(fields) > 2 else "unknown",
        }
    return statuses


def _sudoers_principals(context: AuditContext) -> set[str]:
    principals: set[str] = set()
    paths = ["/etc/sudoers", *glob.glob("/etc/sudoers.d/*")]
    for value in paths:
        path = Path(value)
        if not path.is_file():
            continue
        text, _ = context.read_text(path, max_bytes=256 * 1024)
        for raw in (text or "").splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or line.lower().startswith(("defaults", "host_alias", "user_alias", "cmnd_alias", "runas_alias")):
                continue
            if re.search(r"\bALL\s*=", line):
                principals.add(line.split()[0])
    return principals


def _recently_created_users(context: AuditContext) -> list[dict[str, str]]:
    limit = int(context.config["audit"]["max_log_lines"])
    cutoff = datetime.now() - timedelta(days=int(context.config.get("users", {}).get("recent_account_days", 7)))
    results: list[dict[str, str]] = []
    pattern = re.compile(r"(?:useradd|adduser).*new user: name=([^,\s]+)", re.IGNORECASE)
    for configured in context.config["ssh"]["auth_log_paths"]:
        path = Path(configured)
        if not path.exists():
            continue
        lines, _ = context.tail_lines(path, limit)
        for line in lines:
            match = pattern.search(line)
            timestamp = _syslog_timestamp(line)
            if match and timestamp and timestamp >= cutoff:
                results.append({"name": match.group(1), "event": line[:15].strip(), "source": str(path)})
    return results[-100:]


def _syslog_timestamp(line: str) -> datetime | None:
    try:
        now = datetime.now()
        value = datetime.strptime(f"{line[:15]} {now.year}", "%b %d %H:%M:%S %Y")
        return value.replace(year=now.year - 1) if value > now + timedelta(days=1) else value
    except ValueError:
        return None


def _login_activity(context: AuditContext, accounts: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    activity: dict[str, dict[str, str]] = {}
    cutoff = datetime.now().astimezone() - timedelta(
        days=int(context.config.get("users", {}).get("inactive_days", 90))
    )
    for account in accounts:
        if not account["interactive"]:
            continue
        result = context.run(["lastlog", "-u", account["name"]], timeout=3)
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()] if result.ok else []
        value = lines[-1] if len(lines) >= 2 else "unavailable"
        last_login = _lastlog_timestamp(value)
        if "Never logged in" in value:
            status = "NEVER_LOGGED_IN"
        elif last_login and last_login < cutoff:
            status = "INACTIVE"
        elif last_login:
            status = "ACTIVE"
        else:
            status = "UNRESOLVED"
        activity[account["name"]] = {
            "status": status,
            "lastlog": value[:500],
            "last_login": last_login.isoformat() if last_login else "unknown",
        }
    return activity


def _lastlog_timestamp(value: str) -> datetime | None:
    match = re.search(
        r"([A-Z][a-z]{2} [A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} [+-]\d{4} \d{4})$",
        value,
    )
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1), "%a %b %d %H:%M:%S %z %Y")
    except ValueError:
        return None
