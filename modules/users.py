"""Local account and privilege inventory."""

from __future__ import annotations

from typing import Any

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
    current_names = sorted(item["name"] for item in accounts)
    context.snapshots["users"] = current_names
    return ModuleResult(
        "users",
        {"accounts": accounts, "uid_zero_accounts": uid_zero, "administrative_group_members": sorted(sudo_members)},
        findings,
        errors,
    )


def _group_members(context: AuditContext, group: str) -> set[str]:
    result = context.run(["getent", "group", group])
    if not result.ok or not result.stdout.strip():
        return set()
    fields = result.stdout.strip().split(":")
    return set(fields[3].split(",")) if len(fields) > 3 and fields[3] else set()
