"""OpenSSH configuration, authentication, and key audit."""

from __future__ import annotations

import glob
import hashlib
from pathlib import Path
from typing import Any

from analyzers.brute_force import analyze_auth_lines
from audit_context import AuditContext
from geoip_lookup import countries_for_ips
from models import Finding, ModuleResult, Severity


def audit(context: AuditContext) -> ModuleResult:
    config = context.config["ssh"]
    findings: list[Finding] = []
    errors: list[str] = []
    effective = _effective_config(context, Path(config["config_path"]), errors)

    _config_finding(
        findings,
        effective.get("permitrootlogin", "unknown") not in {"no", "prohibit-password", "forced-commands-only"},
        "ssh.root_login",
        "SSH root login is permitted",
        Severity.HIGH,
        f"PermitRootLogin {effective.get('permitrootlogin', 'not resolved')}",
        "Set PermitRootLogin no and use a named administrative account with sudo.",
        [
            "sudoedit /etc/ssh/sshd_config",
            "sudo sshd -t",
            "sudo systemctl reload ssh",
        ],
    )
    _config_finding(
        findings,
        effective.get("passwordauthentication", "unknown") != "no",
        "ssh.password_authentication",
        "SSH password authentication is enabled or unresolved",
        Severity.HIGH,
        f"PasswordAuthentication {effective.get('passwordauthentication', 'not resolved')}",
        "After confirming key-based access works, set PasswordAuthentication no.",
        [
            "sudoedit /etc/ssh/sshd_config",
            "sudo sshd -t",
            "sudo systemctl reload ssh",
        ],
    )
    _config_finding(
        findings,
        effective.get("permitemptypasswords", "no") != "no",
        "ssh.empty_passwords",
        "SSH permits empty passwords",
        Severity.CRITICAL,
        f"PermitEmptyPasswords {effective.get('permitemptypasswords')}",
        "Set PermitEmptyPasswords no immediately and review all account password states.",
        [
            "sudoedit /etc/ssh/sshd_config",
            "sudo sshd -t",
            "sudo systemctl reload ssh",
        ],
    )
    if not effective.get("allowusers") and not effective.get("allowgroups"):
        findings.append(
            Finding(
                "ssh.no_allowlist",
                "SSH access has no user or group allowlist",
                Severity.LOW,
                "ssh",
                "No effective AllowUsers or AllowGroups directive was found.",
                "AllowUsers: unset; AllowGroups: unset",
                "Consider limiting SSH access with AllowUsers or AllowGroups.",
            )
        )

    auth_lines = _auth_lines(context, config["auth_log_paths"], errors)
    auth_data, auth_findings = analyze_auth_lines(
        auth_lines,
        int(config["failed_login_threshold"]),
        int(config["distributed_attack_threshold"]),
        int(config["unusual_login_start_hour"]),
        int(config["unusual_login_end_hour"]),
        int(config["success_after_failure_threshold"]),
    )
    countries = countries_for_ips(
        [item["ip"] for item in auth_data["failed_by_ip"]],
        context.config.get("privacy", {}).get("geoip_database"),
        errors,
    )
    for attacker in auth_data["failed_by_ip"]:
        attacker["country"] = countries.get(attacker["ip"], "unknown")
    findings.extend(auth_findings)
    key_data = _authorized_keys(config["authorized_keys_globs"], errors)
    fail2ban = context.run(["systemctl", "is-active", "fail2ban"], timeout=3)
    current_keys = sorted(item["fingerprint"] for item in key_data)
    previous_keys = set((context.previous_scan or {}).get("snapshot", {}).get("ssh_keys", []))
    for fingerprint in sorted(set(current_keys) - previous_keys) if context.previous_scan else []:
        findings.append(
            Finding(
                "ssh.new_authorized_key",
                "New SSH authorized key detected",
                Severity.HIGH,
                "ssh",
                "An SSH public-key fingerprint was not present in the previous scan.",
                fingerprint,
                "Confirm the key owner and remove the key manually if it is unauthorized.",
            )
        )

    successful_ips = sorted({item["ip"] for item in auth_data["successful_logins"]})
    context.snapshots["ssh_ips"] = successful_ips
    context.snapshots["ssh_keys"] = current_keys
    return ModuleResult(
        "ssh",
        {
            "config_path": config["config_path"],
            "effective_configuration": effective,
            "security_status": {
                "root_login": (
                    "DISABLED" if effective.get("permitrootlogin") == "no"
                    else "KEY_ONLY" if effective.get("permitrootlogin") in {"prohibit-password", "without-password"}
                    else "RESTRICTED" if effective.get("permitrootlogin") == "forced-commands-only"
                    else "ENABLED_OR_UNRESOLVED"
                ),
                "password_login": (
                    "DISABLED" if effective.get("passwordauthentication") == "no" else "ENABLED_OR_UNRESOLVED"
                ),
                "ssh_keys": "YES" if key_data else "NO",
                "port": int(effective.get("port", "22").split()[0])
                if effective.get("port", "22").split()[0].isdigit()
                else effective.get("port", "unknown"),
            },
            "authentication": auth_data,
            "attack_summary": {
                "failed_login_attempts": auth_data["total_failures"],
                "unique_attacking_ips": auth_data["distinct_failure_ips"],
                "top_attackers": auth_data["failed_by_ip"][:20],
                "fail2ban_active": fail2ban.stdout.strip() == "active",
            },
            "authorized_keys": key_data,
        },
        findings,
        errors,
    )


def _effective_config(context: AuditContext, path: Path, errors: list[str]) -> dict[str, str]:
    result = context.run(["sshd", "-T", "-f", str(path)])
    if result.ok:
        return {
            parts[0].lower(): " ".join(parts[1:]).lower()
            for line in result.stdout.splitlines()
            if len(parts := line.split()) >= 2
        }
    text, error = context.read_text(path)
    if error:
        errors.append(f"SSH configuration unavailable: {error}")
        return {}
    parsed: dict[str, str] = {}
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.lower().startswith(("match ", "include ")):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].lower() not in parsed:
            parsed[parts[0].lower()] = parts[1].strip().lower()
    return parsed


def _auth_lines(context: AuditContext, paths: list[str], errors: list[str]) -> list[str]:
    limit = int(context.config["audit"]["max_log_lines"])
    lines: list[str] = []
    for configured in paths:
        path = Path(configured)
        recent, error = context.tail_lines(path, limit)
        if recent:
            lines.extend(recent)
        elif error and path.exists():
            errors.append(f"Cannot read {path}: {error}")
    if not lines:
        journal = context.run(["journalctl", "-u", "ssh", "-u", "sshd", "--no-pager", "-n", str(limit)])
        if journal.ok:
            lines = journal.stdout.splitlines()
        elif journal.error:
            errors.append("Authentication logs unavailable through files and journalctl")
    return lines[-limit:]


def _authorized_keys(patterns: list[str], errors: list[str]) -> list[dict[str, Any]]:
    keys: list[dict[str, Any]] = []
    for pattern in patterns:
        for value in glob.glob(pattern, recursive=True):
            path = Path(value)
            try:
                owner = path.stat().st_uid
                for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    keys.append(
                        {
                            "path": str(path),
                            "line": number,
                            "owner_uid": owner,
                            "fingerprint": hashlib.sha256(stripped.encode()).hexdigest(),
                            "type": stripped.split()[0],
                        }
                    )
            except OSError as exc:
                errors.append(f"Cannot inspect {path}: {exc}")
    return keys


def _config_finding(
    findings: list[Finding],
    condition: bool,
    finding_id: str,
    title: str,
    severity: Severity,
    evidence: str,
    recommendation: str,
    remediation_commands: list[str] | None = None,
) -> None:
    if condition:
        findings.append(
            Finding(
                finding_id,
                title,
                severity,
                "ssh",
                "The effective SSH policy increases remote-access risk.",
                evidence,
                recommendation,
                remediation_commands=remediation_commands or [],
                confidence=90 if "not resolved" not in evidence else 55,
                reason="The effective SSH authentication policy permits a higher-risk remote access path.",
            )
        )
