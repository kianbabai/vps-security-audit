"""UFW, nftables, and iptables policy inspection."""

from __future__ import annotations

from typing import Any

from audit_context import AuditContext
from models import Finding, ModuleResult, Severity


def audit(context: AuditContext) -> ModuleResult:
    findings: list[Finding] = []
    errors: list[str] = []
    data: dict[str, Any] = {"backend": None, "enabled": False, "rules": []}

    ufw = context.run(["ufw", "status", "verbose"])
    if ufw.returncode == 0 and ufw.stdout:
        data.update({"backend": "ufw", "enabled": "Status: active" in ufw.stdout, "rules": ufw.stdout.splitlines()})
    else:
        nft = context.run(["nft", "list", "ruleset"])
        if nft.returncode == 0 and nft.stdout.strip():
            data.update({"backend": "nftables", "enabled": True, "rules": nft.stdout.splitlines()})
        else:
            iptables = context.run(["iptables", "-S"])
            if iptables.returncode == 0 and iptables.stdout.strip():
                rules = iptables.stdout.splitlines()
                active = any(not line.startswith("-P ") or " ACCEPT" not in line for line in rules)
                data.update({"backend": "iptables", "enabled": active, "rules": rules})
            else:
                errors.append("No readable UFW, nftables, or iptables policy was found")

    if context.config["firewall"].get("required", True) and not data["enabled"]:
        findings.append(
            Finding(
                "firewall.disabled",
                "Host firewall is disabled or has no restrictive policy",
                Severity.HIGH,
                "firewall",
                "No active host-level filtering policy could be verified.",
                f"Detected backend: {data['backend'] or 'none'}",
                "Enable a default-deny host firewall after validating required management and service ports.",
            )
        )
    rule_text = "\n".join(data["rules"]).lower()
    if data["enabled"] and ("0.0.0.0/0" in rule_text or "anywhere" in rule_text) and "allow" in rule_text:
        findings.append(
            Finding(
                "firewall.broad_allow_rules",
                "Firewall contains broadly scoped allow rules",
                Severity.LOW,
                "firewall",
                "One or more allow rules appear to accept traffic from any IPv4 source.",
                "Rule set contains an allow rule with Anywhere or 0.0.0.0/0",
                "Review broad rules and constrain source ranges where operationally possible.",
            )
        )
    context.snapshots["firewall"] = {"enabled": bool(data["enabled"]), "backend": data["backend"]}
    return ModuleResult("firewall", data, findings, errors)
