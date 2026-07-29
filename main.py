#!/usr/bin/env python3
"""Production-safe, report-only VPS security audit orchestrator."""

from __future__ import annotations

import argparse
import copy
import logging
import os
import socket
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from analyzers.risk_engine import calculate_score, compare_snapshots
from audit_context import AuditContext
from config import ConfigError, load_config, project_path
from history import load_history, load_object, save_history, write_json
from models import AuditReport, Finding, ModuleResult, Severity, severity_counts
from modules import (
    caddy,
    cron,
    docker_audit,
    filesystem,
    firewall,
    network,
    persistence,
    process_investigation,
    ssh,
    system,
    users,
    web_server,
    wordpress,
)
from reports.html_generator import generate as generate_html

AuditFunction = Callable[[AuditContext], ModuleResult]
MODULES: dict[str, AuditFunction] = {
    "system": system.audit,
    "ssh": ssh.audit,
    "users": users.audit,
    "firewall": firewall.audit,
    "network": network.audit,
    "docker": docker_audit.audit,
    "caddy": caddy.audit,
    "wordpress": wordpress.audit,
    "filesystem": filesystem.audit,
    "cron": cron.audit,
    "persistence": persistence.audit,
    "process": process_investigation.audit,
    "web": web_server.audit,
}
DEFAULT_MODULES = list(MODULES)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read-only Linux VPS security audit and reporting")
    parser.add_argument("command", nargs="?", choices=("scan", "baseline"), default="scan")
    parser.add_argument("baseline_action", nargs="?", choices=("create", "compare"))
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().with_name("config.yaml"))
    parser.add_argument("--output-dir", type=Path, help="Override the configured report directory")
    parser.add_argument("--modules", nargs="+", choices=sorted(MODULES), help="Run only selected modules")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--no-history", action="store_true", help="Do not read or update scan history")
    return parser.parse_args(argv)


def run(args: argparse.Namespace) -> tuple[AuditReport, Path, Path]:
    config = load_config(args.config)
    if args.output_dir:
        config["audit"]["report_directory"] = str(args.output_dir.resolve())
    report_dir = project_path(config, config["audit"]["report_directory"])
    history_path = project_path(config, config["audit"]["history_file"])
    baseline_path = project_path(config, config["audit"]["baseline_file"])
    history = [] if args.no_history else load_history(history_path)
    if args.command == "baseline" and args.baseline_action == "compare":
        previous = load_object(baseline_path)
        if previous is None:
            raise ConfigError(f"No valid baseline exists at {baseline_path}; run 'baseline create' first")
    elif args.command == "baseline" and args.baseline_action == "create":
        previous = None
    else:
        previous = history[-1] if history else None
    logger = logging.getLogger("vps_security_audit")
    inherited_snapshot = copy.deepcopy(previous.get("snapshot", {})) if previous else {}
    context = AuditContext(config, previous, logger, snapshots=inherited_snapshot)

    selected = args.modules or DEFAULT_MODULES
    results: list[ModuleResult] = []
    for name in selected:
        started = time.monotonic()
        logger.info("Auditing %s", name)
        try:
            result = MODULES[name](context)
        except Exception as exc:  # one collector must never suppress the rest of the report
            logger.exception("Module %s failed", name)
            result = ModuleResult(name=name, errors=[f"Unhandled module error: {type(exc).__name__}: {exc}"])
        result.duration_ms = round((time.monotonic() - started) * 1000)
        results.append(result)

    changes = compare_snapshots(previous, context.snapshots)
    history_findings = _change_findings(changes)
    findings = [finding for result in results for finding in result.findings] + history_findings
    score, risk_level = calculate_score(findings)
    incident_assessment = _incident_assessment(findings)
    now = datetime.now(timezone.utc)
    scan_id = f"{now:%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
    report = AuditReport(
        scan_id=scan_id,
        generated_at=now.isoformat(),
        hostname=context.snapshots.get("hostname", socket.gethostname()),
        score=score,
        risk_level=risk_level,
        previous_score=previous.get("score") if previous else None,
        module_results=results,
        findings=sorted(findings, key=_finding_sort_key),
        changes=changes,
        metadata={
            "modules_requested": selected,
            "running_as_root": hasattr(os, "geteuid") and os.geteuid() == 0,
            "read_only_policy": True,
            "baseline_mode": args.baseline_action if args.command == "baseline" else None,
            "incident_assessment": incident_assessment,
        },
    )
    base = f"security-report-{now:%Y-%m-%d-%H%M%S}-{scan_id[-8:]}"
    html_path, json_path = report_dir / f"{base}.html", report_dir / f"{base}.json"
    generate_html(report, html_path)
    write_json(json_path, report.to_dict())

    if args.command == "baseline" and args.baseline_action == "create":
        write_json(
            baseline_path,
            {
                "schema_version": 1,
                "created_at": report.generated_at,
                "hostname": report.hostname,
                "score": score,
                "snapshot": context.snapshots,
            },
        )

    if not args.no_history:
        history.append(
            {
                "scan_id": scan_id,
                "generated_at": report.generated_at,
                "hostname": report.hostname,
                "score": score,
                "risk_level": risk_level,
                "summary": report.to_dict()["summary"],
                "snapshot": context.snapshots,
            }
        )
        save_history(history_path, history, int(config["audit"]["history_limit"]))
    return report, html_path, json_path


def _change_findings(changes: list[dict[str, object]]) -> list[Finding]:
    findings: list[Finding] = []
    for index, change in enumerate(changes):
        if change.get("type") in {"baseline", "removed"}:
            continue
        severity_name = str(change.get("severity", "info"))
        severity = Severity(severity_name) if severity_name in {item.value for item in Severity} else Severity.INFO
        findings.append(
            Finding(
                f"history.{change.get('category', 'general')}.{index}",
                str(change["description"]),
                severity,
                "history",
                "The item differs from the immediately preceding audit snapshot.",
                str(change["description"]),
                "Validate the change against an approved deployment or administrator action.",
            )
        )
    return findings


def _finding_sort_key(finding: Finding) -> tuple[int, int, str]:
    order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    return order[finding.severity], -(finding.risk_score or 0), finding.title.lower()


def _incident_assessment(findings: list[Finding]) -> dict[str, object]:
    incident_categories = {"process", "persistence"}
    strong = [
        item
        for item in findings
        if item.category in incident_categories and item.severity in {Severity.CRITICAL, Severity.HIGH}
    ]
    credential_events = [item for item in findings if item.finding_id == "ssh.success_after_failures"]
    if any(item.severity is Severity.CRITICAL for item in strong):
        status = "STRONG_INDICATORS"
        conclusion = "Strong compromise indicators require immediate human incident investigation."
    elif strong or credential_events:
        status = "POSSIBLE_COMPROMISE"
        conclusion = "Suspicious activity exists, but the scan alone cannot confirm compromise."
    else:
        status = "NO_DIRECT_INDICATORS"
        conclusion = "No direct compromise indicator was found in the evidence available to this scan."
    return {
        "status": status,
        "conclusion": conclusion,
        "supporting_findings": [item.finding_id for item in (strong + credential_events)[:20]],
        "disclaimer": "Absence of detected indicators is not proof that the host is uncompromised.",
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    if args.command == "baseline" and args.baseline_action is None:
        logging.error("Baseline action required: use 'baseline create' or 'baseline compare'")
        return 2
    try:
        report, html_path, json_path = run(args)
    except ConfigError as exc:
        logging.error("Configuration error: %s", exc)
        return 2
    except OSError as exc:
        logging.error("Cannot write audit output: %s", exc)
        return 3
    _terminal_report(report, html_path, json_path)
    return 0


def _terminal_report(report: AuditReport, html_path: Path, json_path: Path) -> None:
    counts = severity_counts(report.findings)
    print("\nVPS SECURITY AUDIT")
    print("=" * 72)
    print(f"Security score : {report.score}/100")
    print(f"Risk level     : {report.risk_level}")
    assessment = report.metadata["incident_assessment"]
    print(f"Incident status: {assessment['status']}")
    print(f"Assessment     : {assessment['conclusion']}")
    print(
        "Findings       : "
        f"{counts['critical']} critical, {counts['high']} high, "
        f"{counts['medium']} medium, {counts['low']} low"
    )
    if report.previous_score is not None:
        direction = "+" if report.score - report.previous_score >= 0 else ""
        print(f"Previous score : {report.previous_score}/100 ({direction}{report.score - report.previous_score})")
    print("\nMAIN CONCERNS")
    concerns = [item for item in report.findings if (item.risk_score or 0) > 0][:5]
    if concerns:
        for number, finding in enumerate(concerns, 1):
            print(
                f"{number}. [{finding.severity.value.upper()}] {finding.title} "
                f"(risk {finding.risk_score}, confidence {finding.confidence}%)"
            )
    else:
        print("No material security concerns were identified.")
    if report.changes:
        print("\nTIMELINE CHANGES")
        for change in report.changes[:10]:
            print(f"- {change['description']}")
    print(f"\nHTML report    : {html_path}")
    print(f"JSON report    : {json_path}")


if __name__ == "__main__":
    sys.exit(main())
