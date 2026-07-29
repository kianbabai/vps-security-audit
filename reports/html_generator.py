"""Jinja-based standalone HTML security report generation."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from models import AuditReport, Severity, severity_counts


def generate(report: AuditReport, output_path: Path) -> None:
    template_dir = Path(__file__).resolve().parent / "templates"
    environment = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(("html", "xml")),
        undefined=StrictUndefined,
    )
    environment.filters["severity_class"] = lambda value: str(value).lower()
    template = environment.get_template("security_report.html")
    counts = severity_counts(report.findings)
    module_errors = sum(len(item.errors) for item in report.module_results)
    html = template.render(
        report=report,
        counts=counts,
        module_errors=module_errors,
        severities=[item.value for item in Severity if item is not Severity.INFO],
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{output_path.name}.", suffix=".tmp", dir=output_path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(html)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, output_path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
