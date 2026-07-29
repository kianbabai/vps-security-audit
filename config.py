"""Configuration loading and validation."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml


class ConfigError(ValueError):
    pass


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        content = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"Cannot read configuration {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc
    if content is None:
        return {}
    if not isinstance(content, dict):
        raise ConfigError(f"Configuration root must be a mapping: {path}")
    return content


def load_config(path: Path) -> dict[str, Any]:
    default_path = Path(__file__).resolve().with_name("config.yaml")
    defaults = _read_yaml(default_path)
    configured = defaults if path.resolve() == default_path else _deep_merge(defaults, _read_yaml(path))
    _validate(configured)
    configured["_config_path"] = str(path.resolve())
    configured["_project_root"] = str(Path(__file__).resolve().parent)
    return configured


def _validate(config: dict[str, Any]) -> None:
    audit = config.get("audit")
    if not isinstance(audit, dict):
        raise ConfigError("Missing 'audit' configuration section")
    for key in ("command_timeout_seconds", "max_output_bytes", "max_log_lines", "history_limit"):
        value = audit.get(key)
        if not isinstance(value, int) or value <= 0:
            raise ConfigError(f"audit.{key} must be a positive integer")
    for key in ("report_directory", "history_file", "baseline_file"):
        if not isinstance(audit.get(key), str) or not audit[key].strip():
            raise ConfigError(f"audit.{key} must be a non-empty path")
    system = config.get("system", {})
    warning = system.get("disk_warning_percent")
    critical = system.get("disk_critical_percent")
    if not all(isinstance(value, int) and 0 < value <= 100 for value in (warning, critical)):
        raise ConfigError("System disk thresholds must be integers from 1 through 100")
    if warning >= critical:
        raise ConfigError("system.disk_warning_percent must be lower than disk_critical_percent")
    ssh = config.get("ssh", {})
    for key in ("failed_login_threshold", "distributed_attack_threshold", "success_after_failure_threshold"):
        if not isinstance(ssh.get(key), int) or ssh[key] <= 0:
            raise ConfigError(f"ssh.{key} must be a positive integer")
    for key in ("unusual_login_start_hour", "unusual_login_end_hour"):
        if not isinstance(ssh.get(key), int) or not 0 <= ssh[key] <= 23:
            raise ConfigError(f"ssh.{key} must be an integer from 0 through 23")
    users = config.get("users", {})
    for key in ("inactive_days", "recent_account_days"):
        if not isinstance(users.get(key), int) or users[key] <= 0:
            raise ConfigError(f"users.{key} must be a positive integer")


def project_path(config: dict[str, Any], configured_path: str) -> Path:
    path = Path(configured_path)
    if path.is_absolute():
        return path
    return Path(config["_project_root"]) / path
