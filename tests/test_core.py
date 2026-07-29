from __future__ import annotations

import json
import logging
import tempfile
import unittest
from pathlib import Path

from audit_context import AuditContext
from config import load_config
from history import load_history, save_history
from modules.cron import _sanitize
from modules.network import _parse_socket


class ConfigTests(unittest.TestCase):
    def test_default_configuration_loads(self) -> None:
        config = load_config(Path(__file__).resolve().parents[1] / "config.yaml")
        self.assertGreater(config["audit"]["command_timeout_seconds"], 0)

    def test_custom_configuration_is_merged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "custom.yaml"
            path.write_text("system:\n  disk_warning_percent: 70\n", encoding="utf-8")
            config = load_config(path)
            self.assertEqual(config["system"]["disk_warning_percent"], 70)
            self.assertIn("history_file", config["audit"])


class HistoryTests(unittest.TestCase):
    def test_history_is_bounded_and_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.json"
            save_history(path, [{"score": 1}, {"score": 2}, {"score": 3}], 2)
            self.assertEqual(load_history(path), [{"score": 2}, {"score": 3}])
            json.loads(path.read_text(encoding="utf-8"))


class CollectionSafetyTests(unittest.TestCase):
    def test_tail_lines_reads_recent_bounded_content(self) -> None:
        config = load_config(Path(__file__).resolve().parents[1] / "config.yaml")
        context = AuditContext(config, None, logging.getLogger("test"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activity.log"
            path.write_text("\n".join(f"line-{number}" for number in range(100)), encoding="utf-8")
            lines, error = context.tail_lines(path, 3)
            self.assertIsNone(error)
            self.assertEqual(lines, ["line-97", "line-98", "line-99"])

    def test_cron_secret_redaction(self) -> None:
        value = _sanitize("API_TOKEN=supersecret curl 'https://example.test/?token=abc123'")
        self.assertNotIn("supersecret", value)
        self.assertNotIn("abc123", value)
        self.assertEqual(value.count("[REDACTED]"), 2)


class NetworkParserTests(unittest.TestCase):
    def test_public_ipv4_listener(self) -> None:
        item = _parse_socket('tcp LISTEN 0 4096 0.0.0.0:2375 0.0.0.0:* users:(("dockerd",pid=1,fd=3))')
        self.assertIsNotNone(item)
        assert item is not None
        self.assertEqual(item["port"], 2375)
        self.assertTrue(item["public_access"])
        self.assertEqual(item["process"], "dockerd")

    def test_loopback_ipv6_listener(self) -> None:
        item = _parse_socket("tcp LISTEN 0 128 [::1]:2019 [::]:*")
        self.assertIsNotNone(item)
        assert item is not None
        self.assertFalse(item["public_access"])
        self.assertEqual(item["port"], 2019)


if __name__ == "__main__":
    unittest.main()
