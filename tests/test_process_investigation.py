from __future__ import annotations

import unittest

from modules.process_investigation import _assess


class ProcessRiskTests(unittest.TestCase):
    def test_packaged_deleted_systemd_binary_is_low_risk(self) -> None:
        item = {
            "executable": "/usr/lib/systemd/systemd-logind (deleted)",
            "user": "root",
            "parent_tree": [{"pid": 1, "name": "systemd"}],
            "network_connections": [],
            "open_ports": [],
            "package_owner": "systemd",
            "systemd_unit": "systemd-logind.service",
            "custom_systemd_service": False,
        }
        result = _assess(item, False, False, True, False, False)
        self.assertEqual(result["severity"], "low")
        self.assertLessEqual(result["risk_score"], 10)
        self.assertIn("owned by installed package", result["reason"])

    def test_public_root_service_remains_medium_risk_when_packaged(self) -> None:
        item = {
            "executable": "/usr/bin/node",
            "user": "root",
            "parent_tree": [{"pid": 1, "name": "systemd"}],
            "network_connections": [],
            "open_ports": [{"public": True, "port": 5678}],
            "package_owner": "nodejs",
            "systemd_unit": "myapp.service",
            "custom_systemd_service": True,
        }
        result = _assess(item, False, False, False, False, False)
        self.assertEqual(result["severity"], "medium")
        self.assertGreaterEqual(result["risk_score"], 30)


if __name__ == "__main__":
    unittest.main()
