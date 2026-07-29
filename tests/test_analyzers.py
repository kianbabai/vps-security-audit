from __future__ import annotations

import unittest

from analyzers.brute_force import analyze_auth_lines
from analyzers.risk_engine import calculate_score, compare_snapshots
from analyzers.suspicious_activity import parse_access_lines
from models import Finding, Severity


class BruteForceTests(unittest.TestCase):
    def test_detects_failures_and_unusual_success(self) -> None:
        lines = [
            "Jan 10 02:10:00 host sshd[1]: Accepted publickey for admin from 203.0.113.7 port 50000 ssh2",
            *[
                "Jan 10 12:00:00 host sshd[2]: Failed password for invalid user oracle "
                "from 198.51.100.9 port 40000 ssh2"
                for _ in range(3)
            ],
        ]
        data, findings = analyze_auth_lines(lines, 3, 20, 0, 5)
        self.assertEqual(data["total_failures"], 3)
        self.assertEqual(data["successful_logins"][0]["user"], "admin")
        self.assertIn("ssh.brute_force", {item.finding_id for item in findings})
        self.assertIn("ssh.unusual_login_time", {item.finding_id for item in findings})

    def test_detects_success_after_failures(self) -> None:
        lines = [
            "Jan 10 01:00:00 host sshd[1]: Failed password for admin from 203.0.113.7 port 50000 ssh2",
            "Jan 10 01:01:00 host sshd[2]: Accepted password for admin from 203.0.113.7 port 50001 ssh2",
        ]
        data, findings = analyze_auth_lines(lines, 10, 20, 3, 5, 1)
        self.assertEqual(data["successful_after_failures"][0]["prior_failures"], 1)
        self.assertIn("ssh.success_after_failures", {item.finding_id for item in findings})


class WebActivityTests(unittest.TestCase):
    def test_parses_caddy_json_and_combined_logs(self) -> None:
        lines = [
            '{"request":{"client_ip":"192.0.2.10","uri":"/.env",'
            '"headers":{"User-Agent":["nuclei"]}},"status":404}',
            '198.51.100.4 - - [10/Jan/2026:12:00:00 +0000] "POST /wp-login.php HTTP/1.1" '
            '200 12 "-" "Mozilla/5.0"',
        ]
        data, findings = parse_access_lines(lines, 100)
        self.assertEqual(data["parsed_requests"], 2)
        self.assertEqual(data["wp_login_by_ip"]["198.51.100.4"], 1)
        self.assertIn("web.scanner_activity", {item.finding_id for item in findings})

    def test_detects_injection_and_traversal(self) -> None:
        lines = [
            '192.0.2.1 - - [x] "GET /item?id=1%27%20or%201=1 HTTP/1.1" 500 2 "-" "browser"',
            '192.0.2.2 - - [x] "GET /../../etc/passwd HTTP/1.1" 404 2 "-" "browser"',
        ]
        data, findings = parse_access_lines(lines, 100)
        ids = {item.finding_id for item in findings}
        self.assertIn("web.sql_injection_probing", ids)
        self.assertIn("web.path_traversal_probing", ids)
        self.assertEqual(data["parsed_requests"], 2)


class RiskEngineTests(unittest.TestCase):
    def test_penalties_and_threshold(self) -> None:
        findings = [
            Finding("a", "A", Severity.CRITICAL, "x", "d", "e", "r"),
            Finding("b", "B", Severity.HIGH, "x", "d", "e", "r"),
            Finding("c", "C", Severity.LOW, "x", "d", "e", "r"),
        ]
        self.assertEqual(calculate_score(findings), (68, "MEDIUM"))

    def test_repeated_low_findings_have_diminishing_weight(self) -> None:
        findings = [Finding(str(number), "Low", Severity.LOW, "docker", "d", "e", "r") for number in range(20)]
        score, level = calculate_score(findings)
        self.assertGreaterEqual(score, 80)
        self.assertIn(level, {"LOW", "HEALTHY"})

    def test_finding_exports_context_fields(self) -> None:
        finding = Finding("x", "Title", Severity.MEDIUM, "test", "happened", "evidence", "fix")
        value = finding.to_dict()
        self.assertIn("risk_score", value)
        self.assertIn("confidence", value)
        self.assertEqual(value["what_happened"], "happened")
        self.assertEqual(value["how_to_fix"], "fix")

    def test_snapshot_comparison(self) -> None:
        previous = {"snapshot": {"users": ["root"], "ports": ["tcp/22"], "file_hashes": {"/x": "old"}}}
        current = {"users": ["root", "deploy"], "ports": ["tcp/22"], "file_hashes": {"/x": "new"}}
        changes = compare_snapshots(previous, current)
        descriptions = {item["description"] for item in changes}
        self.assertIn("New user: deploy", descriptions)
        self.assertIn("Tracked file changed: /x", descriptions)


if __name__ == "__main__":
    unittest.main()
