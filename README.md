# VPS Security Audit

A report-only security and incident-analysis tool for Ubuntu/Debian VPS hosts running Docker, Caddy, Nginx, Apache, and WordPress. It combines configuration checks with process context, network ownership, authentication attack sequences, persistence, file integrity, and historical state to answer both “what is misconfigured?” and “are there indicators of compromise?”

The auditor **does not** change firewall rules, accounts, services, containers, scheduled jobs, or application files. Its only writes are the configured report directory and `database/history.json`.

## What it audits

- Host identity, OS, kernel, uptime, CPU, memory, disks, public IP, and installed packages
- Effective OpenSSH policy, successful/failed logins, brute force patterns, unusual-hour logins, and authorized-key fingerprints
- Local users, UID 0 accounts, administrative groups, and service accounts with interactive shells
- Password state, recent account creation, inactive administrators, sudo access, and login history
- Public listeners, owning PID/user/executable, encryption expectation, established connections, dangerous ports, and unexpected exposed services
- UFW, nftables, or iptables status and broad allow rules
- Docker daemon access, containers, images, privileged/root containers, namespace sharing, capabilities, mounts, and published ports
- Caddy TLS/admin/header configuration and scanner/request-volume patterns in JSON or combined access logs
- Nginx, Apache, and Caddy detection with scanner, bot, SQL-injection, and path-traversal analysis
- WordPress permissions, installed plugin/theme names, executable uploads, login attacks, and XML-RPC abuse
- SHA-256 integrity state for security-sensitive configuration and Compose files
- System/user cron entries and suspicious persistence/download patterns
- Context-aware process investigation including PID/PPID, user, command, executable, working directory, start time, sockets, connections, parent tree, package ownership, and systemd ownership
- Custom/enabled systemd services and suspicious `.bashrc`, `.profile`, `rc.local`, and system-wide startup persistence
- Historical changes in users, ports, containers, SSH source IPs, SSH keys, and tracked file hashes

## Install

Python 3.12 or newer is recommended.

```bash
sudo install -d -m 0750 /opt/vps-security-audit
sudo cp -a . /opt/vps-security-audit/
cd /opt/vps-security-audit
python3.12 -m venv .venv
.venv/bin/pip install --requirement requirements.txt
sudo install -d -m 0700 reports/output database
```

Review [`config.yaml`](config.yaml) before the first run. In particular, set the actual Caddy logs, WordPress roots, Compose locations, expected public ports, and unusual SSH login window. Public-IP discovery uses the configured HTTPS endpoint; set `system.public_ip_lookup: false` for a fully offline audit. To enrich access-log sources with countries, set `privacy.geoip_database` to a local MaxMind-compatible `.mmdb` file.

## Run

For complete log, account, firewall, process, and Docker visibility, run as root:

```bash
sudo .venv/bin/python main.py
```

Useful scoped invocations:

```bash
sudo .venv/bin/python main.py --modules system ssh network firewall
sudo .venv/bin/python main.py --config /etc/vps-security-audit.yaml
sudo .venv/bin/python main.py --output-dir /secure/audit-reports --no-history
```

The included launcher provides the shorter command form requested by the baseline workflow:

```bash
chmod 0750 vps-audit
sudo ./vps-audit scan
sudo ./vps-audit baseline create
sudo ./vps-audit baseline compare
```

Reports are written with mode `0600` under `reports/output/` by default:

```text
security-report-YYYY-MM-DD-HHMMSS.html
security-report-YYYY-MM-DD-HHMMSS.json
```

Collection failures are recorded as module warnings and do not stop other modules. A non-root run is supported but will normally have gaps in authentication, firewall, Docker, process, shadow-file, and user-cron evidence.

## Risk and confidence model

Every finding includes a 0–100 risk score, 0–100 confidence, severity, evidence, contextual reasoning, recommendation, and optional remediation commands. Commands are displayed only and are never executed.

The overall score starts at 100. Finding risk is multiplied by confidence, then combined with diminishing weight inside each category. This prevents many variants of the same weak signal from overwhelming the host score. Category penalties are capped before the final score is clamped to 0–100.

| Score | Reported risk level |
|---:|---|
| 0–39 | `CRITICAL` |
| 40–59 | `HIGH` |
| 60–79 | `MEDIUM` |
| 80–89 | `LOW` |
| 90–100 | `HEALTHY` |

The report also produces an incident assessment: `NO_DIRECT_INDICATORS`, `POSSIBLE_COMPROMISE`, or `STRONG_INDICATORS`. Findings are still not proof of compromise; absence of indicators is not proof that a host is clean.

### Deleted executables

`(deleted)` is not treated as malware by itself. The process engine lowers risk when the executable is under a standard system path, belongs to an installed package, descends from systemd, or belongs to a standard unit. It raises risk for transient or hidden paths, root execution, unknown ancestry, public listeners, network connections, and custom persistence.

## Historical tracking

`database/history.json` stores bounded scan summaries and snapshots, not full reports or SSH public-key contents. The default retention is 90 scans. Normal scans compare with the immediately previous scan. Running a subset of modules preserves snapshot fields owned by modules that were not run.

Explicit baseline mode stores a stable reference in `database/baseline.json`:

```bash
sudo ./vps-audit baseline create
sudo ./vps-audit baseline compare
```

Creating a baseline replaces only the dedicated baseline file; it does not change the server. Comparing never updates the baseline. Both runtime files are excluded by `.gitignore` because they can reveal host inventory.

Back up or integrity-protect the history file if it is used as a security control. Keep it outside a web-served directory.

## systemd timer

Example hardened units are in `deployment/`. Their paths assume `/opt/vps-security-audit`.

```bash
sudo cp deployment/vps-security-audit.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vps-security-audit.timer
systemctl list-timers vps-security-audit.timer
```

The service gives the process read-only system access and explicitly permits writes only to the report and history directories. If you relocate either directory, update `ReadWritePaths` too.

## Test

The unit suite has no additional test dependency:

```bash
python -m unittest discover -s tests -v
python -m compileall -q .
```

Test on a staging VPS before scheduling it in production. Large logs are read from the end with bounded memory; commands use fixed argument vectors (never a shell), a restricted environment, output limits, and timeouts.

## Operational security

- HTML/JSON reports can contain usernames, IP addresses, paths, service versions, and configuration evidence. Do not publish them.
- File integrity records SHA-256 hashes and metadata, not file contents.
- Authorized keys are recorded as SHA-256 fingerprints; key material is not stored.
- Caddy/SSH log parsing is heuristic and respects `audit.max_log_lines`.
- “Outdated Docker images” cannot be established safely without contacting registries or pulling metadata. This auditor reports image identifiers and mutable `latest` tags; use a separate authenticated image-scanning pipeline for authoritative CVE and freshness data.
- There is intentionally no `--fix` mode. Suggested commands appear as remediation guidance, but every supported invocation remains read-only with respect to host configuration and services.
- GeoIP is only inferred when `privacy.geoip_database` points to a local trusted database; no address is sent to a GeoIP web service.

## Layout

```text
main.py                  orchestration and CLI
audit_context.py         bounded read-only command/file collection
config.py                YAML loading, defaults, validation
models.py                typed report and finding model
modules/                 individual host/service collectors
analyzers/               auth/web activity and risk/history engines
reports/                 HTML generator and template
database/                runtime history and explicit baseline store
deployment/              example systemd service and timer
tests/                   unit tests
```
