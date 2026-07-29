# VPS Security Audit

A report-only security auditor for Ubuntu/Debian VPS hosts running Docker, Caddy, and WordPress. It inventories the host, analyzes authentication and web activity, checks common configuration risks, compares file hashes and infrastructure state with the prior scan, and produces standalone HTML and JSON reports.

The auditor **does not** change firewall rules, accounts, services, containers, scheduled jobs, or application files. Its only writes are the configured report directory and `database/history.json`.

## What it audits

- Host identity, OS, kernel, uptime, CPU, memory, disks, public IP, and installed packages
- Effective OpenSSH policy, successful/failed logins, brute force patterns, unusual-hour logins, and authorized-key fingerprints
- Local users, UID 0 accounts, administrative groups, and service accounts with interactive shells
- Public listeners, established connections, dangerous ports, and unexpected exposed services
- UFW, nftables, or iptables status and broad allow rules
- Docker daemon access, containers, images, privileged/root containers, namespace sharing, capabilities, mounts, and published ports
- Caddy TLS/admin/header configuration and scanner/request-volume patterns in JSON or combined access logs
- WordPress permissions, installed plugin/theme names, executable uploads, login attacks, and XML-RPC abuse
- SHA-256 integrity state for security-sensitive configuration and Compose files
- System/user cron entries and suspicious persistence/download patterns
- High-CPU processes, known miner names, transient executables, and deleted executables
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

Reports are written with mode `0600` under `reports/output/` by default:

```text
security-report-YYYY-MM-DD-HHMMSS.html
security-report-YYYY-MM-DD-HHMMSS.json
```

Collection failures are recorded as module warnings and do not stop other modules. A non-root run is supported but will normally have gaps in authentication, firewall, Docker, process, shadow-file, and user-cron evidence.

## Risk model

The score starts at 100 and subtracts 20 points for each critical finding, 10 for high, 5 for medium, and 2 for low. It is clamped at zero.

| Score | Reported risk level |
|---:|---|
| 0–39 | `CRITICAL` |
| 40–69 | `WARNING` |
| 70–100 | `GOOD` |

Findings are independent signals, not proof of compromise. Validate evidence in operational context before remediation.

## Historical tracking

`database/history.json` stores bounded scan summaries and snapshots, not full reports or SSH public-key contents. The default retention is 90 scans. On the first run, the tool creates a baseline. Subsequent scans report additions/removals and tracked file changes. Running a subset of modules preserves snapshot fields owned by modules that were not run.

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
database/history.json    initial historical baseline store
deployment/              example systemd service and timer
tests/                   unit tests
```
