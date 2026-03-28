# SOCops Administration Manual

**Platform:** Ubuntu 24.04 LTS · **Runtime:** Python 3.12 · **Port:** 8081

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Installation](#2-installation)
   - 2.1 [Dependencies](#21-dependencies)
   - 2.2 [File Layout](#22-file-layout)
   - 2.3 [Initial Configuration](#23-initial-configuration)
   - 2.4 [First Run](#24-first-run)
3. [Running SOCops](#3-running-socops)
   - 3.1 [Direct (foreground)](#31-direct-foreground)
   - 3.2 [Background with nohup](#32-background-with-nohup)
   - 3.3 [systemd Service (recommended)](#33-systemd-service-recommended)
   - 3.4 [Verifying the Process](#34-verifying-the-process)
4. [Configuration Reference](#4-configuration-reference)
   - 4.1 [Required Variables](#41-required-variables)
   - 4.2 [App Behaviour Variables](#42-app-behaviour-variables)
   - 4.3 [AI Analysis Variables](#43-ai-analysis-variables)
   - 4.4 [Threat Intel Variables](#44-threat-intel-variables)
   - 4.5 [Notification Variables](#45-notification-variables)
5. [Architecture and Process Model](#5-architecture-and-process-model)
   - 5.1 [Threads](#51-threads)
   - 5.2 [Wazuh Connection](#52-wazuh-connection)
   - 5.3 [Data Flow](#53-data-flow)
6. [Database Administration](#6-database-administration)
   - 6.1 [Schema Overview](#61-schema-overview)
   - 6.2 [Location and Size](#62-location-and-size)
   - 6.3 [Backup](#63-backup)
   - 6.4 [Restore](#64-restore)
   - 6.5 [Pruning Old Alerts](#65-pruning-old-alerts)
   - 6.6 [Schema Migration](#66-schema-migration)
   - 6.7 [Inspecting the Database](#67-inspecting-the-database)
7. [Wazuh Integration](#7-wazuh-integration)
   - 7.1 [Required Wazuh Account](#71-required-wazuh-account)
   - 7.2 [SSL / Certificate Handling](#72-ssl--certificate-handling)
   - 7.3 [Noise Filtering](#73-noise-filtering)
   - 7.4 [Poll Window and Backfill](#74-poll-window-and-backfill)
   - 7.5 [Alert Fetch Limit](#75-alert-fetch-limit)
8. [Threat Intel Enrichment](#8-threat-intel-enrichment)
   - 8.1 [AbuseIPDB](#81-abuseipdb)
   - 8.2 [AlienVault OTX](#82-alienvault-otx)
   - 8.3 [Rate Limits](#83-rate-limits)
   - 8.4 [Disabling Enrichment](#84-disabling-enrichment)
9. [AI Analysis](#9-ai-analysis)
   - 9.1 [Claude Haiku Integration](#91-claude-haiku-integration)
   - 9.2 [Fallback Stub Analysis](#92-fallback-stub-analysis)
   - 9.3 [Token Usage and Cost](#93-token-usage-and-cost)
   - 9.4 [Model Selection](#94-model-selection)
10. [Notification Setup](#10-notification-setup)
    - 10.1 [Webhook](#101-webhook)
    - 10.2 [Email via SMTP](#102-email-via-smtp)
    - 10.3 [Testing Notifications](#103-testing-notifications)
11. [Telegram Bot](#11-telegram-bot)
    - 11.1 [Setup](#111-setup)
    - 11.2 [Running as a Service](#112-running-as-a-service)
    - 11.3 [Securing the Bot](#113-securing-the-bot)
12. [Logs and Monitoring](#12-logs-and-monitoring)
    - 12.1 [Log Output](#121-log-output)
    - 12.2 [Monitoring with systemd](#122-monitoring-with-systemd)
    - 12.3 [Health Check Endpoint](#123-health-check-endpoint)
    - 12.4 [Thread Health](#124-thread-health)
13. [Security Hardening](#13-security-hardening)
    - 13.1 [Network Access](#131-network-access)
    - 13.2 [Credential Storage](#132-credential-storage)
    - 13.3 [Wazuh Monitor Account](#133-wazuh-monitor-account)
    - 13.4 [Reverse Proxy with HTTPS](#134-reverse-proxy-with-https)
    - 13.5 [File Permissions](#135-file-permissions)
14. [Maintenance Tasks](#14-maintenance-tasks)
    - 14.1 [Updating SOCops](#141-updating-socops)
    - 14.2 [Updating Python Dependencies](#142-updating-python-dependencies)
    - 14.3 [Rotating API Keys](#143-rotating-api-keys)
    - 14.4 [Reviewing Suppression Rules](#144-reviewing-suppression-rules)
    - 14.5 [Database Maintenance](#145-database-maintenance)
15. [Troubleshooting](#15-troubleshooting)
    - 15.1 [App Won't Start](#151-app-wont-start)
    - 15.2 [No Alerts Appearing](#152-no-alerts-appearing)
    - 15.3 [Wazuh Connection Errors](#153-wazuh-connection-errors)
    - 15.4 [AI Analysis Not Running](#154-ai-analysis-not-running)
    - 15.5 [Enrichment Not Working](#155-enrichment-not-working)
    - 15.6 [Notifications Not Sending](#156-notifications-not-sending)
    - 15.7 [UI Issues](#157-ui-issues)
    - 15.8 [Database Errors](#158-database-errors)
    - 15.9 [High Memory or CPU](#159-high-memory-or-cpu)
16. [Disaster Recovery](#16-disaster-recovery)

---

## 1. System Requirements

**Minimum:**
- CPU: 1 core
- RAM: 256 MB
- Disk: 1 GB (database grows ~3 MB per 1,000 alerts with full_json stored)
- OS: Any Linux with Python 3.10+
- Network: HTTP/HTTPS access to Wazuh/OpenSearch host on port 443

**Tested on:**
- Ubuntu 24.04 LTS, Python 3.12.3
- Wazuh 4.x with OpenSearch Dashboards

**External services (all optional):**
- Anthropic API — Claude Haiku for AI alert analysis
- AlienVault OTX — IP threat intel
- AbuseIPDB — IP abuse reputation
- SMTP server — email notifications
- Telegram Bot API — phone interface

**Python packages required:**
```
anthropic>=0.80.0     # AI analysis
pyTelegramBotAPI      # Telegram bot (telebot/ directory only)
```

All other dependencies (sqlite3, http.server, threading, json, csv, ssl, smtplib, urllib) are Python standard library — no additional packages needed for core functionality.

---

## 2. Installation

### 2.1 Dependencies

Install required Python packages system-wide:

```bash
pip3 install anthropic pyTelegramBotAPI --break-system-packages
```

On Ubuntu 24.04 the `--break-system-packages` flag is required due to PEP 668 externally-managed-environment enforcement. The risk is minimal for these packages as they have no conflicting system dependencies.

Alternatively, use a virtual environment:

```bash
python3 -m venv ~/claude/socops/venv
source ~/claude/socops/venv/bin/activate
pip install anthropic pyTelegramBotAPI
```

If using a venv, update the systemd `ExecStart` line to point to the venv Python:
```
ExecStart=~/claude/socops/venv/bin/python3 ~/claude/socops/app.py
```

### 2.2 File Layout

```
~/claude/socops/
├── app.py              Main server (all routes, background threads, all page HTML)
├── db.py               SQLite schema and CRUD helpers
├── wazuh.py            Wazuh/OpenSearch client
├── analyst.py          AI analysis engine (Claude or stub)
├── enrichment.py       IP threat intel (AbuseIPDB + OTX)
├── notifier.py         Outbound notifications (webhook + SMTP)
├── socops.service      systemd unit file
├── .env.example        Configuration template
├── .env                Active configuration (create from .env.example, not in git)
├── socops.db           SQLite database (auto-created on first run, not in git)
├── README.md           Technical reference
├── MANUAL.md           User manual
└── ADMIN.md            This document
```

### 2.3 Initial Configuration

```bash
cd ~/claude/socops
cp .env.example .env
chmod 600 .env          # protect credentials
nano .env               # fill in values
```

At minimum, set:
```env
WAZUH_HOST=<your wazuh host or IP>
WAZUH_USER=<opensearch username>
WAZUH_PASS=<opensearch password>
```

All other variables have safe defaults and can be added incrementally.

### 2.4 First Run

Test the configuration before installing as a service:

```bash
cd ~/claude/socops
env $(cat .env | grep -v '^#' | grep '=' | xargs) python3 app.py
```

Watch the startup output:
```
[poller] starting
[analyst] starting
[enrichment] starting
SOCops listening on port 8081
```

Open `http://localhost:8081/api/stats` in a browser or with curl. If you see a JSON stats object, the app is healthy. The database is created automatically on first start.

The first poll runs immediately. With `INITIAL_WINDOW=now-24h`, the first fetch may import hundreds or thousands of alerts. Subsequent polls only fetch alerts newer than the last successful poll timestamp.

---

## 3. Running SOCops

### 3.1 Direct (foreground)

Useful for testing and debugging. Logs print to the terminal. Ctrl+C to stop.

```bash
cd ~/claude/socops
env $(cat .env | grep -v '^#' | grep '=' | xargs) python3 app.py
```

### 3.2 Background with nohup

Useful for quick ad-hoc runs without setting up systemd. Not recommended for production — does not auto-restart on failure.

```bash
cd ~/claude/socops
nohup env $(cat .env | grep -v '^#' | grep '=' | xargs) python3 app.py > /tmp/socops.log 2>&1 &
echo "PID: $!"
```

Stop:
```bash
ps aux | grep "[a]pp.py" | awk '{print $2}' | xargs kill
```

View logs:
```bash
tail -f /tmp/socops.log
```

### 3.3 systemd Service (recommended)

Provides automatic startup on boot, restart on failure, and proper log integration.

**Install:**
```bash
sudo cp ~/claude/socops/socops.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable socops          # start on boot
sudo systemctl start socops
```

**Check status:**
```bash
sudo systemctl status socops
```

**View logs:**
```bash
sudo journalctl -u socops -f          # follow live
sudo journalctl -u socops --since "1 hour ago"
sudo journalctl -u socops -n 100      # last 100 lines
```

**Restart after config change:**
```bash
sudo systemctl restart socops
```

**Stop:**
```bash
sudo systemctl stop socops
```

**The service unit** (`socops.service`) reads credentials from `.env` via the `EnvironmentFile=` directive. The `.env` file must exist and be readable by the service user (`YOUR_USER`) before starting.

Service unit summary:
```ini
[Service]
Type=simple
User=YOUR_USER
WorkingDirectory=~/claude/socops
EnvironmentFile=~/claude/socops/.env
ExecStart=/usr/bin/python3 ~/claude/socops/app.py
Restart=on-failure
RestartSec=10
```

`Restart=on-failure` means systemd will restart the process if it exits with a non-zero code (crashes, unhandled exceptions). It will not restart if you stop it manually with `systemctl stop`.

### 3.4 Verifying the Process

```bash
# Check process is running
ps aux | grep "[a]pp.py"

# Check port is listening
ss -tlnp | grep 8081

# Health check
curl -s http://localhost:8081/api/stats | python3 -m json.tool

# Confirm Wazuh polling is working
curl -s http://localhost:8081/api/stats | python3 -c "import json,sys; s=json.load(sys.stdin); print('Last poll:', s['last_poll'])"
```

---

## 4. Configuration Reference

All configuration is via environment variables. When running as a systemd service, these are loaded from `.env`. When running directly, source `.env` or pass variables on the command line.

### 4.1 Required Variables

| Variable | Description | Example |
|---|---|---|
| `WAZUH_HOST` | Wazuh/OpenSearch host (IP or hostname, no protocol) | `your.wazuh.host` |
| `WAZUH_USER` | OpenSearch Dashboards username | `monitor` |
| `WAZUH_PASS` | OpenSearch Dashboards password | `SecurePass123` |

### 4.2 App Behaviour Variables

| Variable | Default | Description |
|---|---|---|
| `SOCOPS_PORT` | `8081` | TCP port to listen on |
| `POLL_INTERVAL` | `60` | Seconds between Wazuh polls |
| `INITIAL_WINDOW` | `now-24h` | How far back to fetch on first run (OpenSearch relative time format) |

**`INITIAL_WINDOW` values:** `now-1h`, `now-6h`, `now-24h`, `now-7d`, `now-30d`. On subsequent runs, the last poll timestamp stored in the database is used instead, so this only affects the very first run or after a database reset.

### 4.3 AI Analysis Variables

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | (empty) | Anthropic API key (`sk-ant-...`). If empty, falls back to stub analysis. |

### 4.4 Threat Intel Variables

| Variable | Default | Description |
|---|---|---|
| `OTX_KEY` | (empty) | AlienVault OTX API key. If empty, OTX enrichment is skipped. |
| `ABUSEIPDB_KEY` | (empty) | AbuseIPDB API key. If empty, AbuseIPDB enrichment is skipped. |

Both keys are independently optional. If neither is set, the enrichment worker runs but produces no results and makes no network calls.

### 4.5 Notification Variables

| Variable | Default | Description |
|---|---|---|
| `NOTIFY_WEBHOOK` | (empty) | Webhook URL for alert notifications (Slack, ntfy, generic). |
| `NOTIFY_EMAIL` | (empty) | Recipient email address. |
| `SMTP_HOST` | (empty) | SMTP server hostname. Required if `NOTIFY_EMAIL` is set. |
| `SMTP_PORT` | `587` | SMTP port. Use 465 for SSL, 587 for STARTTLS. |
| `SMTP_USER` | (empty) | SMTP authentication username. |
| `SMTP_PASS` | (empty) | SMTP authentication password. |
| `NOTIFY_LEVEL` | `12` | Minimum Wazuh rule level to trigger automatic notification. |

---

## 5. Architecture and Process Model

SOCops is a single Python process with one `ThreadingHTTPServer` and three background daemon threads.

### 5.1 Threads

| Thread | Name | Behaviour |
|---|---|---|
| **Main** | (main) | ThreadingHTTPServer — handles HTTP requests, spawns a new thread per connection |
| **Poller** | `poller` | Wakes every `POLL_INTERVAL` seconds, fetches new alerts from Wazuh, stores in SQLite, checks suppression rules, triggers notifications for high-severity alerts |
| **Analyst** | `analyst` | Continuous loop — finds unanalyzed alerts (highest level first), calls Claude Haiku API or stub, stores analysis. Sleeps 10 seconds between batches. |
| **Enrichment** | `enrichment` | Wakes every 30 seconds — finds alerts with a srcip that have no enrichment data, queries AbuseIPDB/OTX at 1 IP/second, stores results |

All background threads are daemon threads — they die automatically if the main process exits. Each thread has its own `try/except` wrapper that prints errors and continues, preventing a single API failure from killing the thread.

### 5.2 Wazuh Connection

The `WazuhClient` in `wazuh.py` communicates with Wazuh's OpenSearch Dashboards HTTPS endpoint:

1. **Authentication**: `POST https://<WAZUH_HOST>/auth/login` with JSON credentials. Receives a `security_authentication` session cookie.
2. **Query**: `POST https://<WAZUH_HOST>/internal/search/opensearch-with-long-numerals` with an OpenSearch DSL query body. Returns paginated hits from the Wazuh alerts index.
3. **Session reuse**: The session cookie is cached and reused across polls. If a query returns a 401 (session expired), the client re-authenticates automatically.

SSL certificate verification is disabled (`ssl.CERT_NONE`) to support self-signed certificates common in Wazuh deployments. All traffic is still encrypted; only the certificate identity check is skipped.

Connection timeout: 10 seconds for auth, 30 seconds for queries.

### 5.3 Data Flow

```
Wazuh/OpenSearch
      │
      ▼ (every POLL_INTERVAL seconds)
 _poller() thread
      │  fetch_new_alerts(since=last_poll_ts)
      │  for each hit:
      │    db.save_alert(hit)           → INSERT alerts (group_key computed)
      │    check_suppressed(alert)      → if match: UPDATE status='suppressed'
      │    notify_alert(alert)          → if level >= NOTIFY_LEVEL: webhook/email
      │  db.set_setting('last_poll_ts') → store watermark for next poll
      │
      ▼ (continuous, 10s sleep between batches)
 _analyst_worker() thread
      │  db.get_unanalyzed(limit=5)     → SELECT unanalyzed, ORDER BY level DESC
      │  analyst.analyze(alert)         → Claude Haiku API or stub
      │  db.update_alert(analysis=...)  → UPDATE alerts
      │
      ▼ (every 30s, 1 IP/sec)
 _enrichment_worker() thread
      │  db.get_ips_needing_enrichment()→ SELECT WHERE srcip!='' AND enrichment IS NULL
      │  enrichment.enrich_ip(ip)       → AbuseIPDB + OTX
      │  db.set_enrichment(id, json)    → UPDATE alerts
      │
      ▼ (on HTTP request)
 ThreadingHTTPServer (main thread)
      │  GET /api/alerts               → db.get_alerts()
      │  GET /api/alerts/<id>          → db.get_alert() + parse full_json
      │  POST /api/alerts/<id>/action  → db.update_alert() + notifier if escalate
      │  GET /api/data                 → wazuh.fetch_*() with 5-min in-memory cache
      │  ... all other routes
      ▼
    Browser
```

---

## 6. Database Administration

### 6.1 Schema Overview

SOCops uses a single SQLite file with six tables:

**`alerts`** — Primary alert store. One row per Wazuh alert hit.

Key columns: `id`, `wazuh_id` (unique — prevents duplicate imports), `timestamp`, `agent_name`, `agent_ip`, `rule_id`, `rule_level`, `rule_description`, `rule_groups` (JSON array), `mitre_technique`, `mitre_tactic`, `srcip`, `full_json` (complete Wazuh event JSON), `group_key` (`agent::rule_id`), `enrichment` (JSON from threat intel), `assigned_to`, `status`, `analysis`, `operator_notes`, `created_at`, `updated_at`.

**`alert_notes`** — Timestamped notes thread per alert. `auto_generated=1` for system-generated status change entries.

**`cases`** — Incident containers. `status` lifecycle: `open` → `in_progress` → `resolved` → `closed`.

**`case_alerts`** — Many-to-many join: alerts ↔ cases.

**`suppression_rules`** — Ingest-time suppression conditions. `hits` counter incremented on each suppression.

**`settings`** — Key/value store. Currently holds: `last_poll_ts` (ISO timestamp of last successful poll) and `last_poll_time` (human-readable last poll time shown in header).

**Indexes:** `status`, `timestamp`, `rule_level`, `agent_name`, `alert_notes.alert_id`.

### 6.2 Location and Size

```
~/claude/socops/socops.db
```

Database size grows with alert volume. The `full_json` column stores the complete raw Wazuh event JSON (typically 1–5 KB per alert). Rough estimates:

| Alerts | Approximate DB size |
|---|---|
| 1,000 | ~3 MB |
| 10,000 | ~25–30 MB |
| 100,000 | ~250–300 MB |
| 1,000,000 | ~2.5 GB |

At current ingestion rates (~1,500–2,000 alerts/day), plan for ~60–80 MB/month. Monitor with:

```bash
du -sh ~/claude/socops/socops.db
```

### 6.3 Backup

SOCops has no built-in backup. Use standard SQLite backup methods.

**Safe online backup (while app is running):**

```bash
sqlite3 ~/claude/socops/socops.db ".backup /backup/socops-$(date +%Y%m%d).db"
```

The `.backup` command uses the SQLite online backup API — it is safe to run while the application is writing to the database.

**Scheduled backup with cron:**

```bash
crontab -e
```

Add:
```
0 2 * * * sqlite3 ~/claude/socops/socops.db ".backup /backup/socops-$(date +\%Y\%m\%d).db" && find /backup -name "socops-*.db" -mtime +30 -delete
```

This backs up nightly at 02:00 and retains 30 days of backups.

**Simple file copy (requires stopping the app first):**

```bash
sudo systemctl stop socops
cp ~/claude/socops/socops.db /backup/socops-$(date +%Y%m%d).db
sudo systemctl start socops
```

### 6.4 Restore

```bash
sudo systemctl stop socops
cp /backup/socops-20260327.db ~/claude/socops/socops.db
sudo systemctl start socops
```

After restore, verify:
```bash
curl -s http://localhost:8081/api/stats
```

Note: restoring an older backup means alerts ingested after the backup date will be re-imported on the next poll (they will not create duplicates, as `wazuh_id` is UNIQUE — they will simply be skipped). The `last_poll_ts` setting in the restored database determines how far back the next poll fetches.

To force a full re-import from a specific date after restore:

```bash
python3 -c "
import sys; sys.path.insert(0, '~/claude/socops')
import db
db.set_setting('last_poll_ts', 'now-7d')
print('Done')
"
```

### 6.5 Pruning Old Alerts

To prevent unbounded growth, periodically delete old resolved alerts. Always keep a backup before pruning.

**Delete acknowledged and FP alerts older than 90 days:**

```bash
python3 -c "
import sys; sys.path.insert(0, '~/claude/socops')
import sqlite3, db
conn = sqlite3.connect(db.DB_PATH)
result = conn.execute(\"\"\"
    DELETE FROM alerts
    WHERE status IN ('ack', 'fp', 'suppressed')
    AND created_at < datetime('now', '-90 days')
\"\"\")
conn.commit()
print(f'Deleted {result.rowcount} alerts')
conn.close()
"
```

**Reclaim disk space after deletion (VACUUM):**

Stop the app first, then:
```bash
sudo systemctl stop socops
sqlite3 ~/claude/socops/socops.db "VACUUM;"
sudo systemctl start socops
```

`VACUUM` rewrites the database file to reclaim freed pages. It can take minutes on large databases and requires approximately the same amount of free disk space as the current database size.

### 6.6 Schema Migration

New columns are added automatically by `db.init_db()` using `ALTER TABLE ... ADD COLUMN` inside a `try/except` block. This means:

- Upgrading to a new version of SOCops that adds columns is safe — `init_db()` runs on startup and adds missing columns idempotently.
- New tables are created with `CREATE TABLE IF NOT EXISTS` — also idempotent.
- Column type changes or column renames are **not** handled automatically and would require a manual migration.

To manually add a column if needed:

```bash
python3 -c "
import sqlite3
conn = sqlite3.connect('~/claude/socops/socops.db')
try:
    conn.execute('ALTER TABLE alerts ADD COLUMN my_new_column TEXT DEFAULT \"\"')
    conn.commit()
    print('Column added')
except Exception as e:
    print(f'Skipped: {e}')
"
```

### 6.7 Inspecting the Database

While the app is running, use the API for safe read access. For direct inspection, use Python's sqlite3 module:

```bash
python3 -c "
import sqlite3, json
conn = sqlite3.connect('~/claude/socops/socops.db')
conn.row_factory = sqlite3.Row

# Alert counts by status
for row in conn.execute('SELECT status, COUNT(*) as n FROM alerts GROUP BY status ORDER BY n DESC'):
    print(f'{row[\"status\"]:15} {row[\"n\"]}')
"
```

```bash
# Top rules
python3 -c "
import sqlite3
conn = sqlite3.connect('~/claude/socops/socops.db')
for r in conn.execute('SELECT rule_id, rule_description, COUNT(*) n FROM alerts GROUP BY rule_id ORDER BY n DESC LIMIT 10').fetchall():
    print(f'{r[2]:6} {r[0]:8} {r[1][:60]}')
"
```

---

## 7. Wazuh Integration

### 7.1 Required Wazuh Account

SOCops requires a Wazuh/OpenSearch Dashboards account with read access to the alerts index. Create a dedicated `monitor` (read-only) account:

In Wazuh/OpenSearch Dashboards → Security → Internal users → Create user:
- Username: `monitor`
- Password: strong password
- Backend roles: `readall` (read-only access to all indices)

This account only needs `GET` and `POST` (for search) permissions on the `wazuh-alerts-*` index pattern. It does not need write, delete, or admin permissions.

### 7.2 SSL / Certificate Handling

SOCops disables SSL certificate verification (`ssl.CERT_NONE`) to support Wazuh deployments with self-signed certificates, which is the default for most Wazuh installations. Traffic is still encrypted.

If your Wazuh uses a trusted CA-signed certificate and you want to enforce verification, edit `wazuh.py`:

```python
# Line 44-46: replace
self._ctx = ssl.create_default_context()
self._ctx.check_hostname = False
self._ctx.verify_mode = ssl.CERT_NONE

# With:
self._ctx = ssl.create_default_context()
# (default: verify_mode=CERT_REQUIRED, check_hostname=True)
```

To use a specific CA certificate:
```python
self._ctx = ssl.create_default_context(cafile="/etc/ssl/certs/your-ca.pem")
```

### 7.3 Noise Filtering

Alerts matching entries in `NOISE_MUST_NOT` in `wazuh.py` are excluded from the OpenSearch query entirely — they are never fetched and never stored. This is more efficient than suppression rules (which store alerts but hide them) and should be used for alerts that are universally worthless.

Current noise filters:
- VirusTotal rate limit errors
- VirusTotal no-records messages
- PAM login session opened/closed
- SSH authentication success
- Wazuh agent started
- Wazuh manager started
- OSSEC server started

**To add a noise filter**, edit `wazuh.py` → `NOISE_MUST_NOT` list:

```python
NOISE_MUST_NOT = [
    ...existing entries...,
    {"match_phrase": {"rule.description": "Your noisy rule description here"}},
    # Or match on rule.id:
    {"match": {"rule.id": "12345"}},
]
```

Restart the app after editing. Changes only affect future polls — already-stored alerts are not retroactively removed.

**Difference between noise filters and suppression rules:**

| | Noise filters | Suppression rules |
|---|---|---|
| Where configured | `wazuh.py` source code | Web UI / API |
| Storage | Alerts never stored | Alerts stored with status=suppressed |
| Audit trail | None | Hits counter, reason field |
| Reversible | Requires code edit + restart | Delete rule in UI |
| Best for | Universally irrelevant alerts | Environment-specific tuning |

### 7.4 Poll Window and Backfill

The poller uses a high-water-mark approach:
1. On first run: fetch all alerts from `INITIAL_WINDOW` to now.
2. Store the latest alert timestamp as `last_poll_ts` in the settings table.
3. On subsequent runs: fetch only alerts newer than `last_poll_ts`.

If the app is stopped for an extended period, it will backfill on restart from `last_poll_ts`. If the gap is larger than Wazuh's index retention window, some alerts may be missed — this is expected behaviour.

**To reset the poll window** (fetch from a specific point):

```bash
python3 -c "
import sys; sys.path.insert(0, '~/claude/socops')
import db
db.set_setting('last_poll_ts', '2026-03-01T00:00:00.000+0000')
print('Poll window reset')
"
```

Restart the app — the next poll will fetch all alerts since that timestamp.

### 7.5 Alert Fetch Limit

`fetch_new_alerts()` in `wazuh.py` fetches up to 500 alerts per poll by default (`size=500` in the OpenSearch query). If your environment generates more than 500 alerts per `POLL_INTERVAL` seconds, some alerts may be missed.

To increase the limit, edit `wazuh.py`:

```python
def fetch_new_alerts(self, since_iso, size=500):  # change to 1000 or 2000
```

Higher values increase memory usage and response time. For very high-volume environments, reduce `POLL_INTERVAL` instead of increasing `size`, so alerts are fetched more frequently in smaller batches.

---

## 8. Threat Intel Enrichment

### 8.1 AbuseIPDB

Register at https://www.abuseipdb.com → API → Create key.

Free tier: 1,000 lookups/day. Each unique `srcip` is looked up once and cached permanently in the `enrichment` column. With a typical alert environment, daily lookup counts stay well within the free tier.

Set in `.env`:
```env
ABUSEIPDB_KEY=your_key_here
```

Data stored per IP: `abuseConfidenceScore` (0–100%), `totalReports`, `countryCode`, `isp`.

### 8.2 AlienVault OTX

Log in at https://otx.alienvault.com → API Keys → Copy your key.

Free for commercial use with no documented rate limit (soft limit applies — stay under ~1,000 lookups/day to be safe).

Set in `.env`:
```env
OTX_KEY=your_key_here
```

Data stored per IP: `pulse_count` (threat intel reports referencing this IP), `country`, `reputation`.

### 8.3 Rate Limits

The enrichment worker enforces a 1-second sleep between IP lookups (`time.sleep(1)` in `_enrichment_worker()`). This limits throughput to ~60 enrichments per minute, ~3,600/hour.

At startup with a large existing alert database, the enrichment backlog (alerts with srcip but no enrichment) may take time to process. Priority is given to recently ingested alerts as they are processed in insertion order.

To check enrichment progress:

```bash
python3 -c "
import sqlite3
conn = sqlite3.connect('~/claude/socops/socops.db')
total = conn.execute(\"SELECT COUNT(*) FROM alerts WHERE srcip != ''\").fetchone()[0]
done  = conn.execute(\"SELECT COUNT(*) FROM alerts WHERE srcip != '' AND enrichment IS NOT NULL\").fetchone()[0]
print(f'Enriched: {done}/{total} ({100*done//total if total else 0}%)')
"
```

### 8.4 Disabling Enrichment

Leave both `OTX_KEY` and `ABUSEIPDB_KEY` empty. The enrichment worker will start but make no API calls and produce no results. No code change needed.

---

## 9. AI Analysis

### 9.1 Claude Haiku Integration

When `ANTHROPIC_API_KEY` is set and the account has credits, each alert is analyzed by `claude-haiku-4-5-20251001`. The analysis worker runs continuously, processing the highest-severity unanalyzed alerts first.

The system prompt instructs the model to produce structured markdown analysis covering: what happened, severity context, and numbered remediation steps. The full alert context is passed: rule description, level, agent, MITRE mapping, and raw event fields.

Token usage per alert: approximately 600–800 tokens (prompt + completion). At Claude Haiku's pricing, this is less than $0.001 per alert.

### 9.2 Fallback Stub Analysis

When no API key is configured, or when the API returns an error (rate limit, insufficient credits, network failure), `analyst.py` falls back to a rule-based stub:

- MITRE tactic → remediation action mapping
- Rule group context for event framing
- Severity-based urgency text

The stub analysis is less nuanced than Claude but remains actionable. It does not require any external connectivity.

The fallback is automatic — no configuration change needed. If the API key is later added or credits are replenished, new alerts will use Claude immediately. Existing stub-analyzed alerts will not be re-analyzed.

### 9.3 Token Usage and Cost

To estimate costs for your alert volume:

```
Daily alerts × 700 tokens average × Claude Haiku price per million tokens
```

At ~1,500 new alerts/day: 1,500 × 700 = ~1.05M tokens/day. At Haiku pricing (~$0.80/1M input + $4.00/1M output tokens), expect roughly $1–2/day for a medium-volume environment.

To reduce cost:
- Increase suppression coverage to reduce the number of alerts reaching the analyst queue
- The analyst worker only processes alerts with `status='new'` and `analysis IS NULL` — acknowledged and FP alerts are never re-analyzed

### 9.4 Model Selection

The model is hardcoded in `analyst.py`. To change it, edit:

```python
# analyst.py
MODEL = "claude-haiku-4-5-20251001"   # current
# Options:
# "claude-sonnet-4-6"                 # smarter, ~10x cost
# "claude-haiku-4-5-20251001"         # fast, cheap — recommended for bulk analysis
```

Restart the app after changing. Existing analyses are not re-run.

---

## 10. Notification Setup

### 10.1 Webhook

SOCops sends a `POST` request to `NOTIFY_WEBHOOK` with `Content-Type: application/json`:

```json
{
  "text": "🚨 CRITICAL | Registry Key Integrity Checksum Changed\nAgent: SV08 | Level: 14\nTime: 2026-03-28T09:14:22.000+0100",
  "alert_id": 4521
}
```

**Slack incoming webhook:**
```env
NOTIFY_WEBHOOK=https://hooks.slack.com/services/T.../B.../...
```

**ntfy.sh (self-hosted or cloud push notifications):**
```env
NOTIFY_WEBHOOK=https://ntfy.sh/your-topic
```

**Generic webhook (e.g. n8n, Make, Zapier):**
```env
NOTIFY_WEBHOOK=https://your-webhook-endpoint.com/socops
```

### 10.2 Email via SMTP

Example configuration for Gmail (requires App Password, not account password):

```env
NOTIFY_EMAIL=analyst@yourcompany.com
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=sender@gmail.com
SMTP_PASS=xxxx-xxxx-xxxx-xxxx   # Gmail App Password
```

Example for a corporate SMTP relay:
```env
NOTIFY_EMAIL=soc-team@company.com
SMTP_HOST=smtp.company.com
SMTP_PORT=587
SMTP_USER=socops-notifications@company.com
SMTP_PASS=password
```

For SMTP on port 465 (implicit SSL), change `SMTP_PORT=465` and update `notifier.py` to use `smtplib.SMTP_SSL` instead of `smtplib.SMTP` with `starttls()`.

### 10.3 Testing Notifications

Test the notification configuration without waiting for a real high-severity alert:

```bash
python3 -c "
import sys; sys.path.insert(0, '~/claude/socops')
import os
os.environ['NOTIFY_WEBHOOK'] = 'https://your-webhook-url'
os.environ['NOTIFY_EMAIL']   = 'you@example.com'
os.environ['SMTP_HOST']      = 'smtp.example.com'
os.environ['SMTP_USER']      = 'user'
os.environ['SMTP_PASS']      = 'pass'
os.environ['NOTIFY_LEVEL']   = '0'   # send for all levels
import notifier
notifier.notify_alert({
    'id': 0,
    'rule_level': 14,
    'rule_description': 'TEST - SOCops notification test',
    'agent_name': 'test-agent',
    'timestamp': '2026-03-28T00:00:00.000Z',
}, trigger='auto')
print('Sent (check for errors above)')
"
```

---

## 11. Telegram Bot

A separate Telegram bot at `~/claude/telebot/` lets you interact with Claude from a phone. It is independent of the SOCops queue — it provides a direct Claude conversation interface, not SOCops alert access.

### 11.1 Setup

1. Create a bot via Telegram's @BotFather → `/newbot` → copy the token.
2. Edit `~/claude/telebot/.env`:
   ```env
   TELEGRAM_BOT_TOKEN=your_bot_token
   ALLOWED_USER_ID=0              # 0 = accept all (setup mode)
   ANTHROPIC_API_KEY=sk-ant-...
   CLAUDE_MODEL=claude-sonnet-4-6
   MAX_TURNS=40
   ```
3. Start the bot: `cd ~/claude/telebot && python3 bot.py`
4. Message the bot on Telegram and send `/myid` — it will reply with your numeric Telegram user ID.
5. Update `.env`: set `ALLOWED_USER_ID=<your_id>` and restart.

### 11.2 Running as a Service

```bash
sudo cp ~/claude/telebot/telebot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now telebot
sudo journalctl -u telebot -f
```

### 11.3 Securing the Bot

`ALLOWED_USER_ID` restricts the bot to a single Telegram account. Messages from any other user ID are silently dropped. This is enforced in `bot.py` before any processing occurs.

In setup mode (`ALLOWED_USER_ID=0`), the bot responds to anyone. Never leave the bot in setup mode in production — always set an ALLOWED_USER_ID.

Bot commands: `/clear` reset conversation history · `/model` show active model · `/myid` show your user ID · `/help` command list.

---

## 12. Logs and Monitoring

### 12.1 Log Output

SOCops logs to stdout/stderr. When running as a systemd service, logs go to the journal. When running with nohup, logs go to the specified file.

Log lines use `[thread_name]` prefixes:
```
[poller] starting
[poller] fetched 47 new alerts
[poller] error: <exception message>
[analyst] starting
[analyst] error: <exception message>
[enrichment] starting
[enrichment] error: <exception message>
```

HTTP request logs use the standard `BaseHTTPRequestHandler` format:
```
10.0.0.10 - - [28/Mar/2026 09:15:32] "GET /api/stats HTTP/1.1" 200 -
```

### 12.2 Monitoring with systemd

```bash
# Is the service running?
systemctl is-active socops

# Last 50 log lines
journalctl -u socops -n 50

# Follow live
journalctl -u socops -f

# Errors only
journalctl -u socops -p err

# Since last restart
journalctl -u socops --since "$(systemctl show socops -p ActiveEnterTimestamp --value)"
```

### 12.3 Health Check Endpoint

`GET /api/stats` always returns a JSON object. Use it as a health check:

```bash
# Simple health check
curl -sf http://localhost:8081/api/stats > /dev/null && echo OK || echo FAIL

# Check polling is recent (last_poll within last 5 minutes)
python3 -c "
import urllib.request, json
from datetime import datetime, timezone, timedelta
data = json.loads(urllib.request.urlopen('http://localhost:8081/api/stats').read())
last = data.get('last_poll','never')
if last == 'never':
    print('WARN: never polled')
else:
    age = datetime.now(timezone.utc) - datetime.fromisoformat(last)
    if age > timedelta(minutes=5):
        print(f'WARN: last poll {int(age.total_seconds()/60)}m ago')
    else:
        print(f'OK: last poll {int(age.total_seconds())}s ago')
"
```

Add this to a cron job or monitoring system to alert when polling stops:
```
*/5 * * * * curl -sf http://localhost:8081/api/stats > /dev/null || echo "SOCops unhealthy" | mail -s "SOCops alert" admin@company.com
```

### 12.4 Thread Health

SOCops does not expose a thread health API. To verify background threads are alive, check that `last_poll_time` is updating:

```bash
# Poll time should update every POLL_INTERVAL seconds
watch -n 5 'curl -s http://localhost:8081/api/stats | python3 -c "import json,sys; s=json.load(sys.stdin); print(s[\"last_poll\"])"'
```

If `last_poll` stops updating, the poller thread has died (usually due to repeated unhandled errors). Restart the service to recover:
```bash
sudo systemctl restart socops
```

---

## 13. Security Hardening

### 13.1 Network Access

SOCops binds to `0.0.0.0:8081` by default — it is accessible from any network interface. There is no authentication on the web UI.

**Recommended approach:** restrict access to the management VLAN or trusted IPs using the host firewall.

```bash
# Allow only from specific management subnet
sudo ufw allow from 10.0.0.0/24 to any port 8081

# Or allow only from a specific host
sudo ufw allow from 10.0.0.10 to any port 8081

# Deny all other access to port 8081
sudo ufw deny 8081
```

If SOCops must be accessible over the internet, place it behind a reverse proxy with TLS and HTTP basic auth (see section 13.4).

### 13.2 Credential Storage

The `.env` file contains all credentials (Wazuh password, API keys). Protect it:

```bash
chmod 600 ~/claude/socops/.env
chown YOUR_USER:YOUR_USER ~/claude/socops/.env
```

Do not commit `.env` to git. The `.gitignore` should exclude it:
```
.env
socops.db
__pycache__/
*.pyc
```

### 13.3 Wazuh Monitor Account

The Wazuh account used by SOCops should be read-only. Verify:
- Account role: `readall` only, no write permissions
- No ability to modify Wazuh agent configuration, rules, or decoders
- No cluster admin permissions

Rotate the password every 90 days (or per your security policy) by updating `WAZUH_PASS` in `.env` and restarting the service.

### 13.4 Reverse Proxy with HTTPS

To expose SOCops over HTTPS with authentication, proxy through nginx:

```nginx
server {
    listen 443 ssl;
    server_name socops.yourcompany.com;

    ssl_certificate     /etc/ssl/certs/socops.crt;
    ssl_certificate_key /etc/ssl/private/socops.key;

    auth_basic "SOCops";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

Create the password file:
```bash
htpasswd -c /etc/nginx/.htpasswd analyst
```

After adding a reverse proxy, bind SOCops to localhost only by editing the bind address in `app.py`:

```python
# In main():
server = http.server.ThreadingHTTPServer(("127.0.0.1", SOCOPS_PORT), Handler)
```

### 13.5 File Permissions

```bash
# App files — readable by service user only
chown -R YOUR_USER:YOUR_USER ~/claude/socops/
chmod 750 ~/claude/socops/
chmod 640 ~/claude/socops/*.py
chmod 600 ~/claude/socops/.env
chmod 600 ~/claude/socops/socops.db
```

The database contains full alert data including any sensitive fields captured by Wazuh (usernames, commands, file paths). Treat it with the same care as the Wazuh data itself.

---

## 14. Maintenance Tasks

### 14.1 Updating SOCops

SOCops has no package manager — updates are applied by replacing source files.

```bash
# Stop the service
sudo systemctl stop socops

# Backup current state
cp ~/claude/socops/socops.db /backup/socops-pre-update-$(date +%Y%m%d).db
cp -r ~/claude/socops/ /backup/socops-src-$(date +%Y%m%d)/

# Apply new files (copy new .py files)
cp /path/to/new/app.py ~/claude/socops/
cp /path/to/new/db.py  ~/claude/socops/
# etc.

# Start service — init_db() will apply any schema migrations on startup
sudo systemctl start socops
sudo journalctl -u socops -f    # watch for startup errors
```

### 14.2 Updating Python Dependencies

```bash
pip3 install --upgrade anthropic pyTelegramBotAPI --break-system-packages
sudo systemctl restart socops
```

Check the Anthropic SDK changelog before upgrading — the API interface occasionally changes between major versions.

### 14.3 Rotating API Keys

When rotating an API key:

1. Generate the new key in the provider's dashboard.
2. Edit `.env`: replace the old key value.
3. Restart the service: `sudo systemctl restart socops`
4. Verify functionality: check logs for errors, test an enrichment lookup or analysis.
5. Revoke the old key in the provider's dashboard.

Never put the old and new key in `.env` simultaneously.

### 14.4 Reviewing Suppression Rules

Monthly suppression rule review:

1. Open **Suppressions** in the UI.
2. Review all rules with `expires_at` in the past — delete or renew them.
3. Review rules with `hits = 0` after 7+ days — the condition may no longer match (check for typos or rule changes in Wazuh).
4. Review rules with very high hit counts — confirm the suppressed alerts are still genuinely benign.
5. Cross-reference with the **Noisy Rules** table on the Metrics page — identify new candidates for suppression.

### 14.5 Database Maintenance

**Monthly:**
```bash
# Check database size
du -sh ~/claude/socops/socops.db

# Count rows by status
python3 -c "
import sqlite3
conn = sqlite3.connect('~/claude/socops/socops.db')
for row in conn.execute('SELECT status, COUNT(*) FROM alerts GROUP BY status'):
    print(f'{row[0]:15} {row[1]}')
"
```

**Quarterly:**
- Prune old resolved alerts (see section 6.5)
- Run VACUUM to reclaim space
- Review and rotate database backup retention

**Annually:**
- Assess whether `full_json` storage is needed for old alerts — this column is the main driver of database size
- Consider archiving the database and starting fresh if size becomes unmanageable

---

## 15. Troubleshooting

### 15.1 App Won't Start

**Python import error:**
```
ModuleNotFoundError: No module named 'anthropic'
```
Fix: `pip3 install anthropic --break-system-packages`

**Port already in use:**
```
OSError: [Errno 98] Address already in use
```
Fix: find and kill the existing process: `ps aux | grep "[a]pp.py" | awk '{print $2}' | xargs kill -9`
Or change `SOCOPS_PORT` to an unused port.

**`.env` not found (systemd):**
The service unit uses `EnvironmentFile=` which fails silently if the file doesn't exist. Check with:
```bash
sudo systemctl status socops
# look for "Failed to load environment files"
```
Fix: create the `.env` file, then `sudo systemctl start socops`.

**Database permissions error:**
```
OperationalError: unable to open database file
```
Fix: ensure the service user (`YOUR_USER`) has write permission to the socops directory.

### 15.2 No Alerts Appearing

1. Check that the poller is running: `journalctl -u socops | grep poller`
2. Check `last_poll` via API: `curl -s http://localhost:8081/api/stats | python3 -c "import json,sys; print(json.load(sys.stdin)['last_poll'])"`
3. Verify the poll window — if `INITIAL_WINDOW` is `now-1h` and there are no alerts in the last hour, the queue will be empty.
4. Check Wazuh connectivity (see section 15.3).
5. Check if alerts exist in Wazuh UI for the same time range — if Wazuh has no alerts, SOCops will have none either.

### 15.3 Wazuh Connection Errors

**Authentication failure:**
```
[poller] error: Login failed — no session cookie returned
```
Fix: verify `WAZUH_USER` and `WAZUH_PASS` are correct. Test manually:
```bash
curl -k -s -X POST "https://<WAZUH_HOST>/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"monitor","password":"yourpassword"}' | head -c 200
```
Should return a response containing `security_authentication` cookie.

**Connection refused / timeout:**
```
[poller] error: <urlopen error [Errno 111] Connection refused>
[poller] error: <urlopen error timed out>
```
Fix: verify `WAZUH_HOST` is reachable and port 443 is open:
```bash
curl -k -I "https://<WAZUH_HOST>/auth/login"
```

**SSL error:**
```
[poller] error: SSL: CERTIFICATE_VERIFY_FAILED
```
This should not occur since certificate verification is disabled. If it does, check that `wazuh.py` line 46 reads `self._ctx.verify_mode = ssl.CERT_NONE`.

### 15.4 AI Analysis Not Running

**Missing API key:**
```
analyst.py falls back to stub
```
Set `ANTHROPIC_API_KEY` in `.env` and restart.

**Insufficient credits:**
The analyst stub analysis will include a note: `*(Claude API error 400: Your credit balance is too low)*`
Fix: add credits to your Anthropic account at console.anthropic.com.

**Analysis stuck / not progressing:**
Check the analyst thread is alive via log output. If no `[analyst]` lines appear after startup, the thread may have died. Restart the service.

To force re-analysis of all alerts (e.g., after adding API key):
```bash
python3 -c "
import sqlite3
conn = sqlite3.connect('~/claude/socops/socops.db')
conn.execute(\"UPDATE alerts SET analysis=NULL WHERE analysis LIKE '%stub%' OR analysis LIKE '%API error%'\")
conn.commit()
print(conn.total_changes, 'alerts queued for re-analysis')
"
```
The analyst worker will pick these up automatically.

### 15.5 Enrichment Not Working

**No API keys configured:**
No enrichment occurs. Set `OTX_KEY` and/or `ABUSEIPDB_KEY` in `.env` and restart.

**Rate limit exceeded:**
AbuseIPDB returns HTTP 429 after 1,000 daily lookups. The enrichment worker logs errors per IP and continues. Wait until midnight UTC for the limit to reset.

**All srcip fields are empty:**
Many alert types (FIM, systemd, CIS) do not have a source IP — enrichment only applies to alerts with a non-empty `srcip` field. This is expected.

**No risk badges visible despite API keys being set:**
Check enrichment progress (section 8.3). Newly added keys will only enrich new alerts going forward plus backlog. If the IP has a score of 0, no badge is shown (by design — 0 risk is unremarkable).

### 15.6 Notifications Not Sending

**Webhook not firing:**
1. Verify `NOTIFY_WEBHOOK` is set and the URL is reachable from the server: `curl -s <NOTIFY_WEBHOOK>`
2. Check `NOTIFY_LEVEL` — if set to 12, only alerts with rule_level ≥ 12 trigger it. Lower it for testing.
3. Check for errors in logs: `journalctl -u socops | grep notif`

**Email not sending:**
1. Verify SMTP connectivity: `telnet <SMTP_HOST> <SMTP_PORT>`
2. Test with Python directly (section 10.3).
3. For Gmail: ensure you're using an App Password (account password won't work with 2FA enabled).
4. Check spam folder — the first email from a new sender may be filtered.

### 15.7 UI Issues

**Alert detail panel shows content but no action bar buttons:**
Hard-refresh the browser (`Ctrl+Shift+R`) to clear cached JavaScript.

**Dashboard shows "Loading dashboard data..." indefinitely:**
Open browser developer tools → Console and look for JavaScript errors. The most common cause is a syntax error in the dashboard script introduced by a code change. Check `journalctl -u socops` for Python errors on the `/api/data` endpoint.

**Queue shows "No alerts." when you expect alerts:**
Check the active status and category filters — a combination with no matches produces an empty list. Reset to All + All.

**Export buttons produce empty files:**
The export uses the current status filter. If filtered to `fp` and there are no FP alerts, the export is empty. Check the filter settings.

### 15.8 Database Errors

**Database is locked:**
```
OperationalError: database is locked
```
This can occur under heavy concurrent load. SOCops opens a new connection per query (`_get_conn()` creates a new `sqlite3.connect()` each call). If this becomes persistent, it indicates a long-running transaction. Restart the service.

For production environments with high write concurrency, consider enabling WAL mode:
```bash
python3 -c "
import sqlite3
conn = sqlite3.connect('~/claude/socops/socops.db')
conn.execute('PRAGMA journal_mode=WAL')
conn.commit()
print(conn.execute('PRAGMA journal_mode').fetchone())
"
```
WAL mode allows concurrent reads and writes and significantly reduces lock contention.

**Database corruption:**
```
DatabaseError: database disk image is malformed
```
Restore from backup (section 6.4). If no backup is available:
```bash
sqlite3 ~/claude/socops/socops.db ".recover" | sqlite3 ~/claude/socops/socops-recovered.db
```

### 15.9 High Memory or CPU

**High CPU:**
Usually caused by the analyst worker tight-looping if `time.sleep()` is not being reached. Check logs for rapid repeated `[analyst]` lines. Restart the service.

**High memory:**
SQLite caches query results in memory. For databases over 100 MB, the process may use 150–300 MB of RSS. This is expected. If memory grows unboundedly over time, check for a connection leak (connections not being closed after use in `_get_conn()`).

The ThreadingHTTPServer spawns a new thread per HTTP request. Each thread holds memory for the duration of the request. Under very high request rates (e.g., aggressive browser polling), memory can spike. Ensure browser pages are not polling more frequently than every 60 seconds.

---

## 16. Disaster Recovery

### Full Recovery Procedure

**Scenario:** Server destroyed or SOCops directory deleted.

1. Provision a new server with Python 3.10+.
2. Copy SOCops source files to `~/claude/socops/`.
3. Install dependencies: `pip3 install anthropic pyTelegramBotAPI --break-system-packages`
4. Restore database from backup: `cp /backup/socops-YYYYMMDD.db ~/claude/socops/socops.db`
5. Create `.env` with credentials (from password manager / secrets vault).
6. Start the service: `sudo systemctl enable --now socops`
7. Verify: `curl -s http://localhost:8081/api/stats`

Recovery time: ~15 minutes from a recent backup.

### Database-Only Recovery

**Scenario:** Database corrupted or accidentally deleted, app is still running.

1. Stop the service: `sudo systemctl stop socops`
2. Restore: `cp /backup/socops-YYYYMMDD.db ~/claude/socops/socops.db`
3. Start: `sudo systemctl start socops`

Alerts created between the backup date and the restoration will be re-fetched from Wazuh on the next poll (within `POLL_INTERVAL` seconds). Suppression rules, cases, case links, and notes created after the backup date will be lost.

### Recovery Without a Backup

If no database backup exists:

1. Delete the corrupt database file.
2. Start SOCops — `init_db()` creates a fresh empty database.
3. Set `INITIAL_WINDOW=now-30d` in `.env` to back-fill alerts from Wazuh.
4. Restart. Wazuh alert history will be re-imported (subject to Wazuh index retention).

Analyst notes, cases, and suppression rules cannot be recovered without a backup.

---

*SOCops Administration Manual · Last updated 2026-03-28*
