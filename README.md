# SOCops

AI-assisted SOC workbench for Wazuh. Lightweight, self-hosted, single-process Python app — no external dependencies beyond the Anthropic SDK and pyTelegramBotAPI.

Runs on a single Linux host. Connects to Wazuh/OpenSearch, stores alerts in SQLite, and serves a dark-theme web UI on port 8081.

---

## Features

### Alert Queue (`/`)
- Live alert queue pulled from Wazuh every 60 seconds
- Status lifecycle: `new` → `ack` | `escalated` | `fp` | `suppressed` (reopen to `new`)
- **Category filters**: All / Systemd / Integrity (FIM) / CIS / Web / Windows
- **Status filters**: All / New / Escalated / Ack / FP
- **Group view**: toggle between individual alerts and grouped view (collapses same rule + same agent, shows ×N count)
- Per-alert AI analysis via Claude Haiku (falls back to rule-based stub if no API key/credits)
- Threat intel risk badge on source IPs (AbuseIPDB + OTX)
- Assign alerts to analysts
- Add notes with full timestamped thread; status changes are auto-logged
- Add alert to a case from the action bar
- Clickable agent name / source IP open 24h entity timeline

### Dashboard (`/dashboard`)
Chart.js panels updated every 5 minutes:
- Alert severity over time (bar chart)
- Top agents by alert count (bar chart)
- MITRE ATT&CK tactics distribution (doughnut)
- CIS compliance gauges (pass / fail / error rates)

### Cases (`/cases`)
- Create named incident containers (title, severity, description)
- Link multiple alerts to a case
- Case status lifecycle: `open` → `in_progress` → `resolved` → `closed`
- Case detail shows all linked alerts

### Suppressions (`/suppressions`)
- Define rules to auto-suppress noisy alerts at ingest time
- Match on: `rule_id`, `agent_name`, `srcip`, `rule_description`
- Operators: `equals`, `contains`, `starts_with`
- Optional expiry date; hit counter shows how many alerts each rule has suppressed
- "⊘ Suppress" button in alert detail pre-fills the form from the current alert

### Metrics (`/metrics`)
- **KPI cards**: MTTR, FP rate, 24h volume, backlog age, escalation rate
- **Hourly volume sparkline**: last 24h alert count by hour
- **Top agents table**: top 5 agents by alert volume (last 7d)
- **Noisy rules table**: detection rules ranked by FP rate (red > 50%, orange > 30%)
- **MITRE ATT&CK coverage**: 14-tactic grid showing which tactics fired in last 7 days
- **Detection rule library**: full rule table with total/ack/fp/escalated counts, sortable

---

## Requirements

- Python 3.10+
- Wazuh with OpenSearch Dashboards accessible over HTTPS
- `anthropic` Python package (optional — for AI analysis)
- `pyTelegramBotAPI` (optional — for Telegram bot)

```bash
pip3 install anthropic pyTelegramBotAPI --break-system-packages
```

---

## Configuration

Copy `.env.example` to `.env` and fill in values:

```env
# Required
WAZUH_HOST=your.wazuh.host        # Wazuh/OpenSearch host
WAZUH_USER=changeme                # OpenSearch user
WAZUH_PASS=yourpassword            # OpenSearch password

# App settings
SOCOPS_PORT=8081
POLL_INTERVAL=60                   # Wazuh poll interval (seconds)
INITIAL_WINDOW=now-24h             # How far back to fetch on first run

# AI analysis (optional)
ANTHROPIC_API_KEY=sk-ant-...       # Claude Haiku analysis per alert

# Threat intel enrichment (optional)
OTX_KEY=                           # AlienVault OTX API key
ABUSEIPDB_KEY=                     # AbuseIPDB API key (1000 lookups/day free)

# Outbound notifications (optional)
NOTIFY_WEBHOOK=                    # Slack / ntfy / generic webhook URL
NOTIFY_EMAIL=                      # Recipient email for high-severity alerts
SMTP_HOST=                         # SMTP server hostname
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
NOTIFY_LEVEL=12                    # Minimum rule level to trigger notification
```

---

## Running

### Direct

```bash
cd /path/to/socops
env WAZUH_HOST=your.wazuh.host WAZUH_USER=changeme WAZUH_PASS='yourpassword' \
  SOCOPS_PORT=8081 ANTHROPIC_API_KEY='sk-ant-...' \
  python3 app.py
```

Or with a `.env` file:

```bash
env $(cat .env | grep -v '^#' | xargs) python3 app.py
```

### As a systemd service

```bash
# Edit .env with real credentials first
sudo cp socops.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now socops
sudo journalctl -u socops -f
```

The service unit reads credentials from `.env` via `EnvironmentFile=`.

---

## Architecture

```
Browser → http://<host>:8081
              ↓
    Python ThreadingHTTPServer (app.py)
       ├─ GET  /                    → Alert queue (HTML)
       ├─ GET  /dashboard           → Wazuh dashboard (HTML)
       ├─ GET  /cases               → Case management (HTML)
       ├─ GET  /suppressions        → Suppression rules (HTML)
       ├─ GET  /metrics             → KPIs + MITRE heatmap (HTML)
       ├─ GET  /api/alerts          → Alert list JSON (?status=&category=&group_key=&rule_id=&since=)
       ├─ GET  /api/alerts/<id>     → Single alert + analysis + enrichment
       ├─ POST /api/alerts/<id>/action → {action, notes, assigned_to}
       ├─ GET  /api/alerts/<id>/notes  → Notes thread
       ├─ POST /api/alerts/<id>/notes  → Add note
       ├─ GET  /api/stats           → Queue statistics
       ├─ GET  /api/groups          → Grouped alert view (?status=&category=)
       ├─ GET  /api/kpis            → SOC KPI metrics
       ├─ GET  /api/mitre           → MITRE tactic coverage
       ├─ GET  /api/rules           → Detection rule stats
       ├─ GET  /api/timeline        → Entity timeline (?agent=|?ip=&hours=)
       ├─ GET  /api/enrich/<ip>     → On-demand IP enrichment
       ├─ GET  /api/suppressions    → List suppression rules
       ├─ POST /api/suppressions    → Create suppression rule
       ├─ DELETE /api/suppressions/<id> → Delete rule
       ├─ GET  /api/cases           → List cases
       ├─ POST /api/cases           → Create case
       ├─ GET  /api/cases/<id>      → Case detail + alerts
       ├─ POST /api/cases/<id>/alerts → Link alert to case
       ├─ POST /api/cases/<id>/action → Update case status
       ├─ GET  /api/export/alerts.csv  → CSV export (?status=&category=&since=7d)
       ├─ GET  /api/export/alerts.json → JSON export
       └─ GET  /api/data            → Dashboard chart data (5-min cache)
              ↓ background threads
    _poller()           — every 60s: fetch new Wazuh alerts → SQLite, check suppression, notify
    _analyst_worker()   — continuous: AI analysis for unanalyzed alerts (highest level first)
    _enrichment_worker()— every 30s: enrich srcIPs via AbuseIPDB + OTX (1 IP/sec rate limit)
              ↓
    wazuh.py  WazuhClient  → OpenSearch at WAZUH_HOST:443
    db.py     SQLite        → socops.db
    analyst.py             → Claude Haiku API or rule-based stub
    enrichment.py          → AbuseIPDB + OTX APIs
    notifier.py            → Webhook + SMTP email
```

---

## File Layout

| File | Role |
|---|---|
| `app.py` | Main server — all routes, background threads, inline HTML/CSS/JS for all pages |
| `db.py` | SQLite schema, CRUD helpers, suppression engine |
| `wazuh.py` | WazuhClient — OpenSearch queries, noise filtering |
| `analyst.py` | Analysis engine: Claude Haiku or rule-based stub |
| `enrichment.py` | IP threat intel: AbuseIPDB + OTX |
| `notifier.py` | Outbound alerts: webhook + SMTP email |
| `socops.service` | systemd unit file |
| `.env.example` | Config template |
| `socops.db` | SQLite database (auto-created, not in git) |

---

## Database Schema

```
alerts            — main alert store (Wazuh hits + SOC workflow state)
alert_notes       — timestamped notes thread per alert (analyst + auto-generated)
cases             — incident containers
case_alerts       — many-to-many: alerts ↔ cases
suppression_rules — ingest-time suppression conditions
settings          — key/value store (last_poll_time, etc.)
```

Key alert fields: `wazuh_id`, `timestamp`, `agent_name`, `agent_ip`, `rule_id`, `rule_level`, `rule_description`, `rule_groups`, `mitre_technique`, `mitre_tactic`, `srcip`, `status`, `group_key`, `analysis`, `enrichment`, `assigned_to`, `operator_notes`, `full_json`.

---

## Noise Filtering

Alerts matching the following are dropped at ingest (never stored):

- VirusTotal rate limit / no records errors
- PAM login session opened/closed
- SSH authentication success
- Wazuh agent/manager/server started messages

Configure additional filters in `wazuh.py` → `NOISE_MUST_NOT`.

---

## Alert Categories

| Category | Rule group match |
|---|---|
| Systemd | `rule_groups LIKE '%systemd%'` |
| Integrity | `rule_groups LIKE '%syscheck%'` (FIM + registry) |
| CIS | `rule_groups LIKE '%sca%'` |
| Web | `rule_groups LIKE '%web%'` |
| Windows | `rule_groups LIKE '%windows%'` |

---

## Telegram Bot

A separate bot at `telebot/` lets you chat with Claude from your phone.

```bash
cd /path/to/telebot
# Edit .env: add TELEGRAM_BOT_TOKEN and ANTHROPIC_API_KEY
python3 bot.py
```

Commands: `/clear` reset history · `/model` show active model · `/myid` show your Telegram user ID.

Lock to your account only: set `ALLOWED_USER_ID=<your_id>` in `.env`.

---

## Wazuh Connection

- Host: `WAZUH_HOST` port 443 (OpenSearch Dashboards)
- Auth: session cookie via `POST /auth/login`
- Queries: last N hours of alerts, filtered by minimum rule level and noise exclusions
- FIM path exclusions: `*/.cache/*`, `*/tmp/*`
