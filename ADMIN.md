# SOCops Administration Manual

**This manual teaches administrators how to install, run, maintain, and troubleshoot SOCops.**

Think of SOCops as a traffic controller in your security center. Your Wazuh system is like a giant alarm bell ringing constantly with security events. SOCops catches those alarms, writes them down, and gives your security team a friendly tool to sort through them and decide what matters.

**Before you start:** You need a working Wazuh system with OpenSearch Dashboards running. SOCops cannot replace Wazuh or work without it — it only makes Wazuh easier to use.

---

## What You're About to Do

By the end of this guide, you will have:
1. ✅ Installed SOCops on a Linux server
2. ✅ Connected it to your Wazuh system
3. ✅ Configured it to run automatically (systemd)
4. ✅ Set up notifications and AI analysis (optional)
5. ✅ Learned how to troubleshoot when things break

**Time required:** 30 minutes for basic setup. Another 30 minutes if you want AI analysis and email notifications.

---

## Part 1: System Requirements

### What Hardware Do You Need?

**Absolute minimum** (for small teams, <100 alerts/day):
- **CPU:** 1 core (even an old laptop CPU is fine)
- **RAM:** 256 MB (seriously — Python uses very little memory)
- **Disk:** 1 GB free (the database starts at ~1 MB and grows slowly)
- **Network:** Internet access to your Wazuh server on port 443

**Recommended** (for production, 500+ alerts/day):
- **CPU:** 2 cores
- **RAM:** 512 MB – 1 GB
- **Disk:** 10 GB free (database grows about 3 MB per 1,000 alerts)
- **Network:** Direct network connection to Wazuh (same datacenter preferred)

SOCops is famously lightweight. It runs happily on virtual machines, Raspberry Pis, and old office computers. The only heavy lifting is done by Wazuh — SOCops just reads its data.

### What Software Is Required?

**Operating System:**
- Ubuntu 22.04 or later (what we tested)
- CentOS/Rocky Linux 8+
- Any Linux with Python 3.10 or newer

Check your Python version:
```bash
python3 --version
```

Should show `Python 3.10.x` or higher.

**Python Packages:**
Most Python packages come built-in with your OS. You only need to install **two** optional packages if you want AI analysis and phone notifications:

```bash
pip3 install anthropic pyTelegramBotAPI --break-system-packages
```

**What does `--break-system-packages` mean?**
On newer Ubuntu versions, Python tries to protect system packages. This flag tells Python "I know what I'm doing, let me install anyway." It's safe for these packages — they don't conflict with anything.

**What if you don't have sudo?**
If you can't run `pip3 install`, that's okay. SOCops still works without these packages — you just won't have AI analysis or phone bot features.

---

## Part 2: Installation

### Step 1: Prepare Your Directory

Make a folder where SOCops will live:

```bash
mkdir -p ~/claude/socops
cd ~/claude/socops
```

The `~` means "your home folder." If you're not sure where that is, run:
```bash
echo $HOME
```

### Step 2: Copy Configuration Template

SOCops needs a configuration file (`.env`) with your Wazuh credentials. A template is provided:

```bash
cp .env.example .env
```

This creates a `.env` file that looks like:
```env
WAZUH_HOST=your.wazuh.host
WAZUH_USER=changeme
WAZUH_PASS=yourpassword
```

### Step 3: Edit Your Configuration

Open the `.env` file with your editor:

```bash
nano .env
```

(If `nano` doesn't work, try `vi` or `cat .env` to see what's there.)

**Find these three lines and fill them in:**

| Line | Example | What It Means |
|------|---------|--------------|
| `WAZUH_HOST=` | `wazuh.company.com` | The hostname or IP address of your Wazuh server |
| `WAZUH_USER=` | `monitor` | Username for Wazuh OpenSearch Dashboards (NOT the manager UI) |
| `WAZUH_PASS=` | `MySecurePass123` | Password for that OpenSearch user |

**Important:** The Wazuh credentials you put here are for **OpenSearch Dashboards**, not the Wazuh agent manager. OpenSearch Dashboards usually runs on the same server as Wazuh, on port 443.

To test if you have the right credentials, try this in your browser:
```
https://your.wazuh.host/auth/login
```

You should see a login form. If you can log in with the username and password you put in `.env`, you have the right ones.

**Protect Your Configuration:**
The `.env` file contains passwords. Make sure only the SOCops server user can read it:

```bash
chmod 600 ~/.env
```

This means "only I can read and write this file, nobody else."

---

## Part 3: First Run (Testing)

Before setting up automatic startup, test that everything works:

```bash
cd ~/claude/socops
env $(cat .env | grep -v '^#' | xargs) python3 app.py
```

**What this command does:**
1. `env $(cat .env | grep -v '^#' | xargs)` — reads your `.env` file and loads all the variables into memory
2. `python3 app.py` — starts the SOCops program

**What you should see:**
```
[poller] starting
[analyst] starting
[enrichment] starting
SOCops listening on port 8081
```

If you see those four lines, congratulations — SOCops is running!

**To access it:**
Open your web browser and visit:
```
http://localhost:8081
```

(Or if you're running this on a remote server, use the server's IP address instead of `localhost`.)

**If nothing appears:**
This usually means a port is already in use, or the `.env` file has a wrong password. See the Troubleshooting section below.

**To stop it:**
Press `Ctrl+C` in the terminal where it's running.

---

## Part 4: Running SOCops Permanently (systemd)

The test above works, but if your server restarts, SOCops stops. To make it run automatically:

### Step 1: Create a systemd Service Unit

SOCops comes with a service file. Copy it to the system directory:

```bash
sudo cp ~/claude/socops/socops.service /etc/systemd/system/
```

### Step 2: Tell systemd About the New Service

```bash
sudo systemctl daemon-reload
```

This tells the system "I just added a new service file, re-read your configuration."

### Step 3: Enable It (So It Starts on Boot)

```bash
sudo systemctl enable socops
```

### Step 4: Start It Now

```bash
sudo systemctl start socops
```

### Step 5: Verify It's Running

```bash
sudo systemctl status socops
```

You should see:
```
● socops.service - SOCops — AI SOC Workbench for Wazuh
     Loaded: loaded (/etc/systemd/system/socops.service; enabled; ...)
     Active: active (running) since Thu 2026-04-19 10:15:32 UTC; 2min ago
   Main PID: 1234 (python3)
```

If it says "Active: active (running)" — you're done! SOCops will now:
- Start automatically when the server boots
- Restart automatically if it crashes
- Run in the background forever

---

## Part 5: Configuration Reference

All settings come from the `.env` file. Here are all possible options:

### Critical (Without These, SOCops Won't Start)

```env
WAZUH_HOST=your.wazuh.host    # IP or hostname of Wazuh OpenSearch
WAZUH_USER=monitor             # OpenSearch Dashboards username
WAZUH_PASS=yourpassword        # OpenSearch Dashboards password
```

### Useful (Recommended)

```env
SOCOPS_PORT=8081               # Port to listen on (default 8081)
POLL_INTERVAL=60               # Fetch alerts every N seconds (default 60)
INITIAL_WINDOW=now-24h         # On first run, fetch last 24 hours (try now-7d if you want more)
NOTIFY_LEVEL=12                # Send notifications for alerts this severe or worse (0-15)
```

### For AI Analysis (Optional But Recommended)

**Pick ONE of these:**

#### Option A: Free local AI (Ollama)
```env
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen2.5:3b
```

**What this does:** Runs an AI model locally on your machine. No API keys needed, no monthly costs, all data stays private. Requires 4-8 GB RAM for the model.

#### Option B: Free cloud AI (OpenRouter)
```env
OPENROUTER_API_KEY=sk-or-...  # Get free key at openrouter.ai
```

**What this does:** Uses OpenRouter's free models. Slower than Ollama but simpler setup, no local GPU needed.

#### Option C: Paid cloud AI (Claude)
```env
ANTHROPIC_API_KEY=sk-ant-...  # Get key at console.anthropic.com
```

**What this does:** Uses Claude Haiku (Anthropic's fast AI). Costs roughly $1-2/day for typical alert volumes. Best analysis quality.

**If you set none of these:** SOCops falls back to simple rule-based analysis. Still useful, just less detailed.

### For Threat Intelligence (Optional)

```env
ABUSEIPDB_KEY=abc123def456     # Get free key from abuseipdb.com (1000 lookups/day)
OTX_KEY=xyz789uvw012           # Get free key from otx.alienvault.com
```

**What this does:** Looks up suspicious source IPs in threat intelligence databases. Shows you if an attacker IP is known to be malicious. Free tier is usually enough.

### For Notifications (Optional)

**Via Slack or ntfy (webhooks):**
```env
NOTIFY_WEBHOOK=https://hooks.slack.com/services/YOUR/SLACK/URL
```

**Via Email:**
```env
NOTIFY_EMAIL=analyst@company.com
SMTP_HOST=smtp.gmail.com          # or your company's SMTP server
SMTP_PORT=587
SMTP_USER=sender@gmail.com
SMTP_PASS=app-password-here       # For Gmail, get from myaccount.google.com
```

---

## Part 6: Understanding What's Happening

### The Three Worker Threads

SOCops runs three background tasks in parallel:

#### 1. The Poller (Every 60 Seconds)
**What it does:** Wakes up, checks Wazuh for new alerts, stores them in the local database.

**In plain English:** Every 60 seconds, SOCops asks Wazuh "Hey, any new problems?" If Wazuh says yes, SOCops writes them down.

**If it fails:** Usually means the Wazuh credentials are wrong, or Wazuh is down. Check the logs.

#### 2. The Analyst (Continuous)
**What it does:** Reads unanalyzed alerts and asks an AI to explain them (Claude, Ollama, or a fallback rule set).

**In plain English:** SOCops looks for alerts that nobody has explained yet. It asks an AI to say "here's what happened, here's what to do about it." This analysis shows up in the web interface for analysts to read.

**If it fails:** Usually means the AI API key is wrong or the AI service is down. Falls back to rule-based analysis automatically.

**Cost:** If using Claude API, expect $0.001-$0.01 per alert depending on alert size.

#### 3. The Enrichment Worker (Every 30 Seconds)
**What it does:** Looks for suspicious IP addresses in alerts and queries threat intelligence databases to see if they're known bad.

**In plain English:** When an alert contains a source IP, SOCops asks "is this IP on any blocklists?" and shows the analyst a risk score.

**If it fails:** Usually means the API keys are wrong or rate limits are hit. Continues automatically the next day.

---

## Part 7: Database Management

### Where Is My Data?

All alert data lives in a single SQLite database file:

```
~/claude/socops/socops.db
```

SQLite is a file-based database (not a server). Think of it like a spreadsheet that Python can query quickly.

### How Big Will It Get?

Database size depends on how many alerts you get:

| Alerts Per Day | Approx Database Size | Growth Per Month |
|---|---|---|
| 100 | 3 MB | 3 MB |
| 500 | 15 MB | 15 MB |
| 1,000 | 30 MB | 30 MB |
| 5,000 | 150 MB | 150 MB |
| 10,000 | 300 MB | 300 MB |

**At typical SOC volumes (1,000-2,000 alerts/day), expect 30-60 MB per month.**

### How to Backup

The database is just one file. Back it up like any other file:

```bash
# Quick backup
cp ~/claude/socops/socops.db ~/claude/socops/socops.db.backup

# Scheduled daily backup at 2 AM
crontab -e
# Add this line:
# 0 2 * * * cp ~/claude/socops/socops.db /backups/socops-$(date +\%Y\%m\%d).db
```

**Online backup (while SOCops is running):**
```bash
sqlite3 ~/claude/socops/socops.db ".backup /backups/socops-$(date +%Y%m%d).db"
```

### How to Restore

If the database gets corrupted or deleted:

```bash
# Stop SOCops
sudo systemctl stop socops

# Restore from backup
cp /backups/socops-20260419.db ~/claude/socops/socops.db

# Start it again
sudo systemctl start socops
```

On the next poll, SOCops will fetch any missing alerts from Wazuh and fill in the gaps.

### How to Clean Up Old Data

After several months, the database might get large. You can safely delete old acknowledged alerts:

```bash
python3 -c "
import sqlite3
conn = sqlite3.connect('~/claude/socops/socops.db')
# Delete acknowledged and false positive alerts older than 90 days
conn.execute(\"\"\"
    DELETE FROM alerts
    WHERE status IN ('ack', 'fp')
    AND created_at < datetime('now', '-90 days')
\"\"\")
conn.commit()
print(f'Deleted {conn.total_changes} old alerts')
conn.close()
"
```

Then reclaim disk space:
```bash
sudo systemctl stop socops
sqlite3 ~/claude/socops/socops.db "VACUUM;"
sudo systemctl start socops
```

---

## Part 8: Wazuh Integration

### How Does SOCops Connect to Wazuh?

**The simple answer:** SOCops opens a web browser session to Wazuh's login page, just like a human would. Once logged in, it uses that session to request alerts.

**The technical answer:** SOCops sends HTTPS requests to:
1. `https://WAZUH_HOST/auth/login` — logs in with your credentials
2. `https://WAZUH_HOST/internal/search/opensearch-with-long-numerals` — queries for new alerts
3. All requests use the session cookie from step 1

### What Credentials Does SOCops Need?

SOCops needs a **read-only** OpenSearch Dashboards account. You should create a dedicated account just for SOCops:

**In Wazuh Web UI:**
1. Go to Security → Internal Users
2. Click "Create user"
3. Username: `socops` or `monitor`
4. Password: something long and random
5. Backend roles: `readall` (read-only)
6. Confirm

This account can read alerts but cannot change anything in Wazuh.

### SSL Certificates

By default, most Wazuh installations use a self-signed SSL certificate (not from a trusted authority). This is fine — SOCops accepts these certificates. All traffic is still encrypted, even if the certificate isn't "trusted."

If your Wazuh uses a real SSL certificate from a trusted authority, SOCops will accept that too.

### What If Wazuh Is Down?

SOCops handles this gracefully:
1. If Wazuh is down when the poller runs, it logs the error and tries again in 60 seconds.
2. The web interface still works — it just shows old data from the last successful poll.
3. Once Wazuh comes back, SOCops catches up automatically.

---

## Part 9: Filtering Noisy Alerts

### What's a "Noisy" Alert?

Some alerts fire constantly but are harmless. Examples:
- "SSH authentication succeeded" (thousands per day)
- "VirusTotal API rate limit exceeded" (not a real threat)
- "Systemd service restarted" (normal on test servers)

These clutter the queue and hide real security issues.

### How to Filter Them

Edit `wazuh.py` and find the `NOISE_MUST_NOT` list (around line 30):

```python
NOISE_MUST_NOT = [
    {"match_phrase": {"rule.description": "VirusTotal: Error"}},
    {"match_phrase": {"rule.description": "SSH authentication success"}},
    # Add more here like this:
    {"match_phrase": {"rule.description": "Your noisy alert description"}},
]
```

**Each line:** "If an alert matches this description, don't even store it."

This is different from suppression rules in the UI — these filters prevent alerts from entering the database at all.

### How to Find Noisy Rules

1. Run SOCops for a week
2. Go to Metrics page
3. Look at "Noisy Rules Table"
4. Find rules with high counts and high false positive rates
5. Add them to the filter list above

---

## Part 10: Troubleshooting

### Problem: "Port 8081 already in use"

**Error message:**
```
OSError: [Errno 98] Address already in use
```

**Cause:** Another process is using port 8081.

**Fix:**
```bash
# Find what's using port 8081
lsof -i :8081
# or
ss -tlnp | grep 8081

# Kill it
kill -9 <PID>

# Or change the port in .env
SOCOPS_PORT=8082
```

### Problem: "Connection refused" when accessing SOCops

**What you see:** Browser says "Connection refused" or "Cannot reach server"

**Causes:**
1. SOCops isn't running
2. Firewall is blocking port 8081
3. You're using the wrong IP/hostname

**Fixes:**
```bash
# Check if it's running
sudo systemctl status socops

# Check if port is listening
ss -tlnp | grep 8081

# Check if firewall allows it
sudo ufw status

# If firewall blocks it, allow it:
sudo ufw allow 8081
```

### Problem: "Login failed" — Wazuh Connection Error

**Error message in logs:**
```
[poller] error: Login failed — no session cookie returned
```

**Causes:**
1. Wrong username or password in `.env`
2. OpenSearch Dashboards is down
3. Wazuh hostname is wrong

**Fixes:**
```bash
# Test the credentials manually
curl -k -X POST "https://YOUR.WAZUH.HOST/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"monitor","password":"yourpassword"}'

# If you get a response (not an error), credentials are right

# Test if Wazuh is reachable
curl -k "https://YOUR.WAZUH.HOST/auth/login"

# Should show a login page (or JSON response)
```

### Problem: No Alerts Appearing

**What you see:** Queue is empty even though Wazuh has alerts

**Causes:**
1. First poll window is wrong (no alerts in last 24 hours)
2. Poller is failing silently
3. All alerts are being suppressed

**Fixes:**
```bash
# Check logs for errors
sudo journalctl -u socops | grep error

# Check if poller is running
sudo journalctl -u socops | grep poller

# Force a full re-import from last 7 days
python3 -c "
import sqlite3
conn = sqlite3.connect('socops.db')
conn.execute(\"UPDATE settings SET last_poll_ts = '2026-04-10T00:00:00Z'\")
conn.commit()
print('Reset poll window. Next poll will backfill.')
"

# Restart SOCops
sudo systemctl restart socops
```

### Problem: AI Analysis Isn't Working

**What you see:** Alerts show "Analysis not available" or stub/fallback text

**Causes:**
1. API key is missing or wrong
2. API service is down
3. Account has no credits

**Fixes:**
```bash
# If using Ollama, check it's running
curl http://127.0.0.1:11434/api/tags

# If using Claude, check the key in .env is correct (sk-ant-...)

# Force re-analysis of all alerts
python3 -c "
import sqlite3
conn = sqlite3.connect('socops.db')
conn.execute('UPDATE alerts SET analysis = NULL')
conn.commit()
print('Reset all analyses. Next run will re-analyze.')
"

# Check logs for API errors
sudo journalctl -u socops | grep -i "claude\|anthropic\|ollama\|error"
```

### Problem: High Memory or CPU Usage

**Causes:**
1. Database is very large (500K+ alerts)
2. Analyst worker is stuck in a loop
3. Browser is polling too frequently

**Fixes:**
```bash
# Check database size
du -sh socops.db

# If > 1 GB, prune old alerts (see Part 7)

# Check what Python is doing
ps aux | grep "[p]ython3 app.py"

# Check if analyst worker is running
sudo journalctl -u socops | tail -20 | grep analyst

# Restart to reset memory
sudo systemctl restart socops
```

---

## Part 11: Monitoring & Maintenance

### Daily Health Check

```bash
# Is it running?
sudo systemctl is-active socops

# Any errors overnight?
sudo journalctl -u socops --since "8 hours ago" | grep error

# When was the last poll?
curl -s http://localhost:8081/api/stats | python3 -c "
import json, sys
data = json.load(sys.stdin)
print('Last poll:', data['last_poll'])
"
```

### Weekly Tasks

**Every Monday:**
1. Check database size: `du -sh ~/claude/socops/socops.db`
2. Review the Metrics page for top noisy rules
3. Check if any suppression rules need renewal (expiration dates)

**Every Month:**
1. Rotate API keys (AbuseIPDB, OTX, Anthropic) if using them
2. Clean up old acknowledged alerts (see Part 7)
3. Verify backups are working

### Updating SOCops

If a new version is released:

```bash
# Backup first
cp ~/claude/socops/socops.db ~/claude/socops/socops.db.backup

# Download new version (exact steps depend on your setup)
# Replace app.py, db.py, wazuh.py, etc. with new files

# Restart
sudo systemctl restart socops

# Watch logs for errors
sudo journalctl -u socops -f
```

Database migrations (schema changes) run automatically on startup.

---

## Part 12: Security

### Who Can Access SOCops?

By default, **anyone on your network** can access SOCops at port 8081. There's no login screen.

**For production, restrict access:**

```bash
# Option 1: Firewall — only allow from specific IPs
sudo ufw allow from 10.0.0.0/24 to any port 8081

# Option 2: Reverse proxy with nginx + password (see below)

# Option 3: VPN — require VPN to reach the server
```

### Add a Login Screen (Optional)

Put SOCops behind nginx with HTTP basic auth:

```bash
# Install nginx
sudo apt install nginx

# Create password file
sudo htpasswd -c /etc/nginx/.htpasswd analyst

# Create nginx config (edit /etc/nginx/sites-enabled/socops)
sudo nano /etc/nginx/sites-enabled/socops
```

Paste this:
```nginx
server {
    listen 8080;
    server_name _;
    
    auth_basic "SOCops";
    auth_basic_user_file /etc/nginx/.htpasswd;
    
    location / {
        proxy_pass http://127.0.0.1:8081;
    }
}
```

Then:
```bash
sudo systemctl restart nginx

# SOCops now available at port 8080 with password
```

### Protect Your Credentials

```bash
# .env file permissions
chmod 600 ~/claude/socops/.env

# Database file permissions
chmod 600 ~/claude/socops/socops.db

# Never put .env in git
echo ".env" >> ~/claude/socops/.gitignore
echo "socops.db" >> ~/claude/socops/.gitignore
```

---

## Part 13: Getting Help

If something breaks:

1. **Check logs first:**
   ```bash
   sudo journalctl -u socops -n 50   # last 50 lines
   sudo journalctl -u socops -f      # follow live
   ```

2. **Check database:**
   ```bash
   sqlite3 socops.db
   SELECT COUNT(*) FROM alerts;      # how many alerts?
   SELECT status, COUNT(*) FROM alerts GROUP BY status;  # by status
   ```

3. **Test Wazuh connection:**
   ```bash
   curl -k "https://YOUR.WAZUH.HOST/auth/login"
   ```

4. **Restart and observe:**
   ```bash
   sudo systemctl restart socops
   sleep 3
   sudo journalctl -u socops -f
   ```

---

**That's it. You're an SOCops administrator now.** If anything confuses you, the logs tell you exactly what went wrong.
