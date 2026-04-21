# SOCops User Manual

**This manual teaches security analysts how to use SOCops to do their job.**

Think of SOCops as a **smart assistant for your security alerts**. Your Wazuh system constantly generates security alarms. SOCops helps you:
- Understand what each alarm means
- Decide if it's important
- Take action on it
- Track related alarms together
- Avoid seeing the same alarm over and over

You don't need to be a computer expert to use SOCops. If you can use a web browser and a spreadsheet, you can use SOCops.

---

## How SOCops Fits Into Your Job

**Without SOCops:**
1. You log into Wazuh
2. You see 500+ alerts
3. You read each one individually
4. You manually copy details to notepad
5. You mark it as "done" somehow
6. Repeat 500 times

**With SOCops:**
1. You open SOCops in your browser
2. You see alerts ranked by severity
3. You click one to read it
4. AI explains what it means
5. You click "Acknowledge" or "Escalate"
6. You move to the next one

SOCops does the boring parts so you can focus on the important ones.

---

## Getting Started (First 5 Minutes)

### Open SOCops

In your web browser, go to:
```
http://your-server.com:8081
```

Or ask your administrator for the correct URL.

### You Should See This

A dark screen with:
- **Top navigation:** Queue | Dashboard | Cases | Suppressions | Metrics
- **Left side:** List of alerts
- **Right side:** Empty (click an alert to see details)
- **Bottom:** Action buttons

### Read the Red Numbers

In the top-right of the header, you see three numbers in colored pills:

- **Red pill (number)** — how many NEW alerts need your attention
- **Orange pill (number)** — how many you ESCALATED (serious incidents)
- **Blue pill (number)** — how many you already ACKNOWLEDGED (reviewed and understood)

These update every 60 seconds as new alerts come in.

---

## Part 1: Understanding Alerts (The Queue)

### What Is an Alert?

An alert is a **security event that happened on your network**. Examples:
- "Someone tried to log in 10 times with the wrong password"
- "A file on this server was modified in the middle of the night"
- "This IP address is known to be malicious"

Each alert has:
- **Rule description** — what it detected
- **Agent/computer** — where it happened
- **Severity** — how important it is (1-15, where 15 = CRITICAL)
- **Timestamp** — when it happened

### Severity Levels Explained

Each alert has a color badge with a number inside. Here's what they mean:

| Color | Number | Name | What It Means |
|-------|--------|------|--------------|
| 🔴 Red | 12-15 | CRITICAL | **DO THIS NOW** — stop what you're doing and investigate |
| 🟠 Orange | 10-11 | HIGH | **Check this in the next hour** — probably a real problem |
| 🟡 Yellow | 7-9 | MEDIUM | **Check this today** — worth investigating but not urgent |
| 🟢 Green | 1-6 | LOW | **Check at the end of your shift** — probably harmless |

**Real-world examples:**

| Alert | Severity | Why |
|-------|----------|-----|
| "Ransomware detected on server" | 🔴 15 | This is an active attack |
| "Failed login 10 times in 1 minute" | 🔴 14 | Brute force attack |
| "Unusual network port opened" | 🟠 11 | Suspicious but could be legitimate |
| "File modified in temp folder" | 🟡 8 | Needs checking but probably benign |
| "Service restarted normally" | 🟢 3 | Expected behavior |

---

## Part 2: Your First 30 Minutes

### Step 1: Look at the Queue

The left side shows a list of alerts. Each alert shows:
- **Severity badge** (colored square with number)
- **Rule description** (what it detected)
- **Agent name** (which computer, like "server-01")
- **Timestamp** (when it happened)

Alerts are sorted by **highest severity first**. The red ones are at the top.

### Step 2: Click on a Red Alert

Click any alert. The right side panel opens with full details:

**Header section shows:**
- Rule name
- Agent name (click it to see timeline)
- Source IP (click it to see if it's bad)
- MITRE ATT&CK tags (what attack technique this is)

**Analysis section shows:**
- **What happened:** Plain English summary
- **Severity context:** Why this matters
- **Remediation steps:** Numbered steps for what to do

**Event details section shows:**
- Raw technical data (file path, user, command, etc.)

**Notes section shows:**
- Any comments previous analysts added
- Auto-generated "status changed" entries

### Step 3: Make a Decision

At the bottom of the alert, you have action buttons. Pick one:

| Button | Meaning | When to Use | Example |
|--------|---------|------------|---------|
| **✓ Ack** | Acknowledge — "I reviewed it, it's fine" | Alert is not a problem | "This FIM event is expected, I acknowledge" |
| **↑ Escalate** | "This needs more investigation" | Alert is suspicious or concerning | "Lateral movement detected, escalating" |
| **✗ FP** | False Positive — "This is a mistake" | Alert should not have fired | "VPN client flagged as trojan, but it's legit" |
| **⊘ Suppress** | "Stop showing me this alert forever" | Alert is noise (fires constantly, never matters) | "Systemd service restarting is normal" |

**Pro tip:** Don't spend more than 30 seconds per alert. If you can't decide, click **Escalate** and come back to it.

### Step 4: Read the Analysis

SOCops includes **AI-generated analysis** for each alert. This explains:
- What the alert detected
- Why it matters
- What steps to take

**Example analysis:**
```
🔴 Lateral Movement Detected

What happened:
An attacker has moved from the initial compromised host (192.168.1.10) 
to another host (192.168.1.50) and attempted to execute commands.

Severity Context:
This indicates the attacker is exploring your network and escalating 
the attack from initial access to active exploitation.

Remediation Steps:
1. Immediately isolate 192.168.1.50 from the network
2. Check event logs on 192.168.1.10 for credential theft
3. Reset passwords for affected users
4. Scan both hosts for backdoors
```

The analysis is written in plain English, not technical jargon (usually).

---

## Part 3: Understanding the Views

### The Status Filter (Top Left)

Four buttons filter which alerts you see:

| Button | Shows | When to Use |
|--------|-------|------------|
| **All** | Every alert (including old ones) | Get a complete picture |
| **New** | Unreviewed alerts | Start your shift here |
| **Escalated** | Alerts you marked as suspicious | Follow up on serious incidents |
| **Ack** | Alerts you already reviewed | Verify your work |
| **FP** | Alerts you marked as false positives | Tune detection rules |

**Common workflow:**
1. Start with **New** — work through new alerts
2. Switch to **Escalated** — manage ongoing incidents
3. At end of shift, check **Escalated** again

### The Category Filter (Below Status)

Further filter by alert type:

| Category | What It Is | Examples |
|----------|-----------|----------|
| **Systemd** | Service/system startup events | "Apache started", "Service crashed" |
| **Integrity** | File/registry changes | "Important file modified", "Permission changed" |
| **CIS** | Compliance benchmarks | "Password policy not set", "Antivirus disabled" |
| **Web** | Web server activity | "SQL injection attempt", "Directory traversal" |
| **Windows** | Windows system events | "Failed login", "Privilege escalation" |

**Tip:** Start with **Web** + **New** (these have highest signal-to-noise), then **CIS**, then **Integrity**, then **Systemd** (usually lowest priority).

### Alerts View vs Groups View

Two ways to see the same data:

**Alerts view** (default):
- Shows every individual alert
- Good for detailed work
- Can show 300 alerts per page

**Groups view**:
- Combines identical alerts (same rule + same agent)
- Shows count badge (e.g., "×47" means 47 identical alerts)
- Good for spotting recurring patterns
- Faster to scan for "noisy" alerts

**Example:**
- Alerts view: 47 separate "Failed SSH login" entries
- Groups view: One card saying "Failed SSH login ×47"

Use Groups to quickly find recurring alerts, then switch back to Alerts to investigate.

---

## Part 4: Detailed Alert Investigation

### When You Select an Alert

The right panel shows complete information:

**1. Header (Most Important):**
- Alert title and severity
- Computer it happened on
- Source IP (with threat intel risk score)
- MITRE ATT&CK technique/tactic

**2. Analysis Section (Read This):**
This is the AI-generated explanation. It usually answers:
- What happened?
- Is it dangerous?
- What should I do?

**3. Event Details:**
Raw technical fields (log data, user accounts, file paths, etc.)

**4. Notes Thread:**
Comments from you or other analysts, plus auto-generated status changes.

### Threat Intel Risk Badge

If an alert has a source IP, you see a risk badge:

```
⚑ LOW 12
⚑ MEDIUM 45
⚑ HIGH 73
⚑ CRITICAL 95
```

This means: "SOCops looked up this IP in threat databases and it has a score of 12-95 out of 100." Higher = more suspicious.

**How to interpret:**
- **0-19 (LOW):** Probably fine
- **20-49 (MEDIUM):** Worth noting, but not rare
- **50-79 (HIGH):** Known to be suspicious
- **80-100 (CRITICAL):** Very likely malicious

**Pro tip:** High risk doesn't automatically mean you should panic. Sometimes legitimate security tools (vulnerability scanners, penetration testers) show up as "high risk" because they probe networks. Ask your team about any expected high-risk IPs.

### Entity Timeline

Want to see if this computer or IP has had other problems?

**Click the agent name** (computer name) → see all alerts from that computer in the last 24 hours.

**Click the source IP** → see all alerts involving that IP in the last 24 hours.

This timeline shows:
- When it happened
- What happened
- If you acknowledged/escalated it

**Use this to answer:** "Is this computer having ongoing problems or is it just this one alert?"

---

## Part 5: Taking Action

### Acknowledge (✓)

**What it means:** "I reviewed this alert. It's not a problem."

**When to use:**
- Alert fired on expected/normal activity
- You investigated and it's benign
- You've taken action and it's resolved

**Example:**
- Alert: "SSH login from IP 1.2.3.4"
- You check: That's the VPN server (expected)
- Action: Acknowledge

### Escalate (↑)

**What it means:** "This needs deeper investigation or is a real security issue."

**When to use:**
- You're not sure if it's a problem
- Investigation requires more time
- It looks like a real security incident
- You need to create a case for it

**Example:**
- Alert: "Lateral movement detected"
- Action: Escalate (mark for further investigation)

### False Positive (✗)

**What it means:** "This alert should never have fired."

**When to use:**
- Legitimate activity was incorrectly flagged
- Alert rule needs tuning
- You want to track that this rule has false positives

**Example:**
- Alert: "Trojan detected: c:\antivirus\update.exe"
- You check: That's your antivirus software, not a trojan
- Action: Mark False Positive

**Important:** Marking False Positive helps your team improve detection rules over time.

### Suppress (⊘)

**What it means:** "Stop showing me this alert. Ever."

**When to use:**
- Alert fires constantly
- You've confirmed it's always harmless
- It's noise obscuring real threats

**Example:**
- Alert: "Failed SSH login from 192.168.1.1" (your CI/CD server, happens 100x per day)
- Action: Create suppression rule → never see it again

**Note:** This requires adding a reason (for audit trail). Be specific: "CI/CD system expected to fail SSH logins during deployments."

---

## Part 6: Adding Notes

Every alert has a notes thread (bottom of panel).

**To add a note:**
1. Type in the text field at the bottom
2. Click **Add Note**
3. Your note appears in the thread with timestamp

**Use notes for:**
- Recording your investigation steps
- Noting decisions you made
- Linking to external tickets (Jira, ServiceNow, etc.)
- Handoff information for next analyst

**Example notes:**
```
Checked Windows event logs on server-01. User "admin" logged in at 3:47 PM 
from IP 10.0.0.5 (office network). Expected login. —Alice

Confirmed with user. Login attempt was Alice from her office machine. No issue. —Bob
```

---

## Part 7: Cases (Group Related Alerts)

Sometimes multiple alerts indicate one **incident**. Example:

**Scenario:** You get three alerts:
1. "Failed login 10 times from IP 1.2.3.4"
2. "Privilege escalation on server-05"
3. "File accessed that user shouldn't have access to"

These might be one attack, not three separate events.

### Creating a Case

**Go to Cases page → Create Case button:**

| Field | What to Put |
|-------|------------|
| **Title** | Short description of incident (e.g., "Suspected credential attack on server-05") |
| **Severity** | 1-15, usually same as highest alert severity |
| **Description** | Your initial hypothesis and notes |

**Example:**
```
Title: Suspected credential attack on server-05
Severity: 14 (HIGH)
Description: Multiple failed login attempts from external IP 1.2.3.4 followed by 
successful privilege escalation. Attacker may have obtained credentials. 
Checking Windows logs for lateral movement.
```

### Linking Alerts to Cases

Once you've created a case, go to each alert and click **+ Case** → select your case.

The alert is now part of the case. You can see it on the Cases page.

### Managing Cases

On the Cases page, you see all your incidents:

| Status | Meaning | When to Update |
|--------|---------|----------------|
| **open** | Just created | On creation |
| **in_progress** | Actively working | Once you start investigating |
| **resolved** | Issue is fixed | Once you've fixed the problem |
| **closed** | Fully closed, confirmed safe | Once you've verified no ongoing impact |

**Typical lifecycle:**
1. Open → (detect incident)
2. In progress → (investigate)
3. Resolved → (fix the problem)
4. Closed → (verify it's actually fixed)

---

## Part 8: Suppressions (Mute Noise)

Some alerts repeat constantly but are harmless:
- "Service restarted" (normal on a test server)
- "Failed SSH login" (CI/CD system expected to fail)
- "VPN traffic detected" (employees using VPN is expected)

Instead of acknowledging these 100 times per day, you can **suppress** them.

### How Suppression Works

**Without suppression:**
- Alert fires 100 times per day
- You acknowledge 100 times per day
- Wastes your time

**With suppression:**
- Alert fires 100 times per day
- Never appears in your queue
- Stored in database but marked "suppressed"

### Creating a Suppression Rule

Go to **Suppressions page** → **Create Rule:**

| Field | Example | What It Means |
|-------|---------|--------------|
| **Field** | `agent_name` | Which part of the alert to match against |
| **Operator** | `equals` | How strict to match (equals, contains, starts_with) |
| **Value** | `test-server-01` | What to match |
| **Reason** | "Test server expected to restart services constantly" | Why (audit trail) |
| **Expires** | 2026-06-30 | Optional: auto-remove on this date |

**Common examples:**

**Example 1: Suppress one noisy server**
- Field: agent_name
- Operator: equals
- Value: build-server-01
- Reason: "Build server performs expected automated restarts"

**Example 2: Suppress a specific rule**
- Field: rule_id
- Operator: equals
- Value: 40704
- Reason: "Systemd exit code 0 is normal"

**Example 3: Suppress a known-benign IP**
- Field: srcip
- Operator: equals
- Value: 192.168.0.50
- Reason: "Internal vulnerability scanner — scheduled weekly"

### Managing Rules

On the Suppressions page:

| Column | What It Tells You |
|--------|-----------------|
| **hits** | How many alerts this rule has suppressed. If it's 0 after 3 days, maybe you have a typo |
| **expires** | When rule auto-deletes (if you set an expiry) |

**Pro tip:** Always set an expiry date for suppressions. After a few months, revisit and decide if you still need it.

---

## Part 9: Dashboard & Metrics

### Dashboard

Shows charts of Wazuh data (updated every 5 minutes):

| Chart | What It Shows |
|-------|--------------|
| **Active Agents** | How many computers are connected to Wazuh |
| **Alert Volume Over Time** | How many alerts per hour (spot spikes) |
| **Top Agents** | Which computers generate most alerts |
| **MITRE Coverage** | What attack techniques you're detecting |
| **CIS Compliance** | Compliance benchmark status |

**Use this for:** Getting a bird's-eye view of your security posture. "Are there any unexpected spikes? Is an agent down? Are we covering the right attack techniques?"

### Metrics

Shows how your **SOC team** is performing (not infrastructure):

| KPI | What It Means | Why It Matters |
|-----|--------------|----------------|
| **MTTR** | Average time to respond to alerts (minutes) | Lower is better. Shows how fast your team works. |
| **FP Rate** | Percentage of false positives | Lower is better. Shows if detection rules are accurate. |
| **24h Volume** | Alerts ingested today | Trending up? Might be an incident or new noise. |
| **Backlog Age** | Hours since oldest unreviewed alert | If > 8 hours, queue is building up. |
| **Escalation Rate** | % of alerts marked "escalate" | Should be 2-10%. If 0%, alerts aren't serious enough. |

**Example interpretation:**
```
MTTR: 45 minutes
FP Rate: 25%
24h Volume: 342 alerts
Backlog Age: 2 hours
Escalation Rate: 5%

Translation: We're responding to alerts in 45 minutes on average. 
25% are false alarms (room for tuning). Normal volume today. 
No backlog building up. 5% escalation rate is healthy.
```

### Noisy Rules Table

Shows which detection rules generate the most alerts and how many are false positives.

**Use this to:** Identify which rules should be suppressed, tuned, or investigated.

**Example:**
```
Rule: "VirusTotal: Error loading API"
Count: 2,341 (last 7 days)
FP Rate: 95%

Translation: This rule fired 2,341 times and 95% were false positives. 
This should be suppressed immediately.
```

---

## Part 10: Daily Workflow

### Start of Shift

1. **Open SOCops** at `http://your-server:8081`
2. **Check header counts:**
   - How many NEW alerts?
   - How many ESCALATED (ongoing incidents)?
3. **Check Metrics page:**
   - Is backlog age building up?
   - Any unusual trends in the sparkline chart?

### Triage the Queue

1. **Set status filter to NEW**
2. **Sort by priority:**
   - First: Web alerts (usually highest signal-to-noise)
   - Second: CIS/compliance alerts
   - Third: Integrity/FIM alerts
   - Last: Systemd/noise alerts
3. **For each alert:**
   - Spend 10 seconds reading rule description
   - Click to see AI analysis
   - Acknowledge or Escalate
4. **If you see recurring patterns:**
   - Create a suppression rule
   - Cuts future triage time dramatically

### Investigate Escalated Alerts

1. **Set status filter to ESCALATED**
2. **For each alert:**
   - Read previous analyst notes
   - Update notes with new findings
   - If resolved, acknowledge it

### End of Shift

1. **Export current state for handoff:**
   - CSV button (top-right) → Escalated alerts → save
2. **Add handoff notes:**
   - Check if backlog is building
   - Note any ongoing incidents
   - Suggest priority items for next shift

---

## Part 11: Common Scenarios

### Scenario 1: Multiple Failed Logins

**Alert:** "Failed SSH login 10 times in 1 minute"

**Your investigation:**
1. Click the source IP → see timeline
2. Is this IP in geolocation? (click IP to see enrichment)
3. Is this a known service (IP in threat intel)?

**Decision:**
- **If IP is from office:** Acknowledge (employee probably typed wrong password)
- **If IP is external + high threat score:** Escalate (potential brute force attack)
- **If it's happening daily + always from same IP + always fails:** Create suppression rule (expected service behavior)

### Scenario 2: File Modified in Important Folder

**Alert:** "File integrity check — /etc/shadow modified"

**Your investigation:**
1. When did it change? Click timestamp.
2. Who changed it? Check user field.
3. Is the user supposed to be able to change this file?
4. Was this a scheduled backup/update?

**Decision:**
- **If it's the root user running scheduled updates:** Acknowledge
- **If it's a regular user or unexpected time:** Escalate immediately and create case
- **If it's a CI/CD system expected to modify files:** Suppress

### Scenario 3: Lateral Movement Alert

**Alert:** "Lateral movement detected: 10.0.0.55 → 10.0.0.60"

**Your investigation:**
1. Click 10.0.0.55 → see all alerts from that computer
2. Are there previous compromise indicators?
3. Escalate immediately
4. Create a case
5. Notify your manager

**Decision:** Always escalate this. Contact security team. This is a real attack in progress.

---

## Part 12: Tips & Tricks

### Time-Saving Shortcuts

1. **Bulk actions:** Filter to "New" + "Systemd" → if you recognize them all as benign, use Groups view and acknowledge 10 at a time
2. **Copy notes:** Use browser copy-paste to share alert details with team chat
3. **Entity timeline:** Click agent name → instantly see if this computer has other problems
4. **Search:** Use the search box (top-left) to find alerts about a specific word

### Keyboard Navigation

- **Arrow keys:** Navigate between alerts
- **Enter:** Open selected alert
- **A:** Acknowledge
- **E:** Escalate
- **F:** False Positive
- **S:** Suppress

(These may not be enabled — check with your administrator.)

### Exporting Data

**CSV export (top-right button):**
- Spreadsheet format
- Good for: reports, team sharing, historical analysis
- Includes: all fields except raw JSON payload

**JSON export:**
- Machine-readable format
- Good for: integration with other tools, IR handoffs
- Includes: everything (full event data)

### Reporting to Management

Use Metrics page:

```
Weekly SOC Report
═══════════════════
MTTR:              43 minutes (target: 60 minutes)  ✓
FP Rate:           22% (target: <30%)               ✓
24h Volume:        287 alerts (normal)
Escalation Rate:   4% (healthy)
Backlog Age:       1.5 hours (healthy)

Noisy Rules for Tuning:
- VirusTotal API timeouts (1,247 alerts, 98% FP)
- SSH login failures on build server (302 alerts, 100% FP)

Action Items:
- Suppress VirusTotal API timeout rule
- Escalate build server SSH config review to DevOps
```

---

## Part 13: Getting Help

### If Something Doesn't Make Sense

1. **Check the Analysis section** — SOCops explains what the alert means
2. **Click the source IP** — see if it's a known-bad IP
3. **Use entity timeline** — see if the computer has other problems
4. **Add a note** — ask a colleague in the notes thread

### If the UI is Confusing

1. **Hover over buttons** — most have tooltips
2. **Try the API docs** — `/api/docs/user-manual`
3. **Ask your administrator** — they may have trained you on your specific setup

### If You Think You Found a Security Issue

1. **Create a case immediately**
2. **Escalate all related alerts**
3. **Add detailed notes**
4. **Alert your manager/security lead**
5. **Don't wait for approval — escalate first**

---

**That's it. You now know how to use SOCops like a professional security analyst.**

Questions? The Analysis section on each alert usually explains what to do. When in doubt, escalate and let your team decide together.

Good luck catching the bad guys. 🛡️
