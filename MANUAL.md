# SOCops User Manual

**Version:** 1.0 · **Platform:** Self-hosted Linux · **Access:** `http://<server>:8081`

---

## Table of Contents

1. [Overview](#1-overview)
2. [Navigation](#2-navigation)
3. [Alert Queue](#3-alert-queue)
   - 3.1 [Understanding the Layout](#31-understanding-the-layout)
   - 3.2 [Alert Severity Levels](#32-alert-severity-levels)
   - 3.3 [Status Filters](#33-status-filters)
   - 3.4 [Category Filters](#34-category-filters)
   - 3.5 [Alerts View vs Groups View](#35-alerts-view-vs-groups-view)
   - 3.6 [Searching Alerts](#36-searching-alerts)
   - 3.7 [Selecting and Investigating an Alert](#37-selecting-and-investigating-an-alert)
   - 3.8 [Threat Intel Enrichment](#38-threat-intel-enrichment)
   - 3.9 [AI Analysis](#39-ai-analysis)
   - 3.10 [Taking Action on an Alert](#310-taking-action-on-an-alert)
   - 3.11 [Notes](#311-notes)
   - 3.12 [Assigning Alerts](#312-assigning-alerts)
   - 3.13 [Entity Timeline](#313-entity-timeline)
   - 3.14 [Suppressing from an Alert](#314-suppressing-from-an-alert)
   - 3.15 [Adding an Alert to a Case](#315-adding-an-alert-to-a-case)
   - 3.16 [Exporting Alerts](#316-exporting-alerts)
4. [Dashboard](#4-dashboard)
5. [Cases](#5-cases)
   - 5.1 [Creating a Case](#51-creating-a-case)
   - 5.2 [Managing Cases](#52-managing-cases)
   - 5.3 [Linking Alerts to Cases](#53-linking-alerts-to-cases)
6. [Suppressions](#6-suppressions)
   - 6.1 [How Suppression Works](#61-how-suppression-works)
   - 6.2 [Creating a Suppression Rule](#62-creating-a-suppression-rule)
   - 6.3 [Managing Rules](#63-managing-rules)
   - 6.4 [Suppression Strategy](#64-suppression-strategy)
7. [Metrics](#7-metrics)
   - 7.1 [KPI Cards](#71-kpi-cards)
   - 7.2 [Hourly Volume Sparkline](#72-hourly-volume-sparkline)
   - 7.3 [Top Agents](#73-top-agents)
   - 7.4 [Noisy Rules Table](#74-noisy-rules-table)
   - 7.5 [MITRE ATT&CK Coverage](#75-mitre-attck-coverage)
   - 7.6 [Detection Rule Library](#76-detection-rule-library)
8. [Analyst Workflow Guide](#8-analyst-workflow-guide)
   - 8.1 [Starting a Shift](#81-starting-a-shift)
   - 8.2 [Triaging the Queue](#82-triaging-the-queue)
   - 8.3 [Investigating an Alert](#83-investigating-an-alert)
   - 8.4 [Escalating to an Incident](#84-escalating-to-an-incident)
   - 8.5 [Tuning Noisy Rules](#85-tuning-noisy-rules)
   - 8.6 [Ending a Shift](#86-ending-a-shift)
9. [Notifications](#9-notifications)
10. [API Reference](#10-api-reference)

---

## 1. Overview

SOCops is a lightweight, self-hosted Security Operations Center workbench built on top of Wazuh. It replaces the Wazuh UI for day-to-day analyst operations with a purpose-built alert queue, AI-assisted investigation, case management, suppression rules, and SOC performance metrics.

**What SOCops does:**
- Pulls alerts from Wazuh every 60 seconds and stores them locally in SQLite
- Provides an analyst-focused queue UI for triaging, acknowledging, escalating, and marking false positives
- Runs AI analysis on each alert using Claude Haiku (falls back to rule-based analysis if no API key)
- Enriches source IPs against AbuseIPDB and AlienVault OTX threat intel feeds
- Lets you group related alerts into named incident cases
- Lets you suppress recurring noise with point-and-click rules
- Tracks SOC KPIs: MTTR, FP rate, alert volume, backlog age
- Sends high-severity and escalation notifications via webhook or email

**What SOCops does not do:**
- It does not replace Wazuh for agent management, rule configuration, or raw log search
- It does not provide real-time streaming — alerts arrive in 60-second batches
- It does not enforce multi-user auth — it is designed for a single analyst or a small trusted team on a private network

---

## 2. Navigation

The top navigation bar is present on every page:

```
[S] SOCops   Queue  Dashboard  Cases  Suppressions  Metrics       CSV  JSON
```

| Link | Page | Purpose |
|---|---|---|
| **Queue** | `/` | Alert triage — your primary workspace |
| **Dashboard** | `/dashboard` | Wazuh health and trend charts |
| **Cases** | `/cases` | Incident containers grouping related alerts |
| **Suppressions** | `/suppressions` | Rules to auto-suppress recurring noise |
| **Metrics** | `/metrics` | SOC KPIs, MITRE coverage, noisy rules |

The header also shows three live counters: **new alerts**, **escalated**, and **acknowledged**, updating every 60 seconds.

The **CSV** and **JSON** buttons in the top-right export the current queue view.

---

## 3. Alert Queue

The queue at `/` is your primary workspace. It fills the full browser viewport with a split pane: the alert list on the left, and the investigation detail panel on the right.

### 3.1 Understanding the Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│ Header: logo | nav | stat pills (new / escalated / ack) | poll time │
├────────────────────────┬────────────────────────────────────────────┤
│ STATUS FILTERS         │                                            │
│ All New Escalated Ack FP│         DETAIL PANEL                      │
├────────────────────────┤  (select an alert to investigate)         │
│ CATEGORY FILTERS       │                                            │
│ All Systemd Integrity  │                                            │
│ CIS Web Windows        │                                            │
├──── search ────────────│                                            │
│ ALERT LIST             │                                            │
│ [lvl] Rule description │                                            │
│       Agent · time     │                                            │
│       [MITRE tag]      │                                            │
│ ...                    │                                            │
├────────────────────────┴────────────────────────────────────────────┤
│ ACTION BAR: ✓ Acknowledge  ↑ Escalate  ✗ False Positive  ⊘ Suppress│
│             + Case    Assign: [______]  Note: [__________] Add Note │
└─────────────────────────────────────────────────────────────────────┘
```

The action bar at the bottom becomes active as soon as you click any alert. You do not need to wait for the detail to load before acting.

### 3.2 Alert Severity Levels

Each alert carries a Wazuh rule level from 1–15. SOCops maps these to four severity tiers:

| Badge color | Level range | Label | Meaning |
|---|---|---|---|
| Red | 12–15 | CRITICAL | Immediate investigation required |
| Orange | 10–11 | HIGH | Investigate within 1 hour |
| Yellow | 7–9 | MEDIUM | Investigate within 4 hours |
| Green | 1–6 | LOW | Review at end of shift |

The numeric level is shown inside the badge on each alert card.

### 3.3 Status Filters

The status filter row selects which workflow state to show:

| Button | What it shows |
|---|---|
| **All** | Every alert regardless of status |
| **New** | Unreviewed alerts — your primary triage view |
| **Escalated** | Alerts promoted to active investigation |
| **Ack** | Acknowledged (reviewed, no further action) |
| **FP** | Marked as false positive |

A red badge on the **New** button and an orange badge on the **Escalated** button show the current count. These update every 60 seconds.

Suppressed alerts are excluded from all views. They are automatically set at ingest when a suppression rule matches.

### 3.4 Category Filters

The category bar below the status filters narrows by alert type. Status and category filters combine — for example, New + CIS shows only unreviewed CIS benchmark alerts.

| Button | What it matches |
|---|---|
| **All** | No category filter |
| **Systemd** | Service failures, unit state changes |
| **Integrity** | File integrity monitoring (FIM) — file/registry changes, additions, deletions |
| **CIS** | CIS benchmark compliance checks (SCA scans) |
| **Web** | Web server access log attacks, 400/500 errors |
| **Windows** | Windows application and system event log alerts |

### 3.5 Alerts View vs Groups View

The **Alerts / Groups** toggle to the left of the status filter switches between two views of the same data.

**Alerts view** (default): shows individual alert cards sorted by severity then timestamp, newest first within each severity band. This is the standard triage view.

**Groups view**: collapses alerts with the same rule on the same agent into a single group card with a **×N** count badge. Use this to quickly see which rule/agent combinations are generating the most volume before deciding whether to suppress or investigate.

Group cards show: severity of the highest alert in the group, rule description, agent name, total count, and most recent timestamp.

Clicking a group card expands it inline in the detail pane, showing all individual alerts in that group. Clicking any of those alerts opens the full alert detail.

### 3.6 Searching Alerts

The search box in the filter bar performs a live client-side search across the currently loaded alert list. It matches against:
- Rule description
- Agent name
- MITRE technique name

The search applies on top of the active status and category filters. It searches within the current page of 300 alerts. To search across all alerts, use the export API with filters.

### 3.7 Selecting and Investigating an Alert

Click any alert card to load it in the detail panel. The panel shows:

**Header:**
- Severity badge and rule description
- Chips: agent name, agent IP, MITRE technique, MITRE tactic, source IP, current status
- Threat intel risk badge (if srcip is enriched and has a non-zero risk score)

**Analysis & Remediation section:**
Contains the AI-generated investigation guidance. This includes:
- What happened (event summary)
- Severity context (urgency framing)
- Remediation steps (numbered, actionable)

If the analysis is still processing, a spinner is shown and the panel polls every 4 seconds until complete. If no Anthropic API key is configured, or if the account has no credits, a rule-based analysis is shown instead — still useful but less context-aware.

**Event Details section:**
Raw fields extracted from the Wazuh event: timestamp, rule ID, rule groups, FIM path and event type, source/target user, command, URL, full log line. Not all fields appear for every alert type.

**Notes section:**
Chronological thread of analyst notes and auto-generated status change entries. See section 3.11.

### 3.8 Threat Intel Enrichment

When an alert contains a source IP (`srcip`), SOCops automatically queries threat intel in the background:

- **AbuseIPDB**: returns an abuse confidence score (0–100%) and total report count
- **AlienVault OTX**: returns pulse count (number of threat intel reports referencing this IP) and country

Results are combined into a **risk score** (0–100) and **risk label**:

| Label | Score | Badge color |
|---|---|---|
| low | 0–19 | muted |
| medium | 20–49 | yellow |
| high | 50–79 | orange |
| critical | 80–100 | red |

The risk badge appears next to the source IP chip in the alert header: `⚑ HIGH 73`. For scores ≥ 50, the abuse confidence percentage and OTX pulse count are shown inline.

Enrichment happens in a background worker running every 30 seconds at a rate of 1 IP per second. Newly ingested alerts with a srcip will typically be enriched within 1–2 minutes.

To manually trigger an enrichment lookup, use the API: `GET /api/enrich/<ip>`

Enrichment requires API keys configured in the environment (`OTX_KEY`, `ABUSEIPDB_KEY`). If neither is configured, no enrichment badges appear.

### 3.9 AI Analysis

Each alert is analyzed by a background worker that processes unanalyzed alerts continuously, highest severity first.

**With Anthropic API key + credits:** Analysis is generated by Claude Haiku. The model receives the full alert context — rule, agent, MITRE mapping, raw event fields — and returns structured markdown covering what happened, severity framing, and specific remediation steps.

**Without API key or with zero credits:** A rule-based stub generates analysis from MITRE tactic → remediation mappings plus rule group context. Less nuanced but still actionable.

The analysis section in the detail panel renders markdown: headers, bold text, numbered lists, inline code, and emphasis are all formatted.

### 3.10 Taking Action on an Alert

The action bar at the bottom of the screen is active whenever an alert is selected. Actions are applied immediately — the queue and stats update within seconds.

| Button | Action | When to use |
|---|---|---|
| **✓ Acknowledge** | Sets status to `ack` | Reviewed, understood, no further action needed |
| **↑ Escalate** | Sets status to `escalated` | Requires deeper investigation or a case |
| **✗ False Positive** | Sets status to `fp` | Alert fired on benign activity |
| **↺ Reopen** | Sets status back to `new` | Reconsider a previously actioned alert (shown only when status ≠ new) |

After taking action, the alert detail reloads showing the updated status. The queue list updates to reflect the new status (acknowledged alerts show at reduced opacity; if the status filter is set to New, they disappear from view).

**Escalating a critical alert** also triggers an outbound notification (if `NOTIFY_WEBHOOK` or `NOTIFY_EMAIL` is configured). High-severity alerts (rule level ≥ `NOTIFY_LEVEL`, default 12) trigger notifications automatically on ingest.

### 3.11 Notes

The notes thread at the bottom of the detail panel is a chronological log of analyst observations and system events for that alert.

**Adding a note:**
Type in the note input field and click **Add Note**. The note is stored with a UTC timestamp and appears immediately in the thread.

**Auto-generated entries:**
Every time an alert's status changes (acknowledge, escalate, false positive, reopen), an entry is automatically appended to the notes thread recording what happened and when. These appear in muted italic text to distinguish them from analyst notes. Example: `Status changed to escalated`.

Notes persist across sessions and are included in JSON exports.

### 3.12 Assigning Alerts

The **Assign to:** text field in the action bar lets you record which analyst is working an alert. Type a name or initials and click **Assign**.

Assigned alerts show a small initials badge in the alert list. Use the search box to filter by analyst name if needed.

### 3.13 Entity Timeline

Clicking the **agent name chip** or the **source IP chip** in the alert detail header opens a timeline modal.

The timeline shows all alerts involving that agent or IP from the last 24 hours, sorted chronologically (oldest first). Each event in the timeline shows:
- Timestamp
- Severity badge
- Rule description
- Status dot
- MITRE tactic tag (if present)

Clicking any event in the timeline closes the modal and loads that alert's full detail. This is the fastest way to answer "what else has this host done recently?" during an investigation.

### 3.14 Suppressing from an Alert

The **⊘ Suppress** button in the action bar opens a suppression modal pre-filled with the current alert's rule ID and agent name.

Review the pre-filled values, add a reason (required for audit trail), optionally set an expiry date, then click **Create Rule**. New alerts matching this rule will be automatically suppressed at ingest — they will never appear in the queue.

See section 6 for full suppression documentation.

### 3.15 Adding an Alert to a Case

The **+ Case** button opens a case modal showing existing open cases. Select a case from the dropdown and click **Add to Case** to link the alert. If no cases exist, use the Cases page to create one first, then return to the alert.

An alert can belong to multiple cases.

### 3.16 Exporting Alerts

The **CSV** and **JSON** buttons in the top-right header export the current view — applying the active status filter, category filter, and a default 7-day lookback.

**CSV export** (`/api/export/alerts.csv`): Spreadsheet-compatible, includes all alert fields except the raw JSON payload. Suitable for reporting or importing into other tools.

**JSON export** (`/api/export/alerts.json`): Full alert records including enrichment data and notes, suitable for IR handoffs or downstream processing.

Both endpoints accept query parameters for finer control:
```
/api/export/alerts.csv?status=escalated&category=web&since=30d
```

Supported `since` values: `24h`, `7d`, `30d`.

---

## 4. Dashboard

The dashboard at `/dashboard` shows Wazuh health and alert trend charts, pulling data from Wazuh's OpenSearch directly every 5 minutes.

**Panels:**

| Panel | Description |
|---|---|
| Active Agents | Count of online / total / disconnected Wazuh agents |
| Alert Severity Over Time | Bar chart of alert volume by severity band over the last 24 hours |
| Top Agents | Horizontal bar chart of agents by alert count (last 24h) |
| MITRE ATT&CK Tactics | Doughnut chart of alert volume by MITRE tactic |
| CIS Compliance | Gauge charts showing pass / fail / error rates for CIS benchmark checks |

The dashboard reflects Wazuh's live data, not the SOCops queue. It includes alerts that may have been filtered as noise and never entered the SOCops queue. Use it for situational awareness and trend spotting; use the queue for analyst workflow.

Data auto-refreshes every 5 minutes. A "Last updated" timestamp is shown at the top.

---

## 5. Cases

Cases are named incident containers. Use them to group related alerts into a single tracked incident with its own status lifecycle.

Typical use: you notice three alerts from the same agent — a failed login, a privilege escalation, and a file added. You create a case called "Suspected credential attack on SV08", link all three alerts, and track the investigation to closure.

### 5.1 Creating a Case

Navigate to **Cases** and fill in the form on the right side of the page:

| Field | Description |
|---|---|
| **Title** | Short descriptive name for the incident (required) |
| **Severity** | 1–15 numeric severity, typically matching the highest alert |
| **Description** | Free-text investigation notes, context, or hypothesis |

Click **Create Case**. The case appears in the list with status `open`.

You can also create a case implicitly from the alert action bar by clicking **+ Case** — if no matching case exists, type a new case name in the field provided.

### 5.2 Managing Cases

The case list on the Cases page shows all cases sorted by creation date. Each case shows: title, status, severity badge, creation time, and linked alert count.

Clicking a case opens its detail view with all linked alerts listed. From the detail view you can:
- Change case status (open → in\_progress → resolved → closed)
- View all linked alerts and navigate to any of them
- Add further context in the description

**Case status lifecycle:**

| Status | Meaning |
|---|---|
| `open` | Created, not yet actively worked |
| `in_progress` | Under active investigation |
| `resolved` | Root cause identified, remediation complete |
| `closed` | Fully closed, confirmed resolved |

### 5.3 Linking Alerts to Cases

From the alert detail action bar, click **+ Case**, select the target case from the dropdown, and click **Add to Case**. The alert now appears in the case's alert list.

Alerts can belong to multiple cases. Cases can hold any number of alerts. There is no automatic linking — all case membership is analyst-controlled.

---

## 6. Suppressions

The Suppressions page at `/suppressions` manages rules that automatically suppress matching alerts at ingest time. Suppressed alerts are stored in the database but never appear in the queue. They have status `suppressed` and do not count towards new/escalated/ack statistics.

Use suppressions to eliminate known-benign noise that would otherwise generate constant false positives, obscuring real threats.

### 6.1 How Suppression Works

Every time the poller fetches a new alert from Wazuh, after storing it, SOCops evaluates all active suppression rules against the alert's fields. If any rule matches, the alert status is immediately set to `suppressed`. The hits counter on that rule is incremented.

Rules are evaluated at ingest — they do not retroactively affect alerts already in the queue. To suppress an existing backlog of known-benign alerts, use bulk-acknowledge instead.

Suppression rules with an expiry date are automatically skipped once the expiry passes (they remain visible in the list so you can decide whether to renew or delete them).

### 6.2 Creating a Suppression Rule

Navigate to **Suppressions**. The form on the right has four fields:

| Field | Options | Description |
|---|---|---|
| **Field** | `rule_id`, `agent_name`, `srcip`, `rule_description` | Which alert attribute to match against |
| **Operator** | `equals`, `contains`, `starts_with` | How to compare the value |
| **Value** | text | The value to match (case-sensitive) |
| **Reason** | text | Why this is being suppressed (audit trail — required) |
| **Expires** | date (optional) | Auto-expire the rule on this date |

**Examples:**

Suppress all systemd failure alerts from a specific agent:
- Field: `agent_name`, Operator: `equals`, Value: `SV08`
- Reason: SV08 is a test server with expected service churn

Suppress a specific noisy rule:
- Field: `rule_id`, Operator: `equals`, Value: `40704`
- Reason: Systemd exit alerts confirmed benign across all agents

Suppress a known-benign scanner IP:
- Field: `srcip`, Operator: `equals`, Value: `192.168.0.50`
- Reason: Vulnerability scanner — scheduled weekly

Suppress all VirusTotal lookup errors:
- Field: `rule_description`, Operator: `starts_with`, Value: `VirusTotal:`
- Reason: VT API rate limits generate constant noise

### 6.3 Managing Rules

The rules table shows all suppression rules with: field, operator, value, reason, hit count, creation date, and expiry.

The **hits** counter shows how many alerts have been auto-suppressed by each rule since it was created. A rule with 0 hits after a few days may indicate a typo in the value or a condition that no longer fires.

To delete a rule, click the **Delete** button on its row. Deletion takes effect immediately — subsequent matching alerts will no longer be suppressed.

### 6.4 Suppression Strategy

Good suppression is one of the highest-leverage activities in a SOC. Guidelines:

**Suppress by rule_id + agent_name together** rather than by rule_id alone when the rule is legitimately noisy only on specific hosts. This avoids suppressing real detections on other hosts that happen to fire the same rule for different reasons.

**Always set an expiry** for suppressions tied to temporary conditions (maintenance windows, test activity, pending patches). Indefinite suppressions accumulate and degrade detection coverage over time.

**Review the hits counter monthly.** Rules with very high hits (thousands per week) are prime candidates for moving from suppress to investigate — high volume on a single rule is sometimes a sign of a persistent, low-and-slow threat.

**Use the Noisy Rules table on Metrics** to identify suppression candidates before creating rules manually. Sort by total count to see what rules are generating the most volume.

---

## 7. Metrics

The Metrics page at `/metrics` provides SOC performance visibility — not for monitoring infrastructure (that is the Dashboard's job) but for monitoring the SOC workflow itself.

### 7.1 KPI Cards

Five cards across the top of the page show the most important operational numbers:

| KPI | Description | How it is calculated |
|---|---|---|
| **MTTR** | Mean Time To Respond (minutes) | Average time between alert `created_at` and `updated_at` for all resolved alerts (ack, fp, escalated) |
| **FP Rate** | False positive percentage | `fp_count / (fp + ack + escalated) × 100` |
| **24h Volume** | Alerts ingested in last 24 hours | COUNT WHERE created_at >= now - 24h |
| **Backlog Age** | Hours since oldest unreviewed alert | Hours between now and the earliest `new` alert's created_at |
| **Escalation Rate** | Percentage of closed alerts escalated | `escalated / (fp + ack + escalated) × 100` |

**Interpreting KPIs:**

A rising **Backlog Age** indicates the queue is growing faster than it is being processed — consider adding suppression rules or adjusting shift coverage.

A **FP Rate** consistently above 30–40% suggests the detection ruleset needs tuning — use the Noisy Rules table to identify candidates.

A very low **Escalation Rate** (near 0%) over time may indicate analysts are acknowledging alerts without appropriate investigation. A healthy rate varies by environment but something in the 2–10% range is typical for a well-tuned ruleset.

**MTTR** is most meaningful after the queue has been worked for several days with real acknowledgments and escalations.

### 7.2 Hourly Volume Sparkline

A bar chart showing alert ingestion count by hour over the last 24 hours. Use this to:
- Identify unexpected spikes that may indicate an incident or a noisy rule firing in bursts
- Understand your normal alert rhythm (e.g. scheduled scans, backup jobs, maintenance windows)
- Spot gaps where the poller may have been disconnected

### 7.3 Top Agents

A table of the 5 most active agents by alert count in the last 7 days. Agents generating consistently high volumes are candidates for targeted suppression or ruleset review.

### 7.4 Noisy Rules Table

All detection rules ranked by total alert count, with false positive rate per rule. Rows are color-coded:
- **Red background**: FP rate > 50% — this rule generates more false positives than true positives, suppress or tune it
- **Orange background**: FP rate 30–50% — investigate whether this rule needs scoping to specific agents or conditions

Clicking a rule description filters the alert queue to show only alerts from that rule (uses the `/api/alerts?rule_id=` filter).

### 7.5 MITRE ATT&CK Coverage

A grid of all 14 MITRE ATT&CK tactics. Each card shows:
- Tactic name
- Alert count in the last 7 days
- Top technique observed

Cards are **bright** when alerts fired in the last 7 days and **muted grey** when there is no recent coverage. Use this to understand:
- Which tactics your detection rules currently cover
- Which parts of the ATT&CK framework have blind spots in your environment
- Whether adversary activity is shifting across tactics over time

The tactics shown are: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command & Control, Exfiltration, Impact, Reconnaissance, Resource Development.

### 7.6 Detection Rule Library

A full table of all detection rules that have ever fired in your environment, showing:

| Column | Description |
|---|---|
| Rule ID | Wazuh rule identifier |
| Description | Rule description |
| Total | Total alerts fired (all time) |
| Ack | Count acknowledged |
| FP | Count marked false positive |
| Escalated | Count escalated |
| FP Rate | Percentage false positives |

Click any rule row to filter the alert queue to that rule's alerts. Use this table to build a comprehensive picture of which rules are active in your environment and how accurate they are.

---

## 8. Analyst Workflow Guide

This section describes recommended workflows for common SOC tasks using SOCops.

### 8.1 Starting a Shift

1. Open SOCops at `http://<server>:8081`.
2. Check the **header stat pills**: note the current new / escalated / ack counts.
3. Open **Metrics** and check the **Backlog Age** KPI — if backlog age is > 8 hours, the queue has accumulated overnight and needs prioritised triage.
4. Check the **Hourly Volume sparkline** for any spikes during the previous shift.
5. Return to the **Queue**, set status filter to **Escalated** — review any alerts escalated by the previous shift before clearing the new backlog.

### 8.2 Triaging the Queue

Set status filter to **New**. Work top to bottom (the list is sorted by severity descending).

**For each alert:**

1. Read the rule description and severity badge.
2. Check the agent name and MITRE tactic tag.
3. If the combination is obviously known-benign (e.g. a systemd service that always restarts): click **✗ False Positive**. Done.
4. If it requires a brief look: click the alert to load the detail panel. Read the Analysis section. If benign: click **✓ Acknowledge**. If concerning: click **↑ Escalate**.
5. If it is a recurring pattern you want to eliminate: click **⊘ Suppress** and create a rule.

**Prioritisation shortcuts using category filters:**

- Start with **Web** category + **New** status: these frequently contain active attack attempts and have the highest urgency-to-volume ratio.
- Then **CIS** + **New**: compliance state changes are time-sensitive.
- Then **Integrity** + **New**: FIM events on sensitive paths warrant review.
- Finally **Systemd** + **New**: usually highest volume, lowest signal.

### 8.3 Investigating an Alert

When an alert warrants deeper investigation:

1. **Escalate** it to move it out of the new backlog.
2. Read the full **Analysis & Remediation** section.
3. Click the **agent name chip** to open the 24h entity timeline — look for correlated activity.
4. If there is a source IP, check the **threat intel risk badge** and click the **srcip chip** to see if the IP appears in other alerts.
5. Add investigation notes as you work: type in the note field and click **Add Note**.
6. If the alert is part of a multi-alert incident, click **+ Case** to link it to an existing case or create a new one.
7. If the alert is definitively resolved, **Acknowledge** it. If it is an active incident, leave it as **Escalated** and manage it through the Cases page.

### 8.4 Escalating to an Incident

When multiple related alerts indicate a coordinated or ongoing threat:

1. Navigate to **Cases** and click **Create Case**.
2. Title the case descriptively: `Suspected lateral movement from 10.0.0.55`, `Ransomware precursor activity on SV08`, etc.
3. Set severity to match the highest alert involved.
4. Add a description summarising your current hypothesis and evidence.
5. Return to the queue and link each relevant alert to the case using the **+ Case** button.
6. Update the case status to `in_progress`.
7. Continue adding notes to individual alerts as the investigation progresses.
8. When the incident is resolved: update the case to `resolved`, acknowledge all linked alerts, and add a final closure note explaining root cause and outcome.

### 8.5 Tuning Noisy Rules

When a rule generates consistent false positives:

1. Navigate to **Metrics** → **Noisy Rules Table**.
2. Identify rules with high FP rates or high total counts.
3. Click the rule description to filter the alert queue to that rule.
4. Review 5–10 examples of the alert. Determine whether:
   - The rule fires only on specific agents → suppress by `rule_id` + `agent_name`
   - The rule always fires on benign activity regardless of agent → suppress by `rule_id` alone (use caution)
   - The rule fires on specific IP ranges → suppress by `srcip`
5. Navigate to **Suppressions** and create the appropriate rule with a clear reason.
6. Return to the queue the next day and verify hits are accumulating on the new suppression rule.

### 8.6 Ending a Shift

1. Set status filter to **New** — ensure the new count is at an acceptable level (or hand it off with a note about volume).
2. Set status filter to **Escalated** — add notes to any open escalations summarising current status so the next analyst can pick up without re-reading everything.
3. Check **Metrics** → **Backlog Age** — if rising, note it in a handoff.
4. Export current escalated alerts as CSV for shift handoff documentation: `CSV` button with status filter set to **Escalated**.

---

## 9. Notifications

SOCops can send outbound notifications for high-severity alerts and escalations.

**Triggers:**
- Any newly ingested alert with rule level ≥ `NOTIFY_LEVEL` (default: 12) triggers an automatic notification
- Any alert manually escalated via the **↑ Escalate** button triggers a notification

**Channels:**
- **Webhook**: HTTP POST to `NOTIFY_WEBHOOK` URL. Payload is JSON: `{text: "...", alert_id: N}`. Compatible with Slack incoming webhooks, ntfy.sh, and any generic webhook receiver.
- **Email**: SMTP email sent to `NOTIFY_EMAIL` via the configured SMTP server.

Both channels can be active simultaneously. If neither is configured, notifications are silently skipped.

**Notification message format:**
```
🚨 CRITICAL | Registry Key Integrity Checksum Changed
Agent: SV08 | Level: 14
Time: 2026-03-28T09:14:22.000+0100
```

The prefix emoji indicates severity: 🚨 CRITICAL (≥12), ⚠️ HIGH (≥10), 📋 ESCALATED (manual).

Configure in `.env`:
```env
NOTIFY_WEBHOOK=https://hooks.slack.com/services/xxx
NOTIFY_EMAIL=analyst@company.com
SMTP_HOST=smtp.company.com
SMTP_PORT=587
SMTP_USER=socops@company.com
SMTP_PASS=password
NOTIFY_LEVEL=12
```

---

## 10. API Reference

All endpoints return JSON unless otherwise noted. The base URL is `http://<server>:8081`.

### Alert Endpoints

| Method | Path | Parameters | Description |
|---|---|---|---|
| GET | `/api/alerts` | `status`, `category`, `group_key`, `rule_id`, `since` | List alerts (max 300) |
| GET | `/api/alerts/<id>` | — | Single alert with analysis, enrichment, raw event |
| POST | `/api/alerts/<id>/action` | `{action, notes, assigned_to}` | Update alert status/notes/assignment |
| GET | `/api/alerts/<id>/notes` | — | Alert notes thread |
| POST | `/api/alerts/<id>/notes` | `{body}` | Add note |
| GET | `/api/stats` | — | Queue statistics (counts by status) |
| GET | `/api/groups` | `status`, `category` | Grouped alert view |

**`/api/alerts` parameters:**

| Parameter | Values | Default |
|---|---|---|
| `status` | `all`, `new`, `escalated`, `ack`, `fp` | `all` |
| `category` | `all`, `systemd`, `integrity`, `cis`, `web`, `windows` | `all` |
| `group_key` | `<agent>::<rule_id>` string | — |
| `rule_id` | Wazuh rule ID | — |
| `since` | `24h`, `7d`, `30d` | — |

**`/api/alerts/<id>/action` body:**

| Field | Values | Description |
|---|---|---|
| `action` | `ack`, `escalate`, `fp`, `new` | New status (optional if only updating notes) |
| `notes` | string | Replace operator notes (optional) |
| `assigned_to` | string | Analyst name (optional) |

### Case Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/cases` | List all cases with alert counts |
| POST | `/api/cases` | Create case: `{title, severity, description}` |
| GET | `/api/cases/<id>` | Case detail + linked alerts |
| POST | `/api/cases/<id>/alerts` | Link alert: `{alert_id}` |
| POST | `/api/cases/<id>/action` | Update status: `{status}` |

### Suppression Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/suppressions` | List all suppression rules |
| POST | `/api/suppressions` | Create rule: `{field, operator, value, reason, expires_at}` |
| DELETE | `/api/suppressions/<id>` | Delete rule |

### Analytics Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/kpis` | MTTR, FP rate, volume, top agents, top rules, hourly data |
| GET | `/api/mitre` | MITRE tactic coverage (last 7d) |
| GET | `/api/rules` | Detection rule stats (all rules) |
| GET | `/api/timeline` | Entity timeline: `?agent=<name>` or `?ip=<ip>&hours=24` |
| GET | `/api/enrich/<ip>` | On-demand IP threat intel lookup |
| GET | `/api/data` | Dashboard chart data (Wazuh, 5-min cache) |

### Export Endpoints

| Method | Path | Parameters | Description |
|---|---|---|---|
| GET | `/api/export/alerts.csv` | `status`, `category`, `since` | CSV export |
| GET | `/api/export/alerts.json` | `status`, `category`, `since` | JSON export |

**Export examples:**

```bash
# All escalated alerts from the last 30 days as CSV
curl "http://server:8081/api/export/alerts.csv?status=escalated&since=30d" -o escalated.csv

# All web alerts from the last 24 hours as JSON
curl "http://server:8081/api/export/alerts.json?category=web&since=24h" -o web_alerts.json
```

---

*SOCops is built on Wazuh, Claude (Anthropic), AlienVault OTX, and AbuseIPDB.*
