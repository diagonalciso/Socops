#!/usr/bin/env python3
"""
Alert analysis engine.

Dispatch order: Ollama (local) → OpenRouter (free) → rule-based stub.
"""

import collections
import json
import os
import time
import threading
import urllib.request
import urllib.error
import db

OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
OLLAMA_BASE_URL    = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL       = os.environ.get("OLLAMA_MODEL", "")

# Preferred free models in priority order — overridden dynamically at runtime
_PREFERRED_FREE = [
    "google/gemma-3-12b-it:free",
    "google/gemma-3-27b-it:free",
    "meta-llama/llama-3.3-70b-instruct:free",
    "mistralai/mistral-small-3.1-24b-instruct:free",
    "qwen/qwen3-4b:free",
    "nvidia/nemotron-nano-9b-v2:free",
]

_openrouter_model_cache = None   # resolved at first call
_ollama_model_cache = None       # resolved at first call
_openrouter_rate_reset = None    # epoch ms — don't retry OpenRouter before this

def _load_rate_reset():
    global _openrouter_rate_reset
    val = db.get_setting("openrouter_rate_reset", None)
    if val:
        _openrouter_rate_reset = int(val)

def _save_rate_reset(val):
    global _openrouter_rate_reset
    _openrouter_rate_reset = val
    db.set_setting("openrouter_rate_reset", str(val))

def _next_openrouter_retry():
    """Return epoch-ms for 00:05 UTC the following day (OpenRouter daily quota resets at midnight UTC)."""
    import calendar
    now = time.gmtime()
    # Next midnight UTC + 5 minutes
    next_midnight = calendar.timegm((now.tm_year, now.tm_mon, now.tm_mday + 1, 0, 5, 0, 0, 0, 0))
    return next_midnight * 1000

# Live feed — last 100 analysis interactions, newest first
_LIVE_FEED      = collections.deque(maxlen=100)
_live_seq       = 0
_live_seq_lock  = threading.Lock()

_load_rate_reset()

def _live_entry(alert, engine, model):
    """Create a new live-feed entry in 'analyzing' state and return it."""
    global _live_seq
    with _live_seq_lock:
        _live_seq += 1
        seq = _live_seq
    entry = {
        "seq":        seq,
        "ts":         time.strftime("%H:%M:%S", time.localtime()),
        "alert_id":   alert.get("id"),
        "agent":      alert.get("agent_name", "?"),
        "level":      alert.get("rule_level", 0),
        "rule_id":    alert.get("rule_id", ""),
        "rule":       alert.get("rule_description", "")[:90],
        "engine":     engine,
        "model":      model,
        "status":     "analyzing",
        "response":   "",
        "duration_ms": None,
    }
    _LIVE_FEED.appendleft(entry)
    return entry


def _resolve_ollama_model():
    """Return the configured Ollama model, or auto-detect the first available one."""
    global _ollama_model_cache
    if _ollama_model_cache:
        return _ollama_model_cache
    if OLLAMA_MODEL:
        _ollama_model_cache = OLLAMA_MODEL
        return _ollama_model_cache
    try:
        req = urllib.request.Request(f"{OLLAMA_BASE_URL}/api/tags")
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
        models = [m["name"] for m in data.get("models", [])]
        if models:
            _ollama_model_cache = models[0]
            return _ollama_model_cache
    except Exception:
        pass
    return None


def analyze_with_ollama(alert):
    """Analysis via local Ollama (OpenAI-compatible endpoint)."""
    global _ollama_model_cache
    model = _resolve_ollama_model()
    if not model:
        return None  # signal: Ollama unavailable, fall through to next engine

    level = alert.get("rule_level", 0)
    severity_label, _, _ = _level_info(level)

    system = (
        "You are a concise, expert SOC analyst assistant specializing in Wazuh SIEM and Sophos Central EDR alerts. "
        "You understand Windows Event IDs, Sysmon, MITRE ATT&CK, Sophos threat detections, "
        "Sophos clean-up actions, and Linux syscheck/FIM events. "
        "Produce actionable, structured guidance for a Tier-1 analyst. "
        "Use plain language. No filler. Assume a competent operator. "
        "When analyzing Sophos Central events, reference the specific threat name, detection type, "
        "and whether Sophos already took action (cleaned/quarantined) to calibrate urgency."
    )
    user = f"""Analyze this Wazuh security alert:

Agent:           {alert.get('agent_name', 'unknown')} ({alert.get('agent_ip', 'N/A')})
Rule:            {alert.get('rule_description', 'N/A')} (level {level} — {severity_label})
Groups:          {alert.get('rule_groups', '[]')}
MITRE technique: {alert.get('mitre_technique') or 'N/A'}
MITRE tactic:    {alert.get('mitre_tactic') or 'N/A'}
Source IP:       {alert.get('srcip') or 'N/A'}
Timestamp:       {alert.get('timestamp', 'N/A')}
{_build_event_context(alert)}
Respond with exactly these sections (markdown):

### What happened
2–3 sentences, plain language.

### Severity context
Why this level matters. False positive likelihood (low/medium/high) with one-sentence rationale.

### Immediate actions
Numbered concrete steps for the operator, highest priority first.

### Escalation trigger
One sentence: the specific condition under which this should go to Tier 2.
"""
    payload = json.dumps({
        "model": model,
        "max_tokens": 700,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
    }).encode()

    req = urllib.request.Request(
        f"{OLLAMA_BASE_URL}/v1/chat/completions",
        data=payload, method="POST",
        headers={"Content-Type": "application/json"},
    )
    entry = _live_entry(alert, "ollama", model)
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            resp = json.loads(r.read())
        if "error" in resp:
            _ollama_model_cache = None
            entry["status"] = "error"
            entry["response"] = str(resp.get("error", "unknown error"))
            entry["duration_ms"] = int((time.monotonic() - t0) * 1000)
            return None
        text = resp["choices"][0]["message"]["content"]
        entry["status"]      = "done"
        entry["response"]    = text
        entry["duration_ms"] = int((time.monotonic() - t0) * 1000)
        return text
    except Exception as e:
        _ollama_model_cache = None
        entry["status"]      = "error"
        entry["response"]    = str(e)
        entry["duration_ms"] = int((time.monotonic() - t0) * 1000)
        return None


def _resolve_openrouter_model():
    """Pick the first preferred free model that OpenRouter currently lists."""
    global _openrouter_model_cache
    if _openrouter_model_cache:
        return _openrouter_model_cache
    try:
        req = urllib.request.Request(
            "https://openrouter.ai/api/v1/models",
            headers={"Authorization": f"Bearer {OPENROUTER_API_KEY}"},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        available = {m["id"] for m in data.get("data", []) if ":free" in m["id"]}
        for model in _PREFERRED_FREE:
            if model in available:
                _openrouter_model_cache = model
                return model
        # fallback: first available free model alphabetically
        free = sorted(available)
        if free:
            _openrouter_model_cache = free[0]
            return _openrouter_model_cache
    except Exception:
        pass
    # last resort hardcoded fallback
    _openrouter_model_cache = _PREFERRED_FREE[0]
    return _openrouter_model_cache

# ---------------------------------------------------------------------------
# Rule-based knowledge base
# ---------------------------------------------------------------------------

TACTIC_REMEDIATION = {
    "initial-access": [
        "Verify the source IP against threat intel feeds (VirusTotal, AbuseIPDB).",
        "Check firewall and perimeter logs for additional anomalous access attempts from the same IP.",
        "Review authentication logs to determine if the access attempt succeeded.",
        "Consider blocking the source IP at the perimeter firewall if confirmed malicious.",
    ],
    "execution": [
        "Capture the full process tree (parent → child chain) for the involved process.",
        "Review command-line arguments for LOLBin abuse (e.g., PowerShell, certutil, wscript).",
        "Verify the binary's digital signature and check against known-good hashes.",
        "Isolate the endpoint immediately if malicious payload execution is confirmed.",
    ],
    "persistence": [
        "Audit startup mechanisms: cron jobs, systemd units, registry run keys, scheduled tasks, init.d scripts.",
        "Check for newly created or modified user accounts and SSH authorized_keys.",
        "Scan for new or modified services, kernel modules, or DLLs in system directories.",
        "Compare the current configuration against a known-good baseline snapshot.",
    ],
    "privilege-escalation": [
        "Review the sudo log for the full command, calling user, and target user.",
        "Check for recently added or modified SUID/SGID binaries (find / -perm /6000 -newer /tmp/ref).",
        "Audit recent changes to /etc/sudoers, /etc/passwd, and PAM configuration.",
        "Verify the operation was authorized by checking change management records.",
    ],
    "defense-evasion": [
        "Check for log tampering: missing entries, cleared Windows Event Log, or rotated syslog.",
        "Look for disabled or uninstalled security tools (AV, EDR, Wazuh agent).",
        "Inspect for process injection indicators: hollow processes, unsigned memory regions.",
        "Compare active security tool configuration against the approved baseline.",
    ],
    "credential-access": [
        "Force a password reset for all accounts that may have been exposed.",
        "Enable or enforce MFA on affected accounts and services immediately.",
        "Search for lateral movement attempts using the potentially harvested credentials.",
        "Review LSASS access logs, SAM database read attempts, or /etc/shadow access.",
    ],
    "discovery": [
        "Identify exactly what assets, network ranges, or data were enumerated.",
        "Correlate with other alert types for signs of follow-on attack stages.",
        "Verify whether the activity was authorized (pen test, vulnerability scan, IT inventory).",
        "If unauthorized, treat as active intrusion — escalate to Tier 2 immediately.",
    ],
    "lateral-movement": [
        "Isolate affected systems immediately to prevent further spread.",
        "Review SMB, RDP, SSH, and WMI connection logs across all potentially reached hosts.",
        "Check for new scheduled tasks, services, or user accounts on remote systems.",
        "Map all systems the source account has authenticated to in the last 24 hours.",
    ],
    "collection": [
        "Identify the specific files or data stores that were accessed or staged.",
        "Check for staging directories (large compressed archives in temp folders).",
        "Review DLP and proxy alerts for outbound data movement.",
        "Preserve file access audit logs as forensic evidence before any remediation.",
    ],
    "command-and-control": [
        "Block the identified C2 IP/domain at the perimeter firewall and DNS resolver immediately.",
        "Isolate the affected endpoint to stop ongoing beaconing.",
        "Check for persistence mechanisms that would survive a reboot.",
        "Review DNS query logs for other hosts resolving the same C2 domain or IP.",
    ],
    "exfiltration": [
        "Quantify the data that left the network: volume, type, destination.",
        "Block the destination IP/domain at the firewall.",
        "Preserve full forensic evidence before taking any remediation action.",
        "Initiate incident response and, if applicable, breach notification procedures.",
    ],
    "impact": [
        "Isolate affected systems immediately to limit the blast radius.",
        "Initiate the full incident response procedure and notify management.",
        "Verify backup integrity and begin preparation for restoration if needed.",
        "Engage legal, compliance, and communications teams as appropriate.",
    ],
    "reconnaissance": [
        "Verify whether the scanning activity is from an authorized source (pen test, scanner).",
        "If unauthorized, document the source IP and block at the perimeter.",
        "Review what services and ports were probed to assess exposure.",
        "Correlate with other alerts — reconnaissance often precedes an attack by minutes to days.",
    ],
    "resource-development": [
        "Verify the activity is not from an authorized internal test or research task.",
        "Monitor closely for follow-on attack stages using the developed resources.",
        "Feed any identified IOCs into the threat intel platform for enrichment.",
    ],
}

GROUP_CONTEXT = {
    "syscheck":               "File Integrity Monitoring detected a change to a monitored file or directory.",
    "sudo":                   "A privilege escalation via sudo was detected.",
    "authentication_failed":  "Authentication failure — possible brute force, credential stuffing, or misconfiguration.",
    "authentication_success": "Authentication success in an elevated or unusual context.",
    "web":                    "Web application activity detected — review the URL and user-agent.",
    "attack":                 "Wazuh matched an active attack signature.",
    "exploit":                "Exploit attempt detected against a service or application.",
    "windows":                "Windows security event — review the full event data.",
    "vulnerability-detector": "Vulnerability scanner result — assess patch priority.",
    "sca":                    "CIS Security Configuration Assessment check result.",
    "rootcheck":              "Rootkit or anomalous system configuration detected.",
    "audit":                  "Linux audit subsystem event — possible policy violation.",
    "network":                "Network-level anomaly or connection to suspicious host.",
}

LEVEL_CONTEXT = {
    (12, 15): ("Critical", "Immediate action required — likely active threat or serious policy violation.", "immediately"),
    (10, 11): ("High",     "High-severity event requiring investigation within 1 hour.", "within 1 hour"),
    (7,  9):  ("Medium",   "Investigate within 4 hours — may indicate an early-stage attack.", "within 4 hours"),
    (5,  6):  ("Low",      "Review during daily triage — low-impact or early-warning indicator.", "during daily review"),
}


def _build_event_context(alert):
    """Extract key fields from full_json to enrich the analyst prompt."""
    raw_str = alert.get("full_json") or alert.get("_raw") or ""
    if not raw_str:
        return ""
    try:
        raw = json.loads(raw_str) if isinstance(raw_str, str) else raw_str
    except Exception:
        return ""

    lines = []
    data = raw.get("data", {})
    win  = data.get("win", {})

    # Windows event fields
    winsys = win.get("system", {})
    winevt = win.get("eventdata", {})
    if winsys.get("eventID"):
        lines.append(f"Event ID:    {winsys['eventID']}")
    if winsys.get("providerName"):
        lines.append(f"Provider:    {winsys['providerName']}")
    if winsys.get("channel"):
        lines.append(f"Channel:     {winsys['channel']}")
    if winsys.get("severityValue"):
        lines.append(f"Win severity:{winsys['severityValue']}")
    msg = winsys.get("message", "").strip().strip('"')
    if msg:
        lines.append(f"Message:     {msg[:400]}")
    for k, v in winevt.items():
        if v:
            lines.append(f"{k}:  {v}")

    # Syscheck (FIM)
    syscheck = raw.get("syscheck", {})
    if syscheck.get("path"):
        lines.append(f"FIM path:    {syscheck['path']}")
    if syscheck.get("event"):
        lines.append(f"FIM event:   {syscheck['event']}")
    if syscheck.get("md5") or syscheck.get("sha256"):
        lines.append(f"Hash:        {syscheck.get('sha256') or syscheck.get('md5')}")

    # Sophos Central fields (via Wazuh decoder or direct integration)
    # Handles both flat and nested structures depending on decoder version
    sophos = data.get("sophos", data if data.get("type", "").startswith("Event::") else {})
    if sophos.get("type"):
        lines.append(f"Sophos type:     {sophos['type']}")
    threat = sophos.get("name") or sophos.get("threat") or data.get("threat")
    if threat:
        lines.append(f"Threat name:     {threat}")
    if sophos.get("severity"):
        lines.append(f"Sophos severity: {sophos['severity']}")
    if sophos.get("category"):
        lines.append(f"Category:        {sophos['category']}")
    location = sophos.get("location") or data.get("location")
    if location:
        lines.append(f"File location:   {location[:300]}")
    clean_action = sophos.get("cleanUpAction") or data.get("cleanUpAction")
    if clean_action:
        lines.append(f"Action taken:    {clean_action}")
    detection = sophos.get("detectionIdentity") or {}
    if isinstance(detection, dict) and detection.get("name"):
        lines.append(f"Detection:       {detection['name']}")
    elif isinstance(detection, str) and detection:
        lines.append(f"Detection:       {detection}")
    for field in ("username", "endpoint_hostname", "endpoint_id"):
        val = sophos.get(field) or data.get(field)
        if val:
            lines.append(f"{field}:  {val}")
    if sophos.get("description") and not winsys.get("message"):
        lines.append(f"Description:     {str(sophos['description'])[:300]}")

    # Dpkg fields
    for field in ("dpkg_status", "package", "arch", "version"):
        val = data.get(field)
        if val:
            lines.append(f"{field}:  {str(val)[:200]}")

    # SCA (Security Configuration Assessment) fields
    sca = data.get("sca", {})
    if isinstance(sca, dict):
        if sca.get("policy_id"):
            lines.append(f"SCA policy:  {sca['policy_id']}")
        if sca.get("file"):
            lines.append(f"SCA file:    {sca['file']}")
        if sca.get("score"):
            lines.append(f"SCA score:   {sca['score']}% ({sca.get('total_checks','?')} checks)")
        check = sca.get("check", {})
        if isinstance(check, dict):
            if check.get("title"):
                lines.append(f"SCA check:   {check['title']}")
            if check.get("result"):
                lines.append(f"SCA result:  {check['result']}")
            if check.get("remediation"):
                lines.append(f"Remediation: {str(check['remediation'])[:400]}")

    # Network / generic data fields
    for field in ("srcip", "dstip", "srcport", "dstport", "proto",
                  "srcuser", "dstuser", "command", "url", "protocol", "id"):
        val = data.get(field)
        if val:
            lines.append(f"{field}:  {str(val)[:200]}")

    # full_log lives at the root level (not inside data)
    full_log = raw.get("full_log", "").strip()
    if full_log:
        lines.append(f"full_log:  {full_log[:400]}")

    # log source location (journald, syslog path, etc.)
    log_location = raw.get("location", "")
    if log_location and log_location not in ("syscheck", "sca"):
        lines.append(f"log_source:  {log_location}")

    if not lines:
        return ""
    return "\nRaw event context:\n" + "\n".join(lines)


def _level_info(level):
    for (lo, hi), info in LEVEL_CONTEXT.items():
        if lo <= level <= hi:
            return info
    return ("Info", "Informational event.", "during weekly review")


# ---------------------------------------------------------------------------
# Analysis engines
# ---------------------------------------------------------------------------

def analyze_stub(alert):
    """
    Rule-based analysis. Runs when no OPENROUTER_API_KEY is configured.
    Still produces useful, actionable guidance.
    """
    level = alert.get("rule_level", 0)
    desc = alert.get("rule_description", "")
    groups = json.loads(alert.get("rule_groups") or "[]")
    mitre_tech = alert.get("mitre_technique", "")
    mitre_tactic = (alert.get("mitre_tactic") or "").lower().replace(" ", "-")
    agent = alert.get("agent_name", "unknown")
    agent_ip = alert.get("agent_ip", "")
    srcip = alert.get("srcip", "")

    severity_label, severity_ctx, sla = _level_info(level)

    # What happened
    group_ctx = ""
    for g in groups:
        if g in GROUP_CONTEXT:
            group_ctx = GROUP_CONTEXT[g]
            break

    what_parts = [f"**{severity_label}** (level {level}) event on agent **{agent}**"]
    if agent_ip:
        what_parts[0] += f" ({agent_ip})"
    what_parts[0] += f": {desc}."
    if group_ctx:
        what_parts.append(group_ctx)
    if srcip:
        what_parts.append(f"Source IP: `{srcip}`.")
    if mitre_tech:
        what_parts.append(f"MITRE ATT&CK technique(s): **{mitre_tech}**.")
    what = " ".join(what_parts)

    # Remediation: MITRE tactic first, then group fallback
    remediation = TACTIC_REMEDIATION.get(mitre_tactic, [])
    if not remediation:
        fallback_map = {
            "syscheck":              "persistence",
            "rootcheck":             "defense-evasion",
            "authentication_failed": "credential-access",
            "sudo":                  "privilege-escalation",
            "web":                   "initial-access",
            "exploit":               "execution",
        }
        for g in groups:
            tactic = fallback_map.get(g)
            if tactic:
                remediation = TACTIC_REMEDIATION[tactic]
                break

    if not remediation:
        remediation = [
            "Review the full alert context and raw event data below.",
            "Check agent logs for correlated events in the same time window.",
            "Determine whether the activity was authorized or expected.",
            "Escalate to Tier 2 if the activity cannot be readily explained.",
        ]

    lines = [
        f"### What happened",
        what,
        "",
        f"### Severity context",
        f"{severity_ctx} **Investigate {sla}.**",
        "",
        f"### Remediation steps",
    ]
    for i, step in enumerate(remediation, 1):
        lines.append(f"{i}. {step}")
    lines.append("")
    lines.append(
        "*AI-assisted analysis unavailable — set `OPENROUTER_API_KEY` "
        "in the environment to enable AI-powered investigation guidance.*"
    )

    return "\n".join(lines)



def analyze_with_openrouter(alert):
    """Analysis via OpenRouter (OpenAI-compatible). Used when OPENROUTER_API_KEY is set."""
    level = alert.get("rule_level", 0)
    severity_label, _, _ = _level_info(level)

    system = (
        "You are a concise, expert SOC analyst assistant specializing in Wazuh SIEM and Sophos Central EDR alerts. "
        "You understand Windows Event IDs, Sysmon, MITRE ATT&CK, Sophos threat detections, "
        "Sophos clean-up actions, and Linux syscheck/FIM events. "
        "Produce actionable, structured guidance for a Tier-1 analyst. "
        "Use plain language. No filler. Assume a competent operator. "
        "When analyzing Sophos Central events, reference the specific threat name, detection type, "
        "and whether Sophos already took action (cleaned/quarantined) to calibrate urgency."
    )

    user = f"""Analyze this Wazuh security alert:

Agent:           {alert.get('agent_name', 'unknown')} ({alert.get('agent_ip', 'N/A')})
Rule:            {alert.get('rule_description', 'N/A')} (level {level} — {severity_label})
Groups:          {alert.get('rule_groups', '[]')}
MITRE technique: {alert.get('mitre_technique') or 'N/A'}
MITRE tactic:    {alert.get('mitre_tactic') or 'N/A'}
Source IP:       {alert.get('srcip') or 'N/A'}
Timestamp:       {alert.get('timestamp', 'N/A')}
{_build_event_context(alert)}
Respond with exactly these sections (markdown):

### What happened
2–3 sentences, plain language.

### Severity context
Why this level matters. False positive likelihood (low/medium/high) with one-sentence rationale.

### Immediate actions
Numbered concrete steps for the operator, highest priority first.

### Escalation trigger
One sentence: the specific condition under which this should go to Tier 2.
"""

    model = _resolve_openrouter_model()
    payload = json.dumps({
        "model": model,
        "max_tokens": 700,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
    }).encode()

    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=payload, method="POST",
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        }
    )
    global _openrouter_model_cache, _openrouter_rate_reset
    entry = _live_entry(alert, "openrouter", model)
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            resp = json.loads(r.read())
        if "error" in resp:
            code = resp["error"].get("code", 0)
            msg  = resp["error"].get("message", "")
            if code in (502, 503):
                _openrouter_model_cache = None
            if code == 429:
                meta = resp["error"].get("metadata", {})
                hdrs = meta.get("headers", {})
                reset = hdrs.get("X-RateLimit-Reset")
                _save_rate_reset(int(reset) if reset else _next_openrouter_retry())
            entry["status"]      = "error"
            entry["response"]    = f"error {code}: {msg[:200]}"
            entry["duration_ms"] = int((time.monotonic() - t0) * 1000)
            return analyze_stub(alert) + f"\n\n*(OpenRouter [{model}] error {code}: {msg[:200]})*"
        text = resp["choices"][0]["message"]["content"]
        entry["status"]      = "done"
        entry["response"]    = text
        entry["duration_ms"] = int((time.monotonic() - t0) * 1000)
        return text
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="replace")
        if e.code in (502, 503):
            _openrouter_model_cache = None
        if e.code == 429:
            _save_rate_reset(_next_openrouter_retry())
        entry["status"]      = "error"
        entry["response"]    = f"HTTP {e.code}: {error_body[:200]}"
        entry["duration_ms"] = int((time.monotonic() - t0) * 1000)
        return analyze_stub(alert) + f"\n\n*(OpenRouter [{model}] error {e.code}: {error_body[:200]})*"
    except Exception as e:
        entry["status"]      = "error"
        entry["response"]    = str(e)
        entry["duration_ms"] = int((time.monotonic() - t0) * 1000)
        return analyze_stub(alert) + f"\n\n*(OpenRouter [{model}] error: {e})*"


def analyze(alert):
    """Dispatch: level <=7 → Ollama only; level >7 → OpenRouter → Ollama → stub."""
    level = alert.get("rule_level", 0)
    if level <= 7:
        result = analyze_with_ollama(alert)
        if result:
            return result
        return analyze_stub(alert)
    if OPENROUTER_API_KEY:
        rate_limited = (_openrouter_rate_reset is not None and
                        time.time() * 1000 < _openrouter_rate_reset)
        if not rate_limited:
            result = analyze_with_openrouter(alert)
            if result and "AI-assisted analysis unavailable" not in result:
                return result
    result = analyze_with_ollama(alert)
    if result:
        return result
    return analyze_stub(alert)
