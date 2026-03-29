#!/usr/bin/env python3
"""SOCops — AI-assisted SOC workbench for Wazuh.  Port 8081."""

import collections
import csv
import http.server
import io
import json
import os
import re
import subprocess
import threading
import time
from datetime import datetime, timezone, timedelta

# Load .env if present
_env_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), ".env")
if os.path.exists(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _, _v = _line.partition("=")
                os.environ.setdefault(_k.strip(), _v.strip())

import analyst
import db
import enrichment
import notifier
from wazuh import WazuhClient

SOCOPS_PORT    = int(os.environ.get("SOCOPS_PORT", "8081"))
POLL_INTERVAL  = int(os.environ.get("POLL_INTERVAL", "60"))
INITIAL_WINDOW = os.environ.get("INITIAL_WINDOW", "now-24h")

wazuh = WazuhClient()

# ---------------------------------------------------------------------------
# System metrics ring buffer  (120 samples × 5s = 10 min of history)
# ---------------------------------------------------------------------------

try:
    import psutil as _psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

_SYS_HISTORY = collections.deque(maxlen=120)  # thread-safe appends
_SYS_LOCK    = threading.Lock()

def _collect_sys():
    """Return one system snapshot dict."""
    ts = datetime.now(timezone.utc).isoformat()

    # CPU
    cpu = _psutil.cpu_percent(interval=None) if _PSUTIL else 0.0

    # Memory
    if _PSUTIL:
        m = _psutil.virtual_memory()
        s = _psutil.swap_memory()
        mem_pct  = m.percent
        mem_used = round(m.used  / 1024**3, 2)
        mem_total= round(m.total / 1024**3, 2)
        swp_pct  = s.percent
        swp_used = round(s.used  / 1024**3, 2)
        swp_total= round(s.total / 1024**3, 2)
    else:
        mem_pct = mem_used = mem_total = swp_pct = swp_used = swp_total = 0

    # GPU via nvidia-smi (non-blocking)
    gpu_util = gpu_mem_pct = gpu_mem_used = gpu_mem_total = gpu_temp = None
    try:
        r = subprocess.run(
            ["nvidia-smi", "--query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=3
        )
        if r.returncode == 0 and r.stdout.strip():
            parts = [p.strip() for p in r.stdout.strip().split(",")]
            gpu_util      = float(parts[0])
            gpu_mem_used  = round(float(parts[1]) / 1024, 2)   # MiB → GiB
            gpu_mem_total = round(float(parts[2]) / 1024, 2)
            gpu_mem_pct   = round(gpu_mem_used / gpu_mem_total * 100, 1) if gpu_mem_total else 0
            gpu_temp      = float(parts[3])
    except Exception:
        pass

    return {
        "ts": ts,
        "cpu": cpu,
        "mem_pct": mem_pct, "mem_used": mem_used, "mem_total": mem_total,
        "swp_pct": swp_pct, "swp_used": swp_used, "swp_total": swp_total,
        "gpu_util": gpu_util, "gpu_mem_pct": gpu_mem_pct,
        "gpu_mem_used": gpu_mem_used, "gpu_mem_total": gpu_mem_total,
        "gpu_temp": gpu_temp,
    }

def _sys_collector():
    # Prime psutil cpu_percent baseline (first call always returns 0)
    if _PSUTIL:
        _psutil.cpu_percent(interval=None)
    while True:
        try:
            snap = _collect_sys()
            _SYS_HISTORY.append(snap)
        except Exception:
            pass
        time.sleep(5)

# ---------------------------------------------------------------------------
# Background threads
# ---------------------------------------------------------------------------

def _poller():
    print("[poller] starting")
    while True:
        try:
            since = db.get_setting("last_poll_ts", INITIAL_WINDOW)
            hits = wazuh.fetch_new_alerts(since)
            new_count = 0
            latest_ts = None
            for hit in hits:
                if db.save_alert(hit):
                    new_count += 1
                    # notify high-severity
                    try:
                        src = hit.get("_source", {})
                        rule = src.get("rule", {})
                        alert_dict = {
                            "rule_level": int(rule.get("level", 0)),
                            "rule_description": rule.get("description", ""),
                            "agent_name": src.get("agent", {}).get("name", ""),
                            "timestamp": src.get("timestamp", ""),
                        }
                        notifier.notify_alert(alert_dict)
                    except Exception:
                        pass
                ts = hit.get("_source", {}).get("timestamp")
                if ts and (latest_ts is None or ts > latest_ts):
                    latest_ts = ts
            if latest_ts:
                db.set_setting("last_poll_ts", latest_ts)
            db.set_setting("last_poll_time", datetime.now(timezone.utc).isoformat())
            if new_count:
                print(f"[poller] +{new_count} alerts (latest ts: {latest_ts})")
        except Exception as e:
            print(f"[poller] error: {e}")
        time.sleep(POLL_INTERVAL)


def _analyst_worker():
    OPENROUTER_DELAY = 3   # rate limit: 20 req/min on free tier
    OLLAMA_DELAY     = 2   # no rate limit, but pace to keep system load low
    print("[analyst] starting")
    time.sleep(5)
    while True:
        try:
            priority_only = db.get_setting("analyst_priority_only", "0") == "1"
            pending = db.get_unanalyzed(limit=1, min_level=10 if priority_only else 0)
            for alert in pending:
                if db.is_analysis_excluded(alert.get("rule_id",""), alert.get("agent_name","")):
                    db.update_alert(alert["id"], analysis="[excluded]")
                    continue
                try:
                    analysis_text = analyst.analyze(alert)
                    db.update_alert(alert["id"], analysis=analysis_text)
                except Exception as e:
                    db.update_alert(alert["id"], analysis=f"Analysis error: {e}")
                delay = OPENROUTER_DELAY if analyst._openrouter_model_cache and not analyst._ollama_model_cache else OLLAMA_DELAY
                time.sleep(delay)
            if not pending:
                time.sleep(10)
        except Exception as e:
            print(f"[analyst] error: {e}")
            time.sleep(10)


def _enrichment_worker():
    print("[enrichment] starting")
    time.sleep(15)
    while True:
        try:
            pending = db.get_ips_needing_enrichment(limit=20)
            for row in pending:
                ip = row.get("srcip", "")
                if not ip:
                    continue
                try:
                    result = enrichment.enrich_ip(ip)
                    db.set_enrichment(row["id"], json.dumps(result))
                except Exception:
                    db.set_enrichment(row["id"], json.dumps({"error": "enrichment failed"}))
                time.sleep(1)
            if not pending:
                time.sleep(30)
        except Exception as e:
            print(f"[enrichment] error: {e}")
            time.sleep(30)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_params(query):
    from urllib.parse import unquote_plus
    return {k: unquote_plus(v) for k, v in (p.split("=", 1) for p in query.split("&") if "=" in p)}


def _since_dt(since_str):
    """Convert '7d','24h','30d' to ISO datetime string for SQL comparison."""
    if not since_str:
        return None
    m = re.match(r'^(\d+)([dh])$', since_str)
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2)
    delta = timedelta(days=n) if unit == 'd' else timedelta(hours=n)
    return (datetime.now(timezone.utc) - delta).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, content_type="application/json"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if "text/html" in content_type:
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, default=str), "application/json")

    def do_GET(self):
        path = self.path.split("?")[0]
        query = self.path[len(path)+1:] if "?" in self.path else ""
        params = _parse_params(query)

        if path == "/":
            self._send(200, QUEUE_HTML, "text/html; charset=utf-8")

        elif path == "/dashboard":
            self._send(200, DASHBOARD_HTML, "text/html; charset=utf-8")

        elif path == "/suppressions":
            self._send(200, SUPPRESSIONS_HTML, "text/html; charset=utf-8")

        elif path == "/cases":
            self._send(200, CASES_HTML, "text/html; charset=utf-8")

        elif path == "/metrics":
            self._send(200, METRICS_HTML, "text/html; charset=utf-8")

        elif path == "/system":
            self._send(200, SYSTEM_HTML, "text/html; charset=utf-8")

        elif path == "/analysis-exclusions":
            self._send(200, ANALYSIS_EXCLUSIONS_HTML, "text/html; charset=utf-8")

        elif path == "/live":
            self._send(200, LIVE_HTML, "text/html; charset=utf-8")

        elif path == "/api/alerts":
            status   = params.get("status", "all")
            category = params.get("category", None)
            group_key = params.get("group_key", None)
            rule_id   = params.get("rule_id", None)
            since     = _since_dt(params.get("since", None))
            alerts = db.get_alerts(status=status, category=category,
                                   group_key=group_key, rule_id=rule_id, since=since)
            for a in alerts:
                a.pop("full_json", None)
            self._json(200, alerts)

        elif re.match(r"^/api/alerts/\d+$", path):
            aid = int(path.split("/")[-1])
            alert = db.get_alert(aid)
            if not alert:
                self._json(404, {"error": "not found"})
                return
            try:
                alert["_raw"] = json.loads(alert.get("full_json") or "{}")
            except Exception:
                alert["_raw"] = {}
            alert.pop("full_json", None)
            # parse enrichment
            if alert.get("enrichment"):
                try:
                    alert["_enrichment"] = json.loads(alert["enrichment"])
                except Exception:
                    alert["_enrichment"] = {}
            self._json(200, alert)

        elif path == "/api/alerts/high-severity":
            since = _since_dt(params.get("since", None))
            min_level = int(params.get("min_level", "10"))
            alerts = db.get_alerts(status="new", since=since)
            result = [
                {"id": a["id"], "rule_level": a["rule_level"],
                 "rule_description": a["rule_description"],
                 "agent_name": a["agent_name"], "timestamp": a["timestamp"]}
                for a in alerts if a.get("rule_level", 0) >= min_level
            ]
            self._json(200, result)

        elif re.match(r"^/api/alerts/\d+/notes$", path):
            aid = int(path.split("/")[-2])
            self._json(200, db.get_notes(aid))

        elif path == "/api/stats":
            stats = db.get_stats()
            stats["last_poll"] = db.get_setting("last_poll_time", "never")
            ollama = analyst._ollama_model_cache
            openrouter = analyst._openrouter_model_cache
            stats["analyst_model"] = f"ollama:{ollama}" if ollama else (openrouter or "pending")
            stats["openrouter_rate_reset"] = analyst._openrouter_rate_reset
            stats["analyst_priority_only"] = db.get_setting("analyst_priority_only", "0") == "1"
            self._json(200, stats)

        elif path == "/api/data":
            try:
                data = wazuh.fetch_all()
                self._json(200, data)
            except Exception as e:
                self._json(500, {"error": str(e)})

        elif path == "/api/groups":
            status   = params.get("status", "all")
            category = params.get("category", "all")
            groups = db.get_alert_groups(
                status=status if status != "all" else None,
                category=category if category != "all" else None,
            )
            self._json(200, groups)

        elif path == "/api/suppressions":
            self._json(200, db.get_suppression_rules())

        elif path == "/api/system":
            self._json(200, list(_SYS_HISTORY))

        elif path == "/api/analysis-exclusions":
            self._json(200, db.get_analysis_exclusions())

        elif path == "/api/live":
            since = int(params.get("since", "0"))
            feed  = [e for e in analyst._LIVE_FEED if e["seq"] > since]
            self._json(200, feed)

        elif path == "/api/kpis":
            self._json(200, db.get_kpis())

        elif path == "/api/mitre":
            self._json(200, db.get_mitre_coverage())

        elif path == "/api/rules":
            self._json(200, db.get_rule_stats())

        elif path == "/api/timeline":
            agent = params.get("agent", "")
            ip    = params.get("ip", "")
            hours = int(params.get("hours", "24"))
            if agent:
                rows = db.get_entity_timeline("agent", agent, hours=hours)
            elif ip:
                rows = db.get_entity_timeline("ip", ip, hours=hours)
            else:
                rows = []
            for r in rows:
                r.pop("full_json", None)
            self._json(200, rows)

        elif re.match(r"^/api/enrich/", path):
            ip = path[len("/api/enrich/"):]
            result = enrichment.enrich_ip(ip)
            self._json(200, result)

        elif path == "/api/cases":
            self._json(200, db.get_cases())

        elif re.match(r"^/api/cases/\d+$", path):
            cid = int(path.split("/")[-1])
            case = db.get_case(cid)
            if not case:
                self._json(404, {"error": "not found"})
                return
            case_alerts = db.get_case_alerts(cid)
            for a in case_alerts:
                a.pop("full_json", None)
            case["alerts"] = case_alerts
            self._json(200, case)

        elif re.match(r"^/api/cases/\d+/alerts$", path):
            cid = int(path.split("/")[-2])
            alerts = db.get_case_alerts(cid)
            for a in alerts:
                a.pop("full_json", None)
            self._json(200, alerts)

        elif path == "/api/export/alerts.csv":
            status   = params.get("status", "all")
            category = params.get("category", None)
            since    = _since_dt(params.get("since", "7d"))
            alerts = db.get_alerts(status=status, category=category, since=since, limit=10000)
            out = io.StringIO()
            fields = ["id","wazuh_id","timestamp","agent_name","agent_ip","rule_id",
                      "rule_level","rule_description","mitre_technique","mitre_tactic",
                      "srcip","status","analysis","operator_notes","created_at","updated_at",
                      "assigned_to","group_key"]
            w = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            w.writerows(alerts)
            self._send(200, out.getvalue().encode(), "text/csv")

        elif path == "/api/export/alerts.json":
            status   = params.get("status", "all")
            category = params.get("category", None)
            since    = _since_dt(params.get("since", "7d"))
            alerts = db.get_alerts(status=status, category=category, since=since, limit=10000)
            for a in alerts:
                a.pop("full_json", None)
            self._send(200, json.dumps(alerts, default=str).encode(), "application/json")

        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")

        if re.match(r"^/api/alerts/\d+/action$", path):
            aid = int(path.split("/")[-2])
            valid_actions = {"ack", "escalate", "fp", "new"}
            action = body.get("action", "")
            notes = body.get("notes")
            assigned_to = body.get("assigned_to")

            if action and action not in valid_actions:
                self._json(400, {"error": f"invalid action '{action}'"})
                return

            db.update_alert(aid, status=action or None, notes=notes, assigned_to=assigned_to)

            # escalation notification
            if action == "escalate":
                try:
                    alert = db.get_alert(aid)
                    if alert:
                        notifier.notify_alert(alert, trigger="escalated")
                except Exception:
                    pass

            self._json(200, {"ok": True})

        elif re.match(r"^/api/alerts/\d+/analyze$", path):
            aid = int(path.split("/")[-2])
            alert = db.get_alert(aid)
            if not alert:
                self._json(404, {"error": "not found"})
                return
            try:
                text = analyst.analyze(alert)
                db.update_alert(aid, analysis=text)
                self._json(200, {"analysis": text})
            except Exception as e:
                self._json(500, {"error": str(e)})

        elif path == "/api/settings/analyst_priority":
            current = db.get_setting("analyst_priority_only", "0")
            new_val = "0" if current == "1" else "1"
            db.set_setting("analyst_priority_only", new_val)
            self._json(200, {"analyst_priority_only": new_val == "1"})

        elif re.match(r"^/api/alerts/\d+/notes$", path):
            aid = int(path.split("/")[-2])
            note_body = body.get("body", "").strip()
            if note_body:
                db.add_note(aid, note_body, auto_generated=False)
            self._json(200, {"ok": True})

        elif path == "/api/analysis-exclusions":
            rule_id    = body.get("rule_id", "").strip()
            agent_name = body.get("agent_name", "*").strip() or "*"
            reason     = body.get("reason", "")
            if not rule_id:
                self._json(400, {"error": "rule_id required"})
                return
            eid = db.add_analysis_exclusion(rule_id, agent_name, reason)
            self._json(200, {"ok": True, "id": eid})

        elif path == "/api/suppressions":
            field    = body.get("field", "")
            operator = body.get("operator", "equals")
            value    = body.get("value", "")
            reason   = body.get("reason", "")
            expires  = body.get("expires_at", None)
            if not field or not value:
                self._json(400, {"error": "field and value required"})
                return
            rid = db.add_suppression_rule(field, operator, value, reason, expires)
            self._json(200, {"ok": True, "id": rid})

        elif path == "/api/cases":
            title   = body.get("title", "Untitled Case")
            sev     = int(body.get("severity", 0))
            desc    = body.get("description", "")
            cid = db.create_case(title, sev, desc)
            self._json(200, {"ok": True, "id": cid})

        elif re.match(r"^/api/cases/\d+/alerts$", path):
            cid = int(path.split("/")[-2])
            aid = int(body.get("alert_id", 0))
            db.add_alert_to_case(cid, aid)
            self._json(200, {"ok": True})

        elif re.match(r"^/api/cases/\d+/action$", path):
            cid = int(path.split("/")[-2])
            status = body.get("status")
            title  = body.get("title")
            desc   = body.get("description")
            db.update_case(cid, status=status, title=title, description=desc)
            self._json(200, {"ok": True})

        else:
            self._json(404, {"error": "not found"})

    def do_DELETE(self):
        path = self.path.split("?")[0]
        if re.match(r"^/api/suppressions/\d+$", path):
            sid = int(path.split("/")[-1])
            db.delete_suppression_rule(sid)
            self._json(200, {"ok": True})
        elif re.match(r"^/api/analysis-exclusions/\d+$", path):
            eid = int(path.split("/")[-1])
            db.delete_analysis_exclusion(eid)
            self._json(200, {"ok": True})
        else:
            self._json(404, {"error": "not found"})


# ---------------------------------------------------------------------------
# Shared nav snippet (used in all pages)
# ---------------------------------------------------------------------------

HIGH_SEVERITY_CSS = ""  # disabled

HIGH_SEVERITY_JS = ""  # disabled

def _nav(active):
    links = [("Dashboard","/dashboard"),("Queue","/"),("Live","/live"),("Exclusions","/analysis-exclusions"),
             ("Cases","/cases"),("Suppressions","/suppressions"),("Metrics","/metrics"),("System","/system")]
    items = "".join(
        f'<a href="{u}" class="{"active" if n==active else ""}">{n}</a>'
        for n,u in links
    )
    return f'<nav>{items}</nav>'

COMMON_CSS = """
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2128;--border:#30363d;
  --text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;
  --green:#3fb950;--yellow:#d29922;--orange:#e3873a;--red:#f85149;
  --purple:#bc8cff;--critical:#ff4444;--high:#f0883e;
  --medium:#d29922;--low:#3fb950;--r:8px;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;}
header{background:#0d1117;border-bottom:1px solid var(--border);
  padding:10px 20px;display:flex;align-items:center;gap:16px;position:sticky;top:0;z-index:100;}
.logo{width:32px;height:32px;background:linear-gradient(135deg,#1a73e8,#58a6ff);
  border-radius:6px;display:flex;align-items:center;justify-content:center;
  font-weight:900;font-size:16px;color:#fff;}
.app-name{font-size:16px;font-weight:700;letter-spacing:.3px;}
.app-sub{font-size:11px;color:var(--muted);}
nav{display:flex;gap:4px;margin-left:8px;}
nav a{padding:5px 12px;border-radius:6px;color:var(--muted);text-decoration:none;font-size:13px;transition:.15s;}
nav a:hover{background:var(--surface2);color:var(--text);}
nav a.active{background:var(--surface2);color:var(--accent);border:1px solid var(--border);}
.hdr-right{margin-left:auto;display:flex;align-items:center;gap:16px;font-size:12px;color:var(--muted);}
.stat-pill{background:var(--surface2);border:1px solid var(--border);border-radius:20px;
  padding:3px 10px;display:flex;align-items:center;gap:5px;}
.stat-pill .cnt{font-weight:700;}
.stat-pill.new .cnt{color:var(--red);}
.stat-pill.esc .cnt{color:var(--orange);}
.stat-pill.ack .cnt{color:var(--green);}
.pulse{width:7px;height:7px;border-radius:50%;background:var(--green);animation:pulse 2s infinite;}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(63,185,80,.4);}70%{box-shadow:0 0 0 5px rgba(63,185,80,0);}100%{box-shadow:0 0 0 0 rgba(63,185,80,0);}}
.btn{padding:6px 14px;border-radius:6px;border:1px solid var(--border);
  font-size:13px;cursor:pointer;font-weight:500;transition:.15s;background:transparent;color:var(--text);}
.btn:hover{filter:brightness(1.1);}
.btn.ack{background:rgba(63,185,80,.15);border-color:rgba(63,185,80,.4);color:var(--green);}
.btn.esc{background:rgba(240,136,62,.15);border-color:rgba(240,136,62,.4);color:var(--orange);}
.btn.fp{background:var(--surface2);color:var(--muted);}
.btn.reopen{background:rgba(248,81,73,.1);border-color:rgba(248,81,73,.3);color:var(--red);}
.btn.save{background:var(--surface2);border-color:var(--border);color:var(--muted);font-size:12px;padding:5px 10px;}
.btn.danger{background:rgba(248,81,73,.15);border-color:rgba(248,81,73,.4);color:var(--red);}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff;}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:18px;margin-bottom:16px;}
.card-title{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;
  color:var(--muted);margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--border);}
table{width:100%;border-collapse:collapse;font-size:13px;}
th{text-align:left;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;
  color:var(--muted);padding:0 8px 8px;border-bottom:1px solid var(--border);}
td{padding:8px;border-bottom:1px solid var(--border);vertical-align:top;}
tr:last-child td{border-bottom:none;}
input,select,textarea{background:var(--surface2);border:1px solid var(--border);border-radius:6px;
  color:var(--text);font-size:13px;padding:6px 10px;outline:none;}
input:focus,select:focus,textarea:focus{border-color:var(--accent);}
.mitre-tag{background:rgba(188,140,255,.15);color:var(--purple);border-radius:4px;padding:1px 5px;font-size:10px;font-weight:600;}
.level-badge{display:inline-flex;align-items:center;justify-content:center;width:32px;height:32px;border-radius:6px;font-weight:800;font-size:13px;}
.level-badge.crit,.lvl.crit{background:rgba(255,68,68,.15);color:var(--critical);}
.level-badge.high,.lvl.high{background:rgba(240,136,62,.15);color:var(--high);}
.level-badge.med,.lvl.med{background:rgba(210,153,34,.15);color:var(--medium);}
.level-badge.low,.lvl.low{background:rgba(63,185,80,.1);color:var(--low);}
.lvl{display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:5px;font-size:11px;font-weight:700;}
.chip{background:var(--surface2);border:1px solid var(--border);border-radius:20px;padding:2px 10px;font-size:11px;color:var(--muted);}
.chip.agent{color:var(--accent);}
.chip.mitre{background:rgba(188,140,255,.1);border-color:rgba(188,140,255,.3);color:var(--purple);}
.chip.srcip{background:rgba(248,81,73,.1);border-color:rgba(248,81,73,.3);color:var(--red);}
.chip.status-new{background:rgba(248,81,73,.1);border-color:rgba(248,81,73,.3);color:var(--red);}
.chip.status-escalated{background:rgba(227,135,58,.1);border-color:rgba(227,135,58,.3);color:var(--orange);}
.chip.status-ack{background:rgba(63,185,80,.1);border-color:rgba(63,185,80,.3);color:var(--green);}
.chip.status-fp,.chip.status-suppressed{background:var(--surface2);color:var(--muted);}
.section{margin-bottom:20px;}
.section-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;
  color:var(--muted);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid var(--border);}
.spinner{width:14px;height:14px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;display:inline-block;}
@keyframes spin{to{transform:rotate(360deg);}}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:200;display:flex;align-items:center;justify-content:center;}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:24px;width:480px;max-width:95vw;max-height:90vh;overflow-y:auto;}
.modal h2{font-size:16px;font-weight:700;margin-bottom:16px;}
.form-row{margin-bottom:12px;display:flex;flex-direction:column;gap:4px;}
.form-row label{font-size:12px;color:var(--muted);font-weight:600;}
.form-row input,.form-row select,.form-row textarea{width:100%;}
.form-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:16px;}
""" + HIGH_SEVERITY_CSS

PAGE_FOOTER = """
<div id="toast" style="position:fixed;bottom:24px;right:24px;background:#238636;color:#fff;padding:10px 20px;border-radius:8px;font-size:13px;font-weight:600;z-index:9999;display:none;box-shadow:0 4px 16px rgba(0,0,0,.4)"></div>
<script>
function _toast(msg,color){
  const t=document.getElementById('toast');
  t.textContent=msg; t.style.background=color||'#238636'; t.style.display='block';
  setTimeout(()=>t.style.display='none',2500);
}
</script>
<script>""" + HIGH_SEVERITY_JS + """</script>\n</body>\n</html>"""


# ---------------------------------------------------------------------------
# Queue page
# ---------------------------------------------------------------------------

QUEUE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>SOCops — Alert Queue</title>
<style>
""" + COMMON_CSS + """
body{height:100vh;display:flex;flex-direction:column;overflow:hidden;}
.workspace{display:flex;flex:1;overflow:hidden;}
.list-pane{width:440px;flex-shrink:0;display:flex;flex-direction:column;border-right:1px solid var(--border);overflow:hidden;}
.detail-pane{flex:1;display:flex;flex-direction:column;overflow:hidden;}
.filter-bar{padding:10px 12px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:6px;flex-wrap:wrap;flex-shrink:0;}
.filter-btn{padding:4px 10px;border-radius:20px;border:1px solid var(--border);background:transparent;color:var(--muted);font-size:12px;cursor:pointer;transition:.15s;}
.filter-btn:hover{background:var(--surface2);color:var(--text);}
.filter-btn.active{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600;}
.view-toggle{display:flex;border:1px solid var(--border);border-radius:6px;overflow:hidden;}
.view-toggle button{padding:3px 10px;background:transparent;border:none;color:var(--muted);font-size:12px;cursor:pointer;}
.view-toggle button.active{background:var(--surface2);color:var(--text);}
.cat-bar{padding:6px 12px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:4px;flex-wrap:wrap;flex-shrink:0;background:var(--surface2);}
.cat-btn{padding:2px 9px;border-radius:10px;border:1px solid var(--border);background:transparent;color:var(--muted);font-size:11px;cursor:pointer;transition:.15s;}
.cat-btn:hover{background:var(--surface);color:var(--text);}
.cat-btn.active{border-color:var(--accent);color:var(--accent);background:rgba(88,166,255,.1);}
.badge{background:rgba(248,81,73,.2);color:var(--red);border-radius:10px;padding:1px 6px;font-size:10px;font-weight:700;margin-left:3px;}
.badge.esc{background:rgba(227,135,58,.15);color:var(--orange);}
.search-box{margin-left:auto;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:4px 8px;color:var(--text);font-size:12px;width:130px;outline:none;}
.search-box:focus{border-color:var(--accent);}
.alert-list{flex:1;overflow-y:auto;padding:6px;}
.alert-list::-webkit-scrollbar{width:4px;}
.alert-list::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px;}
.alert-item{display:flex;align-items:flex-start;gap:10px;padding:10px 12px;border-radius:var(--r);cursor:pointer;border:1px solid transparent;margin-bottom:4px;transition:.15s;}
.alert-item:hover{background:var(--surface2);border-color:var(--border);}
.alert-item.selected{background:var(--surface2);border-color:var(--accent);}
.alert-item.status-ack{opacity:.5;}
.alert-item.status-fp,.alert-item.status-suppressed{opacity:.4;}
.alert-info{flex:1;min-width:0;}
.alert-rule{font-size:13px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.alert-meta{font-size:11px;color:var(--muted);margin-top:2px;}
.alert-meta span{margin-right:8px;}
.ai-badge{font-size:10px;padding:1px 5px;border-radius:3px;background:#1a3a1a;color:#4caf50;font-weight:600;letter-spacing:.3px;}
.ai-badge.ai-pending{background:#2a2a1a;color:#888;}
.status-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0;display:inline-block;}
.status-dot.new{background:var(--red);}
.status-dot.escalated{background:var(--orange);}
.status-dot.ack{background:var(--green);}
.status-dot.fp,.status-dot.suppressed{background:var(--muted);}
.count-badge{background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:1px 8px;font-size:11px;font-weight:700;color:var(--text);}
.assign-badge{background:rgba(88,166,255,.15);color:var(--accent);border-radius:10px;padding:1px 6px;font-size:10px;font-weight:700;}
.detail-empty{display:flex;align-items:center;justify-content:center;height:100%;color:var(--muted);font-size:13px;flex-direction:column;gap:8px;}
.detail-scroll{flex:1;overflow-y:auto;padding:20px;}
.detail-scroll::-webkit-scrollbar{width:4px;}
.detail-scroll::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px;}
.detail-header{display:flex;align-items:flex-start;gap:12px;margin-bottom:20px;}
.detail-level{width:48px;height:48px;border-radius:8px;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:18px;}
.detail-level.crit{background:rgba(255,68,68,.15);color:var(--critical);}
.detail-level.high{background:rgba(240,136,62,.15);color:var(--high);}
.detail-level.med{background:rgba(210,153,34,.15);color:var(--medium);}
.detail-level.low{background:rgba(63,185,80,.1);color:var(--low);}
.detail-title{font-size:16px;font-weight:600;line-height:1.3;margin-bottom:6px;}
.detail-chips{display:flex;flex-wrap:wrap;gap:6px;}
.analysis-body{font-size:13px;line-height:1.7;color:#cdd9e5;}
.analysis-body h3{font-size:13px;font-weight:700;color:var(--text);margin:14px 0 6px;}
.analysis-body h3:first-child{margin-top:0;}
.analysis-body ol,.analysis-body ul{padding-left:20px;}
.analysis-body li{margin-bottom:4px;}
.analysis-body strong{color:var(--text);}
.analysis-body code{background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:1px 5px;font-family:monospace;font-size:12px;}
.analysis-body em{color:var(--muted);font-style:italic;}
.analysis-loading{color:var(--muted);font-size:13px;display:flex;align-items:center;gap:8px;}
.raw-grid{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px;font-size:12px;}
.raw-key{color:var(--muted);white-space:nowrap;}
.raw-val{color:var(--text);font-family:monospace;word-break:break-all;}
.action-bar{padding:12px 20px;border-top:1px solid var(--border);display:flex;align-items:center;gap:8px;flex-shrink:0;background:var(--surface);flex-wrap:wrap;}
.notes-thread{background:var(--surface2);border-radius:var(--r);padding:12px;max-height:200px;overflow-y:auto;font-size:12px;}
.note-item{margin-bottom:10px;padding-bottom:10px;border-bottom:1px solid var(--border);}
.note-item:last-child{border-bottom:none;margin-bottom:0;padding-bottom:0;}
.note-ts{font-size:10px;color:var(--muted);margin-bottom:3px;}
.note-body{color:var(--text);}
.note-body.auto{color:var(--muted);font-style:italic;}
.risk-badge{padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;}
.risk-badge.critical{background:rgba(255,68,68,.2);color:var(--critical);}
.risk-badge.high{background:rgba(240,136,62,.2);color:var(--high);}
.risk-badge.medium{background:rgba(210,153,34,.2);color:var(--medium);}
.risk-badge.low{background:rgba(63,185,80,.1);color:var(--low);}
.timeline-modal .tl-item{display:flex;gap:12px;padding:10px 0;border-bottom:1px solid var(--border);cursor:pointer;}
.timeline-modal .tl-item:hover{background:rgba(88,166,255,.05);}
.timeline-modal .tl-time{font-size:11px;color:var(--muted);width:80px;flex-shrink:0;}
</style>
</head>
<body>
<header>
  <div class="logo">S</div>
  <div><div class="app-name">SOCops</div><div class="app-sub">Security Operations Center</div></div>
  """ + _nav("Queue") + """
  <div class="hdr-right">
    <div class="stat-pill new"><span id="stat-new" class="cnt">-</span> new</div>
    <div class="stat-pill esc"><span id="stat-esc" class="cnt">-</span> esc</div>
    <div class="stat-pill ack"><span id="stat-ack" class="cnt">-</span> ack</div>
    <div style="display:flex;align-items:center;gap:5px;"><div class="pulse"></div><span id="last-poll">loading…</span></div>
    <div style="display:flex;gap:6px;">
      <button class="btn save" onclick="exportAlerts('csv')" title="Export CSV">CSV</button>
      <button class="btn save" onclick="exportAlerts('json')" title="Export JSON">JSON</button>
      <button id="btn-priority" class="btn save" onclick="togglePriority()" title="Toggle: analyze all alerts vs high/critical only">⚡ Priority</button>
      <button class="btn save" onclick="clearCache()" title="Clear browser cache and reload">↺ Cache</button>
    </div>
  </div>
</header>
<div class="workspace">
  <div class="list-pane">
    <div class="filter-bar">
      <button class="filter-btn active" data-f="all"       onclick="setFilter('all')">All</button>
      <button class="filter-btn"        data-f="new"       onclick="setFilter('new')">New<span id="bdg-new" class="badge" style="display:none"></span></button>
      <button class="filter-btn"        data-f="escalated" onclick="setFilter('escalated')">Escalated<span id="bdg-esc" class="badge esc" style="display:none"></span></button>
      <button class="filter-btn"        data-f="ack"       onclick="setFilter('ack')">Ack</button>
      <button class="filter-btn"        data-f="fp"        onclick="setFilter('fp')">FP</button>
      <button class="filter-btn"        data-f="excluded"  onclick="setFilter('excluded')">Excluded</button>
      <div class="view-toggle" style="margin-left:4px;">
        <button id="view-alerts" class="active" onclick="setView('alerts')">Alerts</button>
        <button id="view-groups"                onclick="setView('groups')">Groups</button>
      </div>
      <input class="search-box" placeholder="Search…" id="search-box" oninput="currentView==='groups'?renderGroupList():renderList()">
    </div>
    <div class="cat-bar">
      <span style="font-size:10px;color:var(--muted);margin-right:2px;">CAT</span>
      <button class="cat-btn active" data-c="all"       onclick="setCategory('all')">All</button>
      <button class="cat-btn"        data-c="systemd"   onclick="setCategory('systemd')">Systemd</button>
      <button class="cat-btn"        data-c="integrity" onclick="setCategory('integrity')">Integrity</button>
      <button class="cat-btn"        data-c="cis"       onclick="setCategory('cis')">CIS</button>
      <button class="cat-btn"        data-c="web"       onclick="setCategory('web')">Web</button>
      <button class="cat-btn"        data-c="windows"   onclick="setCategory('windows')">Windows</button>
    </div>
    <div class="alert-list" id="alert-list"><div style="padding:20px;color:var(--muted)">Loading…</div></div>
  </div>
  <div class="detail-pane">
    <div class="detail-scroll" id="detail-scroll">
      <div class="detail-empty"><svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg><span>Select an alert to investigate</span></div>
    </div>
    <div class="action-bar" id="action-bar" style="display:none">
      <button class="btn ack"    onclick="doAction('ack')">✓ Acknowledge</button>
      <button class="btn esc"    onclick="doAction('escalate')">↑ Escalate</button>
      <button class="btn fp"     onclick="doAction('fp')">✗ False Positive</button>
      <button class="btn reopen" onclick="doAction('new')" style="display:none" id="btn-reopen">↺ Reopen</button>
      <button class="btn save"   onclick="openSuppressModal()" id="btn-suppress">⊘ Suppress</button>
      <button class="btn save"   onclick="openCaseModal()"     id="btn-addcase">+ Case</button>
      <div style="margin-left:auto;display:flex;align-items:center;gap:6px;">
        <input style="width:120px;font-size:12px;padding:4px 8px;" id="assign-input" placeholder="Assign to…">
        <button class="btn save" onclick="doAssign()">Assign</button>
      </div>
    </div>
  </div>
</div>

<!-- Suppress modal -->
<div id="suppress-modal" style="display:none" class="modal-overlay">
  <div class="modal">
    <h2>Add Suppression Rule</h2>
    <div class="form-row"><label>Field</label>
      <select id="sup-field"><option value="rule_id">Rule ID</option><option value="agent_name">Agent Name</option><option value="srcip">Source IP</option><option value="rule_description">Description</option></select></div>
    <div class="form-row"><label>Operator</label>
      <select id="sup-op"><option value="equals">Equals</option><option value="contains">Contains</option><option value="starts_with">Starts With</option></select></div>
    <div class="form-row"><label>Value</label><input id="sup-value" type="text"></div>
    <div class="form-row"><label>Reason</label><input id="sup-reason" type="text" placeholder="Why suppress?"></div>
    <div class="form-row"><label>Expires At (optional)</label><input id="sup-expires" type="datetime-local"></div>
    <div class="form-actions">
      <button class="btn" onclick="document.getElementById('suppress-modal').style.display='none'">Cancel</button>
      <button class="btn primary" onclick="submitSuppress()">Create Rule</button>
    </div>
  </div>
</div>

<!-- Case modal -->
<div id="case-modal" style="display:none" class="modal-overlay">
  <div class="modal">
    <h2>Add Alert to Case</h2>
    <div class="form-row"><label>Existing Case</label><select id="case-select"><option value="">— select —</option></select></div>
    <div style="text-align:center;color:var(--muted);font-size:12px;margin:8px 0;">— or create new —</div>
    <div class="form-row"><label>New Case Title</label><input id="case-title" type="text" placeholder="Case title"></div>
    <div class="form-row"><label>Description</label><input id="case-desc" type="text"></div>
    <div class="form-row"><label>Severity</label>
      <select id="case-sev"><option value="0">Low</option><option value="5">Medium</option><option value="8">High</option><option value="12">Critical</option></select></div>
    <div class="form-actions">
      <button class="btn" onclick="document.getElementById('case-modal').style.display='none'">Cancel</button>
      <button class="btn primary" onclick="submitCase()">Add to Case</button>
    </div>
  </div>
</div>

<!-- Timeline modal -->
<div id="timeline-modal" style="display:none" class="modal-overlay" onclick="if(event.target===this)this.style.display='none'">
  <div class="modal timeline-modal" style="width:600px;">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
      <h2 id="timeline-title">Timeline</h2>
      <button class="btn" onclick="document.getElementById('timeline-modal').style.display='none'">✕</button>
    </div>
    <div id="timeline-body"><div class="spinner"></div></div>
  </div>
</div>

<script>
let alerts=[], groups=[], selectedId=null, currentFilter='all', currentCategory='all', currentView='alerts';

function loadStats(){
  fetch('/api/stats').then(r=>r.json()).then(s=>{
    document.getElementById('stat-new').textContent=s.new;
    document.getElementById('stat-esc').textContent=s.escalated;
    document.getElementById('stat-ack').textContent=s.ack;
    const lp=s.last_poll==='never'?'never polled':'polled '+new Date(s.last_poll).toLocaleTimeString();
    document.getElementById('last-poll').textContent=lp;
    const bn=document.getElementById('bdg-new'),be=document.getElementById('bdg-esc');
    bn.textContent=s.new; bn.style.display=s.new?'':'none';
    be.textContent=s.escalated; be.style.display=s.escalated?'':'none';
    updatePriorityBtn(s.analyst_priority_only);
  }).catch(()=>{});
}

function setFilter(f){
  currentFilter=f;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.toggle('active',b.dataset.f===f));
  loadData();
}
function setCategory(c){
  currentCategory=c;
  document.querySelectorAll('.cat-btn').forEach(b=>b.classList.toggle('active',b.dataset.c===c));
  loadData();
}
function setView(v){
  currentView=v;
  document.getElementById('view-alerts').classList.toggle('active',v==='alerts');
  document.getElementById('view-groups').classList.toggle('active',v==='groups');
  loadData();
}

function loadData(){
  if(currentView==='groups') loadGroups();
  else loadAlerts();
}

function loadAlerts(){
  let url='/api/alerts?status='+currentFilter;
  if(currentCategory!=='all') url+='&category='+currentCategory;
  return fetch(url).then(r=>r.json()).then(data=>{
    alerts=data;
    if(currentView==='alerts') renderList();
  }).catch(()=>{});
}

function loadGroups(){
  let url='/api/groups?status='+currentFilter+'&category='+currentCategory;
  fetch(url).then(r=>r.json()).then(data=>{
    groups=data;
    if(currentView==='groups') renderGroupList();
  }).catch(()=>{});
}

function renderList(){
  const q=document.getElementById('search-box').value.toLowerCase();
  const el=document.getElementById('alert-list');
  const filtered=q?alerts.filter(a=>(a.rule_description||'').toLowerCase().includes(q)||(a.agent_name||'').toLowerCase().includes(q)):alerts;
  if(!filtered.length){el.innerHTML='<div style="padding:20px;color:var(--muted);text-align:center">No alerts.</div>';return;}
  el.innerHTML=filtered.map(a=>`
    <div class="alert-item status-${a.status}${a.id===selectedId?' selected':''}" onclick="selectAlert(${a.id})">
      <div class="level-badge ${lc(a.rule_level)}">${a.rule_level}</div>
      <div class="alert-info">
        <div class="alert-rule">${esc(a.rule_description)}</div>
        <div class="alert-meta">
          <span class="status-dot ${a.status}"></span>
          <span style="color:var(--muted);font-size:11px">#${a.id}</span>
          <span>${esc(a.agent_name)}</span>
          <span>${fmtTs(a.timestamp)}</span>
          ${a.mitre_technique?`<span class="mitre-tag">${esc(a.mitre_technique.split(',')[0].trim())}</span>`:''}
          ${a.assigned_to?`<span class="assign-badge">${esc(a.assigned_to)}</span>`:''}
          ${a.analysis==='[excluded]'?'<span class="ai-badge ai-pending" title="Excluded from analysis">&#x2205; AI</span>':a.analysis?'<span class="ai-badge" title="AI analyzed">&#x2713; AI</span>':'<span class="ai-badge ai-pending" title="Awaiting analysis">&#x2026; AI</span>'}
        </div>
      </div>
    </div>`).join('');
}

function renderGroupList(){
  const q=document.getElementById('search-box').value.toLowerCase();
  const el=document.getElementById('alert-list');
  const filtered=q?groups.filter(g=>(g.rule_description||'').toLowerCase().includes(q)||(g.agent_name||'').toLowerCase().includes(q)):groups;
  if(!filtered.length){el.innerHTML='<div style="padding:20px;color:var(--muted);text-align:center">No groups.</div>';return;}
  el.innerHTML=filtered.map(g=>`
    <div class="alert-item" onclick="loadGroupAlerts(${JSON.stringify(g.group_key).replace(/"/g,'&quot;')})">
      <div class="level-badge ${lc(g.max_level)}">${g.max_level}</div>
      <div class="alert-info">
        <div class="alert-rule" style="display:flex;align-items:center;gap:6px;">
          ${esc(g.rule_description)}
          <span class="count-badge">×${g.count}</span>
        </div>
        <div class="alert-meta">
          <span>${esc(g.agent_name)}</span>
          <span>${fmtTs(g.latest_ts)}</span>
          ${g.mitre_technique?`<span class="mitre-tag">${esc(g.mitre_technique.split(',')[0].trim())}</span>`:''}
        </div>
      </div>
    </div>`).join('');
}

function loadGroupAlerts(groupKey){
  let url='/api/alerts?group_key='+encodeURIComponent(groupKey)+'&status='+currentFilter;
  document.getElementById('detail-scroll').innerHTML='<div style="padding:20px;color:var(--muted)">Loading group…</div>';
  document.getElementById('action-bar').style.display='none';
  fetch(url).then(r=>r.json()).then(data=>{
    if(!data.length){document.getElementById('detail-scroll').innerHTML='<div style="padding:20px;color:var(--muted)">No alerts in this group.</div>';return;}
    document.getElementById('detail-scroll').innerHTML=`
      <div style="padding:16px 20px;font-size:13px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--border)">${data.length} alerts in group — click one to view</div>`+
      data.map(a=>`
        <div class="alert-item" style="margin:4px 8px;border-radius:6px;" onclick="selectAlert(${a.id})">
          <div class="level-badge ${lc(a.rule_level)}">${a.rule_level}</div>
          <div class="alert-info">
            <div class="alert-rule">${esc(a.rule_description)}</div>
            <div class="alert-meta"><span class="status-dot ${a.status}"></span><span>${esc(a.agent_name)}</span><span>${fmtTs(a.timestamp)}</span>${a.analysis==='[excluded]'?'<span class="ai-badge ai-pending" title="Excluded from analysis">&#x2205; AI</span>':a.analysis?'<span class="ai-badge" title="AI analyzed">&#x2713; AI</span>':'<span class="ai-badge ai-pending" title="Awaiting analysis">&#x2026; AI</span>'}</div>
          </div>
        </div>`).join('');
  }).catch(()=>{});
}

function selectAlert(id){
  selectedId=id;
  if(currentView==='alerts') renderList();
  document.getElementById('detail-scroll').innerHTML='<div class="analysis-loading" style="padding:40px 20px"><div class="spinner"></div> Loading…</div>';
  document.getElementById('action-bar').style.display='flex';
  document.getElementById('btn-reopen').style.display='none';
  fetch('/api/alerts/'+id).then(r=>r.json()).then(a=>renderDetail(a)).catch(e=>{
    document.getElementById('detail-scroll').innerHTML='<div style="padding:20px;color:var(--red)">Error: '+e+'</div>';
  });
}

function renderDetail(a){
  const raw=a._raw||{}, data=raw.data||{}, syscheck=raw.syscheck||{};
  const win=(data.win)||{}, winsys=win.system||{}, winevt=win.eventdata||{};
  const enr=a._enrichment||{};
  const extras=[];
  if(a.timestamp) extras.push(['Time',fmtTs(a.timestamp,true)]);
  if(a.rule_id)   extras.push(['Rule ID',a.rule_id]);
  if(a.rule_groups){try{const g=JSON.parse(a.rule_groups);if(g.length)extras.push(['Groups',g.join(', ')]);}catch(e){}}
  if(syscheck.path)  extras.push(['FIM Path',syscheck.path]);
  if(syscheck.event) extras.push(['FIM Event',syscheck.event]);
  if(data.srcuser)   extras.push(['Source user',data.srcuser]);
  if(data.dstuser)   extras.push(['Target user',data.dstuser]);
  if(data.command)   extras.push(['Command',data.command]);
  if(data.url)       extras.push(['URL',data.url]);
  if(raw.full_log)   extras.push(['Full log',raw.full_log]);

  // Build event summary rows from whatever fields are available
  const evRows=[];
  if(winsys.message)        evRows.push(['Message', winsys.message.replace(/^"|"$/g,'')]);
  if(winsys.providerName)   evRows.push(['Provider', winsys.providerName]);
  if(winsys.eventID)        evRows.push(['Event ID', winsys.eventID]);
  if(winsys.channel)        evRows.push(['Channel', winsys.channel]);
  if(winsys.severityValue)  evRows.push(['Severity', winsys.severityValue]);
  if(winsys.computer)       evRows.push(['Computer', winsys.computer]);
  if(winsys.processID)      evRows.push(['PID', winsys.processID]);
  Object.entries(winevt).forEach(([k,v])=>{ if(v) evRows.push([k,v]); });
  if(data.srcip)   evRows.push(['Src IP', data.srcip]);
  if(data.dstip)   evRows.push(['Dst IP', data.dstip]);
  if(data.srcport) evRows.push(['Src port', data.srcport]);
  if(data.dstport) evRows.push(['Dst port', data.dstport]);
  if(data.proto)   evRows.push(['Protocol', data.proto]);
  if(syscheck.path) evRows.push(['Path', syscheck.path]);
  if(syscheck.event) evRows.push(['FIM event', syscheck.event]);
  if(syscheck.md5||syscheck.sha1) evRows.push(['Hash', syscheck.md5||syscheck.sha1]);
  if(raw.full_log && !winsys.message) evRows.push(['Log', raw.full_log]);
  // Sophos Central fields
  const sophos=data.sophos||(data.type&&data.type.startsWith('Event::')?data:{});
  if(sophos.type)        evRows.push(['Sophos type', sophos.type]);
  if(sophos.name||sophos.threat||data.threat) evRows.push(['Threat', sophos.name||sophos.threat||data.threat]);
  if(sophos.severity)    evRows.push(['Sophos severity', sophos.severity]);
  if(sophos.category)    evRows.push(['Category', sophos.category]);
  if(sophos.location||data.location) evRows.push(['File', sophos.location||data.location]);
  if(sophos.cleanUpAction||data.cleanUpAction) evRows.push(['Action taken', sophos.cleanUpAction||data.cleanUpAction]);
  const det=sophos.detectionIdentity||{};
  if(det.name) evRows.push(['Detection', det.name]);
  if(sophos.username||data.username) evRows.push(['Username', sophos.username||data.username]);
  if(sophos.endpoint_hostname||data.endpoint_hostname) evRows.push(['Endpoint', sophos.endpoint_hostname||data.endpoint_hostname]);

  const eventSummaryHtml = evRows.length
    ? `<div class="raw-grid" style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border)">${evRows.map(([k,v])=>`<div class="raw-key">${esc(k)}</div><div class="raw-val">${esc(String(v))}</div>`).join('')}</div>`
    : '';

  const analysisHtml=a.analysis
    ?`<div class="analysis-body">${mdToHtml(a.analysis)}</div><button class="btn save" style="margin-top:8px;font-size:11px" onclick="reanalyze(${a.id})">↻ Re-analyze</button>`
    :`<div class="analysis-loading"><div class="spinner"></div> Analyzing… <button class="btn save" style="margin-left:8px;font-size:11px" onclick="reanalyze(${a.id})">Run now</button></div>`;

  // enrichment badge
  let enrHtml='';
  if(enr.risk_score>0){
    enrHtml=`<span class="risk-badge ${enr.risk_label}" title="Threat intel risk">⚑ ${enr.risk_label.toUpperCase()} ${enr.risk_score}</span>`;
    if(enr.risk_score>=50){
      const ab=enr.sources&&enr.sources.abuseipdb||{};
      const otx=enr.sources&&enr.sources.otx||{};
      if(ab.abuseConfidenceScore) enrHtml+=` <span style="font-size:11px;color:var(--muted)">Abuse: ${ab.abuseConfidenceScore}%</span>`;
      if(otx.pulse_count) enrHtml+=` <span style="font-size:11px;color:var(--muted)">OTX: ${otx.pulse_count} pulses</span>`;
    }
  }

  document.getElementById('detail-scroll').innerHTML=`
    <div class="detail-header">
      <div class="detail-level ${lc(a.rule_level)}">${a.rule_level}</div>
      <div>
        <div class="detail-title">${esc(a.rule_description)}</div>
        <div class="detail-chips">
          <span class="chip agent" style="cursor:pointer" onclick="openTimeline('agent','${esc(a.agent_name)}')">🖥 ${esc(a.agent_name)}</span>
          ${a.agent_ip?`<span class="chip">${esc(a.agent_ip)}</span>`:''}
          ${a.mitre_technique?`<span class="chip mitre">⚡ ${esc(a.mitre_technique)}</span>`:''}
          ${a.mitre_tactic?`<span class="chip mitre">${esc(a.mitre_tactic)}</span>`:''}
          ${a.srcip?`<span class="chip srcip" style="cursor:pointer" onclick="openTimeline('ip','${esc(a.srcip)}')">⚠ src: ${esc(a.srcip)}</span> ${enrHtml}`:''}
          <span class="chip status-${a.status||'new'}">${(a.status||'new').toUpperCase()}</span>
          ${a.assigned_to?`<span class="chip" style="color:var(--accent)">👤 ${esc(a.assigned_to)}</span>`:''}
        </div>
      </div>
    </div>
    <div class="section">
      <div class="section-title">Analysis &amp; Remediation</div>
      ${analysisHtml}
      ${eventSummaryHtml}
    </div>
    ${extras.length?`<div class="section"><div class="section-title">Event Details</div><div class="raw-grid">${extras.map(([k,v])=>`<div class="raw-key">${esc(k)}</div><div class="raw-val">${esc(String(v))}</div>`).join('')}</div></div>`:''}
    <div class="section" id="notes-section">
      <div class="section-title">Notes</div>
      <div class="notes-thread" id="notes-thread"></div>
      <div style="display:flex;gap:6px;margin-top:8px;">
        <input style="flex:1;font-size:12px;" id="note-input" placeholder="Add a note…">
        <button class="btn save" onclick="addNote()">Add Note</button>
      </div>
    </div>
  `;

  document.getElementById('btn-reopen').style.display=a.status!=='new'?'':'none';
  document.getElementById('assign-input').value=a.assigned_to||'';

  // pre-fill suppress modal
  document.getElementById('sup-value').value=a.rule_id||'';

  loadNotes(a.id);
  if(!a.analysis) setTimeout(()=>selectAlert(a.id),4000);
}

function loadNotes(id){
  fetch('/api/alerts/'+id+'/notes').then(r=>r.json()).then(notes=>{
    const el=document.getElementById('notes-thread');
    if(!el)return;
    if(!notes.length){el.innerHTML='<div style="color:var(--muted);font-size:12px">No notes yet.</div>';return;}
    el.innerHTML=notes.map(n=>`
      <div class="note-item">
        <div class="note-ts">${fmtTs(n.created_at,true)}</div>
        <div class="note-body ${n.auto_generated?'auto':''}">${esc(n.body)}</div>
      </div>`).join('');
    el.scrollTop=el.scrollHeight;
  }).catch(()=>{});
}

function addNote(){
  if(!selectedId)return;
  const body=document.getElementById('note-input').value.trim();
  if(!body)return;
  fetch('/api/alerts/'+selectedId+'/notes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({body})})
    .then(()=>{document.getElementById('note-input').value='';loadNotes(selectedId);});
}

function reanalyze(id){
  const sec=document.querySelector('.section-title');
  document.querySelector('.analysis-body,  .analysis-loading').outerHTML='<div class="analysis-loading"><div class="spinner"></div> Running AI analysis…</div>';
  fetch('/api/alerts/'+id+'/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
    .then(r=>r.json()).then(d=>{
      if(d.analysis) selectAlert(id);
    }).catch(()=>selectAlert(id));
}

function doAction(action){
  if(!selectedId){_toast('No alert selected','#b94040');return;}
  const labels={'ack':'✓ Acknowledged','escalate':'↑ Escalated','fp':'✗ Marked FP','new':'↺ Reopened'};
  const colors={'ack':'#238636','escalate':'#d47500','fp':'#555','new':'#1a73e8'};
  fetch('/api/alerts/'+selectedId+'/action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action})})
    .then(r=>r.json()).then(d=>{
      if(d.error){_toast('Error: '+d.error,'#b94040');return;}
      _toast(labels[action]||action, colors[action]);
      loadData();loadStats();selectAlert(selectedId);
    }).catch(e=>_toast('Request failed: '+e.message,'#b94040'));
}

function doAssign(){
  if(!selectedId)return;
  const assigned_to=document.getElementById('assign-input').value.trim();
  fetch('/api/alerts/'+selectedId+'/action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({assigned_to})})
    .then(()=>selectAlert(selectedId));
}

function openSuppressModal(){
  if(!selectedId)return;
  document.getElementById('suppress-modal').style.display='flex';
}
function submitSuppress(){
  const field=document.getElementById('sup-field').value;
  const operator=document.getElementById('sup-op').value;
  const value=document.getElementById('sup-value').value.trim();
  const reason=document.getElementById('sup-reason').value.trim();
  const expires_at=document.getElementById('sup-expires').value||null;
  if(!value)return;
  fetch('/api/suppressions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({field,operator,value,reason,expires_at})})
    .then(()=>{document.getElementById('suppress-modal').style.display='none';});
}

let _cases=[];
function openCaseModal(){
  if(!selectedId)return;
  fetch('/api/cases').then(r=>r.json()).then(cases=>{
    _cases=cases;
    const sel=document.getElementById('case-select');
    sel.innerHTML='<option value="">— select existing —</option>'+cases.map(c=>`<option value="${c.id}">${esc(c.title)}</option>`).join('');
    document.getElementById('case-modal').style.display='flex';
  });
}
function submitCase(){
  const existingId=document.getElementById('case-select').value;
  const title=document.getElementById('case-title').value.trim();
  const desc=document.getElementById('case-desc').value.trim();
  const sev=parseInt(document.getElementById('case-sev').value);
  if(existingId){
    fetch('/api/cases/'+existingId+'/alerts',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({alert_id:selectedId})})
      .then(()=>{document.getElementById('case-modal').style.display='none';});
  } else if(title){
    fetch('/api/cases',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title,description:desc,severity:sev})})
      .then(r=>r.json()).then(res=>{
        if(res.id){
          fetch('/api/cases/'+res.id+'/alerts',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({alert_id:selectedId})})
            .then(()=>{document.getElementById('case-modal').style.display='none';});
        }
      });
  }
}

function openTimeline(type,value){
  const modal=document.getElementById('timeline-modal');
  document.getElementById('timeline-title').textContent='Timeline: '+value+' (last 24h)';
  document.getElementById('timeline-body').innerHTML='<div class="spinner"></div>';
  modal.style.display='flex';
  const param=type==='agent'?'agent='+encodeURIComponent(value):'ip='+encodeURIComponent(value);
  fetch('/api/timeline?'+param+'&hours=24').then(r=>r.json()).then(rows=>{
    if(!rows.length){document.getElementById('timeline-body').innerHTML='<div style="color:var(--muted)">No events in last 24h.</div>';return;}
    document.getElementById('timeline-body').innerHTML=rows.map(r=>`
      <div class="tl-item" onclick="document.getElementById('timeline-modal').style.display='none';selectAlert(${r.id})">
        <div class="tl-time">${fmtTs(r.timestamp,true)}</div>
        <div class="level-badge ${lc(r.rule_level)}" style="width:28px;height:28px;font-size:11px;flex-shrink:0">${r.rule_level}</div>
        <div style="flex:1;min-width:0">
          <div style="font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(r.rule_description)}</div>
          <div style="font-size:11px;color:var(--muted)">${r.mitre_technique?`<span class="mitre-tag">${esc(r.mitre_technique.split(',')[0].trim())}</span>`:''}</div>
        </div>
        <span class="status-dot ${r.status}" style="margin-top:8px;flex-shrink:0"></span>
      </div>`).join('');
  }).catch(()=>{document.getElementById('timeline-body').innerHTML='<div style="color:var(--red)">Error loading timeline.</div>';});
}

function togglePriority(){
  fetch('/api/settings/analyst_priority',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
    .then(r=>r.json()).then(d=>updatePriorityBtn(d.analyst_priority_only));
}
function updatePriorityBtn(on){
  const b=document.getElementById('btn-priority');
  if(!b)return;
  b.title=on?'Priority mode ON — analyzing level ≥10 only (click to analyze all)':'Priority mode OFF — analyzing all alerts (click to limit to high/critical)';
  b.style.color=on?'var(--orange)':'';
  b.style.borderColor=on?'var(--orange)':'';
}

function clearCache(){
  const bust=()=>{const u=new URL(location.href);u.searchParams.set('_',Date.now());location.replace(u.toString());};
  if('caches' in window){caches.keys().then(k=>Promise.all(k.map(x=>caches.delete(x)))).then(bust);}
  else{bust();}
}

function exportAlerts(fmt){
  const since='7d';
  window.open('/api/export/alerts.'+fmt+'?status='+currentFilter+'&since='+since,'_blank');
}

function lc(n){return n>=12?'crit':n>=10?'high':n>=7?'med':'low';}
function fmtTs(iso,full=false){
  if(!iso)return'';
  try{
    const d=new Date(iso);
    if(full)return d.toLocaleString();
    const diff=(new Date()-d)/1000;
    if(diff<60)return Math.round(diff)+'s ago';
    if(diff<3600)return Math.round(diff/60)+'m ago';
    if(diff<86400)return Math.round(diff/3600)+'h ago';
    return d.toLocaleDateString();
  }catch(e){return iso;}
}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function mdToHtml(md){
  return md.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/^### (.+)$/gm,'<h3>$1</h3>').replace(/^## (.+)$/gm,'<h3>$1</h3>')
    .replace(/\\*\\*(.+?)\\*\\*/g,'<strong>$1</strong>').replace(/\\*(.+?)\\*/g,'<em>$1</em>')
    .replace(/`(.+?)`/g,'<code>$1</code>')
    .replace(/^\\d+\\. (.+)$/gm,'<li>$1</li>').replace(/^- (.+)$/gm,'<li>$1</li>')
    .replace(/\\n\\n/g,'<br><br>').replace(/\\n/g,' ');
}

const _highlightId = new URLSearchParams(window.location.search).get('highlight');
loadStats();
loadAlerts().then(()=>{ if(_highlightId) selectAlert(parseInt(_highlightId)); });
setInterval(()=>{loadData();loadStats();},60000);
</script>
""" + PAGE_FOOTER


# ---------------------------------------------------------------------------
# Suppressions page
# ---------------------------------------------------------------------------

SUPPRESSIONS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>SOCops — Suppressions</title>
<style>""" + COMMON_CSS + """
body{min-height:100vh;}
main{max-width:960px;margin:0 auto;padding:24px;}
</style>
</head>
<body>
<header>
  <div class="logo">S</div>
  <div><div class="app-name">SOCops</div><div class="app-sub">Security Operations Center</div></div>
  """ + _nav("Suppressions") + """
</header>
<main>
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
    <h1 style="font-size:20px;font-weight:700;">Suppression Rules</h1>
    <button class="btn primary" onclick="document.getElementById('add-form').style.display='block'">+ Add Rule</button>
  </div>

  <div class="card" id="add-form" style="display:none">
    <div class="card-title">New Suppression Rule</div>
    <div style="display:grid;grid-template-columns:1fr 1fr 2fr;gap:12px;align-items:end;">
      <div class="form-row"><label>Field</label>
        <select id="f-field"><option value="rule_id">Rule ID</option><option value="agent_name">Agent Name</option><option value="srcip">Source IP</option><option value="rule_description">Description</option></select></div>
      <div class="form-row"><label>Operator</label>
        <select id="f-op"><option value="equals">Equals</option><option value="contains">Contains</option><option value="starts_with">Starts With</option></select></div>
      <div class="form-row"><label>Value</label><input id="f-value" type="text" placeholder="Match value"></div>
    </div>
    <div style="display:grid;grid-template-columns:2fr 1fr;gap:12px;margin-top:12px;align-items:end;">
      <div class="form-row"><label>Reason</label><input id="f-reason" type="text" placeholder="Why suppress?"></div>
      <div class="form-row"><label>Expires At</label><input id="f-expires" type="datetime-local"></div>
    </div>
    <div style="display:flex;gap:8px;margin-top:12px;">
      <button class="btn primary" onclick="addRule()">Create Rule</button>
      <button class="btn" onclick="document.getElementById('add-form').style.display='none'">Cancel</button>
    </div>
  </div>

  <div class="card">
    <div class="card-title">Active Rules</div>
    <div id="rules-table"><div style="color:var(--muted);font-size:13px">Loading…</div></div>
  </div>
</main>
<script>
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function loadRules(){
  fetch('/api/suppressions').then(r=>r.json()).then(rules=>{
    const el=document.getElementById('rules-table');
    if(!rules.length){el.innerHTML='<div style="color:var(--muted);font-size:13px">No suppression rules defined.</div>';return;}
    el.innerHTML=`<table>
      <thead><tr><th>Field</th><th>Op</th><th>Value</th><th>Reason</th><th>Hits</th><th>Expires</th><th>Created</th><th></th></tr></thead>
      <tbody>`+rules.map(r=>`<tr>
        <td style="font-weight:600">${esc(r.field)}</td>
        <td>${esc(r.operator)}</td>
        <td><code style="background:var(--surface2);border-radius:4px;padding:1px 5px;font-size:12px">${esc(r.value)}</code></td>
        <td style="color:var(--muted);font-size:12px">${esc(r.reason)}</td>
        <td style="font-weight:700;color:var(--accent)">${r.hits}</td>
        <td style="font-size:11px;color:var(--muted)">${r.expires_at||'—'}</td>
        <td style="font-size:11px;color:var(--muted)">${(r.created_at||'').slice(0,16)}</td>
        <td><button class="btn danger" onclick="deleteRule(${r.id})">Delete</button></td>
      </tr>`).join('')+`</tbody></table>`;
  });
}
function addRule(){
  const field=document.getElementById('f-field').value;
  const operator=document.getElementById('f-op').value;
  const value=document.getElementById('f-value').value.trim();
  const reason=document.getElementById('f-reason').value.trim();
  const expires_at=document.getElementById('f-expires').value||null;
  if(!value)return;
  fetch('/api/suppressions',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({field,operator,value,reason,expires_at})})
    .then(()=>{document.getElementById('add-form').style.display='none';loadRules();});
}
function deleteRule(id){
  if(!confirm('Delete this suppression rule?'))return;
  fetch('/api/suppressions/'+id,{method:'DELETE'}).then(()=>loadRules());
}
loadRules();
</script>
""" + PAGE_FOOTER


# ---------------------------------------------------------------------------
# Cases page
# ---------------------------------------------------------------------------

CASES_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>SOCops — Cases</title>
<style>""" + COMMON_CSS + """
body{min-height:100vh;}
main{max-width:1200px;margin:0 auto;padding:24px;}
.case-grid{display:grid;grid-template-columns:360px 1fr;gap:20px;}
.case-list-item{padding:12px;border-radius:var(--r);cursor:pointer;border:1px solid transparent;margin-bottom:6px;}
.case-list-item:hover{background:var(--surface2);border-color:var(--border);}
.case-list-item.selected{background:var(--surface2);border-color:var(--accent);}
.sev-badge{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:5px;font-size:11px;font-weight:700;}
.status-open{color:var(--red);background:rgba(248,81,73,.1);border-radius:4px;padding:1px 8px;font-size:11px;}
.status-closed{color:var(--muted);background:var(--surface2);border-radius:4px;padding:1px 8px;font-size:11px;}
</style>
</head>
<body>
<header>
  <div class="logo">S</div>
  <div><div class="app-name">SOCops</div><div class="app-sub">Security Operations Center</div></div>
  """ + _nav("Cases") + """
</header>
<main>
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
    <h1 style="font-size:20px;font-weight:700;">Cases / Incidents</h1>
    <button class="btn primary" onclick="document.getElementById('new-case-form').style.display='block'">+ New Case</button>
  </div>
  <div class="card" id="new-case-form" style="display:none">
    <div class="card-title">Create New Case</div>
    <div style="display:grid;grid-template-columns:2fr 1fr;gap:12px">
      <div class="form-row"><label>Title</label><input id="nc-title" type="text" placeholder="Case title"></div>
      <div class="form-row"><label>Severity</label>
        <select id="nc-sev"><option value="0">Low</option><option value="5">Medium</option><option value="8">High</option><option value="12">Critical</option></select></div>
    </div>
    <div class="form-row" style="margin-top:8px"><label>Description</label><textarea id="nc-desc" rows="2" style="width:100%;resize:vertical"></textarea></div>
    <div style="display:flex;gap:8px;margin-top:12px">
      <button class="btn primary" onclick="createCase()">Create</button>
      <button class="btn" onclick="document.getElementById('new-case-form').style.display='none'">Cancel</button>
    </div>
  </div>
  <div class="case-grid">
    <div>
      <div id="case-list"><div style="color:var(--muted)">Loading…</div></div>
    </div>
    <div id="case-detail" style="color:var(--muted);font-size:13px;padding:20px">Select a case to view details.</div>
  </div>
</main>
<script>
let selectedCase=null;
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function lc(n){return n>=12?'crit':n>=10?'high':n>=7?'med':'low';}
function fmtTs(iso){if(!iso)return'';try{return new Date(iso).toLocaleString();}catch(e){return iso;}}

function loadCases(){
  fetch('/api/cases').then(r=>r.json()).then(cases=>{
    const el=document.getElementById('case-list');
    if(!cases.length){el.innerHTML='<div style="color:var(--muted);font-size:13px">No cases yet.</div>';return;}
    el.innerHTML=cases.map(c=>`
      <div class="case-list-item${c.id===selectedCase?' selected':''}" onclick="loadCase(${c.id})">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
          <span class="sev-badge ${lc(c.severity)}">${c.severity||0}</span>
          <span style="font-weight:600;font-size:13px">${esc(c.title)}</span>
          <span class="status-${c.status}">${c.status}</span>
        </div>
        <div style="font-size:11px;color:var(--muted)">${fmtTs(c.created_at)} &nbsp;·&nbsp; ${c.alert_count||0} alerts</div>
      </div>`).join('');
  });
}

function loadCase(id){
  selectedCase=id;
  loadCases();
  fetch('/api/cases/'+id).then(r=>r.json()).then(c=>{
    const det=document.getElementById('case-detail');
    det.innerHTML=`
      <div style="margin-bottom:16px">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
          <span class="sev-badge ${lc(c.severity)}">${c.severity||0}</span>
          <span style="font-size:18px;font-weight:700">${esc(c.title)}</span>
          <span class="status-${c.status}">${c.status}</span>
        </div>
        <div style="font-size:12px;color:var(--muted);margin-bottom:8px">Created: ${fmtTs(c.created_at)}${c.closed_at?' &nbsp;·&nbsp; Closed: '+fmtTs(c.closed_at):''}</div>
        ${c.description?`<div style="font-size:13px;color:var(--muted)">${esc(c.description)}</div>`:''}
      </div>
      <div style="display:flex;gap:8px;margin-bottom:16px">
        ${c.status==='open'?`<button class="btn fp" onclick="closeCase(${c.id})">Close Case</button>`:`<button class="btn reopen" onclick="reopenCase(${c.id})">Reopen</button>`}
      </div>
      <div class="card-title" style="margin-bottom:12px">Alerts in Case (${(c.alerts||[]).length})</div>
      ${(c.alerts||[]).length?`<table>
        <thead><tr><th>Level</th><th>Time</th><th>Agent</th><th>Rule</th><th>Status</th></tr></thead>
        <tbody>`+(c.alerts||[]).map(a=>`<tr>
          <td><span class="lvl ${lc(a.rule_level)}">${a.rule_level}</span></td>
          <td style="font-size:11px;color:var(--muted)">${fmtTs(a.timestamp)}</td>
          <td style="font-size:12px">${esc(a.agent_name)}</td>
          <td style="font-size:12px">${esc(a.rule_description)}</td>
          <td><span class="chip status-${a.status}">${a.status}</span></td>
        </tr>`).join('')+`</tbody></table>`:'<div style="color:var(--muted);font-size:13px">No alerts linked to this case.</div>'}
    `;
  });
}

function createCase(){
  const title=document.getElementById('nc-title').value.trim();
  const desc=document.getElementById('nc-desc').value.trim();
  const sev=parseInt(document.getElementById('nc-sev').value);
  if(!title)return;
  fetch('/api/cases',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title,description:desc,severity:sev})})
    .then(r=>r.json()).then(res=>{
      document.getElementById('new-case-form').style.display='none';
      loadCases();
      if(res.id)loadCase(res.id);
    });
}
function closeCase(id){
  fetch('/api/cases/'+id+'/action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:'closed'})})
    .then(()=>{loadCases();loadCase(id);});
}
function reopenCase(id){
  fetch('/api/cases/'+id+'/action',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:'open'})})
    .then(()=>{loadCases();loadCase(id);});
}
loadCases();
</script>
""" + PAGE_FOOTER


# ---------------------------------------------------------------------------
# Metrics page
# ---------------------------------------------------------------------------

METRICS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>SOCops — Metrics</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>""" + COMMON_CSS + """
body{min-height:100vh;}
main{max-width:1400px;margin:0 auto;padding:24px;}
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:24px;}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:18px;position:relative;overflow:hidden;}
.kpi::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;}
.kpi.c-red::before{background:var(--red);}.kpi.c-orange::before{background:var(--orange);}
.kpi.c-blue::before{background:var(--accent);}.kpi.c-green::before{background:var(--green);}
.kpi.c-yellow::before{background:var(--yellow);}.kpi.c-purple::before{background:var(--purple);}
.kpi-label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-bottom:10px;}
.kpi-value{font-size:28px;font-weight:800;line-height:1;}
.kpi-sub{font-size:11px;color:var(--muted);margin-top:6px;}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px;}
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:16px;}
@media(max-width:900px){.grid2,.grid3{grid-template-columns:1fr;}}
.chart-wrap{height:180px;position:relative;}
.fp-high{color:var(--red)!important;font-weight:700;}
.fp-med{color:var(--orange)!important;}
.mitre-grid{display:flex;flex-wrap:wrap;gap:10px;}
.mitre-card{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px;width:160px;transition:.15s;}
.mitre-card.active{border-color:var(--accent);background:rgba(88,166,255,.05);}
.mitre-card.inactive{opacity:.35;}
.mitre-name{font-size:11px;font-weight:700;margin-bottom:4px;}
.mitre-count{font-size:20px;font-weight:800;}
.mitre-tech{font-size:10px;color:var(--muted);margin-top:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
</style>
</head>
<body>
<header>
  <div class="logo">S</div>
  <div><div class="app-name">SOCops</div><div class="app-sub">Security Operations Center</div></div>
  """ + _nav("Metrics") + """
</header>
<main>
  <h1 style="font-size:20px;font-weight:700;margin-bottom:20px;">SOC Metrics</h1>

  <div class="kpi-grid" id="kpi-grid"><div style="color:var(--muted)">Loading…</div></div>

  <div class="grid2">
    <div class="card">
      <div class="card-title">Alert Volume (last 24h)</div>
      <div class="chart-wrap"><canvas id="hourlyChart"></canvas></div>
    </div>
    <div class="card">
      <div class="card-title">Analysis Rate (last 24h) <span style="font-size:10px;color:var(--muted);font-weight:400">— AI-analyzed events/hr, excludes [excluded]</span></div>
      <div class="chart-wrap"><canvas id="analysisRateChart"></canvas></div>
    </div>
  </div>

  <div class="grid2">
    <div class="card">
      <div class="card-title">Top 5 Agents (last 7d)</div>
      <div id="agents-table"></div>
    </div>
  </div>

  <div class="grid2">
    <div class="card">
      <div class="card-title">Noisy Rules (last 7d) <span style="font-size:10px;color:var(--muted);font-weight:400">— red=FP&gt;50%, orange=FP&gt;30%</span></div>
      <div id="rules-table"></div>
    </div>
    <div class="card">
      <div class="card-title">Detection Rule Library</div>
      <div id="rule-lib-table"></div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">MITRE ATT&amp;CK Coverage (last 7d)</div>
    <div class="mitre-grid" id="mitre-grid"><div style="color:var(--muted)">Loading…</div></div>
  </div>
</main>

<script>
const MITRE_TACTICS=['initial-access','execution','persistence','privilege-escalation',
  'defense-evasion','credential-access','discovery','lateral-movement','collection',
  'command-and-control','exfiltration','impact','reconnaissance','resource-development'];

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function lc(n){return n>=12?'crit':n>=10?'high':n>=7?'med':'low';}

function loadKpis(){
  fetch('/api/kpis').then(r=>r.json()).then(k=>{
    document.getElementById('kpi-grid').innerHTML=`
      <div class="kpi c-blue"><div class="kpi-label">MTTR</div><div class="kpi-value">${k.mttr_minutes}</div><div class="kpi-sub">minutes avg</div></div>
      <div class="kpi c-orange"><div class="kpi-label">FP Rate</div><div class="kpi-value">${k.fp_rate}%</div><div class="kpi-sub">false positive</div></div>
      <div class="kpi c-red"><div class="kpi-label">Alerts 24h</div><div class="kpi-value">${k.alerts_last_24h}</div><div class="kpi-sub">7d: ${k.alerts_last_7d}</div></div>
      <div class="kpi c-yellow"><div class="kpi-label">Backlog Age</div><div class="kpi-value">${k.oldest_new_hours}h</div><div class="kpi-sub">oldest unacked</div></div>
      <div class="kpi c-purple"><div class="kpi-label">Escalation Rate</div><div class="kpi-value">${k.escalation_rate}%</div><div class="kpi-sub">of resolved</div></div>
      <div class="kpi c-green"><div class="kpi-label">Analysis Rate</div><div class="kpi-value">${k.analysis_rate_1h}</div><div class="kpi-sub">events/hr now &nbsp;·&nbsp; 6h avg: ${k.analysis_rate_6h}</div></div>
    `;
    renderAgents(k.top_agents||[]);
    renderRules(k.top_rules||[]);
    renderHourlyChart(k.hourly_volume||[]);
    renderAnalysisRateChart(k.analysis_hourly||[]);
  });
}

function renderAgents(agents){
  const el=document.getElementById('agents-table');
  if(!agents.length){el.innerHTML='<div style="color:var(--muted);font-size:13px">No data.</div>';return;}
  el.innerHTML=`<table><thead><tr><th>Agent</th><th>Alerts</th></tr></thead><tbody>`+
    agents.map(a=>`<tr><td style="font-weight:600">${esc(a.agent_name)}</td><td style="color:var(--accent);font-weight:700">${a.count}</td></tr>`).join('')+
    `</tbody></table>`;
}

function renderRules(rules){
  const el=document.getElementById('rules-table');
  if(!rules.length){el.innerHTML='<div style="color:var(--muted);font-size:13px">No data.</div>';return;}
  el.innerHTML=`<table><thead><tr><th>Rule ID</th><th>Description</th><th>Total</th><th>FP</th><th>FP Rate</th></tr></thead><tbody>`+
    rules.map(r=>{
      const cls=r.fp_rate>50?'fp-high':r.fp_rate>30?'fp-med':'';
      return`<tr>
        <td><a href="/?rule_id=${esc(r.rule_id)}" style="color:var(--accent);text-decoration:none;font-size:12px">${esc(r.rule_id)}</a></td>
        <td style="font-size:12px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.rule_description)}</td>
        <td>${r.total}</td><td>${r.fp_count}</td>
        <td class="${cls}">${r.fp_rate}%</td>
      </tr>`;
    }).join('')+`</tbody></table>`;
}

function renderHourlyChart(data){
  const ctx=document.getElementById('hourlyChart');if(!ctx)return;
  new Chart(ctx,{type:'bar',data:{
    labels:data.map(d=>d.hour?d.hour.slice(11,16):''),
    datasets:[{data:data.map(d=>d.count),backgroundColor:'rgba(88,166,255,.5)',borderColor:'#58a6ff',borderWidth:1}]
  },options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
    scales:{x:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'#21262d'}},
            y:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'#21262d'},beginAtZero:true}}}});
}

function renderAnalysisRateChart(data){
  const ctx=document.getElementById('analysisRateChart');if(!ctx)return;
  new Chart(ctx,{type:'bar',data:{
    labels:data.map(d=>d.hour?d.hour.slice(11,16):''),
    datasets:[{data:data.map(d=>d.count),backgroundColor:'rgba(63,185,80,.5)',borderColor:'#3fb950',borderWidth:1,label:'analyzed/hr'}]
  },options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
    scales:{x:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'#21262d'}},
            y:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'#21262d'},beginAtZero:true}}}});
}

function loadRuleLib(){
  fetch('/api/rules').then(r=>r.json()).then(rules=>{
    const el=document.getElementById('rule-lib-table');
    if(!rules.length){el.innerHTML='<div style="color:var(--muted);font-size:13px">No rules.</div>';return;}
    el.innerHTML=`<div style="max-height:300px;overflow-y:auto"><table>
      <thead><tr><th>Rule ID</th><th>Total</th><th>New</th><th>FP%</th><th>Last Seen</th></tr></thead>
      <tbody>`+rules.slice(0,50).map(r=>{
        const cls=r.fp_rate>50?'fp-high':r.fp_rate>30?'fp-med':'';
        return`<tr style="cursor:pointer" onclick="window.location='/?rule_id='+encodeURIComponent('${esc(r.rule_id)}')">
          <td style="font-size:12px;color:var(--accent)">${esc(r.rule_id)}</td>
          <td>${r.total}</td><td>${r.new_count}</td>
          <td class="${cls}">${r.fp_rate}%</td>
          <td style="font-size:11px;color:var(--muted)">${r.last_seen?new Date(r.last_seen).toLocaleDateString():''}</td>
        </tr>`;
      }).join('')+`</tbody></table></div>`;
  });
}

function loadMitre(){
  fetch('/api/mitre').then(r=>r.json()).then(coverage=>{
    const el=document.getElementById('mitre-grid');
    el.innerHTML=MITRE_TACTICS.map(tactic=>{
      const d=coverage[tactic]||coverage[tactic.replace(/-/g,' ')]||null;
      const count=d?d.count:0;
      const tech=d&&d.techniques&&d.techniques[0]||'';
      const active=count>0;
      return`<div class="mitre-card ${active?'active':'inactive'}">
        <div class="mitre-name">${esc(tactic.replace(/-/g,' ').replace(/\\b\\w/g,c=>c.toUpperCase()))}</div>
        <div class="mitre-count">${count}</div>
        ${tech?`<div class="mitre-tech">${esc(tech)}</div>`:'<div class="mitre-tech">No coverage</div>'}
      </div>`;
    }).join('');
  });
}

loadKpis();
loadRuleLib();
loadMitre();
</script>
""" + PAGE_FOOTER


# ---------------------------------------------------------------------------
# Live analysis feed page
# ---------------------------------------------------------------------------

LIVE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>SOCops — Live</title>
<style>""" + COMMON_CSS + """
body{min-height:100vh;}
main{max-width:960px;margin:0 auto;padding:24px;}
.feed{display:flex;flex-direction:column;gap:12px;}
.entry{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);overflow:hidden;transition:border-color .2s;}
.entry.status-analyzing{border-color:var(--accent);animation:pulse-border 1.5s ease-in-out infinite;}
.entry.status-error{border-color:var(--red);}
@keyframes pulse-border{0%,100%{border-color:var(--accent);}50%{border-color:#1a4a7a;}}
.entry-header{display:flex;align-items:center;gap:10px;padding:10px 14px;border-bottom:1px solid var(--border);flex-wrap:wrap;}
.entry-header.status-analyzing{background:rgba(88,166,255,.06);}
.entry-header.status-error{background:rgba(248,81,73,.06);}
.engine-tag{font-size:10px;font-weight:700;padding:2px 7px;border-radius:10px;letter-spacing:.3px;flex-shrink:0;}
.engine-tag.ollama{background:rgba(63,185,80,.2);color:#3fb950;}
.engine-tag.openrouter{background:rgba(188,140,255,.2);color:#bc8cff;}
.entry-rule{font-size:13px;font-weight:600;flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.entry-meta{font-size:11px;color:var(--muted);display:flex;gap:8px;flex-shrink:0;align-items:center;}
.duration-badge{font-size:10px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:1px 7px;color:var(--muted);}
.entry-body{padding:14px 16px;font-size:13px;line-height:1.6;}
.entry-body h3{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin:14px 0 4px;}
.entry-body h3:first-child{margin-top:0;}
.entry-body p{margin:0 0 6px;}
.entry-body ol,.entry-body ul{margin:0 0 6px;padding-left:18px;}
.entry-body li{margin-bottom:3px;}
.entry-body code{background:var(--surface2);padding:1px 5px;border-radius:3px;font-family:monospace;font-size:12px;}
.analyzing-indicator{display:flex;align-items:center;gap:8px;color:var(--accent);font-size:13px;padding:14px 16px;}
.dots span{animation:blink 1.2s infinite;}
.dots span:nth-child(2){animation-delay:.2s;}
.dots span:nth-child(3){animation-delay:.4s;}
@keyframes blink{0%,80%,100%{opacity:.2;}40%{opacity:1;}}
.status-bar{display:flex;align-items:center;gap:12px;margin-bottom:20px;font-size:12px;color:var(--muted);}
.live-dot{width:8px;height:8px;border-radius:50%;background:var(--green);animation:livepulse 1.5s ease-in-out infinite;flex-shrink:0;}
@keyframes livepulse{0%,100%{opacity:1;}50%{opacity:.3;}}
.empty-state{color:var(--muted);font-size:13px;text-align:center;padding:60px 0;}
</style>
</head>
<body>
""" + _nav("Live") + """
<main>
  <div class="status-bar">
    <div class="live-dot"></div>
    <span id="status-text">Connecting…</span>
    <span id="unanalyzed-count" style="background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:2px 10px;font-size:11px;display:none"></span>
    <span style="margin-left:auto">Last 100 analyses · polls every 3s</span>
  </div>
  <div class="feed" id="feed"><div class="empty-state">Waiting for analysis activity…</div></div>
</main>

<script>
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

function lc(n){return n>=12?'crit':n>=10?'high':n>=7?'med':'low';}


function fmt(ms){
  if(ms===null||ms===undefined) return '';
  if(ms<1000) return ms+'ms';
  return (ms/1000).toFixed(1)+'s';
}

function renderEntry(e){
  const hdrCls = `entry-header status-${e.status}`;
  const engCls = `engine-tag ${e.engine}`;
  const lvlCls = `level-badge ${lc(e.level)}`;

  let body;
  if(e.status==='analyzing'){
    body=`<div class="analyzing-indicator">
      <div class="dots"><span>●</span><span>●</span><span>●</span></div>
      Sending to ${esc(e.engine)} (${esc(e.model)})…
    </div>`;
  } else if(e.status==='error'){
    body=`<div class="entry-body" style="color:var(--red)">Error: ${esc(e.response)}</div>`;
  } else {
    body=`<div class="entry-body">${renderMd(e.response)}</div>`;
  }

  return `<div class="entry status-${e.status}" id="entry-${e.seq}">
    <div class="${hdrCls}">
      <span class="${engCls}">${esc(e.engine)}</span>
      <span class="${lvlCls}">${e.level}</span>
      <span class="entry-rule">${esc(e.rule)}</span>
      <div class="entry-meta">
        <span>${esc(e.agent)}</span>
        <span style="color:var(--muted)">#${e.alert_id}</span>
        <span>${esc(e.ts)}</span>
        ${e.duration_ms!==null?`<span class="duration-badge">${fmt(e.duration_ms)}</span>`:''}
      </div>
    </div>
    ${body}
  </div>`;
}

// Markdown renderer for response body
function renderMd(text){
  if(!text) return '';
  // Process line by line for clean output
  const lines = esc(text).split('\\n');
  let html = '';
  let inOl = false;
  for(const raw of lines){
    const line = raw.trim();
    if(!line){ if(inOl){html+='</ol>';inOl=false;} html+=''; continue; }
    if(line.startsWith('### ')){
      if(inOl){html+='</ol>';inOl=false;}
      html+=`<h3>${line.slice(4)}</h3>`;
    } else if(/^\\d+\\.\\s/.test(line)){
      if(!inOl){html+='<ol>';inOl=true;}
      html+=`<li>${line.replace(/^\\d+\\.\\s/,'').replace(/\\*\\*(.+?)\\*\\*/g,'<strong>$1</strong>').replace(/`([^`]+)`/g,'<code>$1</code>')}</li>`;
    } else {
      if(inOl){html+='</ol>';inOl=false;}
      html+=`<p>${line.replace(/\\*\\*(.+?)\\*\\*/g,'<strong>$1</strong>').replace(/`([^`]+)`/g,'<code>$1</code>')}</p>`;
    }
  }
  if(inOl) html+='</ol>';
  return html;
}

let knownSeqs = new Set();
let maxSeq = 0;

function poll(){
  fetch('/api/live?since=0').then(r=>r.json()).then(entries=>{
    const feed = document.getElementById('feed');

    if(!entries.length && knownSeqs.size===0){
      document.getElementById('status-text').textContent='Idle — no analysis activity yet';
      return;
    }

    // Find entries to add or update
    let changed = false;
    for(const e of entries){
      const existing = document.getElementById('entry-'+e.seq);
      if(!existing){
        // Prepend new entry
        feed.insertAdjacentHTML('afterbegin', renderEntry(e));
        knownSeqs.add(e.seq);
        changed = true;
      } else if(e.status!=='analyzing'){
        // Update in-place (was analyzing, now done/error)
        existing.outerHTML = renderEntry(e);
        changed = true;
      }
      if(e.seq > maxSeq) maxSeq = e.seq;
    }

    // Remove "empty state" placeholder once we have entries
    const empty = feed.querySelector('.empty-state');
    if(empty && knownSeqs.size>0) empty.remove();

    // Status bar
    const analyzing = entries.filter(e=>e.status==='analyzing');
    document.getElementById('status-text').textContent =
      analyzing.length
        ? `Analyzing — ${analyzing.map(e=>e.engine+' #'+e.alert_id).join(', ')}`
        : `Live · ${knownSeqs.size} analyses loaded`;
  }).catch(()=>{
    document.getElementById('status-text').textContent='Connection error — retrying…';
  });
}

function pollStats(){
  fetch('/api/stats').then(r=>r.json()).then(s=>{
    const el = document.getElementById('unanalyzed-count');
    const n = s.unanalyzed || 0;
    el.textContent = n.toLocaleString() + ' unanalyzed';
    el.style.display = '';
    el.style.color = n > 500 ? 'var(--orange)' : n > 0 ? 'var(--yellow)' : 'var(--green)';
    el.style.borderColor = n > 500 ? 'var(--orange)' : n > 0 ? 'var(--yellow)' : 'var(--border)';
  }).catch(()=>{});
}

poll();
pollStats();
setInterval(poll, 3000);
setInterval(pollStats, 15000);
</script>
""" + PAGE_FOOTER


# ---------------------------------------------------------------------------
# Analysis Exclusions page
# ---------------------------------------------------------------------------

ANALYSIS_EXCLUSIONS_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>SOCops — Analysis Exclusions</title>
<style>""" + COMMON_CSS + """
body{min-height:100vh;}
main{max-width:960px;margin:0 auto;padding:24px;}
.form-row{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap;margin-bottom:20px;}
.form-group{display:flex;flex-direction:column;gap:4px;}
.form-group label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);}
.form-group input{background:var(--surface2);border:1px solid var(--border);color:var(--text);border-radius:var(--r);padding:7px 10px;font-size:13px;width:100%;}
.form-group input:focus{outline:none;border-color:var(--accent);}
.form-group input::placeholder{color:var(--muted);}
.excl-table{width:100%;border-collapse:collapse;}
.excl-table th{text-align:left;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);padding:8px 10px;border-bottom:1px solid var(--border);}
.excl-table td{padding:9px 10px;font-size:13px;border-bottom:1px solid var(--border);}
.excl-table tr:last-child td{border-bottom:none;}
.excl-table tr:hover td{background:var(--surface2);}
.rule-id-cell{font-family:monospace;color:var(--accent);font-size:12px;}
.agent-cell{font-weight:600;}
.agent-all{color:var(--muted);font-style:italic;}
.del-btn{background:none;border:none;color:var(--red);cursor:pointer;font-size:14px;padding:2px 6px;border-radius:4px;}
.del-btn:hover{background:rgba(248,81,73,.15);}
.badge-count{font-size:11px;background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:1px 8px;color:var(--muted);}
</style>
</head>
<body>
""" + _nav("Exclusions") + """
<main>
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
    <div>
      <h1 style="font-size:20px;font-weight:700;margin:0 0 4px">Analysis Exclusions</h1>
      <div style="font-size:12px;color:var(--muted)">Skip AI analysis for specific rule IDs — globally or per agent. Excluded alerts are stamped <code>[excluded]</code> and won't consume Ollama/OpenRouter quota.</div>
    </div>
  </div>

  <div class="card" style="margin-bottom:20px;">
    <div class="card-title">Add Exclusion</div>
    <div class="form-row">
      <div class="form-group" style="flex:0 0 160px;">
        <label>Rule ID</label>
        <input id="inp-rule" placeholder="e.g. 40704" />
      </div>
      <div class="form-group" style="flex:0 0 200px;">
        <label>Agent (blank = all agents)</label>
        <input id="inp-agent" placeholder="e.g. SV08  (leave blank for *)" />
      </div>
      <div class="form-group" style="flex:1;min-width:200px;">
        <label>Reason</label>
        <input id="inp-reason" placeholder="e.g. known noise — systemd restarts" />
      </div>
      <button class="btn save" onclick="addExclusion()">Add</button>
    </div>

    <div style="font-size:11px;color:var(--muted);margin-top:-8px;">
      Tip: rule IDs are shown as <strong>#id</strong> in the alert list and in the alert detail header.
      Use agent name <strong>*</strong> (or leave blank) to exclude across all hosts.
    </div>
  </div>

  <div class="card">
    <div class="card-title" style="display:flex;align-items:center;gap:8px;">
      Active Exclusions <span class="badge-count" id="excl-count">0</span>
    </div>
    <div id="excl-list"><div style="color:var(--muted);font-size:13px">Loading…</div></div>
  </div>
</main>

<script>
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

function load(){
  fetch('/api/analysis-exclusions').then(r=>r.json()).then(rows=>{
    document.getElementById('excl-count').textContent = rows.length;
    const el = document.getElementById('excl-list');
    if(!rows.length){
      el.innerHTML='<div style="color:var(--muted);font-size:13px;padding:8px 0">No exclusions defined.</div>';
      return;
    }
    el.innerHTML=`<table class="excl-table">
      <thead><tr>
        <th>Rule ID</th><th>Agent</th><th>Reason</th><th>Added</th><th></th>
      </tr></thead>
      <tbody>`+rows.map(r=>`
      <tr>
        <td class="rule-id-cell">${esc(r.rule_id)}</td>
        <td class="agent-cell">${r.agent_name==='*'?'<span class="agent-all">all agents</span>':esc(r.agent_name)}</td>
        <td style="color:var(--muted)">${esc(r.reason||'—')}</td>
        <td style="font-size:11px;color:var(--muted)">${r.created_at?r.created_at.slice(0,10):''}</td>
        <td><button class="del-btn" title="Remove exclusion" onclick="del(${r.id})">✕</button></td>
      </tr>`).join('')+`</tbody></table>`;
  });
}

function addExclusion(){
  const rule_id    = document.getElementById('inp-rule').value.trim();
  const agent_name = document.getElementById('inp-agent').value.trim() || '*';
  const reason     = document.getElementById('inp-reason').value.trim();
  if(!rule_id){alert('Rule ID is required.');return;}
  fetch('/api/analysis-exclusions',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({rule_id, agent_name, reason})
  }).then(r=>r.json()).then(res=>{
    if(res.error){alert('Error: '+res.error);return;}
    document.getElementById('inp-rule').value='';
    document.getElementById('inp-agent').value='';
    document.getElementById('inp-reason').value='';
    load();
  });
}

function del(id){
  if(!confirm('Remove this exclusion?'))return;
  fetch('/api/analysis-exclusions/'+id,{method:'DELETE'}).then(()=>load());
}

document.getElementById('inp-rule').addEventListener('keydown', e=>{ if(e.key==='Enter') document.getElementById('inp-agent').focus(); });
document.getElementById('inp-agent').addEventListener('keydown', e=>{ if(e.key==='Enter') document.getElementById('inp-reason').focus(); });
document.getElementById('inp-reason').addEventListener('keydown', e=>{ if(e.key==='Enter') addExclusion(); });

load();
</script>
""" + PAGE_FOOTER


# ---------------------------------------------------------------------------
# System page
# ---------------------------------------------------------------------------

SYSTEM_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>SOCops — System</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>""" + COMMON_CSS + """
body{min-height:100vh;}
main{max-width:1400px;margin:0 auto;padding:24px;}
.sys-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px;margin-bottom:20px;}
.chart-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:16px;}
.chart-title{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-bottom:4px;display:flex;justify-content:space-between;align-items:center;}
.chart-title span.val{font-size:18px;font-weight:800;color:var(--text);letter-spacing:0;text-transform:none;}
.chart-wrap{height:140px;position:relative;}
.gauge-row{display:flex;gap:24px;margin-top:10px;flex-wrap:wrap;}
.gauge-item{flex:1;min-width:100px;text-align:center;}
.gauge-label{font-size:10px;color:var(--muted);margin-bottom:4px;}
.gauge-bar{height:6px;border-radius:3px;background:var(--surface2);overflow:hidden;margin-bottom:3px;}
.gauge-fill{height:100%;border-radius:3px;transition:width .4s;}
.gauge-fill.ok{background:var(--green);}.gauge-fill.warn{background:var(--orange);}.gauge-fill.crit{background:var(--red);}
.gauge-val{font-size:12px;font-weight:700;}
.status-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px;}
.stat-pill{background:var(--surface);border:1px solid var(--border);border-radius:20px;padding:6px 14px;font-size:12px;display:flex;align-items:center;gap:6px;}
.stat-pill .lbl{color:var(--muted);}
.stat-pill .v{font-weight:700;}
#no-gpu{color:var(--muted);font-size:13px;padding:20px;text-align:center;}
</style>
</head>
<body>
""" + _nav("System") + """
<main>
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
    <h1 style="font-size:20px;font-weight:700;margin:0">System Health</h1>
    <div style="font-size:11px;color:var(--muted)">Live · updates every 5s &nbsp;<span id="last-update"></span></div>
  </div>

  <div class="status-row" id="status-row">
    <div class="stat-pill"><span class="lbl">CPU</span><span class="v" id="pill-cpu">—</span></div>
    <div class="stat-pill"><span class="lbl">RAM</span><span class="v" id="pill-mem">—</span></div>
    <div class="stat-pill"><span class="lbl">Swap</span><span class="v" id="pill-swp">—</span></div>
    <div class="stat-pill" id="pill-gpu-wrap" style="display:none"><span class="lbl">GPU</span><span class="v" id="pill-gpu">—</span></div>
    <div class="stat-pill" id="pill-temp-wrap" style="display:none"><span class="lbl">GPU Temp</span><span class="v" id="pill-temp">—</span></div>
  </div>

  <div class="sys-grid">
    <div class="chart-card">
      <div class="chart-title">CPU Usage <span class="val" id="cur-cpu">—</span></div>
      <div class="chart-wrap"><canvas id="cpuChart"></canvas></div>
    </div>
    <div class="chart-card">
      <div class="chart-title">Memory &amp; Swap <span class="val" id="cur-mem">—</span></div>
      <div class="chart-wrap"><canvas id="memChart"></canvas></div>
      <div class="gauge-row" id="mem-gauges"></div>
    </div>
    <div class="chart-card" id="gpu-card" style="display:none">
      <div class="chart-title">GPU Utilisation <span class="val" id="cur-gpu">—</span></div>
      <div class="chart-wrap"><canvas id="gpuChart"></canvas></div>
    </div>
    <div class="chart-card" id="gpu-mem-card" style="display:none">
      <div class="chart-title">GPU Memory <span class="val" id="cur-gpu-mem">—</span></div>
      <div class="chart-wrap"><canvas id="gpuMemChart"></canvas></div>
      <div class="gauge-row" id="gpu-mem-gauges"></div>
    </div>
  </div>
</main>

<script>
const COLORS = {
  cpu:    {line:'#58a6ff', fill:'rgba(88,166,255,.15)'},
  mem:    {line:'#3fb950', fill:'rgba(63,185,80,.15)'},
  swp:    {line:'#d29922', fill:'rgba(210,153,34,.15)'},
  gpu:    {line:'#bc8cff', fill:'rgba(188,140,255,.15)'},
  gpumem: {line:'#ff7b72', fill:'rgba(255,123,114,.15)'},
};

function mkChart(id, datasets){
  const ctx = document.getElementById(id);
  return new Chart(ctx, {
    type: 'line',
    data: { labels: [], datasets },
    options: {
      responsive: true, maintainAspectRatio: false, animation: false,
      plugins: { legend: { display: datasets.length > 1, labels: { color:'#8b949e', font:{size:10}, boxWidth:10 } } },
      scales: {
        x: { ticks:{ color:'#8b949e', font:{size:9}, maxTicksLimit:8 }, grid:{ color:'#21262d' } },
        y: { min:0, max:100, ticks:{ color:'#8b949e', font:{size:10}, callback: v=>v+'%' }, grid:{ color:'#21262d' } }
      }
    }
  });
}

function mkDataset(label, c){ return { label, data:[], borderColor:c.line, backgroundColor:c.fill, borderWidth:1.5, pointRadius:0, fill:true, tension:.3 }; }

const cpuChart    = mkChart('cpuChart',    [mkDataset('CPU %', COLORS.cpu)]);
const memChart    = mkChart('memChart',    [mkDataset('RAM %', COLORS.mem), mkDataset('Swap %', COLORS.swp)]);
let   gpuChart    = null;
let   gpuMemChart = null;

function gaugeClass(pct){ return pct>=85?'crit':pct>=60?'warn':'ok'; }

function gauge(label, pct, used, total, unit){
  const cls = gaugeClass(pct);
  return `<div class="gauge-item">
    <div class="gauge-label">${label}</div>
    <div class="gauge-bar"><div class="gauge-fill ${cls}" style="width:${Math.min(pct,100)}%"></div></div>
    <div class="gauge-val" style="color:var(--${cls==='ok'?'green':cls==='warn'?'orange':'red'})">${pct.toFixed(1)}%</div>
    <div style="font-size:10px;color:var(--muted)">${used} / ${total} ${unit}</div>
  </div>`;
}

function pushPoint(chart, label, ...vals){
  chart.data.labels.push(label);
  vals.forEach((v,i) => chart.data.datasets[i].data.push(v));
  if(chart.data.labels.length > 120){ chart.data.labels.shift(); chart.data.datasets.forEach(d=>d.data.shift()); }
  chart.update('none');
}

let gpuPresent = false;

function applyData(history){
  if(!history.length) return;

  // Detect GPU from latest snapshot
  const latest = history[history.length-1];
  if(latest.gpu_util !== null && !gpuPresent){
    gpuPresent = true;
    document.getElementById('gpu-card').style.display    = '';
    document.getElementById('gpu-mem-card').style.display= '';
    document.getElementById('pill-gpu-wrap').style.display = '';
    document.getElementById('pill-temp-wrap').style.display = '';
    gpuChart    = mkChart('gpuChart',    [mkDataset('GPU %',    COLORS.gpu)]);
    gpuMemChart = mkChart('gpuMemChart', [mkDataset('VRAM %',   COLORS.gpumem)]);
  }

  // Replay all history into charts (on first load)
  const needsReplay = cpuChart.data.labels.length === 0;
  const points = needsReplay ? history : [latest];

  points.forEach(s => {
    const lbl = s.ts ? s.ts.slice(11,19) : '';
    pushPoint(cpuChart, lbl, s.cpu);
    pushPoint(memChart, lbl, s.mem_pct, s.swp_pct);
    if(gpuPresent && gpuChart){
      pushPoint(gpuChart,    lbl, s.gpu_util  ?? 0);
      pushPoint(gpuMemChart, lbl, s.gpu_mem_pct ?? 0);
    }
  });

  // Pills
  document.getElementById('pill-cpu').textContent  = latest.cpu.toFixed(1)+'%';
  document.getElementById('pill-mem').textContent  = latest.mem_pct.toFixed(1)+'%';
  document.getElementById('pill-swp').textContent  = latest.swp_pct.toFixed(1)+'%';
  document.getElementById('cur-cpu').textContent   = latest.cpu.toFixed(1)+'%';
  document.getElementById('cur-mem').textContent   = latest.mem_pct.toFixed(1)+'%';

  // Gauges
  document.getElementById('mem-gauges').innerHTML =
    gauge('RAM',  latest.mem_pct, latest.mem_used, latest.mem_total, 'GiB') +
    gauge('Swap', latest.swp_pct, latest.swp_used, latest.swp_total, 'GiB');

  if(gpuPresent && latest.gpu_util !== null){
    document.getElementById('pill-gpu').textContent   = latest.gpu_util.toFixed(0)+'%';
    document.getElementById('cur-gpu').textContent    = latest.gpu_util.toFixed(0)+'%';
    document.getElementById('cur-gpu-mem').textContent= latest.gpu_mem_pct.toFixed(1)+'%';
    if(latest.gpu_temp !== null)
      document.getElementById('pill-temp').textContent = latest.gpu_temp.toFixed(0)+'°C';
    document.getElementById('gpu-mem-gauges').innerHTML =
      gauge('VRAM', latest.gpu_mem_pct, latest.gpu_mem_used, latest.gpu_mem_total, 'GiB');
  }

  document.getElementById('last-update').textContent = 'Updated ' + new Date().toLocaleTimeString();
}

let lastTs = null;

function poll(){
  fetch('/api/system').then(r=>r.json()).then(history => {
    if(!history.length) return;
    const newLatest = history[history.length-1].ts;
    if(newLatest === lastTs) return;
    if(lastTs === null){
      applyData(history);
    } else {
      const fresh = history.filter(s => s.ts > lastTs);
      if(fresh.length) applyData(fresh);
    }
    lastTs = newLatest;
  }).catch(()=>{});
}

// Initial load, then poll every 5s regardless of tab focus
poll();
setInterval(poll, 5000);
</script>
""" + PAGE_FOOTER


# ---------------------------------------------------------------------------
# Dashboard page (preserving original, with updated nav)
# ---------------------------------------------------------------------------

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>SOCops — Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2128;--border:#30363d;
  --text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;
  --green:#3fb950;--yellow:#d29922;--orange:#e3873a;--red:#f85149;
  --purple:#bc8cff;--critical:#ff6b6b;--high:#f0883e;--medium:#d29922;--low:#3fb950;
  --r:10px;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;min-height:100vh;}
header{background:#0d1117;border-bottom:1px solid var(--border);padding:10px 20px;display:flex;align-items:center;gap:16px;position:sticky;top:0;z-index:100;}
.logo{width:32px;height:32px;background:linear-gradient(135deg,#1a73e8,#58a6ff);border-radius:6px;display:flex;align-items:center;justify-content:center;font-weight:900;font-size:16px;color:#fff;}
.app-name{font-size:16px;font-weight:700;}
.app-sub{font-size:11px;color:var(--muted);}
nav{display:flex;gap:4px;margin-left:8px;}
nav a{padding:5px 12px;border-radius:6px;color:var(--muted);text-decoration:none;font-size:13px;transition:.15s;}
nav a:hover{background:var(--surface2);color:var(--text);}
nav a.active{background:var(--surface2);color:var(--accent);border:1px solid var(--border);}
.hdr-right{margin-left:auto;display:flex;align-items:center;gap:12px;font-size:12px;color:var(--muted);}
.pulse{width:7px;height:7px;border-radius:50%;background:var(--green);animation:pulse 2s infinite;}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(63,185,80,.4);}70%{box-shadow:0 0 0 5px rgba(63,185,80,0);}100%{box-shadow:0 0 0 0 rgba(63,185,80,0);}}
.countdown{font-variant-numeric:tabular-nums;min-width:70px;text-align:right;}
.countdown.soon{color:var(--yellow);}
main{padding:20px 24px;max-width:1600px;margin:0 auto;}
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:20px;}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:18px;position:relative;overflow:hidden;}
.kpi::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;}
.kpi.c-red::before{background:var(--red);}.kpi.c-orange::before{background:var(--orange);}
.kpi.c-blue::before{background:var(--accent);}.kpi.c-green::before{background:var(--green);}
.kpi.c-purple::before{background:var(--purple);}.kpi.c-yellow::before{background:var(--yellow);}
.kpi-label{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-bottom:10px;}
.kpi-value{font-size:28px;font-weight:800;line-height:1;}
.kpi-sub{font-size:11px;color:var(--muted);margin-top:6px;}.kpi-sub span{color:var(--text);font-weight:600;}
.delta-up{color:var(--red);}.delta-down{color:var(--green);}
.grid2{display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:16px;}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:16px;}
.grid2x{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px;}
@media(max-width:1100px){.grid2{grid-template-columns:1fr;}.grid3{grid-template-columns:1fr;}}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:18px;}
.card-title{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--border);}
.chart-wrap{position:relative;height:220px;}
table{width:100%;border-collapse:collapse;font-size:13px;}
th{text-align:left;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);padding:0 8px 8px;border-bottom:1px solid var(--border);}
td{padding:8px;border-bottom:1px solid var(--border);vertical-align:top;}
tr:last-child td{border-bottom:none;}
.lvl{display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:5px;font-size:11px;font-weight:700;}
.lvl.crit{background:rgba(255,107,107,.15);color:var(--critical);}.lvl.high{background:rgba(240,136,62,.15);color:var(--high);}
.lvl.med{background:rgba(210,153,34,.15);color:var(--medium);}.lvl.low{background:rgba(63,185,80,.1);color:var(--low);}
.agent-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px;}
.agent-card{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px;}
.agent-name{font-size:14px;font-weight:600;margin-bottom:4px;}.agent-meta{font-size:11px;color:var(--muted);}
.agent-status{display:inline-flex;align-items:center;gap:4px;font-size:11px;font-weight:600;padding:2px 8px;border-radius:20px;margin-top:6px;}
.agent-status.active{background:rgba(63,185,80,.1);color:var(--green);border:1px solid rgba(63,185,80,.3);}
.agent-status.disconnected{background:rgba(248,81,73,.1);color:var(--red);border:1px solid rgba(248,81,73,.3);}
.gauge-wrap{display:flex;flex-direction:column;gap:10px;}.gauge-row{display:flex;align-items:center;gap:10px;}
.gauge-label{width:100px;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.gauge-bar{flex:1;height:8px;background:var(--border);border-radius:4px;overflow:hidden;}
.gauge-fill{height:100%;border-radius:4px;background:var(--accent);}.gauge-fill.bad{background:var(--red);}.gauge-fill.warn{background:var(--yellow);}
.gauge-pct{width:36px;font-size:12px;font-weight:600;text-align:right;}
.cve-link{color:var(--accent);text-decoration:none;font-size:12px;}.cve-link:hover{text-decoration:underline;}
.mitre-tag{background:rgba(188,140,255,.1);color:var(--purple);border-radius:4px;padding:1px 5px;font-size:10px;font-weight:600;}
.empty{color:var(--muted);font-size:13px;padding:12px 0;text-align:center;}
""" + HIGH_SEVERITY_CSS + """
</style>
</head>
<body>
<header>
  <div class="logo">S</div>
  <div><div class="app-name">SOCops</div><div class="app-sub">Security Operations Center</div></div>
  """ + _nav("Dashboard") + """
  <div class="hdr-right">
    <div class="pulse"></div>
    <span id="last-update">Loading…</span>
    <div class="countdown" id="countdown">1:00</div>
    <span onclick="(function(){var bust=function(){var u=new URL(location.href);u.searchParams.set('_',Date.now());location.replace(u.toString());};if('caches' in window){caches.keys().then(function(k){return Promise.all(k.map(function(x){return caches.delete(x)}))}).then(bust)}else{bust()}})()" title="Clear browser cache and reload" style="color:var(--yellow);cursor:pointer;font-size:12px;">↺ Cache</span>
  </div>
</header>
<main id="main"><p style="color:var(--muted);padding:40px">Loading dashboard data…</p></main>
<script>
const REFRESH=60,WARN=10;
let cd=REFRESH,cdTimer;
const PALETTE=['#58a6ff','#3fb950','#bc8cff','#f0883e','#ff6b6b','#d29922','#79c0ff','#56d364'];
function levelCls(n){return n>=12?'crit':n>=10?'high':n>=7?'med':'low';}
function fmtTs(iso){if(!iso)return'';try{const d=new Date(iso),now=new Date(),diff=(now-d)/1000;if(diff<60)return Math.round(diff)+'s ago';if(diff<3600)return Math.round(diff/60)+'m ago';if(diff<86400)return Math.round(diff/3600)+'h ago';return d.toLocaleString();}catch(e){return iso;}}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function bar(items,max){if(!items||!items.length)return'<div class="empty">No data</div>';return items.slice(0,10).map(x=>{const pct=max?Math.round(x.count/max*100):0;return`<div style="margin-bottom:8px"><div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:3px"><span style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:80%;color:var(--text)">${esc(x.label)}</span><span style="color:var(--muted);flex-shrink:0;margin-left:8px">${x.count}</span></div><div style="height:5px;background:var(--border);border-radius:3px"><div style="width:${pct}%;height:100%;background:var(--accent);border-radius:3px"></div></div></div>`;}).join('');}
function render(d){
  const a24=d.alerts_24h,a7=d.alerts_7d,v=d.vulnerabilities,ac=d.agent_count;
  const pTotal=a7.prior_total||0,cTotal=a7.total||0;
  const deltaRaw=pTotal?Math.round((cTotal-pTotal)/pTotal*100):0;
  const deltaTxt=deltaRaw===0?'±0%':(deltaRaw>0?`+${deltaRaw}%`:`${deltaRaw}%`);
  const deltaCls=deltaRaw>0?'delta-up':'delta-down';
  document.getElementById('last-update').textContent='Updated '+fmtTs(d.generated_at);
  document.getElementById('main').innerHTML=`
  <div class="kpi-grid">
    <div class="kpi c-red"><div class="kpi-label">Alerts (24h)</div><div class="kpi-value">${a24.total||0}</div><div class="kpi-sub">High+: <span>${a24.high_plus||0}</span> Critical: <span>${a24.critical||0}</span></div></div>
    <div class="kpi c-green"><div class="kpi-label">Active Agents</div><div class="kpi-value">${ac.active||0}</div><div class="kpi-sub">Total: <span>${ac.total||0}</span> Down: <span>${ac.disconnected||0}</span></div></div>
    <div class="kpi c-orange"><div class="kpi-label">Critical Vulns</div><div class="kpi-value">${v.critical||0}</div><div class="kpi-sub">High: <span>${v.high||0}</span> Total: <span>${v.total||0}</span></div></div>
    <div class="kpi c-yellow"><div class="kpi-label">High Vulns</div><div class="kpi-value">${v.high||0}</div><div class="kpi-sub">Medium: <span>${v.medium||0}</span></div></div>
    <div class="kpi c-purple"><div class="kpi-label">FIM Events (24h)</div><div class="kpi-value">${(a24.by_group||[]).filter(g=>g.label==='syscheck').reduce((s,g)=>s+g.count,0)}</div><div class="kpi-sub">File integrity changes</div></div>
    <div class="kpi c-blue"><div class="kpi-label">Alerts (7d)</div><div class="kpi-value">${cTotal}</div><div class="kpi-sub">vs prior 7d: <span class="${deltaCls}">${deltaTxt}</span></div></div>
  </div>
  <div class="grid2">
    <div class="card"><div class="card-title">Alert Trend (7 days)</div><div class="chart-wrap"><canvas id="trendChart"></canvas></div></div>
    <div class="card"><div class="card-title">Alerts by Agent (24h)</div><div class="chart-wrap"><canvas id="agentChart"></canvas></div></div>
  </div>
  <div class="grid3">
    <div class="card"><div class="card-title">MITRE ATT&amp;CK Techniques</div><div id="mitreBar">${bar(a24.by_mitre,(a24.by_mitre&&a24.by_mitre[0])?a24.by_mitre[0].count:1)}</div></div>
    <div class="card"><div class="card-title">Top Rules (7d)</div><div id="rulesBar">${bar(a7.by_rule,(a7.by_rule&&a7.by_rule[0])?a7.by_rule[0].count:1)}</div></div>
    <div class="card"><div class="card-title">Vulnerability Severity</div><div class="chart-wrap"><canvas id="vulnChart"></canvas></div></div>
  </div>
  <div class="card" style="margin-bottom:16px"><div class="card-title">Agents</div><div class="agent-grid">${(d.agents||[]).map(a=>`<div class="agent-card"><div class="agent-name">${esc(a.name)}</div><div class="agent-meta">${esc(a.os)}</div><div class="agent-meta">${esc(a.ip||'—')}</div><div class="agent-meta">Group: ${esc(a.group||'—')}</div><div class="agent-status ${a.status}">${a.status==='active'?'● Active':'● Disconnected'}</div><div class="agent-meta" style="margin-top:4px">Last seen: ${fmtTs(a.lastKeepAlive)}</div></div>`).join('')}</div></div>
  <div class="grid2x">
    <div class="card"><div class="card-title">Recent Alerts (10)</div>${recentTable(d.recent_alerts)}</div>
    <div class="card"><div class="card-title">Privilege Escalation / Sudo (7d)</div>${sudoTable(d.sudo_events)}</div>
  </div>
  <div class="grid2x">
    <div class="card"><div class="card-title">FIM Changed Files (7d)</div>${fimTable(d.fim_changes)}</div>
    <div class="card"><div class="card-title">Windows Service Changes (7d)</div>${winSvcTable(d.win_svc_changes)}</div>
  </div>
  <div class="grid2x">
    <div class="card"><div class="card-title">Critical CVEs</div>${cveTable(d.critical_cves)}</div>
    <div class="card"><div class="card-title">Vulnerability by Agent</div><div id="vulnAgentBar">${bar(v.by_agent,(v.by_agent&&v.by_agent[0])?v.by_agent[0].count:1)}</div></div>
  </div>
  <div class="grid2x">
    <div class="card"><div class="card-title">CIS Compliance Score</div><div class="gauge-wrap" id="cisGauge"></div></div>
    <div class="card"><div class="card-title">CIS Failed Checks</div>${cisFailedTable(d.sca_failed_checks)}</div>
  </div>`;
  mkLine('trendChart',a7.over_time||[]);
  mkDoughnut('agentChart',a24.by_agent||[]);
  mkDoughnut('vulnChart',v.by_severity||[],['#ff6b6b','#f0883e','#d29922','#3fb950']);
  cisGauges(d.sca_scores||[]);
}
function mkLine(id,pts){const ctx=document.getElementById(id);if(!ctx)return;new Chart(ctx,{type:'line',data:{labels:pts.map(p=>{try{return new Date(p.ts).toLocaleDateString('en',{month:'short',day:'numeric'});}catch{return p.label;}}),datasets:[{label:'Alerts',data:pts.map(p=>p.count),borderColor:'#58a6ff',backgroundColor:'rgba(88,166,255,.08)',borderWidth:2,pointRadius:2,tension:.4,fill:true}]},options:{responsive:true,maintainAspectRatio:false,scales:{x:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'#21262d'}},y:{ticks:{color:'#8b949e',font:{size:10}},grid:{color:'#21262d'},beginAtZero:true}},plugins:{legend:{display:false}}}});}
function mkDoughnut(id,items,colors){const ctx=document.getElementById(id);if(!ctx)return;new Chart(ctx,{type:'doughnut',data:{labels:items.map(x=>x.label),datasets:[{data:items.map(x=>x.count),backgroundColor:colors||PALETTE,borderWidth:0}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'right',labels:{color:'#8b949e',font:{size:11},padding:10}}}}});}
function cisGauges(scores){const el=document.getElementById('cisGauge');if(!el)return;if(!scores.length){el.innerHTML='<div class="empty">No CIS data</div>';return;}el.innerHTML=scores.map(s=>{const pct=s.total?Math.round(s.score):0;const cls=pct>=70?'':pct>=50?'warn':'bad';return`<div class="gauge-row"><div class="gauge-label" title="${esc(s.agent)}">${esc(s.agent)}</div><div class="gauge-bar"><div class="gauge-fill ${cls}" style="width:${pct}%"></div></div><div class="gauge-pct">${pct}%</div></div>`;}).join('');}
function recentTable(rows){if(!rows||!rows.length)return'<div class="empty">No recent alerts</div>';return`<table><thead><tr><th>Level</th><th>Time</th><th>Agent</th><th>Rule</th></tr></thead><tbody>`+rows.map(r=>`<tr><td><span class="lvl ${levelCls(r.level)}">${r.level}</span></td><td style="white-space:nowrap;font-size:11px;color:var(--muted)">${fmtTs(r.ts)}</td><td style="font-size:12px">${esc(r.agent)}</td><td style="font-size:12px">${esc(r.rule)}${r.mitre?` <span class="mitre-tag">${esc(r.mitre)}</span>`:''}</td></tr>`).join('')+'</tbody></table>';}
function sudoTable(rows){if(!rows||!rows.length)return'<div class="empty">No sudo events</div>';return`<table><thead><tr><th>Time</th><th>Agent</th><th>From→To</th><th>Command</th></tr></thead><tbody>`+rows.map(r=>`<tr><td style="white-space:nowrap;font-size:11px;color:var(--muted)">${fmtTs(r.ts)}</td><td style="font-size:12px">${esc(r.agent)}</td><td style="font-size:12px">${esc(r.from_user)}→${esc(r.to_user)}</td><td style="font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.command)}</td></tr>`).join('')+'</tbody></table>';}
function fimTable(rows){if(!rows||!rows.length)return'<div class="empty">No FIM events</div>';return`<table><thead><tr><th>Level</th><th>Agent</th><th>Path</th><th>Event</th></tr></thead><tbody>`+rows.map(r=>`<tr><td><span class="lvl ${levelCls(r.level)}">${r.level}</span></td><td style="font-size:12px">${esc(r.agent)}</td><td style="font-size:11px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(r.path)}">${esc(r.path)}</td><td style="font-size:11px">${esc(r.event)}</td></tr>`).join('')+'</tbody></table>';}
function winSvcTable(rows){if(!rows||!rows.length)return'<div class="empty">No service changes</div>';return`<table><thead><tr><th>Time</th><th>Agent</th><th>Service</th><th>Change</th></tr></thead><tbody>`+rows.map(r=>`<tr><td style="white-space:nowrap;font-size:11px;color:var(--muted)">${fmtTs(r.ts)}</td><td style="font-size:12px">${esc(r.agent)}</td><td style="font-size:12px">${esc(r.service)}</td><td style="font-size:11px">${esc(r.from)}→${esc(r.to)}</td></tr>`).join('')+'</tbody></table>';}
function cveTable(rows){if(!rows||!rows.length)return'<div class="empty">No critical CVEs</div>';return`<table><thead><tr><th>CVE</th><th>Agent</th><th>Package</th><th>CVSS3</th></tr></thead><tbody>`+rows.map(r=>`<tr><td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${esc(r.cve)}" target="_blank">${esc(r.cve)}</a></td><td style="font-size:12px">${esc(r.agent)}</td><td style="font-size:12px">${esc(r.package)} ${esc(r.version)}</td><td style="font-size:12px;color:var(--critical);font-weight:700">${r.score||'—'}</td></tr>`).join('')+'</tbody></table>';}
function cisFailedTable(rows){if(!rows||!rows.length)return'<div class="empty">No failed checks</div>';return`<table><thead><tr><th>Agent</th><th>Check</th><th>Remediation</th></tr></thead><tbody>`+rows.slice(0,15).map(r=>`<tr><td style="font-size:12px;white-space:nowrap">${esc(r.agent)}</td><td style="font-size:12px">${esc(r.title)}</td><td style="font-size:11px;color:var(--muted)">${esc(r.remediation)}</td></tr>`).join('')+'</tbody></table>';}
function load(){fetch('/api/data').then(r=>r.json()).then(d=>{render(d);cd=REFRESH;}).catch(e=>console.error('data error:',e));}
function tick(){cd--;const el=document.getElementById('countdown');const m=Math.floor(cd/60),s=cd%60;el.textContent=m+':'+(s<10?'0':'')+s;el.classList.toggle('soon',cd<=WARN);if(cd<=0)load();}
load();cdTimer=setInterval(tick,1000);
</script>
""" + PAGE_FOOTER


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    db.init_db()

    t_poll     = threading.Thread(target=_poller,           daemon=True, name="poller")
    t_analyst  = threading.Thread(target=_analyst_worker,   daemon=True, name="analyst")
    t_enrich   = threading.Thread(target=_enrichment_worker,daemon=True, name="enrichment")
    t_sys      = threading.Thread(target=_sys_collector,    daemon=True, name="syscollector")
    t_poll.start()
    t_analyst.start()
    t_enrich.start()
    t_sys.start()

    server = http.server.ThreadingHTTPServer(("0.0.0.0", SOCOPS_PORT), Handler)
    print(f"SOCops listening on http://0.0.0.0:{SOCOPS_PORT}")
    print(f"  Queue:       http://0.0.0.0:{SOCOPS_PORT}/")
    print(f"  Dashboard:   http://0.0.0.0:{SOCOPS_PORT}/dashboard")
    print(f"  Cases:       http://0.0.0.0:{SOCOPS_PORT}/cases")
    print(f"  Suppressions:http://0.0.0.0:{SOCOPS_PORT}/suppressions")
    print(f"  Metrics:     http://0.0.0.0:{SOCOPS_PORT}/metrics")
    print(f"  System:      http://0.0.0.0:{SOCOPS_PORT}/system")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")


if __name__ == "__main__":
    main()
