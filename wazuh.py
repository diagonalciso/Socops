#!/usr/bin/env python3
"""
Wazuh OpenSearch Dashboards API client.
Shared between dashboard rendering and the SOC alert poller.
"""

import json
import os
import ssl
import threading
import time
import urllib.request
import http.cookiejar
from datetime import datetime, timezone

WAZUH_HOST = os.environ.get("WAZUH_HOST", "")
WAZUH_USER = os.environ.get("WAZUH_USER", "")
WAZUH_PASS = os.environ.get("WAZUH_PASS", "")
CACHE_TTL = int(os.environ.get("CACHE_TTL", "300"))

NOISE_MIN_LEVEL = 5

NOISE_MUST_NOT = [
    {"match_phrase": {"rule.description": "VirusTotal: Error: Public API request rate limit reached"}},
    {"match_phrase": {"rule.description": "VirusTotal: Alert - No records in VirusTotal database"}},
    {"match_phrase": {"rule.description": "PAM: Login session opened."}},
    {"match_phrase": {"rule.description": "PAM: Login session closed."}},
    {"match_phrase": {"rule.description": "sshd: authentication success."}},
    {"match_phrase": {"rule.description": "Wazuh agent started."}},
    {"match_phrase": {"rule.description": "Wazuh manager started."}},
    {"match_phrase": {"rule.description": "ossec: Ossec server started."}},
]


def _total(hits_total):
    """Handle both OpenSearch total formats: int or {value: N, relation: eq}."""
    if isinstance(hits_total, dict):
        return hits_total.get("value", 0)
    return hits_total or 0


class WazuhClient:
    def __init__(self):
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE
        self._lock = threading.Lock()
        self._cache = {}
        self._cache_ts = 0
        self._session_cookie = None

    def _login(self):
        cj = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self._ctx),
            urllib.request.HTTPCookieProcessor(cj)
        )
        body = json.dumps({"username": WAZUH_USER, "password": WAZUH_PASS}).encode()
        req = urllib.request.Request(
            f"https://{WAZUH_HOST}/auth/login",
            data=body, method="POST",
            headers={"Content-Type": "application/json", "osd-xsrf": "true"}
        )
        with opener.open(req, timeout=10) as r:
            r.read()
        cookies = {c.name: c.value for c in cj}
        if "security_authentication" not in cookies:
            raise RuntimeError("Login failed — no session cookie returned")
        self._session_cookie = cookies["security_authentication"]

    def _search(self, index, body):
        if not self._session_cookie:
            self._login()
        payload = json.dumps({"params": {"index": index, "body": body}}).encode()
        req = urllib.request.Request(
            f"https://{WAZUH_HOST}/internal/search/opensearch-with-long-numerals",
            data=payload, method="POST",
            headers={
                "Content-Type": "application/json",
                "osd-xsrf": "true",
                "Cookie": f"security_authentication={self._session_cookie}"
            }
        )
        cj = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self._ctx),
            urllib.request.HTTPCookieProcessor(cj)
        )
        try:
            with opener.open(req, timeout=30) as r:
                return json.loads(r.read())["rawResponse"]
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                self._session_cookie = None
                self._login()
                return self._search(index, body)
            raise

    def _alert_query(self, time_range):
        return {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": time_range}}},
                    {"range": {"rule.level": {"gte": NOISE_MIN_LEVEL}}},
                ],
                "must_not": NOISE_MUST_NOT,
            }
        }

    def fetch_new_alerts(self, since_iso, size=500):
        """Fetch filtered alerts since an ISO timestamp (for the SOC poller)."""
        query = {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": since_iso}}},
                    {"range": {"rule.level": {"gte": NOISE_MIN_LEVEL}}},
                ],
                "must_not": NOISE_MUST_NOT,
            }
        }
        result = self._search("wazuh-alerts-*", {
            "query": query,
            "sort": [{"timestamp": {"order": "asc"}}],
            "size": size,
            "_source": True,
        })
        return result.get("hits", {}).get("hits", [])

    def fetch_all(self):
        """Return full dashboard data payload, cached for CACHE_TTL seconds."""
        with self._lock:
            now = time.time()
            if self._cache and (now - self._cache_ts) < CACHE_TTL:
                return self._cache
            data = self._build_data()
            self._cache = data
            self._cache_ts = now
            return data

    def _build_data(self):
        # --- Agents ---
        r_agents = self._search("wazuh-monitoring-*", {
            "size": 0,
            "aggs": {
                "agents": {
                    "terms": {"field": "id", "size": 50},
                    "aggs": {"latest": {"top_hits": {
                        "size": 1,
                        "sort": [{"timestamp": {"order": "desc"}}],
                        "_source": ["id","name","ip","status","os.name","os.platform",
                                    "version","group","dateAdd","lastKeepAlive"]
                    }}}
                }
            }
        })
        agents = []
        for bucket in r_agents["aggregations"]["agents"]["buckets"]:
            src = bucket["latest"]["hits"]["hits"][0]["_source"]
            agents.append({
                "id": src.get("id", ""),
                "name": src.get("name", ""),
                "ip": src.get("ip", ""),
                "status": src.get("status", "unknown"),
                "os": src.get("os", {}).get("name", "Unknown"),
                "platform": src.get("os", {}).get("platform", ""),
                "version": src.get("version", ""),
                "group": ", ".join(src.get("group", [])),
                "lastKeepAlive": src.get("lastKeepAlive", ""),
                "dateAdd": src.get("dateAdd", ""),
            })
        agents.sort(key=lambda a: a["id"])

        # --- Alerts 24h ---
        r_24h = self._search("wazuh-alerts-*", {
            "size": 0,
            "query": self._alert_query("now-24h"),
            "aggs": {
                "over_time": {"date_histogram": {"field": "timestamp", "fixed_interval": "1h"}},
                "by_agent": {"terms": {"field": "agent.name", "size": 10}},
                "by_level": {"terms": {"field": "rule.level", "size": 20}},
                "by_rule": {"terms": {"field": "rule.description", "size": 10}},
                "by_mitre": {"terms": {"field": "rule.mitre.technique", "size": 10}},
                "by_group": {"terms": {"field": "rule.groups", "size": 10}},
                "high_plus": {"filter": {"range": {"rule.level": {"gte": 7}}}},
                "critical": {"filter": {"range": {"rule.level": {"gte": 12}}}},
            }
        })
        agg24 = r_24h["aggregations"]

        # --- Alerts 7d ---
        r_7d = self._search("wazuh-alerts-*", {
            "size": 0,
            "query": self._alert_query("now-7d"),
            "aggs": {
                "over_time": {"date_histogram": {"field": "timestamp", "fixed_interval": "6h"}},
                "by_rule": {"terms": {"field": "rule.description", "size": 15}},
            }
        })

        # --- Prior 7d for week-over-week ---
        r_prior7d = self._search("wazuh-alerts-*", {
            "size": 0,
            "query": {"bool": {
                "must": [
                    {"range": {"timestamp": {"gte": "now-14d", "lt": "now-7d"}}},
                    {"range": {"rule.level": {"gte": NOISE_MIN_LEVEL}}},
                ],
                "must_not": NOISE_MUST_NOT,
            }},
            "aggs": {
                "high_plus": {"filter": {"range": {"rule.level": {"gte": 7}}}},
            }
        })

        # --- Vulnerabilities ---
        r_vulns = self._search("wazuh-states-vulnerabilities-*", {
            "size": 0,
            "aggs": {
                "by_severity": {"terms": {"field": "vulnerability.severity", "size": 10}},
                "by_agent": {"terms": {"field": "agent.name", "size": 10}},
                "top_cves": {"terms": {"field": "vulnerability.id", "size": 10}},
            }
        })

        # --- Recent alerts (last 10) ---
        r_recent = self._search("wazuh-alerts-*", {
            "size": 10,
            "query": self._alert_query("now-7d"),
            "sort": [{"timestamp": {"order": "desc"}}],
            "_source": ["timestamp","agent.name","rule.description","rule.level",
                        "rule.mitre.technique","data.srcip"]
        })
        recent_alerts = []
        for h in r_recent["hits"]["hits"]:
            s = h["_source"]
            recent_alerts.append({
                "ts": s.get("timestamp", ""),
                "agent": s.get("agent", {}).get("name", ""),
                "rule": s.get("rule", {}).get("description", ""),
                "level": s.get("rule", {}).get("level", 0),
                "mitre": ", ".join(s.get("rule", {}).get("mitre", {}).get("technique", [])),
                "srcip": s.get("data", {}).get("srcip", ""),
            })

        # --- CIS individual failed checks ---
        r_sca_checks = self._search("wazuh-alerts-*", {
            "size": 20,
            "query": {"bool": {"must": [
                {"range": {"timestamp": {"gte": "now-30d"}}},
                {"term": {"rule.groups": "sca"}},
                {"term": {"data.sca.check.result": "failed"}},
            ]}},
            "sort": [{"timestamp": {"order": "desc"}}],
            "_source": ["agent.name","data.sca.check.title","data.sca.check.remediation","data.sca.policy_id"]
        })
        sca_failed_checks = []
        seen_checks = set()
        for h in r_sca_checks["hits"]["hits"]:
            s = h["_source"]
            check = s.get("data", {}).get("sca", {}).get("check", {})
            title = check.get("title", "")
            agent = s.get("agent", {}).get("name", "")
            key = (agent, title)
            if title and key not in seen_checks:
                seen_checks.add(key)
                sca_failed_checks.append({
                    "agent": agent,
                    "title": title,
                    "remediation": check.get("remediation", ""),
                    "policy": s.get("data", {}).get("sca", {}).get("policy_id", ""),
                })

        # --- CIS compliance summary per agent ---
        r_sca = self._search("wazuh-alerts-*", {
            "size": 0,
            "query": {"bool": {"must": [
                {"range": {"timestamp": {"gte": "now-30d"}}},
                {"term": {"rule.groups": "sca"}},
                {"term": {"data.sca.type": "summary"}}
            ]}},
            "aggs": {"by_agent": {
                "terms": {"field": "agent.name", "size": 20},
                "aggs": {"latest": {"top_hits": {
                    "size": 1,
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "_source": ["agent.name","data.sca.score","data.sca.passed",
                                "data.sca.failed","data.sca.total_checks","data.sca.policy"]
                }}}
            }}
        })
        sca_scores = []
        for b in r_sca["aggregations"]["by_agent"]["buckets"]:
            s = b["latest"]["hits"]["hits"][0]["_source"]
            sca = s.get("data", {}).get("sca", {})
            sca_scores.append({
                "agent": s.get("agent", {}).get("name", b["key"]),
                "score": int(sca.get("score", 0)),
                "passed": int(sca.get("passed", 0)),
                "failed": int(sca.get("failed", 0)),
                "total": int(sca.get("total_checks", 0)),
                "policy": sca.get("policy", ""),
            })

        # --- FIM changed files (backup noise excluded) ---
        r_fim = self._search("wazuh-alerts-*", {
            "size": 15,
            "query": {"bool": {"must": [
                {"range": {"timestamp": {"gte": "now-7d"}}},
                {"term": {"rule.groups": "syscheck"}}
            ], "must_not": [
                {"wildcard": {"syscheck.path": "*/config_backups/*"}},
                {"wildcard": {"syscheck.path": "*/backup*"}},
                {"wildcard": {"syscheck.path": "*/.cache/*"}},
                {"wildcard": {"syscheck.path": "*/tmp/*"}},
            ]}},
            "sort": [{"timestamp": {"order": "desc"}}],
            "_source": ["timestamp","agent.name","syscheck.path","syscheck.event",
                        "syscheck.changed_attributes","rule.level"]
        })
        fim_changes = []
        seen_fim = set()
        for h in r_fim["hits"]["hits"]:
            s = h["_source"]
            path = s.get("syscheck", {}).get("path", "")
            if path and path not in seen_fim:
                seen_fim.add(path)
                fim_changes.append({
                    "ts": s.get("timestamp", ""),
                    "agent": s.get("agent", {}).get("name", ""),
                    "path": path,
                    "event": s.get("syscheck", {}).get("event", ""),
                    "attrs": ", ".join(s.get("syscheck", {}).get("changed_attributes", [])),
                    "level": s.get("rule", {}).get("level", 0),
                })

        # --- Privilege escalation / sudo ---
        r_sudo = self._search("wazuh-alerts-*", {
            "size": 10,
            "query": {"bool": {"must": [
                {"range": {"timestamp": {"gte": "now-7d"}}},
                {"term": {"rule.groups": "sudo"}}
            ]}},
            "sort": [{"timestamp": {"order": "desc"}}],
            "_source": ["timestamp","agent.name","rule.description","rule.level",
                        "data.srcuser","data.dstuser","data.command"]
        })
        sudo_events = []
        for h in r_sudo["hits"]["hits"]:
            s = h["_source"]
            sudo_events.append({
                "ts": s.get("timestamp", ""),
                "agent": s.get("agent", {}).get("name", ""),
                "rule": s.get("rule", {}).get("description", ""),
                "level": s.get("rule", {}).get("level", 0),
                "from_user": s.get("data", {}).get("srcuser", ""),
                "to_user": s.get("data", {}).get("dstuser", ""),
                "command": s.get("data", {}).get("command", ""),
            })

        # --- Windows service changes ---
        r_winsvc = self._search("wazuh-alerts-*", {
            "size": 10,
            "query": {"bool": {"must": [
                {"range": {"timestamp": {"gte": "now-7d"}}},
                {"term": {"data.win.system.eventID": "7040"}}
            ]}},
            "sort": [{"timestamp": {"order": "desc"}}],
            "_source": ["timestamp","agent.name","rule.level","data.win.eventdata","rule.description"]
        })
        win_svc_changes = []
        for h in r_winsvc["hits"]["hits"]:
            s = h["_source"]
            ed = s.get("data", {}).get("win", {}).get("eventdata", {})
            win_svc_changes.append({
                "ts": s.get("timestamp", ""),
                "agent": s.get("agent", {}).get("name", ""),
                "service": ed.get("param1", ""),
                "from": ed.get("param2", ""),
                "to": ed.get("param3", ""),
                "level": s.get("rule", {}).get("level", 0),
            })

        # --- Critical CVEs ---
        r_cve = self._search("wazuh-states-vulnerabilities-*", {
            "size": 10,
            "query": {"term": {"vulnerability.severity": "Critical"}},
            "_source": ["agent.name","vulnerability.id","vulnerability.severity",
                        "vulnerability.title","package.name","package.version","vulnerability.cvss"],
        })
        critical_cves = []
        seen_cve = set()
        for h in r_cve["hits"]["hits"]:
            s = h["_source"]
            cve_id = s.get("vulnerability", {}).get("id", "")
            key = (cve_id, s.get("agent", {}).get("name", ""))
            if key not in seen_cve:
                seen_cve.add(key)
                cvss3 = s.get("vulnerability", {}).get("cvss", {}).get("cvss3", {})
                critical_cves.append({
                    "agent": s.get("agent", {}).get("name", ""),
                    "cve": cve_id,
                    "title": s.get("vulnerability", {}).get("title", ""),
                    "package": s.get("package", {}).get("name", ""),
                    "version": s.get("package", {}).get("version", ""),
                    "score": cvss3.get("base_score", ""),
                })

        def buckets(agg_key, result):
            return [{"label": b["key"], "count": b["doc_count"]}
                    for b in result["aggregations"][agg_key]["buckets"]]

        def timeseries(agg_key, result):
            return [{"ts": b["key"], "label": b["key_as_string"], "count": b["doc_count"]}
                    for b in result["aggregations"][agg_key]["buckets"]]

        vuln_severity = {b["key"]: b["doc_count"]
                         for b in r_vulns["aggregations"]["by_severity"]["buckets"]}

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "agents": agents,
            "agent_count": {
                "total": len(agents),
                "active": sum(1 for a in agents if a["status"] == "active"),
                "disconnected": sum(1 for a in agents if a["status"] == "disconnected"),
            },
            "alerts_24h": {
                "total": _total(r_24h["hits"]["total"]),
                "high_plus": agg24["high_plus"]["doc_count"],
                "critical": agg24["critical"]["doc_count"],
                "by_agent": buckets("by_agent", r_24h),
                "by_level": buckets("by_level", r_24h),
                "by_rule": buckets("by_rule", r_24h),
                "by_mitre": buckets("by_mitre", r_24h),
                "by_group": buckets("by_group", r_24h),
                "over_time": timeseries("over_time", r_24h),
            },
            "alerts_7d": {
                "total": _total(r_7d["hits"]["total"]),
                "prior_total": _total(r_prior7d["hits"]["total"]),
                "prior_high_plus": r_prior7d["aggregations"]["high_plus"]["doc_count"],
                "by_rule": buckets("by_rule", r_7d),
                "over_time": timeseries("over_time", r_7d),
            },
            "vulnerabilities": {
                "total": _total(r_vulns["hits"]["total"]),
                "critical": vuln_severity.get("Critical", 0),
                "high": vuln_severity.get("High", 0),
                "medium": vuln_severity.get("Medium", 0),
                "low": vuln_severity.get("Low", 0),
                "by_severity": buckets("by_severity", r_vulns),
                "by_agent": buckets("by_agent", r_vulns),
                "top_cves": buckets("top_cves", r_vulns),
            },
            "recent_alerts": recent_alerts,
            "sca_scores": sca_scores,
            "sca_failed_checks": sca_failed_checks,
            "fim_changes": fim_changes,
            "sudo_events": sudo_events,
            "win_svc_changes": win_svc_changes,
            "critical_cves": critical_cves,
        }
