#!/usr/bin/env python3
"""SQLite storage for the SOC alert queue."""

import json
import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "socops.db")

_conn_lock = None  # populated after import of threading


def _get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                wazuh_id        TEXT    UNIQUE,
                timestamp       TEXT,
                agent_name      TEXT,
                agent_ip        TEXT,
                rule_id         TEXT,
                rule_level      INTEGER,
                rule_description TEXT,
                rule_groups     TEXT,
                mitre_technique TEXT,
                mitre_tactic    TEXT,
                srcip           TEXT,
                full_json       TEXT,
                status          TEXT    DEFAULT 'new',
                analysis        TEXT,
                operator_notes  TEXT    DEFAULT '',
                created_at      TEXT    DEFAULT (datetime('now')),
                updated_at      TEXT    DEFAULT (datetime('now'))
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS suppression_rules (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                field      TEXT,
                operator   TEXT,
                value      TEXT,
                reason     TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                expires_at TEXT,
                hits       INTEGER DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alert_notes (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id       INTEGER,
                body           TEXT,
                auto_generated INTEGER DEFAULT 0,
                created_at     TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                title       TEXT,
                status      TEXT DEFAULT 'open',
                severity    INTEGER DEFAULT 0,
                description TEXT,
                created_at  TEXT DEFAULT (datetime('now')),
                closed_at   TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS case_alerts (
                case_id  INTEGER,
                alert_id INTEGER,
                PRIMARY KEY (case_id, alert_id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analysis_exclusions (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id    TEXT NOT NULL,
                agent_name TEXT NOT NULL DEFAULT '*',
                reason     TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_excl_rule_agent ON analysis_exclusions(rule_id, agent_name)")

        conn.execute("CREATE INDEX IF NOT EXISTS idx_status    ON alerts(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ts        ON alerts(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_level     ON alerts(rule_level)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agent     ON alerts(agent_name)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_notes_aid ON alert_notes(alert_id)")

        # ADD new columns to existing alerts table (idempotent)
        for col_sql in [
            "ALTER TABLE alerts ADD COLUMN group_key TEXT",
            "ALTER TABLE alerts ADD COLUMN enrichment TEXT",
            "ALTER TABLE alerts ADD COLUMN assigned_to TEXT DEFAULT ''",
        ]:
            try:
                conn.execute(col_sql)
            except Exception:
                pass  # column already exists

        conn.commit()


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def get_setting(key, default=None):
    with _get_conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default


def set_setting(key, value):
    with _get_conn() as conn:
        conn.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (key, str(value)))
        conn.commit()


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

def save_alert(hit):
    """
    Persist one OpenSearch alert hit.
    Returns True if newly inserted, False if already known (duplicate wazuh_id).
    """
    src = hit.get("_source", {})
    wazuh_id = hit.get("_id", "")

    rule = src.get("rule", {})
    mitre = rule.get("mitre", {})
    agent = src.get("agent", {})
    data = src.get("data", {})

    agent_name = agent.get("name", "")
    rule_id = rule.get("id", "")
    group_key = f"{agent_name}::{rule_id}"

    with _get_conn() as conn:
        try:
            conn.execute("""
                INSERT INTO alerts
                    (wazuh_id, timestamp, agent_name, agent_ip,
                     rule_id, rule_level, rule_description, rule_groups,
                     mitre_technique, mitre_tactic, srcip, full_json, group_key)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                wazuh_id,
                src.get("timestamp", ""),
                agent_name,
                agent.get("ip", ""),
                rule_id,
                int(rule.get("level", 0)),
                rule.get("description", ""),
                json.dumps(rule.get("groups", [])),
                ", ".join(mitre.get("technique", [])),
                ", ".join(mitre.get("tactic", [])),
                data.get("srcip", ""),
                json.dumps(src),
                group_key,
            ))
            conn.commit()

            # check suppression
            alert_id = conn.execute("SELECT id FROM alerts WHERE wazuh_id=?", (wazuh_id,)).fetchone()
            if alert_id:
                alert_dict = {
                    "rule_id": rule_id,
                    "agent_name": agent_name,
                    "srcip": data.get("srcip", ""),
                    "rule_description": rule.get("description", ""),
                }
                if check_suppressed(alert_dict, conn=conn):
                    conn.execute(
                        "UPDATE alerts SET status='suppressed', updated_at=datetime('now') WHERE wazuh_id=?",
                        (wazuh_id,)
                    )
                    conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


CATEGORY_SQL = {
    "systemd":   "rule_groups LIKE '%systemd%'",
    "integrity": "rule_groups LIKE '%syscheck%'",
    "cis":       "rule_groups LIKE '%sca%'",
    "web":       "rule_groups LIKE '%web%'",
    "windows":   "rule_groups LIKE '%windows%'",
}


def get_alerts(status=None, category=None, limit=300, offset=0, group_key=None, rule_id=None, since=None):
    with _get_conn() as conn:
        conditions, params = [], []
        if status == "excluded":
            conditions.append("analysis='[excluded]'")
        elif status and status != "all":
            conditions.append("status=?")
            conditions.append("analysis!='[excluded]'")
            params.append(status)
        else:
            conditions.append("(analysis IS NULL OR analysis!='[excluded]')")
        if category and category in CATEGORY_SQL:
            conditions.append(CATEGORY_SQL[category])
        if group_key:
            conditions.append("group_key=?")
            params.append(group_key)
        if rule_id:
            conditions.append("rule_id=?")
            params.append(rule_id)
        if since:
            conditions.append("created_at >= ?")
            params.append(since)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY rule_level DESC, timestamp DESC LIMIT ? OFFSET ?",
            (*params, limit, offset)
        ).fetchall()
        return [dict(r) for r in rows]


def get_alert(alert_id):
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        return dict(row) if row else None


def update_alert(alert_id, status=None, analysis=None, notes=None, assigned_to=None):
    with _get_conn() as conn:
        if status is not None:
            conn.execute(
                "UPDATE alerts SET status=?, updated_at=datetime('now') WHERE id=?",
                (status, alert_id)
            )
            # auto-note on status change
            add_note(alert_id, f"Status changed to {status}", auto_generated=True, conn=conn)
        if analysis is not None:
            conn.execute(
                "UPDATE alerts SET analysis=?, updated_at=datetime('now') WHERE id=?",
                (analysis, alert_id)
            )
        if notes is not None:
            conn.execute(
                "UPDATE alerts SET operator_notes=?, updated_at=datetime('now') WHERE id=?",
                (notes, alert_id)
            )
        if assigned_to is not None:
            conn.execute(
                "UPDATE alerts SET assigned_to=?, updated_at=datetime('now') WHERE id=?",
                (assigned_to, alert_id)
            )
        conn.commit()


def get_stats():
    with _get_conn() as conn:
        def count(where="", params=()):
            return conn.execute(f"SELECT COUNT(*) FROM alerts {where}", params).fetchone()[0]

        return {
            "total":      count(),
            "new":        count("WHERE status='new'"),
            "escalated":  count("WHERE status='escalated'"),
            "ack":        count("WHERE status='ack'"),
            "fp":         count("WHERE status='fp'"),
            "today":      count("WHERE date(created_at)=date('now')"),
            "unanalyzed": count("WHERE analysis IS NULL AND status='new'"),
        }


def get_unanalyzed(limit=10, min_level=0):
    """Return alerts that have not yet been analyzed, highest level first."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE analysis IS NULL AND rule_level >= ? ORDER BY rule_level DESC, timestamp DESC LIMIT ?",
            (min_level, limit)
        ).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Alert grouping
# ---------------------------------------------------------------------------

def get_alert_groups(status=None, category=None):
    """Return one row per group_key with aggregate stats."""
    with _get_conn() as conn:
        conditions, params = [], []
        if status and status != "all":
            conditions.append("status=?")
            params.append(status)
        if category and category in CATEGORY_SQL:
            conditions.append(CATEGORY_SQL[category])
        conditions.append("group_key IS NOT NULL AND group_key != ''")
        where = "WHERE " + " AND ".join(conditions)
        rows = conn.execute(f"""
            SELECT
                group_key,
                COUNT(*) as count,
                MAX(rule_level) as max_level,
                MAX(timestamp) as latest_ts,
                rule_description,
                agent_name,
                mitre_tactic,
                mitre_technique,
                (SELECT status FROM alerts a2
                 WHERE a2.group_key=a.group_key
                 ORDER BY rule_level DESC, timestamp DESC LIMIT 1) as status
            FROM alerts a
            {where}
            GROUP BY group_key
            ORDER BY max_level DESC, latest_ts DESC
        """, params).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Suppression rules
# ---------------------------------------------------------------------------

def get_suppression_rules():
    with _get_conn() as conn:
        rows = conn.execute("SELECT * FROM suppression_rules ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]


def add_suppression_rule(field, operator, value, reason, expires_at=None):
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO suppression_rules (field, operator, value, reason, expires_at) VALUES (?,?,?,?,?)",
            (field, operator, value, reason, expires_at)
        )
        conn.commit()
        return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def delete_suppression_rule(rule_id):
    with _get_conn() as conn:
        conn.execute("DELETE FROM suppression_rules WHERE id=?", (rule_id,))
        conn.commit()


def check_suppressed(alert_dict, conn=None):
    """Return True if the alert matches any active suppression rule."""
    def _do_check(c):
        now = datetime.now(timezone.utc).isoformat()
        rules = c.execute(
            "SELECT * FROM suppression_rules WHERE (expires_at IS NULL OR expires_at > ?)",
            (now,)
        ).fetchall()
        for rule in rules:
            field = rule["field"]
            operator = rule["operator"]
            pattern = rule["value"]
            alert_val = str(alert_dict.get(field, "") or "")
            matched = False
            if operator == "equals":
                matched = alert_val == pattern
            elif operator == "contains":
                matched = pattern.lower() in alert_val.lower()
            elif operator == "starts_with":
                matched = alert_val.lower().startswith(pattern.lower())
            if matched:
                c.execute("UPDATE suppression_rules SET hits=hits+1 WHERE id=?", (rule["id"],))
                return True
        return False

    if conn is not None:
        return _do_check(conn)
    else:
        with _get_conn() as c:
            result = _do_check(c)
            c.commit()
            return result


# ---------------------------------------------------------------------------
# Analysis exclusions
# ---------------------------------------------------------------------------

def get_analysis_exclusions():
    with _get_conn() as conn:
        rows = conn.execute("SELECT * FROM analysis_exclusions ORDER BY rule_id, agent_name").fetchall()
        return [dict(r) for r in rows]


def add_analysis_exclusion(rule_id, agent_name, reason):
    rule_id    = rule_id.strip()
    agent_name = agent_name.strip() or "*"
    with _get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO analysis_exclusions (rule_id, agent_name, reason) VALUES (?,?,?)",
            (rule_id, agent_name, reason)
        )
        # Bulk-stamp existing unanalyzed alerts that match this exclusion
        if agent_name == "*":
            conn.execute(
                "UPDATE alerts SET analysis='[excluded]', updated_at=datetime('now') WHERE rule_id=? AND analysis IS NULL",
                (rule_id,)
            )
        else:
            conn.execute(
                "UPDATE alerts SET analysis='[excluded]', updated_at=datetime('now') WHERE rule_id=? AND agent_name LIKE ? AND analysis IS NULL",
                (rule_id, agent_name)
            )
        conn.commit()
        return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def delete_analysis_exclusion(excl_id):
    with _get_conn() as conn:
        conn.execute("DELETE FROM analysis_exclusions WHERE id=?", (excl_id,))
        conn.commit()


def is_analysis_excluded(rule_id, agent_name):
    """Return True if this rule_id+agent combo should be skipped by the analyst."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM analysis_exclusions WHERE rule_id=? AND (agent_name='*' OR agent_name LIKE ?) LIMIT 1",
            (rule_id, agent_name)
        ).fetchone()
        return row is not None


# ---------------------------------------------------------------------------
# Threat intel enrichment
# ---------------------------------------------------------------------------

def get_ips_needing_enrichment(limit=20):
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, srcip FROM alerts WHERE srcip != '' AND srcip IS NOT NULL AND enrichment IS NULL LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def set_enrichment(alert_id, enrichment_json):
    with _get_conn() as conn:
        conn.execute(
            "UPDATE alerts SET enrichment=? WHERE id=?",
            (enrichment_json, alert_id)
        )
        conn.commit()


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------

def add_note(alert_id, body, auto_generated=False, conn=None):
    def _insert(c):
        c.execute(
            "INSERT INTO alert_notes (alert_id, body, auto_generated) VALUES (?,?,?)",
            (alert_id, body, 1 if auto_generated else 0)
        )

    if conn is not None:
        _insert(conn)
    else:
        with _get_conn() as c:
            _insert(c)
            c.commit()


def get_notes(alert_id):
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM alert_notes WHERE alert_id=? ORDER BY created_at ASC",
            (alert_id,)
        ).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Cases
# ---------------------------------------------------------------------------

def create_case(title, severity, description):
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO cases (title, severity, description) VALUES (?,?,?)",
            (title, severity, description)
        )
        conn.commit()
        return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def get_cases():
    with _get_conn() as conn:
        rows = conn.execute("""
            SELECT c.*, COUNT(ca.alert_id) as alert_count
            FROM cases c
            LEFT JOIN case_alerts ca ON ca.case_id=c.id
            GROUP BY c.id
            ORDER BY c.created_at DESC
        """).fetchall()
        return [dict(r) for r in rows]


def get_case(case_id):
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        return dict(row) if row else None


def add_alert_to_case(case_id, alert_id):
    with _get_conn() as conn:
        try:
            conn.execute(
                "INSERT INTO case_alerts (case_id, alert_id) VALUES (?,?)",
                (case_id, alert_id)
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def get_case_alerts(case_id):
    with _get_conn() as conn:
        rows = conn.execute("""
            SELECT a.* FROM alerts a
            JOIN case_alerts ca ON ca.alert_id=a.id
            WHERE ca.case_id=?
            ORDER BY a.rule_level DESC, a.timestamp DESC
        """, (case_id,)).fetchall()
        return [dict(r) for r in rows]


def update_case(case_id, status=None, title=None, description=None):
    with _get_conn() as conn:
        if status is not None:
            closed_at = datetime.now(timezone.utc).isoformat() if status == "closed" else None
            conn.execute(
                "UPDATE cases SET status=?, closed_at=? WHERE id=?",
                (status, closed_at, case_id)
            )
        if title is not None:
            conn.execute("UPDATE cases SET title=? WHERE id=?", (title, case_id))
        if description is not None:
            conn.execute("UPDATE cases SET description=? WHERE id=?", (description, case_id))
        conn.commit()


# ---------------------------------------------------------------------------
# Entity timeline
# ---------------------------------------------------------------------------

def get_entity_timeline(entity_type, entity_value, hours=24, limit=100):
    with _get_conn() as conn:
        if entity_type == "agent":
            col = "agent_name"
        elif entity_type == "ip":
            col = "srcip"
        else:
            return []
        rows = conn.execute(
            f"SELECT * FROM alerts WHERE {col}=? AND timestamp >= datetime('now',?) ORDER BY timestamp ASC LIMIT ?",
            (entity_value, f"-{hours} hours", limit)
        ).fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# KPI metrics
# ---------------------------------------------------------------------------

def get_kpis():
    with _get_conn() as conn:
        # MTTR: avg minutes from created_at to updated_at for resolved alerts
        mttr_row = conn.execute("""
            SELECT AVG((julianday(updated_at) - julianday(created_at)) * 1440) as mttr
            FROM alerts
            WHERE status IN ('ack','fp','escalated')
            AND updated_at != created_at
        """).fetchone()
        mttr = round(mttr_row["mttr"] or 0, 1)

        # FP rate
        fp_row = conn.execute("""
            SELECT
                SUM(CASE WHEN status='fp' THEN 1 ELSE 0 END) as fp_count,
                SUM(CASE WHEN status IN ('fp','ack','escalated') THEN 1 ELSE 0 END) as resolved
            FROM alerts
        """).fetchone()
        fp_count = fp_row["fp_count"] or 0
        resolved = fp_row["resolved"] or 0
        fp_rate = round(fp_count / resolved * 100, 1) if resolved > 0 else 0

        # Volume
        alerts_24h = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE created_at >= datetime('now','-24 hours')"
        ).fetchone()[0]
        alerts_7d = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE created_at >= datetime('now','-7 days')"
        ).fetchone()[0]

        # Oldest new alert
        oldest_row = conn.execute(
            "SELECT MIN(created_at) as oldest FROM alerts WHERE status='new'"
        ).fetchone()
        oldest_new_hours = 0
        if oldest_row["oldest"]:
            try:
                oldest_dt = datetime.fromisoformat(oldest_row["oldest"].replace("Z", "+00:00"))
                now_dt = datetime.now(timezone.utc)
                if oldest_dt.tzinfo is None:
                    from datetime import timedelta
                    delta = now_dt.replace(tzinfo=None) - oldest_dt
                else:
                    delta = now_dt - oldest_dt
                oldest_new_hours = round(delta.total_seconds() / 3600, 1)
            except Exception:
                oldest_new_hours = 0

        # Escalation rate
        esc_row = conn.execute("""
            SELECT
                SUM(CASE WHEN status='escalated' THEN 1 ELSE 0 END) as esc_count,
                SUM(CASE WHEN status IN ('fp','ack','escalated') THEN 1 ELSE 0 END) as resolved
            FROM alerts
        """).fetchone()
        esc_count = esc_row["esc_count"] or 0
        esc_resolved = esc_row["resolved"] or 0
        escalation_rate = round(esc_count / esc_resolved * 100, 1) if esc_resolved > 0 else 0

        # Top agents last 7d
        top_agents = conn.execute("""
            SELECT agent_name, COUNT(*) as count
            FROM alerts
            WHERE created_at >= datetime('now','-7 days')
            GROUP BY agent_name
            ORDER BY count DESC
            LIMIT 5
        """).fetchall()

        # Top rules last 7d with fp rate
        top_rules = conn.execute("""
            SELECT
                rule_id,
                rule_description,
                COUNT(*) as total,
                SUM(CASE WHEN status='fp' THEN 1 ELSE 0 END) as fp_count,
                ROUND(SUM(CASE WHEN status='fp' THEN 1.0 ELSE 0 END)/COUNT(*)*100, 1) as fp_rate
            FROM alerts
            WHERE created_at >= datetime('now','-7 days')
            GROUP BY rule_id
            ORDER BY total DESC
            LIMIT 10
        """).fetchall()

        # Hourly volume last 24h
        hourly_rows = conn.execute("""
            SELECT
                strftime('%Y-%m-%dT%H:00:00', created_at) as hour,
                COUNT(*) as count
            FROM alerts
            WHERE created_at >= datetime('now','-24 hours')
            GROUP BY hour
            ORDER BY hour ASC
        """).fetchall()

        # Analysis rate — alerts with non-null, non-excluded analysis stamped per hour
        analysis_1h = conn.execute("""
            SELECT COUNT(*) FROM alerts
            WHERE analysis IS NOT NULL
              AND analysis != '[excluded]'
              AND updated_at >= datetime('now','-1 hour')
        """).fetchone()[0]
        analysis_6h = conn.execute("""
            SELECT COUNT(*) FROM alerts
            WHERE analysis IS NOT NULL
              AND analysis != '[excluded]'
              AND updated_at >= datetime('now','-6 hours')
        """).fetchone()[0]
        analysis_rate_1h = analysis_1h
        analysis_rate_6h = round(analysis_6h / 6, 1)

        # Hourly analysis rate for the last 24h (for sparkline)
        analysis_hourly = conn.execute("""
            SELECT
                strftime('%Y-%m-%dT%H:00:00', updated_at) as hour,
                COUNT(*) as count
            FROM alerts
            WHERE analysis IS NOT NULL
              AND analysis != '[excluded]'
              AND updated_at >= datetime('now','-24 hours')
            GROUP BY hour
            ORDER BY hour ASC
        """).fetchall()

        return {
            "mttr_minutes": mttr,
            "fp_rate": fp_rate,
            "alerts_last_24h": alerts_24h,
            "alerts_last_7d": alerts_7d,
            "oldest_new_hours": oldest_new_hours,
            "escalation_rate": escalation_rate,
            "top_agents": [dict(r) for r in top_agents],
            "top_rules": [dict(r) for r in top_rules],
            "hourly_volume": [dict(r) for r in hourly_rows],
            "analysis_rate_1h": analysis_rate_1h,
            "analysis_rate_6h": analysis_rate_6h,
            "analysis_hourly": [dict(r) for r in analysis_hourly],
        }


# ---------------------------------------------------------------------------
# MITRE coverage
# ---------------------------------------------------------------------------

def get_mitre_coverage():
    with _get_conn() as conn:
        rows = conn.execute("""
            SELECT mitre_tactic, mitre_technique, COUNT(*) as count
            FROM alerts
            WHERE created_at >= datetime('now','-7 days')
            AND mitre_tactic != ''
            GROUP BY mitre_tactic, mitre_technique
            ORDER BY count DESC
        """).fetchall()
        # aggregate by tactic
        result = {}
        for r in rows:
            tactics = [t.strip() for t in (r["mitre_tactic"] or "").split(",") if t.strip()]
            for tactic in tactics:
                if tactic not in result:
                    result[tactic] = {"count": 0, "techniques": []}
                result[tactic]["count"] += r["count"]
                tech = (r["mitre_technique"] or "").split(",")[0].strip()
                if tech and tech not in result[tactic]["techniques"]:
                    result[tactic]["techniques"].append(tech)
        return result


# ---------------------------------------------------------------------------
# Rule stats
# ---------------------------------------------------------------------------

def get_rule_stats():
    with _get_conn() as conn:
        rows = conn.execute("""
            SELECT
                rule_id,
                rule_description,
                COUNT(*) as total,
                SUM(CASE WHEN status='new' THEN 1 ELSE 0 END) as new_count,
                SUM(CASE WHEN status='ack' THEN 1 ELSE 0 END) as ack_count,
                SUM(CASE WHEN status='fp' THEN 1 ELSE 0 END) as fp_count,
                SUM(CASE WHEN status='escalated' THEN 1 ELSE 0 END) as escalated_count,
                ROUND(SUM(CASE WHEN status='fp' THEN 1.0 ELSE 0 END)/COUNT(*)*100, 1) as fp_rate,
                MAX(timestamp) as last_seen
            FROM alerts
            GROUP BY rule_id
            ORDER BY total DESC
        """).fetchall()
        return [dict(r) for r in rows]
