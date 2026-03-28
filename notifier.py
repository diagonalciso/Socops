"""Outbound notifications for high-severity or escalated alerts."""
import os, json, urllib.request, smtplib
from email.mime.text import MIMEText

WEBHOOK_URL  = os.environ.get("NOTIFY_WEBHOOK", "")
NOTIFY_EMAIL = os.environ.get("NOTIFY_EMAIL", "")
SMTP_HOST    = os.environ.get("SMTP_HOST", "")
SMTP_PORT    = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER    = os.environ.get("SMTP_USER", "")
SMTP_PASS    = os.environ.get("SMTP_PASS", "")
NOTIFY_LEVEL = int(os.environ.get("NOTIFY_LEVEL", "12"))


def notify_alert(alert: dict, trigger: str = "auto"):
    """Send notification for high-severity alert. trigger: 'auto'|'escalated'"""
    if not (WEBHOOK_URL or NOTIFY_EMAIL):
        return
    level = alert.get("rule_level", 0)
    if trigger == "auto" and level < NOTIFY_LEVEL:
        return
    msg = _format_message(alert, trigger)
    if WEBHOOK_URL:
        _send_webhook(msg, alert)
    if NOTIFY_EMAIL and SMTP_HOST:
        _send_email(msg, alert)


def _format_message(alert, trigger):
    level = alert.get("rule_level", 0)
    prefix = "CRITICAL" if level >= 12 else "HIGH" if level >= 10 else "ESCALATED"
    return (f"{prefix} | {alert.get('rule_description', '')}\n"
            f"Agent: {alert.get('agent_name', '')} | Level: {level}\n"
            f"Time: {alert.get('timestamp', '')}")


def _send_webhook(text, alert):
    try:
        payload = json.dumps({"text": text, "alert_id": alert.get("id")}).encode()
        req = urllib.request.Request(WEBHOOK_URL, data=payload,
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass


def _send_email(text, alert):
    try:
        msg = MIMEText(text)
        msg["Subject"] = f"SOCops Alert: {alert.get('rule_description', '')[:60]}"
        msg["From"] = SMTP_USER
        msg["To"] = NOTIFY_EMAIL
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            if SMTP_USER and SMTP_PASS:
                s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    except Exception:
        pass
