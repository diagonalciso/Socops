"""Threat intel enrichment for IP addresses."""
import os, json, urllib.request, urllib.error

ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "")
OTX_KEY = os.environ.get("OTX_KEY", "")


def enrich_ip(ip: str) -> dict:
    """Return combined enrichment dict for an IP. Cached in DB."""
    if not ip or ip in ("", "0.0.0.0", "127.0.0.1"):
        return {}
    result = {"ip": ip, "sources": {}}
    if ABUSEIPDB_KEY:
        result["sources"]["abuseipdb"] = _abuseipdb(ip)
    if OTX_KEY:
        result["sources"]["otx"] = _otx(ip)
    # compute composite risk score 0-100
    score = 0
    ab = result["sources"].get("abuseipdb", {})
    if ab.get("abuseConfidenceScore"):
        score = max(score, ab["abuseConfidenceScore"])
    otx = result["sources"].get("otx", {})
    if otx.get("pulse_count", 0) > 0:
        score = max(score, min(50 + otx["pulse_count"] * 5, 100))
    result["risk_score"] = score
    result["risk_label"] = "critical" if score >= 80 else "high" if score >= 50 else "medium" if score >= 20 else "low"
    return result


def _abuseipdb(ip):
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(url, headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())["data"]
            return {"abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
                    "totalReports": data.get("totalReports", 0),
                    "countryCode": data.get("countryCode", ""),
                    "isp": data.get("isp", "")}
    except Exception as e:
        return {"error": str(e)}


def _otx(ip):
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        req = urllib.request.Request(url, headers={"X-OTX-API-KEY": OTX_KEY})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
            return {"pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "country": data.get("country_name", ""),
                    "reputation": data.get("reputation", 0)}
    except Exception as e:
        return {"error": str(e)}
