#!/usr/bin/env python3
import sys
import json
import requests

# Wazuh passes: alert_file, api_key(unused), hook_url
alert_file = sys.argv[1]
webhook_url = sys.argv[3]

try:
    with open(alert_file) as f:
        alert_data = json.load(f)
except Exception:
    sys.exit(1)

# Extract relevant fields from the alert JSON
data = alert_data.get("data", {})

payload = {
    "timestamp": alert_data.get("timestamp", ""),
    "agent_name": data.get("agent_name", "unknown"),
    "platform": data.get("platform", "unknown"),
    "version": data.get("version", "unknown"),
    "risk_score": data.get("risk_score", ""),
    "risk_level": data.get("risk_level", ""),
    "cve_count": data.get("cve_count", ""),
    "kev_matches": data.get("kev_matches", []),
    "description": alert_data.get("rule", {}).get("description", "")
}

try:
    requests.post(webhook_url, json=payload, timeout=10)
except Exception:
    pass

sys.exit(0)
