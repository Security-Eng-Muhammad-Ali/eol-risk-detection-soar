#!/usr/bin/env python3
"""
EOL Detector for Wazuh
Checks OS versions of all active agents against endoflife.date
and logs findings for Wazuh to ingest and alert on.
"""

import requests
import json
import urllib3
from datetime import datetime, timezone

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---- CONFIG ----
WAZUH_API = "https://localhost:55000"
API_USER = "wazuh-wui"
API_PASS = "CHANGE_ME"  # set via environment variable in production
LOG_FILE = "/var/log/eol-findings/eol.json"

# Map Wazuh OS platform names -> endoflife.date product slugs
OS_SLUG_MAP = {
    "ubuntu": "ubuntu",
    "windows": "windows-server",  # adjust per version if needed
}


def get_token():
    resp = requests.post(
        f"{WAZUH_API}/security/user/authenticate",
        auth=(API_USER, API_PASS),
        verify=False,
    )
    resp.raise_for_status()
    return resp.json()["data"]["token"]


def get_agents(token):
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(
        f"{WAZUH_API}/agents?select=id,name,status,os.platform,os.version",
        headers=headers,
        verify=False,
    )
    resp.raise_for_status()
    agents = resp.json()["data"]["affected_items"]
    # Skip manager (id 000), only active agents
    return [a for a in agents if a["id"] != "000" and a.get("status") == "active"]


def check_eol(product_slug, version):
    """Query endoflife.date for a product's cycles and match version."""
    url = f"https://endoflife.date/api/{product_slug}.json"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return None
        cycles = resp.json()
        for cycle in cycles:
            cycle_label = str(cycle.get("cycle", ""))
            if version.startswith(cycle_label):
                eol_date = cycle.get("eol")
                return cycle, eol_date
    except requests.RequestException:
        return None
    return None


def main():
    token = get_token()
    agents = get_agents(token)

    findings = []

    for agent in agents:
        os_info = agent.get("os", {})
        platform = os_info.get("platform", "").lower()
        version = os_info.get("version", "")

        slug = None
        for key in OS_SLUG_MAP:
            if key in platform:
                slug = OS_SLUG_MAP[key]
                break

        if not slug or not version:
            continue

        result = check_eol(slug, version)
        if not result:
            continue

        cycle, eol_date = result
        if not eol_date or eol_date is False:
            continue  # not EOL or no data

        try:
            eol_dt = datetime.strptime(eol_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            days_past = (datetime.now(timezone.utc) - eol_dt).days
        except (ValueError, TypeError):
            continue

        if days_past > 0:
            finding = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "agent_id": agent["id"],
                "agent_name": agent["name"],
                "platform": platform,
                "version": version,
                "eol_date": eol_date,
                "days_past_eol": days_past,
            }
            findings.append(finding)

    # Write findings as JSON lines
    with open(LOG_FILE, "a") as f:
        for finding in findings:
            f.write(json.dumps(finding) + "\n")

    print(f"[+] Checked {len(agents)} agents, found {len(findings)} EOL findings.")


if __name__ == "__main__":
    main()
