#!/usr/bin/env python3
"""
Risk Scorer - Enriches EOL findings with CVE + CISA KEV data
Reads: /var/log/eol-findings/eol.json
Writes: /var/log/eol-findings/eol_risk.json
"""

import json
import os
import time
import requests
from datetime import datetime, timezone

NVD_API_KEY = os.environ.get("NVD_API_KEY")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

EOL_LOG = "/var/log/eol-findings/eol.json"
RISK_LOG = "/var/log/eol-findings/eol_risk.json"
ASSET_TAGS_FILE = "/opt/eol-detector/asset_tags.json"

# Simple cache to avoid repeat NVD calls for same platform/version
cve_cache = {}


def load_kev_list():
    """Download CISA KEV list, return set of CVE IDs."""
    try:
        resp = requests.get(KEV_URL, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        return {v["cveID"] for v in data["vulnerabilities"]}
    except requests.RequestException as e:
        print(f"[!] Failed to load KEV list: {e}")
        return set()


def load_asset_tags():
    """Load internet-facing / criticality tags per agent_id."""
    if os.path.exists(ASSET_TAGS_FILE):
        with open(ASSET_TAGS_FILE) as f:
            return json.load(f)
    return {}


def search_cves(platform, version):
    """Search NVD for CVEs matching platform+version keyword."""
    cache_key = f"{platform}:{version}"
    if cache_key in cve_cache:
        return cve_cache[cache_key]

    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    params = {
        "keywordSearch": f"{platform} {version}",
        "resultsPerPage": 10,
    }
    try:
        resp = requests.get(NVD_URL, headers=headers, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        cve_ids = []
        for item in data.get("vulnerabilities", []):
            cve_id = item["cve"]["id"]
            # Try to get CVSS score (v3 preferred, fallback v2)
            metrics = item["cve"].get("metrics", {})
            cvss_score = None
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics:
                    cvss_score = metrics[key][0]["cvssData"]["baseScore"]
                    break
            cve_ids.append({"id": cve_id, "cvss": cvss_score})
        cve_cache[cache_key] = cve_ids
        # Respect NVD rate limits: ~50 req/30s with key, ~5 req/30s without
        time.sleep(1 if NVD_API_KEY else 6)
        return cve_ids
    except requests.RequestException as e:
        print(f"[!] NVD lookup failed for {platform} {version}: {e}")
        return []


def calculate_risk(cve_list, kev_set, is_internet_facing):
    """Tiered risk scoring."""
    score = 1  # base: it's EOL
    matched_kev = []
    max_cvss = 0

    for cve in cve_list:
        if cve["id"] in kev_set:
            matched_kev.append(cve["id"])
        if cve["cvss"] and cve["cvss"] > max_cvss:
            max_cvss = cve["cvss"]

    if cve_list:
        score += 3  # has known CVEs
    if max_cvss >= 7:
        score += 3  # high/critical CVSS
    if matched_kev:
        score += 5  # actively exploited
    if is_internet_facing:
        score += 3

    if score >= 9:
        level = "Critical"
    elif score >= 6:
        level = "High"
    elif score >= 4:
        level = "Medium"
    else:
        level = "Low"

    return score, level, matched_kev, max_cvss


def main():
    if not os.path.exists(EOL_LOG):
        print(f"[!] {EOL_LOG} not found. Run eol_detector.py first.")
        return

    print("[*] Loading CISA KEV list...")
    kev_set = load_kev_list()
    print(f"[+] Loaded {len(kev_set)} KEV entries.")

    asset_tags = load_asset_tags()

    findings = []
    with open(EOL_LOG) as f:
        for line in f:
            line = line.strip()
            if line:
                findings.append(json.loads(line))

    print(f"[*] Processing {len(findings)} EOL findings...")

    enriched = []
    for finding in findings:
        platform = finding.get("platform", "")
        version = finding.get("version", "")
        agent_id = finding.get("agent_id", "")

        print(f"  Checking CVEs for {platform} {version}...")
        cve_list = search_cves(platform, version)

        tags = asset_tags.get(agent_id, {})
        is_internet_facing = tags.get("internet_facing", False)

        score, level, matched_kev, max_cvss = calculate_risk(
            cve_list, kev_set, is_internet_facing
        )

        finding["risk_score"] = score
        finding["risk_level"] = level
        finding["cve_count"] = len(cve_list)
        finding["max_cvss"] = max_cvss
        finding["kev_matches"] = matched_kev
        finding["internet_facing"] = is_internet_facing
        finding["scored_at"] = datetime.now(timezone.utc).isoformat()

        enriched.append(finding)

    with open(RISK_LOG, "a") as f:
        for item in enriched:
            f.write(json.dumps(item) + "\n")

    print(f"[+] Wrote {len(enriched)} enriched findings to {RISK_LOG}")
    for item in enriched:
        print(f"    {item['agent_name']}: {item['risk_level']} (score={item['risk_score']}, CVEs={item['cve_count']}, KEV={len(item['kev_matches'])})")


if __name__ == "__main__":
    main()
