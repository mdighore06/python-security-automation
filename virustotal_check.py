#!/usr/bin/env python3
"""
Task 4: VirusTotal REST API v3 Integration
Usage: python virustotal_check.py <ip_1> [ip_2 ...]
"""

import json
import os
import sys
from typing import Any, Dict
import requests


def query_virustotal(ip: str, api_key: str) -> Dict[str, Any]:
    """Queries VirusTotal API v3 for IP reputational stats."""
    if not api_key:
        return {"error": "VT_API_KEY environment variable not set"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        return {
            "vt_malicious_detections": stats.get("malicious", 0),
            "vt_harmless_count": stats.get("harmless", 0),
            "vt_last_analysis_date": attributes.get("last_analysis_date", "N/A"),
        }
    except requests.exceptions.HTTPError as e:
        return {"vt_error": f"HTTP Error {e.response.status_code}: {e.response.reason}"}
    except (requests.RequestException, json.JSONDecodeError) as e:
        return {"vt_error": f"VirusTotal query failed: {str(e)}"}


def main():
    if len(sys.argv) < 2:
        print("Usage: python virustotal_check.py <ip_1> [ip_2 ...]")
        sys.exit(1)

    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        print("[-] Error: VT_API_KEY environment variable not set.", file=sys.stderr)
        sys.exit(1)

    target_ips = sys.argv[1:]
    results = {ip: query_virustotal(ip, api_key) for ip in target_ips}
    print(json.dumps(results, indent=4))


if __name__ == "__main__":
    main()
