#!/usr/bin/env python3
"""
Task 2: Log Parser with Regex IP Extraction & Threat Intelligence Enrichment
Usage: python log_enricher.py <path_to_log_file>
"""

import json
import re
import sys
from typing import Any, Dict, Set
import requests

# Pattern matches dotted-decimal IPv4 address format (4 groups of 1-3 digits)
IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


def is_public_ip(ip: str) -> bool:
    """Filters out RFC 1918 private IPv4 subnets, loopback, and broadcast ranges."""
    try:
        parts = list(map(int, ip.split(".")))
    except ValueError:
        return False

    if any(p < 0 or p > 255 for p in parts):
        return False

    # Private Range Checks: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
    if parts[0] == 10:
        return False
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return False
    if parts[0] == 192 and parts[1] == 168:
        return False
    # Loopback (127.x.x.x) and Multicast/Broadcast (>=224.x.x.x)
    if parts[0] in (127, 169) or parts[0] >= 224:
        return False

    return True


def extract_public_ips(file_path: str) -> Set[str]:
    """Reads log file and extracts unique public IPv4 addresses using a set."""
    public_ips = set()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                matches = IP_REGEX.findall(line)
                for ip in matches:
                    if is_public_ip(ip):
                        public_ips.add(ip)
    except FileNotFoundError:
        print(f"[-] Error: File '{file_path}' not found.", file=sys.stderr)
        sys.exit(1)
    return public_ips


def query_ip_api(ip: str) -> Dict[str, Any]:
    """Queries ip-api.com REST API for geolocational and ISP metadata."""
    url = f"http://ip-api.com/json/{ip}?fields=country,isp,hosting,proxy,mobile"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        return {
            "country": data.get("country", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "is_hosting": data.get("hosting", False),
            "is_proxy": data.get("proxy", False),
            "is_mobile": data.get("mobile", False),
        }
    except (requests.RequestException, json.JSONDecodeError) as e:
        return {"error": f"ip-api query failed: {str(e)}"}


def main():
    if len(sys.argv) != 2:
        print("Usage: python log_enricher.py <path_to_log_file>")
        sys.exit(1)

    log_file = sys.argv[1]
    public_ips = extract_public_ips(log_file)

    enrichment_results = {}
    for ip in public_ips:
        enrichment_results[ip] = query_ip_api(ip)

    print(json.dumps(enrichment_results, indent=4))


if __name__ == "__main__":
    main()
