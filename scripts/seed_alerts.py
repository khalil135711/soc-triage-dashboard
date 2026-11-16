#!/usr/bin/env python3
"""Spielt Beispiel-Alerts über die REST-API ein.

Nutzung:  python scripts/seed_alerts.py [--url http://localhost:8000] [--count 60]
Nur Standardbibliothek nötig.
"""
import argparse
import json
import random
import urllib.request
from datetime import datetime, timedelta, timezone

SIGNATURES = [
    ("SSH brute force attempt", "high"), ("Port scan detected", "low"),
    ("SQL injection attempt on /login", "high"), ("Malware download from known host", "critical"),
    ("Possible C2 beacon to rare domain", "critical"), ("Phishing URL clicked", "medium"),
    ("Modbus write to unauthorized PLC", "high"), ("Data exfiltration over DNS", "critical"),
    ("Ransomware file extension activity", "critical"), ("Suspicious PowerShell command", "medium"),
]
EXTERNAL = ["203.0.113.5", "198.51.100.23", "45.155.205.10", "185.220.101.4", "91.240.118.7"]
INTERNAL = ["10.0.0.4", "10.0.0.15", "192.168.1.20", "192.168.1.77"]


def call(url, path, payload=None, token=None):
    req = urllib.request.Request(url + path, method="POST" if payload else "GET",
                                 data=json.dumps(payload).encode() if payload else None)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--count", type=int, default=60)
    ap.add_argument("--user", default="analyst")
    ap.add_argument("--password", default="analyst123")
    a = ap.parse_args()

    token = call(a.url, "/api/auth/login", {"username": a.user, "password": a.password})["access_token"]
    now = datetime.now(timezone.utc)
    for _ in range(a.count):
        sig, sev = random.choice(SIGNATURES)
        ts = now - timedelta(days=random.randint(0, 9), minutes=random.randint(0, 1439))
        call(a.url, "/api/alerts", {
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source_ip": random.choice(EXTERNAL), "dest_ip": random.choice(INTERNAL),
            "signature": sig, "severity": sev,
            "raw": json.dumps({"sensor": "demo", "signature": sig}),
        }, token)
    print(f"{a.count} Alerts eingespielt. Öffne {a.url}")


if __name__ == "__main__":
    main()
