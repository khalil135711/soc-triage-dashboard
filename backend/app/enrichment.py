"""Anreicherung: Severity-Score und MITRE-ATT&CK-Mapping (regelbasiert)."""
import ipaddress

# Stichwort -> (Technik-ID, Name, Basis-Score)
RULES = [
    ("brute", "T1110", "Brute Force", 60),
    ("ssh", "T1021.004", "Remote Services: SSH", 40),
    ("scan", "T1046", "Network Service Discovery", 30),
    ("sql", "T1190", "Exploit Public-Facing Application", 75),
    ("exploit", "T1190", "Exploit Public-Facing Application", 80),
    ("malware", "T1204", "User Execution", 85),
    ("ransom", "T1486", "Data Encrypted for Impact", 95),
    ("c2", "T1071", "Application Layer Protocol (C2)", 85),
    ("beacon", "T1071", "Application Layer Protocol (C2)", 80),
    ("exfil", "T1041", "Exfiltration Over C2 Channel", 90),
    ("modbus", "T0855", "Unauthorized Command Message (ICS)", 70),
    ("phish", "T1566", "Phishing", 65),
]

SEVERITY_BONUS = {"low": 0, "medium": 10, "high": 20, "critical": 30}


def is_external_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def enrich(signature: str, severity: str, source_ip: str) -> dict:
    sig = signature.lower()
    technique_id, technique_name, score = None, None, 20
    for keyword, tid, tname, base in RULES:
        if keyword in sig and base >= score:
            technique_id, technique_name, score = tid, tname, base
    score += SEVERITY_BONUS.get(severity, 0)
    if is_external_ip(source_ip):
        score += 5
    return {"mitre_id": technique_id, "mitre_name": technique_name, "score": min(score, 100)}
