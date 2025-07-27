import pytest
import re
import ipaddress
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from generator.incident_factory import (
    generate_phishing_incident,
    generate_bruteforce_incident,
    generate_malware_incident,
    generate_ransomware_incident,
    generate_data_exfiltration_incident,
    generate_command_and_control_incident,
    generate_insider_threat_incident,
    generate_port_scanning_incident,
    generate_web_exploit_incident,
    generate_suspicious_powershell_incident
)


def is_valid_iso8601(timestamp: str) -> bool:
    pattern = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(\+\d{2}:\d{2})?Z"
    return bool(re.fullmatch(pattern, timestamp))

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def test_generate_phishing_fields():
    incident = generate_phishing_incident()
    
    assert incident["type"] == "phishing"
    assert "id" in incident
    assert is_valid_iso8601(incident["timestamp"])
    assert is_valid_ip(incident["source_ip"])
    assert isinstance(incident["iocs"], list)
    assert incident["mitre_techniques"] == ["T1566.001"]

def test_generate_bruteforce_fields():
    incident = generate_bruteforce_incident()
    
    assert incident["type"] == "bruteforce"
    assert "username_attempted" in incident
    assert isinstance(incident["attempt_count"], int)
    assert 1 <= incident["attempt_count"] <= 50

def test_generate_malware_fields():
    incident = generate_malware_incident()
    
    assert incident["type"] == "malware"
    assert "malware_name" in incident
    assert "file_hash" in incident
    assert re.fullmatch(r"[a-f0-9]{32,}", incident["file_hash"])

def test_generate_ransomware_fields():
    incident = generate_ransomware_incident()
    
    assert incident["type"] == "ransomware"
    assert isinstance(incident["encrypted_extensions"], list)
    assert incident["ransomware_family"] in ["LockBit", "Conti", "BlackCat", "REvil", "Clop"]

def test_generate_data_exfiltration_fields():
    incident = generate_data_exfiltration_incident()

    assert incident["type"] == "data_exfiltration"
    assert "protocol" in incident
    assert incident["protocol"] in ["FTP", "HTTP", "HTTPS", "DNS", "SMB"]
    assert isinstance(incident["data_volume_mb"], float)
    assert 0.1 <= incident["data_volume_mb"] <= 500

def test_generate_command_and_control_fields():
    incident = generate_command_and_control_incident()

    assert incident["id"].startswith("INC-")
    assert "infected_host" in incident
    assert "c2_ip" in incident
    assert "c2_domain" in incident
    assert incident["protocol"] in ["HTTPS", "DNS", "HTTP", "TLS", "WebSocket"]
    assert isinstance(incident["beacon_interval_sec"], int)
    assert incident["beacon_interval_sec"] in [10, 30, 60, 300, 900]

def test_generate_insider_threat_fields():
    incident = generate_insider_threat_incident()

    actions = [
        "accessed payroll database out of hours",
        "downloaded over 200 documents",
        "accessed confidential project repo",
        "disabled EDR agent",
        "exported full mailbox to PST"
    ]

    assert incident["type"] == "insider_threat"
    assert "username" in incident
    assert "user_role" in incident
    assert "suspicious_action" in incident
    assert incident["suspicious_action"] in actions
    assert "target_resource" in incident
    assert "justification_provided" in incident

def test_generate_port_scanning_fields():
    incident = generate_port_scanning_incident()

    assert incident["type"] == "port_scanning"
    assert is_valid_ip(incident["scanner_ip"])
    assert is_valid_ip(incident["target_ip"])
    assert isinstance(incident["scanned_ports"], list)
    assert all(isinstance(port, int) and 0 < port < 65536 for port in incident["scanned_ports"])
    assert incident["tool_used"] in ["nmap", "masscan", "zmap", "netcat", "angryIP"]
    assert incident["scan_type"] in ["TCP SYN", "TCP Connect", "UDP", "Ping Sweep", "Stealth"]

def test_generate_web_exploit_fields():
    incident = generate_web_exploit_incident()

    assert incident["type"] == "web_exploit"
    assert is_valid_ip(incident["attacker_ip"])
    assert incident["http_method"] in ["GET", "POST"]
    assert isinstance(incident["payload"], str)
    assert incident["exploit_type"] in [
        "SQL Injection", "XSS", "Command Injection",
        "Local File Inclusion", "Directory Traversal"
    ]

def test_generate_suspicious_powershell_fields():
    incident = generate_suspicious_powershell_incident()

    assert incident["type"] == "suspicious_powershell"
    assert isinstance(incident["host"], str)
    assert isinstance(incident["user"], str)
    assert isinstance(incident["command"], str)
    assert incident["parent_process"] in ["explorer.exe", "winword.exe", "outlook.exe", "cmd.exe", "teams.exe"]
    assert incident["execution_context"] in ["user", "admin", "scheduled_task", "startup", "remote_session"]
