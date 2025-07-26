import pytest
from generator import incident_factory
import re
import ipaddress

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
    incident = incident_factory.generate_phishing_incident()
    
    assert incident["type"] == "phishing"
    assert "id" in incident
    assert is_valid_iso8601(incident["timestamp"])
    assert is_valid_ip(incident["source_ip"])
    assert isinstance(incident["iocs"], list)
    assert incident["mitre_techniques"] == ["T1566.001"]

def test_generate_bruteforce_fields():
    incident = incident_factory.generate_bruteforce_incident()
    
    assert incident["type"] == "bruteforce"
    assert "username_attempted" in incident
    assert isinstance(incident["attempt_count"], int)
    assert 1 <= incident["attempt_count"] <= 50

def test_generate_malware_fields():
    incident = incident_factory.generate_malware_incident()
    
    assert incident["type"] == "malware"
    assert "malware_name" in incident
    assert "file_hash" in incident
    assert re.fullmatch(r"[a-f0-9]{32,}", incident["file_hash"])

def test_generate_ransomware_fields():
    incident = incident_factory.generate_ransomware_incident()
    
    assert incident["type"] == "ransomware"
    assert isinstance(incident["encrypted_extensions"], list)
    assert incident["ransomware_family"] in ["LockBit", "Conti", "BlackCat", "REvil", "Clop"]

def test_generate_data_exfiltration_fields():
    incident = incident_factory.generate_data_exfiltration_incident()

    assert incident["type"] == "data_exfiltration"
    assert "protocol" in incident
    assert incident["protocol"] in ["FTP", "HTTP", "HTTPS", "DNS", "SMB"]
    assert isinstance(incident["data_volume_mb"], float)
    assert 0.1 <= incident["data_volume_mb"] <= 500