import random
import uuid
import json
import os
from datetime import datetime

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), 'templates')

def load_template(name):
    with open(os.path.join(TEMPLATES_DIR, f"{name}.json"), 'r') as f:
        return json.load(f)
    
def generate_phishing_incident():
    template = load_template("phishing")

    subjects = [
        "Reset your password", "Invoice overdue",
        "You’ve won a prize!", "Security alert on your account"
    ]
    domains = ["malicious-site.biz", "click-here-now.net", "login-update.com"]
    target_users = ["alice@acme.corp", "bob@corp.local", "user123@domain.com"]

    # Rellenamos los campos dinámicos
    template["id"] = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
    template["timestamp"] = datetime.utcnow().isoformat() + "Z"
    template["source_ip"] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    template["target_user"] = random.choice(target_users)
    template["subject"] = random.choice(subjects)
    template["iocs"] = [random.choice(domains)]

    return template

def generate_bruteforce_incident():
    template = load_template("bruteforce")

    usernames = ["admin", "root", "jsmith", "alice"]
    endpoints = ["/login", "/auth", "/admin", "/api/auth"]
    target_users = ["bob@company.com", "carol@domain.net", "hr@acme.corp"]

    template["id"] = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
    template["timestamp"] = datetime.utcnow().isoformat() + "Z"
    template["source_ip"] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    template["target_user"] = random.choice(target_users)
    template["username_attempted"] = random.choice(usernames)
    template["login_endpoint"] = random.choice(endpoints)
    template["attempt_count"] = random.randint(5, 20)

    return template

def generate_malware_incident():
    template = load_template("malware")

    malware_names = ["Emotet", "TrickBot", "FormBook", "AgentTesla", "Remcos"]
    file_paths = [r"C:\Users\Public\winlogon.exe", r"/tmp/evil.sh", r"/usr/local/bin/update"]
    hosts = ["host01.internal", "hr-laptop-22", "dev-machine-07"]

    template["id"] = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
    template["timestamp"] = datetime.utcnow().isoformat() + "Z"
    template["source_ip"] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    template["affected_host"] = random.choice(hosts)
    template["malware_name"] = random.choice(malware_names)
    template["file_path"] = random.choice(file_paths)
    template["file_hash"] = uuid.uuid4().hex  # Hash simulado

    return template

def generate_ransomware_incident():
    template = load_template("ransomware")

    families = ["LockBit", "Conti", "BlackCat", "REvil", "Clop"]
    extensions = [".locked", ".enc", ".payme", ".crypted", ".fuck"]
    ransom_notes = [
        r"C:\Users\Public\README.txt",
        r"/home/user/README_FOR_RESCUE.txt"
    ]
    btc_wallets = [
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
    ]
    infected_hosts = ["finance-srv01", "hr-laptop-09", "dev-ubuntu-22"]

    template["id"] = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
    template["timestamp"] = datetime.utcnow().isoformat() + "Z"
    template["source_ip"] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    template["infected_host"] = random.choice(infected_hosts)
    template["ransomware_family"] = random.choice(families)
    template["encrypted_extensions"] = random.sample(extensions, k=2)
    template["ransom_note_path"] = random.choice(ransom_notes)
    template["btc_wallet"] = random.choice(btc_wallets)
    

    return template

def generate_data_exfiltration_incident():
    template = load_template("data_exfiltration")

    data_types = ["PII", "credentials", "intellectual property", "HR records", "financial reports"]
    protocols = ["FTP", "HTTP", "HTTPS", "DNS", "SMB"]
    hosts = ["legal-srv01", "vpn-gateway", "secops-laptop", "rdp-win10-3"]

    template["id"] = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
    template["timestamp"] = datetime.utcnow().isoformat() + "Z"
    template["source_ip"] = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    template["source_host"] = random.choice(hosts)
    template["destination_ip"] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    template["protocol"] = random.choice(protocols)
    template["data_type"] = random.choice(data_types)
    template["data_volume_mb"] = round(random.uniform(0.5, 250), 2)

    return template