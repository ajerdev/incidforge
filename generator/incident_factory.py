import random
import uuid
from datetime import datetime, timezone
from generator.utils import load_template
    
def generate_phishing_incident():
    template = load_template("phishing")

    subjects = [
        "Reset your password", "Invoice overdue",
        "You’ve won a prize!", "Security alert on your account"
    ]
    domains = ["malicious-site.biz", "click-here-now.net", "login-update.com"]
    target_users = ["alice@acme.corp", "bob@corp.local", "user123@domain.com"]

    template["id"] = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
    template["timestamp"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
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

    template["id"] = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
    template["timestamp"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
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

    template["id"] = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
    template["timestamp"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
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

    template["id"] = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
    template["timestamp"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
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

    template["id"] = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
    template["timestamp"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    template["source_ip"] = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    template["source_host"] = random.choice(hosts)
    template["destination_ip"] = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
    template["protocol"] = random.choice(protocols)
    template["data_type"] = random.choice(data_types)
    template["data_volume_mb"] = round(random.uniform(0.5, 250), 2)

    return template

def generate_command_and_control_incident():
    template = load_template("command_and_control")

    infected_hosts = ["host-dev01", "hr-win11", "vpn-compromised", "ws-corp-02"]
    c2_domains = ["cnc.evilcorp.com", "command.darkweb.net", "c2panel.anonym.tld"]
    protocols = ["HTTPS", "DNS", "HTTP", "TLS", "WebSocket"]

    template["id"] = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
    template["timestamp"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    template["infected_host"] = random.choice(infected_hosts)
    template["c2_ip"] = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
    template["c2_domain"] = random.choice(c2_domains)
    template["protocol"] = random.choice(protocols)
    template["beacon_interval_sec"] = random.choice([10, 30, 60, 300, 900])

    return template

def generate_insider_threat_incident():
    template = load_template("insider_threat")

    usernames = ["jdoe", "hr-manager", "backup-admin", "it_support", "intern-23"]
    roles = ["HR", "IT", "Finance", "Intern", "Developer"]
    actions = [
        "accessed payroll database out of hours",
        "downloaded over 200 documents",
        "accessed confidential project repo",
        "disabled EDR agent",
        "exported full mailbox to PST"
    ]
    resources = [
        "payroll_db", "confidential_share", "vpn_logs", "employee_email", "source_code_repo"
    ]
    justifications = [
        "needed for report", "requested by manager", "not specified", "temporary access", "unknown"
    ]

    template["id"] = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
    template["timestamp"] = datetime.now(timezone.utc).isoformat()
    template["username"] = random.choice(usernames)
    template["user_role"] = random.choice(roles)
    template["suspicious_action"] = random.choice(actions)
    template["target_resource"] = random.choice(resources)
    template["justification_provided"] = random.choice(justifications)

    return template