import random
import uuid
import json
import os
from datetime import datetime

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), '..', 'templates')

def load_template(name):
    with open(os.path.join(TEMPLATES_DIR, f"{name}.json"), 'r') as f:
        return json.load(f)
    
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