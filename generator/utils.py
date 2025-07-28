import uuid
import random
import json
import os
from datetime import datetime, timezone

#TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), '..', 'templates')
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), 'templates')

def generate_incident_id() -> str:
    return f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"

def get_current_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def generate_random_ip() -> str:
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

def generate_fake_hash(length=32) -> str:
    return ''.join(random.choices('abcdef0123456789', k=length))

def generate_random_email():
    usernames = ["alice", "bob", "charlie", "david", "eva", "frank", "grace", "henry", "irene", "john"]
    domains = ["example.com", "corp.local", "domain.com", "acme.corp", "internal.net"]
    return f"{random.choice(usernames)}@{random.choice(domains)}"

def load_template(name: str) -> dict:
    with open(os.path.join(TEMPLATES_DIR, f"{name}.json"), 'r') as f:
        return json.load(f)