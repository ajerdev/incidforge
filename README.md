# 🛠️ IncidForge – Fake Incident Generator for SOC & SOAR Testing

**IncidForge** is a lightweight Python-based tool designed to simulate cybersecurity incidents for testing and validation of SOC pipelines, SIEM parsing, and SOAR automation workflows.

Whether you're a blue team engineer, SOAR developer, or simply want to stress-test your playbooks, **IncidForge** provides realistic, customizable incident data in JSON and STIX formats.

---

## 📌 Features

- 🔄 **Generate fake incidents** (phishing, brute force, malware, etc.)
- 🧱 **Structured output** in JSON (future implementation of STIX 2.1 format)
- 🎭 **Noise injection**: add decoy or irrelevant events
- 🔗 **Correlated event chains**: simulate full campaigns
- 🧠 **MITRE ATT&CK mapped techniques** for realism
- ⚙️ **Customizable via CLI** (argparse or Typer-based)

---

## 🚀 Use Cases

- ✅ Testing SOAR workflows and enrichment playbooks
- 🧪 Simulating alerts for incident response drills
- 🔍 Validating SIEM ingestion and parsing rules
- 📦 Generating datasets for training and demos

---

## ⚙️ Installation

```bash
git clone https://github.com/yourusername/incidforge.git
cd incidforge
pip install -r requirements.txt
```
---

## 🧪 Example Usage

```bash
# Generate 5 phishing incidents in JSON format:
python main.py generate --type phishing --format json --count 5

# Generate a correlated campaign (brute force + phishing):
python main.py generate --type campaign --correlated true --count 10

# Generate events with noise:
python main.py generate --type malware --noise true --count 20
```

---

## 📝 Output Example

```json
{
  "id": "INC-20250726-0012",
  "type": "phishing",
  "timestamp": "2025-07-26T14:35:22Z",
  "source_ip": "185.133.111.24",
  "target_user": "alice@acme.corp",
  "subject": "Urgent: Reset Your Password",
  "iocs": [
    "malicious-site.biz",
    "http://phish.link/reset"
  ],
  "mitre_tactics": ["Initial Access"],
  "mitre_techniques": ["T1566.001"]
}
```

---

## 🗃️ Project Structure

```
incidforge/
│
├── generator/
│   ├── incident_factory.py      # Core logic for fake incident generation
│   ├── templates/               # JSON/STIX base templates
│   └── utils.py                 # Timestamping, ID generation, helpers
│
├── examples/                    # Sample generated datasets
│
├── tests/                       # Unit tests for key modules
│
├── main.py                      # CLI interface
├── requirements.txt
└── README.md
```

---

## 🧠 Design Philosophy

**IncidForge** was built to provide SOC and SOAR teams with realistic, flexible, and reusable simulated data that mimics real-world incident patterns.  
Its modular design makes it easy to extend, integrate, and customize for blue-team exercises and automation development.

---

## 🧪 Future Features

- [ ] GUI mode or Web UI with FastAPI  
- [ ] Integration with MITRE ATT&CK API  
- [ ] Generation of timeline-based incidents  
- [ ] Simulated alert correlation engine  
- [ ] Support for exporting directly to SIEM via Syslog/HTTP

---

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## 🧠 About the Author

Made with ❤️ by [Adrián Jerez](https://www.linkedin.com/in/adrianjjerez), cybersecurity engineer passionate about automation, threat detection, and building tools that empower blue teams.
