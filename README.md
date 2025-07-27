# 🛠️ IncidForge – Synthetic Incident Generator for SOC & SOAR Testing

**IncidForge** is a lightweight Python-based tool designed to simulate cybersecurity incidents for testing and validation of SOC pipelines, SIEM parsing, and SOAR automation workflows.

Whether you're a blue team engineer, SOAR developer, or simply want to stress-test your playbooks, **IncidForge** provides realistic, customizable incident data in JSON and STIX formats.

---

## 📌 Features

- 🔄 **Generate fake incidents** (phishing, brute force, malware, etc.)
- 🧱 **Structured output** in JSON (future implementation of STIX 2.1 format)
- 🎭 **Noise injection**: add decoy or irrelevant events
- 💾 **Export results** to file with dynamic filenames (timestamped & labeled)
- 🔗 **Correlated event chains**: simulate full campaigns
- 🧠 **MITRE ATT&CK mapped techniques** for realism
- ⚙️ **Customizable via CLI** Typer-based

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

## 🔧 Command Options

| Flag         | Description                                      | Default |
|--------------|--------------------------------------------------|---------|
| `--type`     | Type of incident to generate                     | phishing |
| `--count`    | Number of incidents to generate                  | 1       |
| `--noise`    | Include decoy/noisy events                       | False   |
| `--export`   | Save incidents to a timestamped `.json` file     | False   |
| `--correlated` | Simulate related events (e.g. phishing + brute force) | False |

#### Available values for `--type`:

- `phishing`
- `bruteforce`
- `malware`
- `ransomware`
- `data_exfiltration`
- `command_and_control`
- `insider_threat`
- `port_scanning`
- `web_exploit`
- `suspicious_powershell`

---

## 🧪 Example Usage

```bash
# Generate 5 phishing incidents in JSON format:
python main.py --type phishing --count 5

# Generate 5 phishing incidents (output will be in JSON format by default — the --format flag is not required at this time)
python main.py --type phishing --format json --count 7

# Generate events with noise:
python main.py --type malware --count 20 --noise

# Generate 3 brute force events and export to file
python main.py --type bruteforce --count 3 --export
> ✔ Incidents exported to: exports/incidents_20250727_2010_3phishing.json
```

### 🧾 Sample Output: Phishing + Noise Events

Below is an example of a mixed output containing both a simulated phishing incident and a decoy (noise) event. This illustrates how realistic alerts can be blended with benign activity to simulate real-world SOC conditions.

```json
  {
    "id": "INC-20250727-2022e5",
    "type": "phishing",
    "timestamp": "2025-07-27T16:52:10.874900Z",
    "source_ip": "117.29.237.142",
    "target_user": "user123@domain.com",
    "subject": "Reset your password",
    "iocs": [
      "login-update.com"
    ],
    "mitre_tactics": [
      "Initial Access"
    ],
    "mitre_techniques": [
      "T1566.001"
    ]
  },
  {
    "type": "noise::login_success",
    "description": "Benign login event from internal user",
    "details": {
      "user": "jsmith",
      "host": "hr-laptop",
      "resource": "vpn.acme.corp"
    },
    "id": "INC-20250727-1146c4",
    "timestamp": "2025-07-27T16:52:10.875136Z",
    "source_ip": "167.117.68.70"
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
├── exports/                     # Sample generated datasets
│
├── tests/                       # Unit tests for key modules
│   └── test_factory.py          # Pytest testing for incident generation
│
├── main.py                      # CLI interface
├── requirements.txt
└── README.md
```

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
