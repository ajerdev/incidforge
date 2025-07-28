# 🛠️ IncidForge – Synthetic Incident Generator for SOC & SOAR Testing

**IncidForge** is a lightweight Python-based tool designed to simulate cybersecurity incidents for testing and validation of SOC pipelines, SIEM parsing, and SOAR automation workflows.

Whether you're a blue team engineer, SOAR developer, or simply want to stress-test your playbooks, **IncidForge** provides realistic, customizable incident data in JSON and STIX formats.

---

## 📌 Features

- 🔄 **Generate synthetic incidents** (phishing, brute force, malware, etc.)
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
# Generate a phishing incident in JSON format:
python main.py --type phishing

# Generate 7 phishing incidents (output will be in JSON format by default — the --format flag is not required at this time)
python main.py --type phishing --format json --count 7

# Generate multiple events with noise:
python main.py --type malware --count 20 --noise

# Generate 3 brute force events and export to file
python main.py --type bruteforce --count 3 --export
> ✔ Incidents exported to: exports/incidents_20250727_2010_3phishing.json

#Generate 2 phishing events correlated with 2 data exfiltration
python main.py --type phishing --count 2 --correlate data_exfiltration
```

### 🧾 Sample Output: Phishing + Correlated Exfiltration + Noise Events

This example showcases a realistic output combining:

- **Phishing incidents** as the primary attack vector  
- **Correlated data exfiltration events** that reuse shared attributes (e.g., IPs or users) to simulate attack chaining  
- **Noise events** (benign activity) to mimic real-world SOC signal-to-noise conditions  

This output demonstrates how **IncidForge** can blend meaningful alerts with harmless events to emulate complex threat scenarios for **detection engineering** and **blue team training**.

```json
[
  {
    "id": "INC-20250728-bd6d62",
    "type": "phishing",
    "timestamp": "2025-07-28T00:15:20.175666Z",
    "source_ip": "235.215.89.51",
    "target_user": "alice@acme.corp",
    "subject": "Invoice overdue",
    "iocs": [
      "malicious-site.biz"
    ],
    "mitre_tactics": [
      "Initial Access"
    ],
    "mitre_techniques": [
      "T1566.001"
    ]
  },
  {
    "id": "INC-20250728-d16144",
    "type": "data_exfiltration",
    "timestamp": "2025-07-28T00:15:20.175784Z",
    "source_ip": "235.215.89.51",
    "source_host": "rdp-win10-3",
    "destination_ip": "239.193.250.67",
    "protocol": "HTTP",
    "data_type": "PII",
    "data_volume_mb": 232.88,
    "mitre_tactics": [
      "Exfiltration"
    ],
    "mitre_techniques": [
      "T1041"
    ]
  },
  {
    "id": "INC-20250728-63e947",
    "type": "phishing",
    "timestamp": "2025-07-28T00:15:20.175877Z",
    "source_ip": "239.142.179.28",
    "target_user": "user123@domain.com",
    "subject": "Invoice overdue",
    "iocs": [
      "malicious-site.biz"
    ],
    "mitre_tactics": [
      "Initial Access"
    ],
    "mitre_techniques": [
      "T1566.001"
    ]
  },
  {
    "id": "INC-20250728-788446",
    "type": "data_exfiltration",
    "timestamp": "2025-07-28T00:15:20.175949Z",
    "source_ip": "239.142.179.28",
    "source_host": "legal-srv01",
    "destination_ip": "75.52.86.149",
    "protocol": "HTTPS",
    "data_type": "intellectual property",
    "data_volume_mb": 143.32,
    "mitre_tactics": [
      "Exfiltration"
    ],
    "mitre_techniques": [
      "T1041"
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
    "id": "INC-20250728-43e3c9",
    "timestamp": "2025-07-28T00:15:20.176036Z",
    "source_ip": "181.71.192.61"
  },
  {
    "type": "noise::http_200",
    "description": "Successful HTTP request",
    "details": {
      "url": "/index.html",
      "method": "GET",
      "status": 200
    },
    "id": "INC-20250728-fc14f7",
    "timestamp": "2025-07-28T00:15:20.176103Z",
    "source_ip": "224.41.225.119"
  }
]
```

### 🧾 Sample Output: Phishing + Noise Events

Below is an example of a mixed output containing both a simulated phishing incident and a decoy (noise) event. This illustrates how realistic alerts can be blended with benign activity to simulate real-world SOC conditions.


---

## 🗃️ Project Structure

```
incidforge/
│
├── generator/
│   ├── templates/               # JSON/STIX base templates
│   ├── incident_factory.py      # Core logic for synthetic incident generation
│   ├── stix_exporter.py         # Stix format compatibility
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
- [ ] Simulated alert correlation engine (automatically generate coherent attack chains across multiple techniques and stages)
- [ ] Support for exporting directly to SIEM via Syslog/HTTP

---

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## 🧠 About the Author

Made with ❤️ by [Adrián Jerez](https://www.linkedin.com/in/adrianjjerez), cybersecurity engineer passionate about automation, threat detection, and building tools that empower blue teams.
