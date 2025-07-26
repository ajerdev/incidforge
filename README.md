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