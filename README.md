
# 🛡️ PhishGuard SOC

### Professional Phishing Email Analysis & Security Operations Tool

PhishGuard SOC is a Python-based security analysis tool designed to help security analysts investigate suspicious emails, identify phishing indicators, assess security risks, and manage security incidents.

The project combines email security analysis, IOC investigation, MITRE ATT&CK mapping, and incident management in a lightweight SOC-oriented application.

---

## 🚀 Project Objectives

- Detect suspicious and potentially malicious emails.
- Identify sender impersonation and suspicious domains.
- Analyze email authentication information.
- Extract and investigate Indicators of Compromise (IOCs).
- Analyze attachment security metadata.
- Map findings to MITRE ATT&CK techniques.
- Calculate phishing risk scores.
- Manage incidents through a SOC dashboard.
- Generate structured security analysis data.

---

## ✨ Features

### Email Security Analysis
- EML email parsing.
- Sender and Reply-To analysis.
- Suspicious URL detection.
- Urgency keyword detection.
- SPF, DKIM and DMARC analysis.
- Risk scoring and severity classification.

### Advanced Detection
- Sender display-name impersonation detection.
- Domain similarity and typosquatting detection.
- Suspicious attachment extension detection.
- Double-extension detection.
- Macro-enabled document detection.
- Attachment MIME-type consistency checks.
- SHA-256 attachment hashing.

### Threat Intelligence Architecture
- IOC normalization and validation.
- Support for IP, domain, URL and SHA-256 indicators.
- Provider-based architecture.
- Normalized threat intelligence results.

External threat intelligence lookups are optional and should only be performed with appropriate authorization.

### MITRE ATT&CK
- Mapping selected detection findings to MITRE ATT&CK techniques.
- Technique IDs and names.
- Tactic references.
- Links to official MITRE documentation.

### Incident Management
- SQLite-based incident storage.
- Unique incident identifiers.
- Incident history.
- Risk score and severity tracking.
- Incident status management:
  - NEW
  - INVESTIGATING
  - RESOLVED
  - FALSE_POSITIVE
- Analyst notes.

### SOC Dashboard
- Incident overview and statistics.
- Incident history table.
- Status filtering.
- Incident investigation view.
- Findings and MITRE information.
- Attachment metadata.
- Analyst status updates.

---

## 🏗️ Project Architecture

```text
PhishGuard-SOC/
│
├── app.py
├── main.py
├── requirements.txt
│
├── pages/
│   └── 2_SOC_Dashboard.py
│
├── src/
│   ├── email_parser.py
│   ├── detection_engine.py
│   ├── auth_analyzer.py
│   ├── sender_analyzer.py
│   ├── domain_analyzer.py
│   ├── attachment_analyzer.py
│   ├── threat_intel.py
│   ├── mitre_mapper.py
│   ├── incident_manager.py
│   ├── dashboard.py
│   └── schemas.py
│
├── tests/
│   ├── test_email_parser.py
│   ├── test_detection_engine.py
│   ├── test_schemas.py
│   ├── test_sender_analyzer.py
│   ├── test_attachment_analyzer.py
│   ├── test_threat_intel.py
│   └── test_incident_manager.py
│
├── samples/
│   └── suspicious_email.eml
│
└── data/
    └── incidents.db
```

*Note: The architecture above describes the intended V2 organization. Some files and modules may still be under development.*

---

## 🛠️ Technologies

| Technology | Purpose |
|---|---|
| Python | Core application |
| Streamlit | SOC dashboard |
| SQLite | Incident database |
| Pytest | Automated testing |
| Git & GitHub | Version control |
| MITRE ATT&CK | Threat behavior mapping |
| SHA-256 | Attachment hashing |

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/elkhazzarighizlan28-dev/PhishGuard-SOC.git
cd PhishGuard-SOC
```

### 2. Select the V2 development branch

```bash
git checkout feature/v2-foundation
```

### 3. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

### Launch the Streamlit application

```bash
streamlit run app.py
```

### Run the CLI

```bash
python main.py samples/suspicious_email.eml
```

### Run automated tests

```bash
PYTHONPATH=. pytest -v
```

---

## 📊 Risk Assessment

PhishGuard uses a risk-scoring approach to prioritize suspicious emails.

Findings are assigned severity levels:

- LOW
- MEDIUM
- HIGH
- CRITICAL

The final score is used to classify the overall risk level.

Risk scores are heuristic indicators and should support, not replace, analyst investigation.

---

## 🔐 Security Considerations

- Email content and attachments must be treated as untrusted input.
- Attachments are analyzed using metadata and hashing; this is not a full malware sandbox.
- Sender-provided authentication headers must not be blindly trusted.
- External IOC lookups can expose investigated indicators to third parties.
- Database access and report exports should be handled carefully.
- Never execute suspicious attachments.

---

## 🧪 Testing

The project uses Pytest for automated testing.

Run the complete test suite:

```bash
PYTHONPATH=. pytest -v
```

Tests cover detection logic, data validation, email parsing, attachment analysis, and incident management.

---

## 🗺️ Roadmap

- [x] Email parsing and phishing detection foundation
- [x] Validated finding data model
- [x] Sender identity analysis
- [x] Domain similarity detection
- [x] Attachment security metadata analysis
- [x] Threat intelligence architecture foundation
- [x] MITRE ATT&CK mapping foundation
- [x] SQLite incident management foundation
- [ ] Complete SOC dashboard integration
- [ ] External threat intelligence provider integration
- [ ] PDF incident reporting
- [ ] JSON export
- [ ] Incident audit trail
- [ ] Advanced security testing
- [ ] Final documentation and release

---

## 👩‍💻 Author

**Ghizlan El Khazzari**

Cybersecurity, Cloud & Networks Student

GitHub: [@elkhazzarighizlan28-dev](https://github.com/elkhazzarighizlan28-dev)

---

## ⚠️ Disclaimer

PhishGuard SOC is an educational and defensive cybersecurity project.

Use it only for authorized security analysis and investigation.
