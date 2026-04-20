# 🔐 SafeTrace

**Open-source AI-powered cybersecurity toolkit for detecting phishing URLs and malicious text — directly from your terminal.**

```bash
pip install safetrace
safetrace url http://example.com
```

⭐ If you find this useful, consider starring the repo!

---

## 🚀 Demo

<img width="936" height="470" alt="SafeTrace" src="https://github.com/user-attachments/assets/d625aa9c-21e1-429f-b72a-92584606e9eb" />


---

## 🤔 Why SafeTrace?

Most phishing detection tools are either:

* Heavy enterprise-grade SaaS platforms
* Unmaintained research projects

**SafeTrace fills the gap:**

* ⚡ **Zero setup friction** — models auto-train on first run
* 🧠 **Explainable** — shows *why* something is suspicious
* 🧰 **CLI-first** — perfect for scripts, pipelines, automation
* 🪶 **Lightweight** — no cloud, no API keys, minimal dependencies
* 🔌 **Extensible** — easily customizable via `config.py`

---

## 👨‍💻 Who is this for?

* Developers building security tools
* Students learning ML + cybersecurity
* Anyone who wants a lightweight phishing detector

---

## ✨ Features

| Feature          | Description                                                      |
| ---------------- | ---------------------------------------------------------------- |
| URL Scanner      | Extracts 15 structural features and classifies via Random Forest |
| Email Analyzer   | TF-IDF + Logistic Regression + rule-based detection              |
| Batch Processing | Scan multiple URLs or emails from a file                         |
| JSON Output      | `--json` for machine-readable output                             |
| Verbose Mode     | `--verbose` for detailed explanations                            |
| Auto-Training    | Models train automatically on first run                          |
| Explainability   | Clear reasons for every risk decision                            |

---

## 📦 Installation

### From source

```bash
git clone https://github.com/purab-awasthi/SafeTrace.git
cd SafeTrace
pip install -e .
```

### From PyPI 

```bash
pip install safetrace
```

---

## ⚡ Quick Start

### Scan a URL

```bash
safetrace url http://fake-login.xyz/verify-account
```

```
[HIGH RISK ⚠️]
URL:        http://fake-login.xyz/verify-account
Confidence: 0.94
Reasons:
  • Contains suspicious keyword 'login'
  • Multiple suspicious keywords: 'login', 'verify', 'account'
  • Uses TLD '.xyz' — commonly associated with phishing campaigns
  • Does not use HTTPS encryption
```

---

### Analyze text / email

```bash
safetrace email "URGENT: Your account has been compromised. Verify your identity immediately."
```

```
[HIGH RISK ⚠️]
Phishing probability: 0.97
Detected patterns:
  • Urgency: 'immediately', 'urgent'
  • Threats: 'your account has been compromised'
  • Credential Request: 'verify your identity'
```

---

### Scan a safe URL

```bash
safetrace url https://github.com
```

```
[LOW RISK ✅]
Confidence: 0.03
Reasons:
  • No specific risk indicators found
```

---

## 📄 Batch Processing

```bash
# URLs
safetrace url-file urls.txt

# Emails
safetrace email-file emails.txt

# JSON output
safetrace url-file urls.txt --json
```

---

## ⚙️ CLI Flags

| Flag        | Description             |
| ----------- | ----------------------- |
| `--json`    | Machine-readable output |
| `--verbose` | Detailed explanation    |
| `--version` | Show version            |

---

## 🧰 Python API

```python
from safetrace.core import URLScanner, EmailScanner

url_scanner = URLScanner()
print(url_scanner.scan("http://paypal-secure-login.tk"))

email_scanner = EmailScanner()
print(email_scanner.scan("You have won a prize!"))
```

---

## 📁 Project Structure

```
SafeTrace/
├── safetrace/
│   ├── cli.py
│   ├── config.py
│   ├── train.py
│   ├── core/
│   │   ├── url_scanner.py
│   │   ├── email_scanner.py
│   │   ├── feature_extractor.py
│   │   └── utils.py
│   └── models/
├── assets/
│   └── demo.gif
├── pyproject.toml
├── requirements.txt
├── CONTRIBUTING.md
├── LICENSE
└── README.md
```

---

## 🧠 How It Works

### URL Scanner

* Extracts structural + semantic features from URLs
* Uses `RandomForestClassifier`
* Maps probability → LOW / MEDIUM / HIGH risk
* Generates explainable reasons

### Email / Text Scanner

* TF-IDF vectorization
* Logistic Regression classifier
* Rule-based pattern detection (urgency, threats, etc.)
* Hybrid scoring system

---

## ⚙️ Configuration

Defined in `safetrace/config.py`:

* Risk thresholds
* Suspicious keywords
* Suspicious TLDs
* Pattern rules

---

## 🛠️ Manual Training

```bash
safetrace train
```

---

## 📋 Requirements

* Python ≥ 3.9
* scikit-learn
* joblib
* numpy

---

## ⚠️ Disclaimer

SafeTrace is a heuristic-based tool and should not be used as the sole security decision system.

---

## 🤝 Contributing

Contributions are welcome!

See `CONTRIBUTING.md` for guidelines.

---

## 📄 License

MIT License
