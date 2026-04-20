# 🔐 SafeTrace

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-0.1.0-orange.svg)](pyproject.toml)

**Lightweight AI-powered cybersecurity toolkit for phishing detection.**

SafeTrace is a CLI-first Python package that lets developers scan URLs and text for phishing or malicious patterns using machine learning. It ships with auto-training models, a professional command-line interface, and a modular Python API.

---

## 🤔 Why SafeTrace?

Most phishing detection tools are either enterprise-grade SaaS products or unmaintained research projects. SafeTrace fills the gap:

- **Zero setup friction** — models auto-train on first run, no manual steps.
- **CLI-first** — pipe it into scripts, CI pipelines, or security audits.
- **Explainable** — every scan tells you *why* something is suspicious, not just a score.
- **Lightweight** — only 3 dependencies (`scikit-learn`, `joblib`, `numpy`). No cloud, no API keys.
- **Extensible** — add your own patterns in `config.py`, retrain with `safetrace train`.

---

## ✨ Features

| Feature | Description |
|---|---|
| **URL Scanner** | Extracts 15 structural features and classifies via Random Forest |
| **Email Analyser** | TF-IDF + Logistic Regression + rule-based pattern matching |
| **Batch Processing** | Scan entire files of URLs or emails in one command |
| **JSON Output** | `--json` flag for machine-readable output / pipeline integration |
| **Verbose Mode** | `--verbose` flag for detailed breakdowns |
| **Auto-Training** | Models train automatically on first use — no manual step |
| **Explainability** | Specific reasons for each risk assessment, not generic labels |

---

## 📦 Installation

### From source (recommended)

```bash
git clone https://github.com/safetrace/safetrace.git
cd safetrace
pip install -e .
```

### From PyPI (once published)

```bash
pip install safetrace
```

---

## 🚀 Quick Start

Models auto-train on first use — just start scanning:

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

### Analyse text / email

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

### Scan a safe URL

```bash
safetrace url https://www.github.com/explore
```

```
  [LOW RISK ✅]
  URL:        https://www.github.com/explore
  Confidence: 0.03
  Reasons:
    • No specific risk indicators found
```

---

## 📄 Batch Processing

Scan multiple URLs or text entries from a file:

```bash
# URLs — one per line
safetrace url-file urls.txt

# Emails / text — one per line
safetrace email-file emails.txt

# JSON output for scripting
safetrace url-file urls.txt --json
```

---

## ⚙️ CLI Flags

| Flag | Effect |
|---|---|
| `--json` | Output results as machine-readable JSON |
| `--verbose` | Show detailed explanation and thresholds |
| `--version` / `-v` | Print SafeTrace version |

### JSON output example

```bash
safetrace url http://fake-login.xyz --json
```

```json
{
  "url": "http://fake-login.xyz",
  "risk": "HIGH",
  "confidence": 0.94,
  "reasons": [
    "Contains suspicious keyword 'login'",
    "Uses TLD '.xyz' — commonly associated with phishing campaigns",
    "Does not use HTTPS encryption"
  ]
}
```

---

## 🧰 Python API

```python
from safetrace.core import URLScanner, EmailScanner

# URL scanning
url_scanner = URLScanner()
result = url_scanner.scan("http://paypal-secure-login.tk/confirm")
print(result)
# {
#     "url": "http://paypal-secure-login.tk/confirm",
#     "risk": "HIGH",
#     "confidence": 0.93,
#     "reasons": ["Contains suspicious keyword 'login'", ...]
# }

# Email scanning
email_scanner = EmailScanner()
result = email_scanner.scan("Congratulations! You have won a million dollars!")
print(result)
# {
#     "risk": "HIGH",
#     "phishing_probability": 0.88,
#     "flags": ["Too Good To Be True: 'congratulations', 'you have won', 'million dollars'"]
# }
```

---

## 📁 Project Structure

```
SafeTrace/
├── safetrace/
│   ├── __init__.py              # Package metadata
│   ├── __main__.py              # python -m safetrace support
│   ├── cli.py                   # CLI (argparse + --json + --verbose)
│   ├── config.py                # Thresholds, paths, patterns, logging
│   ├── train.py                 # Model training script
│   ├── core/
│   │   ├── __init__.py
│   │   ├── url_scanner.py       # URL risk classifier (auto-trains)
│   │   ├── email_scanner.py     # Email phishing detector (auto-trains)
│   │   ├── feature_extractor.py # 15-feature URL vector + explainability
│   │   └── utils.py             # Risk labels, formatting, model checks
│   └── models/                  # .joblib artifacts (auto-generated)
├── .github/
│   ├── ISSUE_TEMPLATE.md
│   └── PULL_REQUEST_TEMPLATE.md
├── pyproject.toml
├── requirements.txt
├── CONTRIBUTING.md
├── LICENSE (MIT)
├── .gitignore
└── README.md
```

---

## 🧠 How It Works

### URL Scanner

1. **Feature Extraction** — Parses the URL and extracts 15 numerical features:
   - **Structural**: length, dots, hyphens, slashes, digit count
   - **Security**: HTTPS presence, IP address detection, suspicious TLD
   - **Semantic**: count of phishing-related tokens (`login`, `verify`, `account`, etc.)
   - **Complexity**: subdomain depth, path length, query string length

2. **Classification** — A `RandomForestClassifier` (100 trees, balanced classes) predicts phishing probability.

3. **Explainability** — Each risk reason references the *specific indicator* found (e.g., "Contains suspicious keyword 'login'" instead of "Suspicious URL").

### Email / Text Scanner

1. **TF-IDF Vectorization** — Converts text into sparse unigram+bigram features (500 max).

2. **Classification** — `LogisticRegression` predicts phishing probability.

3. **Pattern Matching** — Rule-based detection flags 5 phishing categories:
   - Urgency, Threats, Credential Requests, Too-Good-To-Be-True, Impersonation

4. **Hybrid Correction** — If 3+ pattern categories match but the ML score is low, the probability is boosted for safety.

---

## ⚙️ Configuration

All thresholds and patterns live in `safetrace/config.py`:

| Setting | Default | Description |
|---|---|---|
| `HIGH_RISK_THRESHOLD` | 0.75 | Probability ≥ this → HIGH risk |
| `MEDIUM_RISK_THRESHOLD` | 0.45 | Probability ≥ this → MEDIUM risk |
| `SUSPICIOUS_TOKENS` | 18 items | Keywords common in phishing URLs |
| `SUSPICIOUS_TLDS` | 14 items | TLDs frequently abused by attackers |
| `PHISHING_PATTERNS` | 5 categories | Rule-based text patterns |

---

## 🛠️ Manual Training

Models auto-train on first use, but you can retrain anytime:

```bash
safetrace train
```

This rebuilds models using the built-in synthetic dataset and saves them to `safetrace/models/`.

---

## 📋 Requirements

- Python ≥ 3.9
- scikit-learn ≥ 1.3.0
- joblib ≥ 1.3.0
- numpy ≥ 1.24.0

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Ideas for future development:
- Real-world training datasets (PhishTank, OpenPhish)
- Domain age / WHOIS lookups
- Email header analysis
- REST API server mode
- Browser extension integration
- Confidence calibration with Platt scaling
