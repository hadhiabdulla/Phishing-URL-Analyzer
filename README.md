# 🛡️ Phishing URL Analyzer

![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

A comprehensive Python tool designed to analyze URLs and detect phishing attempts using multiple detection techniques including domain analysis, SSL certificate validation, URL pattern recognition, and behavioral analysis.

## 📋 Table of Contents
- [Features](#features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
- [Detection Techniques](#detection-techniques)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## ✨ Features

- **Multi-layered Detection**: Implements 8 different phishing detection techniques
- **Risk Scoring System**: Calculates comprehensive risk scores (0-100)
- **SSL Certificate Validation**: Checks HTTPS usage and validates SSL certificates
- **Domain Age Analysis**: Identifies newly registered domains (common in phishing)
- **Pattern Recognition**: Detects suspicious URL patterns and keywords
- **URL Shortener Detection**: Identifies masked URLs through shortening services
- **Colored Terminal Output**: Easy-to-read results with color-coded risk levels
- **JSON Export**: Save analysis results for further processing
- **Cross-platform**: Works on Windows, macOS, and Linux

## 🔍 How It Works

The Phishing URL Analyzer uses a weighted scoring system to evaluate URLs:

1. **URL Length Check** (Weight: 5) - Flags unusually long URLs
2. **Suspicious Keywords** (Weight: 15) - Detects phishing-related terms
3. **IP Address Usage** (Weight: 20) - Highly suspicious when domain is an IP
4. **HTTPS/SSL Validation** (Weight: 10) - Checks encryption and certificate validity
5. **URL Shortener Detection** (Weight: 10) - Identifies link masking attempts
6. **Subdomain Analysis** (Weight: 10) - Flags excessive subdomain usage
7. **Special Characters** (Weight: 10) - Detects unusual character patterns
8. **Domain Age** (Weight: 15) - Identifies newly created domains

**Risk Levels:**
- 🟢 **SAFE** (0-14): Appears legitimate
- 🔵 **LOW RISK** (15-29): Minor concerns
- 🟡 **MEDIUM RISK** (30-49): Suspicious indicators
- 🔴 **HIGH RISK** (50+): Likely phishing attempt

## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package manager)

### Step 1: Clone the Repository
```bash
git clone https://github.com/hadhiabdulla/Phishing-URL-Analyzer.git
cd Phishing-URL-Analyzer
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Verify Installation
```bash
python phishing_analyzer.py --help
```

## 💻 Usage

### Basic Analysis
```bash
python phishing_analyzer.py -u https://example.com
```

### Save Results to JSON
```bash
python phishing_analyzer.py -u https://suspicious-site.com -o results.json
```

### Command-Line Arguments
- `-u, --url` : **Required** - URL to analyze
- `-o, --output` : Optional - Save results to JSON file
- `-v, --verbose` : Optional - Enable verbose output
- `-h, --help` : Show help message

## 🔬 Detection Techniques

### 1. URL Length Analysis
Phishing URLs often use long, complex URLs to hide malicious domains.
```
Example: https://legitimate-bank.com/login/verify/account/update/secure/...
```

### 2. Keyword Detection
Scans for common phishing keywords:
- `login`, `signin`, `account`
- `verify`, `update`, `secure`
- `banking`, `paypal`, `amazon`

### 3. IP Address Detection
Legitimate websites rarely use raw IP addresses as domains.
```
Suspicious: http://192.168.1.100/login
Safe: https://legitimate-site.com/login
```

### 4. SSL Certificate Validation
Verifies HTTPS usage and SSL certificate authenticity.

### 5. URL Shortener Detection
Identifies links from services like:
- bit.ly, tinyurl.com, goo.gl
- t.co, ow.ly, is.gd

### 6. Subdomain Analysis
Excessive subdomains often indicate phishing:
```
Suspicious: https://login.verify.secure.paypal-account.com
Safe: https://www.paypal.com
```

### 7. Special Character Analysis
Detects unusual patterns and potential homograph attacks.

### 8. Domain Age Analysis
Phishing domains are typically newly registered (< 6 months old).

## 📊 Examples

### Example 1: Analyzing a Safe URL
```bash
$ python phishing_analyzer.py -u https://google.com

============================================================
              PHISHING URL ANALYZER
        Advanced Threat Detection Tool
============================================================

[*] Analyzing URL: https://google.com
============================================================
[✓] URL length (18) appears normal
[✓] No suspicious keywords detected
[✓] Domain is not an IP address
[✓] HTTPS enabled with valid SSL certificate
[✓] No URL shortener detected
[✓] Subdomain count (1) appears normal
[✓] Special character count appears normal
[✓] Domain age (9156 days) appears legitimate

============================================================
Risk Score: 0/100
Verdict: SAFE - Appears legitimate
============================================================
```

### Example 2: Analyzing a Suspicious URL
```bash
$ python phishing_analyzer.py -u http://192.168.1.100/login-verify-account

[!] Domain is an IP address - highly suspicious
[!] URL does not use HTTPS
[!] Multiple suspicious keywords found: login, verify, account
[!] Special characters detected

Risk Score: 55/100
Verdict: HIGH RISK - Likely Phishing
```

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and research purposes only. Always exercise caution when visiting suspicious URLs. This analyzer is not 100% accurate and should be used as one of multiple security measures.

## 👨‍💻 Author

**Hadhi Abdulla**
- GitHub: [@hadhiabdulla](https://github.com/hadhiabdulla)
- LinkedIn: [Connect with me](https://linkedin.com)

## 🙏 Acknowledgments

- Thanks to the cybersecurity community for phishing research
- Inspired by real-world phishing attack patterns
- Built with Python and open-source libraries

---

⭐ **Star this repository if you found it helpful!**
