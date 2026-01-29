# 🔍 SecretTrack

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PyPI Version](https://img.shields.io/pypi/v/secrettrack)](https://pypi.org/project/secrettrack/)
[![Downloads](https://static.pepy.tech/badge/secrettrack)](https://pepy.tech/project/secrettrack)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**SecretTrack** is a professional open-source security tool designed to detect accidentally exposed secrets in code, configuration files, and software projects. Built for DevSecOps teams and security-conscious developers, it combines advanced detection, contextual analysis, and actionable reporting.

## 🚀 Why SecretTrack?

Secret leaks (API keys, tokens, credentials) are one of the leading causes of security breaches. SecretTrack helps you:

- **Prevent leaks** before they reach production
- **Find existing secrets** in your repositories
- **Educate teams** on security best practices
- **Integrate seamlessly** into your CI/CD pipelines
- **Analyze context** to reduce false positives

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🔍 **Multi-platform Detection** | AWS, GitHub, Stripe, Firebase, generic secrets |
| 🧠 **Intelligent Analysis** | Context detection (dev/staging/prod) and confidence scoring |
| 📊 **Multiple Outputs** | Human-readable reports and JSON for CI/CD |
| ⚡ **Optimized Performance** | Fast scanning with intelligent file exclusion |
| 🛡️ **Security by Design** | 100% local execution, no data exfiltration |
| 🔧 **Extensible** | Modular architecture for easy detector addition |

## 📦 Installation

### Installation via pip (recommended)

```bash
pip install secrettrack
```

### Installation from source

```bash
git clone https://github.com/juphinmbaya/secrettrack.git
cd secrettrack
pip install -e .
```

## 🚀 Quick Start

Scan your project directory:

```bash
# Basic scan
secrettrack scan /path/to/your/project

# Scan current directory
secrettrack scan .

# Scan with JSON output for CI/CD integration
secrettrack scan . --json --severity critical,high

# Scan with custom exclusions
secrettrack scan . --exclude "node_modules,*.log,dist,tests"

# Save report to file
secrettrack scan . --output scan-report.json
```

## 📋 Supported Secrets

SecretTrack detects a wide range of secrets with intelligent pattern matching:

| Secret Type | Pattern Examples | Severity |
|------------|-----------------|----------|
| **AWS Keys** | `AKIAIOSFODNN7EXAMPLE`, `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | Critical-High |
| **GitHub Tokens** | `ghp_abc123def456`, `github_pat_abc123`, `x-access-token:abc123` | High-Critical |
| **Stripe Keys** | `sk_live_abc123`, `pk_test_xyz456`, `whsec_abc123` | Critical |
| **Firebase** | `AIzaSyAbC123Def456`, Firebase service accounts | High |
| **Generic Secrets** | Passwords, API keys, JWT tokens, private keys, connection strings | Variable |
| **Database URLs** | `postgresql://`, `mysql://`, `mongodb://`, `redis://` | Medium-High |

## 🎪 Example Output

### Console Output (Human Readable)

```
🔐 SecretTrack Report
============================================================

📊 Summary:
  Total findings: 3
  🔥 Critical: 1
  ⚠️ High: 1
  🔸 Medium: 1
  ℹ️ Low: 0

🔥 CRITICAL Findings (1):
--------------------------------------------------------
🔥 STRIPE: stripe_live_secret_key
  File: config/.env:3
  Secret: sk_live_***xyz789
  Environment: Production
  Risk: Full payment system takeover, unauthorized charges
  Action: 1. Rotate the key immediately in Stripe Dashboard → Developers → API keys
          2. Revoke compromised key
          3. Check for unauthorized charges and refunds

⚠️ HIGH Findings (1):
--------------------------------------------------------
⚠️ AWS: aws_access_key_id
  File: src/config.py:42
  Secret: AKIA***XYZ789
  Environment: Staging
  Risk: AWS account compromise, resource creation/deletion
  Action: 1. Rotate the compromised key immediately via AWS Console
          2. Remove from git history using BFG or git filter-branch

🛡️ Security Recommendations:
--------------------------------------------------------
❌ CRITICAL ACTION REQUIRED:
  • Rotate compromised credentials IMMEDIATELY
  • Check for unauthorized access
  • Remove secrets from git history

🔧 General recommendations:
  • Use environment variables for secrets
  • Implement a secrets management solution
  • Add pre-commit hooks to prevent future leaks
  • Educate team on secure coding practices
```

### JSON Output (CI/CD Integration)

```json
{
  "metadata": {
    "tool": "secrettrack",
    "version": "1.0.0",
    "scan_timestamp": "2024-01-29T10:30:00Z"
  },
  "summary": {
    "total_findings": 3,
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0
  },
  "findings": [
    {
      "type": "stripe",
      "subtype": "stripe_live_secret_key",
      "severity": "critical",
      "file": "config/.env",
      "line": 3,
      "environment": "production",
      "confidence": 0.95,
      "risk": "Full payment system takeover, unauthorized charges",
      "recommendation": "Rotate the key immediately in Stripe Dashboard",
      "hash": "abc123def456",
      "context_preview": "STRIPE_SECRET_KEY=sk_live_abc123xyz789",
      "secret_preview": "sk_**789"
    }
  ]
}
```

## 🖥️ CLI Usage

### Basic Commands

```bash
# Show help
secrettrack --help

# Show version
secrettrack --version

# Scan command help
secrettrack scan --help
```

### Scan Options

| Option | Description | Default |
|--------|-------------|---------|
| `--json` | Output results in JSON format | `False` |
| `--severity` | Comma-separated severities to include | `low,medium,high,critical` |
| `--exclude` | Comma-separated patterns to exclude | `node_modules,.git,__pycache__,*.pyc` |
| `--output, -o` | Output file path | `stdout` |
| `--max-size` | Maximum file size to scan (MB) | `10` |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success, no secrets found |
| `1` | Secrets found (non-critical) |
| `2` | Critical secrets found |
| `3` | Error occurred during scanning |

## 🛡️ Security Principles

SecretTrack is built with security as a first-class citizen:

### 🔒 No Data Exfiltration
- **100% local execution** - No network calls, no external API dependencies
- **No telemetry** - Your secrets never leave your environment
- **Offline-first** - Works completely offline without internet access

### 🛡️ Safe by Default
- **Conservative detection** - Optimized to minimize false positives
- **Confidence scoring** - Each detection includes a confidence score (0.0-1.0)
- **Context awareness** - Understands dev/staging/prod environments

### 🔐 Secure Implementation
- **Read-only scanning** - Never modifies your files
- **Safe secret masking** - Masks secrets in output to prevent accidental exposure
- **Permission-aware** - Respects file permissions and access controls

## ⚖️ Ethical Use

SecretTrack is designed for **defensive security purposes only**:

### ✅ Approved Uses
- Auditing your own code and repositories
- Educational purposes and security training
- CI/CD security checks in your pipelines
- Internal security audits with proper authorization
- Open-source project security assessments

### ❌ Prohibited Uses
- Scanning systems you don't own or have explicit permission to test
- Attempting to discover secrets in third-party code without authorization
- Using the tool for malicious purposes or unauthorized access
- Bypassing security controls or terms of service

**Always obtain proper authorization before scanning any systems.**

## 🏗️ Architecture

SecretTrack follows a modular, extensible architecture:

```
secrettrack/
├── scanner/              # File system and Git history scanning
│   ├── filesystem.py     # Filesystem scanner
│   └── git_history.py    # Git commit history scanner (optional)
├── detectors/            # Secret detection engines
│   ├── base.py           # Base detector class
│   ├── aws.py            # AWS key detector
│   ├── github.py         # GitHub token detector
│   ├── stripe.py         # Stripe key detector
│   ├── firebase.py       # Firebase credential detector
│   └── generic.py        # Generic secret detector
├── analyzer/             # Analysis and confidence scoring
│   ├── context.py        # Context analysis (dev/staging/prod)
│   └── confidence.py     # Confidence scoring engine
└── report/               # Output generation
    ├── human.py          # Human-readable reports
    └── json.py           # JSON reports for CI/CD
```

### Adding Custom Detectors

Extend SecretTrack with your own detectors:

```python
from secrettrack.detectors.base import BaseDetector
import re

class CustomDetector(BaseDetector):
    def _get_patterns(self):
        return [
            {
                "name": "custom_api_key",
                "pattern": re.compile(r'(?i)custom_api_key[\s:=]+[\'"]([0-9a-zA-Z]{32})[\'"]'),
            }
        ]
    
    def get_secret_type(self):
        return "custom"
    
    def _get_risk_description(self):
        return "Custom API compromise"
    
    def _get_recommendation(self):
        return "Rotate your custom API key immediately"
```

## 🔧 Integration

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/juphinmbaya/secrettrack.git
    rev: v1.0.0
    hooks:
      - id: secrettrack
        args: [--severity, critical,high]
```

### GitHub Actions

```yaml
name: Secret Scan
on: [push, pull_request]
jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Fetch all history for Git history scanning
      
      - name: Install SecretTrack
        run: pip install secrettrack
      
      - name: Scan for secrets
        run: secrettrack scan . --json --severity critical,high
        continue-on-error: true
      
      - name: Upload scan results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: secret-scan-results
          path: |
            scan-report.json
```

### GitLab CI/CD

```yaml
stages:
  - security

secret_scan:
  stage: security
  image: python:3.9
  script:
    - pip install secrettrack
    - secrettrack scan . --json --severity critical,high --output gl-secret-scan.json
  artifacts:
    paths:
      - gl-secret-scan.json
    when: always
  allow_failure: true
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    
    stages {
        stage('Secret Scan') {
            steps {
                script {
                    sh 'pip install secrettrack'
                    sh 'secrettrack scan . --json --severity critical,high --output jenkins-secret-scan.json'
                    
                    // Fail pipeline on critical findings
                    def scanResults = readJSON file: 'jenkins-secret-scan.json'
                    def criticalCount = scanResults.summary.critical
                    
                    if (criticalCount > 0) {
                        error("Found ${criticalCount} critical secrets")
                    }
                }
            }
        }
    }
}
```

## 📊 Performance

SecretTrack is optimized for performance:

- **Intelligent file filtering** - Skips binary files, images, videos, and archives
- **Size limits** - Configurable maximum file size (default: 10MB)
- **Parallel scanning** - Efficient multi-file processing
- **Memory efficient** - Processes files line by line, not all at once

### Benchmark Results

| Scenario | Files Scanned | Time Taken | Memory Usage |
|----------|---------------|------------|--------------|
| Small project (1K files) | ~1,000 | 2-3 seconds | < 50MB |
| Medium project (10K files) | ~10,000 | 15-20 seconds | < 100MB |
| Large project (100K files) | ~100,000 | 2-3 minutes | < 200MB |

## 🚧 Roadmap

### Upcoming Features

- [ ] **Git history scanning** - Detect secrets in commit history
- [ ] **Custom regex patterns** - User-defined detection patterns
- [ ] **Plugin system** - Community-contributed detectors
- [ ] **Performance optimizations** - Parallel scanning, caching
- [ ] **IDE integrations** - VS Code, PyCharm, IntelliJ plugins
- [ ] **Docker support** - Official Docker images and scanning
- [ ] **More detectors** - Additional service providers
- [ ] **Baseline comparisons** - Track findings over time
- [ ] **False positive management** - Mark and ignore known false positives
- [ ] **API mode** - REST API for integration with other tools

### Planned Improvements

- **Enhanced pattern matching** - Machine learning-based detection
- **Better context analysis** - Understanding code structure and usage
- **Remediation automation** - Integration with secret rotation APIs
- **Team collaboration** - Shared configurations and findings
- **Compliance reporting** - SOC2, ISO27001, GDPR reports

## 🤝 Contributing

We welcome contributions from the community! Here's how you can help:

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. **Make your changes**
4. **Run tests**
   ```bash
   pip install pytest
   pytest tests/
   ```
5. **Commit your changes**
   ```bash
   git commit -m "Add amazing feature"
   ```
6. **Push to the branch**
   ```bash
   git push origin feature/amazing-feature
   ```
7. **Open a Pull Request**

### Development Setup

```bash
# Clone the repository
git clone https://github.com/juphinmbaya/secrettrack.git
cd secrettrack

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
flake8 secrettrack/
black secrettrack/

# Build documentation
cd docs && make html
```

### Areas Needing Contribution

- **New detectors** for additional services
- **Performance improvements**
- **Documentation enhancements**
- **Bug fixes and security improvements**
- **CI/CD integrations**
- **Localization and translations**

### Code Standards

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
- Use type hints where appropriate
- Write comprehensive docstrings
- Include unit tests for new features
- Update documentation with changes

## 📄 License

SecretTrack is released under the **MIT License**:

```
MIT License

Copyright (c) 2024 SecretTrack Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## ⚠️ Disclaimer

### Security Notice

SecretTrack is a security tool designed to help improve your security posture. However:

- **No guarantee of completeness** - SecretTrack may not find all secrets
- **False positives** - Some findings may be false positives requiring manual verification
- **Security responsibility** - Ultimately, you are responsible for your own security

### Legal Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Always:
- Obtain proper authorization before scanning systems
- Comply with all applicable laws and regulations
- Respect intellectual property rights
- Use the tool only for legitimate security purposes

## 📞 Support

### Getting Help

- **Issues**: [GitHub Issues](https://github.com/juphinmbaya/secrettrack.git/issues)
- **Discussions**: [GitHub Discussions](https://github.com/juphinmbaya/secrettrack.git/discussions)
- **Email**: security@example.com

### Community

- Follow on [Twitter](https://twitter.com/SecretTrack)
- Star the project on [GitHub](https://github.com/juphinmbaya/secrettrack.git)

### Commercial Support

For enterprise features, custom integrations, or dedicated support, contact us at enterprise@example.com.

---

**SecretTrack** - Because secrets should stay secret. 🔒

*Made with ❤️ by Juphin Mbaya security practitioners for the developer community.*