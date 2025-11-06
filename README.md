[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![CLI Tool](https://img.shields.io/badge/tool-CLI-red)](#how-to-use)
[![Version: v1.3](https://img.shields.io/badge/version-v1.3-success)](https://github.com/ENdev-code/Password-Inspector/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: Privacy-First](https://img.shields.io/badge/security-privacy--first-green)](#privacy--security)
[![HIBP k-anonymity](https://img.shields.io/badge/HIBP-k--anonymity-orange)](#features)

# Password Inspector v1.3

**A privacy-first Python tool for password strength analysis and breach detection via Have I Been Pwned (HIBP) API.**

> **No logs. No storage. Just Clarity.**

Password Inspector is an open-source, modular CLI tool designed and created fro cybersecurity enthusiasts, auditors, developers and corporate IT teams. It evaluates password strength based on best practices and checks if passwords have been breached via k-anonymity ensuring that no passwords are logged nor are they sent in plaintext. Built cleanly, with maintainable code and documentation under MIT License.


**Author**: Emmanuel Nkhoma  
**GitHub**: [@ENdev-code](https://github.com/ENdev-code)  
**License**: MIT  
**Created**: November 2025
**Current Version**: `v1.3`
---

## Features
Below is a description of the features Password Inspector can provide for you. 

| Feature                        | Description                                                                                            |
|--------------------------------|--------------------------------------------------------------------------------------------------------|
| **Password Strength Analysis** | Scores passwords from 0–100 based on security criteria.                                                |
| **Breach Detection**           | Checks Have I Been Pwned via **k-anonymity** to verify if passwords have appeared in  recent breaches. |
| **CLI Support**                | Interactive mode, single password input or batch processing from wordlists.                            |
| **Output Options**             | Provides human-readable reports, CSV exports and live progress updates.                                |
| **Modular Design**             | Separates modules used for strength and breach checks making them easy to test and extend.             |
| **Cross Platform**             | Works on multiple platforms i.e. Windows, Linux, macOS.                                                |
| **Transparent Rules**          | See exactly how points are earned/lost.                                                                |
| **Privacy Focused**            | Password are never saved, never sent in plaintext and are processed locally.                           |


---

## Scoring Criteria (100 points total):
Below is the scoring criteria for passwords that Password Inspector will use 

| Criteria | Points |
|----------|--------|
| 8+ characters | 20 |
| Uppercase letters | 10 |
| Lowercase letters | 10 |
| Symbol(s) (at least one) | 20 | 
| Digit(s) (at least one) | 20 | 
| No 3+ repeating chars | 20 |

### Strength Levels/Thresholds
- **Strong:**              ≥ 80 points 
- **Low:**                 50-79 points (Change password or consider editing)
- **Strength:**            <50 points (Change password ASAP)

---

## Use Cases
Below is a comprehensive summary of use cases for Password Inspector

| Use Case                  | Description                                                                                                                |
|---------------------------|----------------------------------------------------------------------------------------------------------------------------|
| Personal Use              | Check your own passwords for strength level and breach status before using them or after use for evaluation.               |
| Corporate Security Audits | Batch processing employee or system passwords for compliance reports.                                                      |
| Penetration Testing       | Analyse leaked wordlists or default passwords during red team exercises (e.g., analysing common patterns used by targets). |
| Compliance Insurance      | Proves password policy enforcement with frameworks like NIST, ISO27001 e.t.c.                                              |
| Educational Tool          | Demonstrate and prove password best practices in cybersecurity training.                                                   |
| Developer Integration     | Modules can be imported and integrated with custom apps (e.g., password managers).                                         |

---

## Installation
**Step 1: Clone the Repository**
```bash
git clone https:/github.com/ENdev-code/Password-Inspector.git
cd Password-Inspector
```

**Step 2: Create Virtual Environment**
```bash
python -m venv venv
source .venv/bin/activate #Windows: .venv\Scripts\activate
```

**Step 3: Install Dependencies**
```bash
pip install -r requirements.txt
```

Requirements:
- Python 3.13+
- requests (For HIBP API)

---

## How to Use
**i. Help Menu**
- Shows usage options.
```bash
python password_inspector_cli.py --help
```

**ii. Version Check**
- Shows the current version of Password Inspector.
```bash
python password_inspector_cli.py --version
```

### 1. Interactive Mode
- Enter a password when prompted to check its strength level and breach status.

```bash
python password_inspector_cli.py 
```

### 2. Single Password
- Run Password Inspector with a single password. Quotes are required for passwords with special characters.

```bash
python password_inspector_cli.py "yourPassword123!"
```

### 3. Batch Mode (Wordlist)
- Processes passwords from a file (one per line)
- Outputs summary, strength score, breach status and detailed inspection details.

```bash
python password_inspector_cli.py yourwordlist.txt 
```

### 3.1 Password Inspection Report (Batch Mode only)
- Generates a comprehensible report of inspected passwords 
- Report outlines the password, strength score, breach status, breach count, detailed inspection details and recommendations.

```bash
python password_inspector_cli.py yourwordlist.txt --report
```

### 3.2 CSV Export (Batch Mode only)
- Generates CSV file for analysis (Headers being: password, score, strong, pwned, breach_count, issues).

```bash
python password_inspector_cli.py yourwordlist.txt --csv > report.csv
```
--- 

> Do you really know how strong your passwords are? Find out with Password Inspector.  
>~ Emmanuel Nkhoma