# Password Inspector v1.1

**A privacy-first Python tool for password strength analysis and breach detection.**

> **No logs. No storage. Just Clarity.**

---

## Features

>**Breach Detection** has finally been added!
Do you know if your password has been breached?

| Feature | Description |
|---------|-------------|
| **Strength Scoring** | 0–100 score based on security best practices |
| **Breach Detection** | Checks Have I Been Pwned via **k-anonymity** |
| **Transparent Rules** | See exactly how points are earned/lost |
| **Zero Logging** | Password never saved, never sent in plaintext |

---

## Future Features 

| Feature | Description |
|---------|-------------|
| **Batch Mode** | Audit wordlists (company passwords, leaks) |
| **CSV Export** | `--csv` for audit reports |

---

## Scoring Criteria (100 points total):
| Criteria | Points |
|----------|--------|
| 8+ characters | 20 |
| Uppercase letters | 10 |
| Lowercase letters | 10 |
| Symbol(s) (at least one) | 20 | 
| Digit(s) (at least one) | 20 | 
| No 3+ repeating chars | 20 |

**Strong Threshold:**              ≥ 80 points
