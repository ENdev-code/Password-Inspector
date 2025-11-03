# Password Inspector v1.0

**A privacy-first Python tool for password strength analysis and breach detection.**

> **No logs. No storage. Only 5 hash characters sent to HIBP.**

---

## Features

| Feature | Description |
|---------|-------------|
| **Strength Scoring** | 0–100 score based on security best practices |
| **Transparent Rules** | See exactly how points are earned/lost |
| **Zero Logging** | Password never saved, never sent in plaintext |

---

## Future Features 

| Feature | Description |
|---------|-------------|
| **Breach Detection** | Checks Have I Been Pwned via **k-anonymity** |
| **Batch Mode** | Audit wordlists (company passwords, leaks) |
| **CSV Export** | `--csv` for audit reports |

---

## Scoring Criteria (100 points total):
8+ characters                 → 20 points
Uppercase letters             → 10 points
Lowercase letters             → 10 points
Symbol(s) (at least one)      → 20 points
Digit(s) (at least one)       → 20 points
No 3+ repeating chars         → 20 points

*Strong threshold             → ≥80 points
