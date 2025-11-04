"""
Password Inspector v1.1
Copyright (c) 2025 Emmanuel Nkhoma
MIT License - See LICENSE file
"""

import re
from typing import Dict, List


#basic password strength checker
def checkStrength(password: str) -> Dict[str, object]:
    """"
    This function evaluates the strength of a password using a score system based on password best practices

    Best Practices:
        a. 8+ characters
        b. Uppercase and lowercase letters
        c. symbols i.e. ,.<>/?;:'"\\|[]{}-_=+()!`~@#$%^&*
        d. Numbers
        e. no recurring 3 characters i.e. aaaa, 1111, e.t.c.

    Args*
        password - string

    Returns: dict
        a. score - int: 0 to 100
        b. issues - list[str]: too short, no numbers e.t.c.
        c. strong? - boolean: True or false
    """

    score: int = 100  # set to highest score at default
    issues: List[str] = []

    #1. Number of Characters (8+) - len()
    MIN_CHAR_AMOUNT = 8
    if len(password) < MIN_CHAR_AMOUNT:
        score -= 20
        issues.append("Has less than 8 characters: Too short.")

    #2. Uppercase Letters
    if not re.search(r'[A-Z]', password):
        score -= 10
        issues.append("No uppercase letters found: Add uppercase letters.")

    #3. Lowercase Letters
    if not re.search(r'[a-z]', password):
        score -= 10
        issues.append("No lowercase letters found: Add lowercase letters.")

    #4. Symbols [at least one]
    symbols = r'[!@#$%^&*()_+\-=\[\]{}|;:\'",./<>?]'
    if not re.search(symbols, password):
        score -= 20
        issues.append("No symbol found: Add a symbol e.g. {[)=$!*/+ ...")

    #5. Numbers
    # Using r'[0-9]' instead of r'\d' to avoid Unicode digits (e.g., Arabic ١)
    if not re.search(r'[0-9]', password):
        score -= 20
        issues.append("No digits [0-9] found: Add digits to password.")

    #6. No Recurring Characters
    if re.search(r'(.)\1{2,}', password):
        score -= 20
        issues.append("Has recurring characters: Make sure no 3 characters repeat.")

    #7. Evaluate Password Strength Status
    final_score = max(0, score)
    strong: bool = final_score >= 80

    if not strong and final_score >= 50:
        issues.append(f"Password strength is low [Score {final_score}%]: Consider editing or changing password.")
    elif not strong and (final_score < 50 and final_score >=0):
        issues.append(f"Password is poor [Score: {final_score}%]: Change password.")

    #8. Dict output
    return {
        "score": final_score,
        "issues": issues,
        "strong": strong
    }