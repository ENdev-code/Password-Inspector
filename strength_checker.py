"""
Password Inspector v1.1
Copyright (c) 2025 Emmanuel Nkhoma
MIT License - See LICENSE file
"""

import re
import math
from typing import Dict, List
from zxcvbn import zxcvbn

#basic password strength checker
def checkStrength(password: str) -> Dict[str, object]:
    """"
    This function evaluates the strength of a password using a score system based on password best practices and entropy

    Best Practices:
        a. 8+ characters
        b. no recurring 3 characters i.e. aaaa, 1111, e.t.c.

    Entropy:
        The entropy judges the estimated difficulty for a password to be cracked (in bits) and is expressed as a measure of randomness/uncertainty.
        Breaks the password into patterns, calculates the number of guesses per pattern and figures out how many guesses the whole password would take.
        ** Uses zxcvbn
    Args*
        password - string

    Returns: dict
        a. score - int: 0 to 100
        b. issues - list[str]: too short, no numbers e.t.c.
        c. strong? - boolean: True or false
    """

#Scoring criteria
    score: int = 100  # set to highest score at default
    issues: List[str] = []

    #1. Number of Characters (8+) - len()
    MIN_CHAR_AMOUNT = 8
    if len(password) < MIN_CHAR_AMOUNT:
        score -= 5
        issues.append("Has less than 8 characters: Too short.")

    #2. Number of characters (12+)
    if len(password) < 12:
        score -= 10
        issues.append("Has less than 12 characters, not bad but the more the merrier.")

    #3. Number of characters (16+)
    if len(password) < 16:
        score -= 15
        issues.append("Has less than 16 characters, not bad but the more the merrier.")

    #4. Number of characters (20+)
    if len(password) < 20:
        score -= 20
        issues.append("Has less than 20 characters, not bad but the more the merrier.")

    #5. No Recurring Characters
    if re.search(r'(.)\1{2,}', password):
        score -= 10
        issues.append("Has recurring characters: Recurring characters common in weak passwords.")

    #6. Entropy Check
    user_inputs = None #Contextual keywords that an attacker may have to be stricter on check
    entropy_result = zxcvbn(password, user_inputs=user_inputs) #returns a dict

    guesses = entropy_result['guesses'] #number of guesses 2^entropy_bits
    entropy_bits = math.log2(guesses) if guesses > 0 else 0
    crack_time = entropy_result['crack_times_display']['offline_fast_hashing_1e10_per_second']
    #Score from 0-4 based on number of guesses. [0:<10^2, 1: <10^4, 2: <10^6, 3: <10^8, 4: >= 10^10]
    entropy_score = entropy_result['score']
    feedback = entropy_result.get('feedback', {}).get('suggestions', [])
    #for suggestion in suggestions:
     #   issues.append(f"Suggestion: {suggestion.strip()}")

    warning = entropy_result.get('feedback', {}).get('warning', '')
    if warning:
        issues.append(f"Warning: {warning.strip()}")

    if entropy_score:
        if entropy_score >= 0:
            score += 2
        if entropy_score >= 1:
            score += 4
        if entropy_score >= 2:
            score += 6
        if entropy_score >= 3:
            score += 12
        if entropy_score == 4:
            score += 16

    #7. Evaluate Password Strength Status
    final_score = max(0, score)
    strong: bool = final_score >= 38

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