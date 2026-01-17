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
    score: int = 60  # Highest score without entropy check
    issues: List[str] = []

    #1. Length Check - Number of Characters
    #1.1. Number of Characters (8+) - len()
    MIN_CHAR_AMOUNT = 8
    if len(password) < MIN_CHAR_AMOUNT:
        score -= 10
        issues.append("Too short. NIST minimum is 8 characters.")

    #1.2. Number of characters (12+)
    if len(password) < 12:
        score -= 10
        issues.append("Has less than 12 characters. Has minimum characters but can be better with more.")

    #1.3. Number of characters (16+)
    if len(password) < 16:
        score -= 15
        issues.append("Has less than 16 characters. Recommended if MFA is off.")

    #1.4. Number of characters (20+)
    if len(password) < 20:
        score -= 15
        issues.append("Has less than 20 characters. Best for password strength.")

    #2. No Recurring Characters
    if re.search(r'(.)\1{2,}', password):
        score -= 10
        issues.append("Has recurring characters (e.g aaaa, 1111): Recurring characters common in weak passwords.")

    #3. Entropy Check
    user_inputs = None #Contextual keywords that an attacker may have to be stricter on check
    entropy_result = zxcvbn(password, user_inputs=user_inputs) #returns a dict

    guesses = entropy_result['guesses'] #Minimum Number of Guesses to Crack Password
    entropy_bits = math.log2(guesses) if guesses > 0 else 0
    crack_time = entropy_result['crack_times_display']['offline_slow_hashing_1e4_per_second']

    #Score from 0-4 based on number of guesses. [0:<10^2, 1: <10^4, 2: <10^6, 3: <10^8, 4: >= 10^10]
    entropy_score = entropy_result['score']

    #Add Suggestions & Warnings from zxcvbn
    feedback = entropy_result.get('feedback', {}).get('suggestions', [])
    for suggestion in feedback:
        issues.append(f"Suggestion: {suggestion}")
    warning = entropy_result.get('feedback', {}).get('warning', '')
    if warning:
        issues.append(f"Warning: {warning.strip()}")

    added_entropy_points = 0
    #Cumulative point calculation for entropy score
    if entropy_score:
        if entropy_score >= 0: added_entropy_points += 2
        if entropy_score >= 1: added_entropy_points += 4
        if entropy_score >= 2: added_entropy_points += 6
        if entropy_score >= 3: added_entropy_points += 12
        if entropy_score >= 4: added_entropy_points += 16


    #4. Evaluate Password Strength Score & Status
    final_score = score + added_entropy_points

    strength = "Very Strong" if final_score >= 85 else \
               "Strong" if (final_score >= 65 and final_score < 85) else \
               "Fair" if (final_score >= 45 and final_score < 65) else \
               "Weak" if (final_score >= 20 and final_score <= 45) else "Very Weak"

    #5. Dict output
    return {
        "score": final_score,
        "issues": issues,
        "strong": strength,
        "crack_time": crack_time,
        "guesses": guesses,
        "entropy_bits": entropy_bits,
        "entropy_score": entropy_score
    }