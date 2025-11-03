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
        issues.append("Password strength is low: Consider editing or changing password.")
    elif not strong and (final_score < 50 and final_score >=0):
        issues.append("Password is poor: Change password.")

    #8. Dict output
    return {
        "score": final_score,
        "issues": issues,
        "strong": strong
    }


if __name__ == "__main__":

    #Greeting and Manual
    print("\n" + "="*80)
    print("                          PASSWORD INSPECTOR")
    print("="*80)
    print("WHAT I DO:\n\n                      Receive your password and \n\n                   tell you how strong "
          "it is based \n\n            on password best practices like 8+ characters,\n\n                uppercase "
          "and lowercase letters, e.t.c.")
    print("=" * 80)
    print("                     PASSWORD INSPECTING CRITERIA")
    print("=" * 80)
    print("This is my grading system: \n\n         1. 8+ Characters = 20 points \n\n         2. Uppercase Letters ["
          "A-Z] = 10 points \n\n         3. Lowercase Letters [a-z] = 10 points \n\n         4. Symbols = 20 points "
          "\n\n         5. Digits [0-9] = 20 points \n\n         6. No 3+ recurring characters [e.g. 1111, "
          "aaa] = 20 points\n\n           [total Score: 100 points]")
    print("=" * 80)


    #Getting Password for Processing
    pw = input("Enter password: ").strip()
    if not pw:
        print("No password entered.")
        exit()

    result = checkStrength(pw)
    print
    print(f"\nPassword Strength: {result['score']}/100")
    if result['issues']:
        print("Note and Fix These Issues: " + " → ".join(result['issues']))
    else:
        print("All checks passed!")

    status = "Strong!" if result['strong'] else "Weak — Change Password."
    print(f"{status}")
    print("\n[Privacy: Password processed in memory only. No logs.]")