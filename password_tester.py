"""
Password Inspector v1.1
Copyright (c) 2025 Emmanuel Nkhoma
MIT License - See LICENSE file
"""

from breach_checker import checkBreached
from strength_checker import checkStrength

def printGreeting():
    """Prints a greeting to the user and the user manual for Password Inspector"""
    # Greeting and Manual
    print("\n" + "=" * 80)
    print("                          PASSWORD INSPECTOR")
    print("=" * 80)
    print("WHAT I DO: \n\n"
          "     1. Receive a password as input \n"
          "     2. Evaluate its strength and check if it has been breached \n"
          "     3. Output results")
    print("=" * 80)
    print("                     PASSWORD INSPECTING CRITERIA")
    print("=" * 80)
    print("This is my grading system: \n\n"
          "         1. 8+ Characters = 10 points \n"
          "         2. 12+ Characters = 10 points \n"
          "         3. 16+ Characters = 15 points \n"
          "         4. 20+ Characters = 15 points \n"
          "         5. No 3+ recurring characters [e.g. 1111, aaa] = 10 points\n"
          "         6. Entropy Score Points (zxcvbn: 0-4) = 40 points \n\n"
          "     This is my grading system relative to the entropy score:\n"
          "     KEY: Entropy Score = Password Inspector Points\n\n"
          "         a. 0 = 2\n"
          "         b. 1 = 6\n"
          "         c. 2 = 12\n"
          "         d. 3 = 24\n"
          "         e. 4 = 40\n"       
          "           [total Score: 100 points]")
    print("=" * 80)

def passwordInspector(password:str):
    """
    Does 2 checks:
        a. Strength Check using strength_checker's checkStrength function
        b. Breach Check using breach_checker's checkBreached function

    Outputs:
        a. Strength level and issues if present
        b. Breach status
    """

    print("=" * 80)
    print(f"Password Entered: {password} \n\n"
          f"Beginning Inspection ...")
    print("=" * 80)


    #1. Strength Check via checkStrength
    print("                              1. STRENGTH CHECK...")
    print("="*80)
    result = checkStrength(password)
    print
    print(f"\nPassword Strength: {result['score']}/100")
    print(f"\nEntropy Score (zxcvbn): {result['entropy_score']}")
    print(f"\nCrack Time: {result['crack_time']}")
    print(f"\nNumber of Guesses: {result['guesses']}")
    print("=" * 80)
    if result['issues']:
        print("Noted the following issues and provided their fixes: \n\n " + " \n\n ".join(result['issues']))
    else:
        print("All checks passed!")
    print("=" * 80)
    status = f"\n\n {result['score']}% Strong!" if result['strong'] else "Areas to fix shown above."
    print(f"Password is {status} by Password Inspector standard.")
    print("="*80)

    #2. Breach Check
    print("                              2. BREACH CHECK...")
    print("=" * 80)
    pwned, count = checkBreached(check_password)

    if pwned:
        print(f"Password {password} has been breached.\n"
              f"Breach Count [How many times]: {count} \n"
              f"CHANGE PASSWORD AS SOON AS POSSIBLE!")
    else:
        print("All good! No breaches found.")
    print("=" * 80)
    print("[Privacy: Password processed in memory only. No logs.]\n")
    print("[K-Anonymity: Password matched locally with retrieved breached passwords.]")
    print("=" * 80)

if __name__ == "__main__":
    printGreeting()
    check_password = input("Enter password to inspect: ")
    if not check_password:
        print("No password entered.")
        exit()

    #execute
    passwordInspector(check_password)