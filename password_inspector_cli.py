"""
Password Inspector v1.2
Copyright (c) 2025 Emmanuel Nkhoma
MIT License - See LICENSE file
"""

#dependencies to use
import argparse
from pathlib import Path
import csv
import sys

#Modules to use
from breach_checker import checkBreached
from strength_checker import checkStrength
from password_tester import printGreeting

#Current Password Inspector version: 1.2
__version__ = 1.2

#Function that Inspects Passwords at CLI level
def inspectPassword(password: str) -> dict:
    strength_check = checkStrength(password)
    pwned, breach_count = checkBreached(password)
    return {
        "password": password,
        "score": strength_check['score'],
        "issues": strength_check['issues'],
        "strong": strength_check['strong'],
        "pwned": pwned,
        "breach_count": breach_count or 0
    }

#Actual CLI Capability is added here
def main():
    #1. Create parsing instance
    parser = argparse.ArgumentParser(
        description="A privacy-first Python tool for password strength analysis and breach detection.",
        epilog="Privacy: K-anonymity and no passwords are logged."
    )

    #1.1. Create argument for parsing: Input - either a password or a path to a wordlist
    parser.add_argument(
        "input",
        nargs="?",
        help="Password or path to wordlist file of passwords to inspect"
    )

    #1.2. Create a --csv argument to allow output pf CSV if toggled
    parser.add_argument(
        "--csv",
        action="store_true",
        help="Output result of inspection as CSV file"
    )

    #1.3 Create an argument to output the current version of Password Inspector
    parser.add_argument(
        "--version",
        action="version",
        help=f"Password Inspector version {__version__}"
    )

    #2. Parse the arguments in Parser into a variable: args
    args = parser.parse_args()

    #3. Inspection
    # *** BATCH MODE: if path to wordlist.txt is provided ***
    if args.input and Path(args.input).exists():

        #3.1. Save path to wordlist
        path = Path(args.input)

        #3.2. Read wordlist and split each password into a new line with no unnecessary spaces nor empty lines
        passwords = [
            line.strip() for line in path.read_text().splitlines() if line.strip()
        ]

        if not passwords:
            print(f"No passwords in file: '{path.name}'")
            return

        print(f"Loading {len(passwords)} passwords from: '{path.name}' ...")
        printGreeting()

        #3.3. Iterate through passwords array and process passwords
        inspected_passwords = []
        total_passwords = len(passwords)
        weak_passwords = pwned_passwords = 0

        for i, pw in enumerate(passwords, 1):
            inspected_pw = inspectPassword(pw)
            inspected_passwords.append(inspected_pw)

            if not inspected_pw['strong']:
                weak_passwords += 1
            if inspected_pw['pwned']:
                pwned_passwords += 1

            #3.4. Live Progress Updates
            progress: float = (i / total_passwords) * 100
            print(f"Progress: {progress:.2f}% ({i}/{total_passwords}) passwords inspected ...", end="\r")

        #Processing Complete
        #4. Output
        print("=" * 80)
        print(f"\n                  BATCH PASSWORD INSPECTION COMPLETE! \n\n"
              f"Weak Passwords (%):{weak_passwords:,}% {(weak_passwords/len(inspected_passwords)) *100} \n"
              f"Breached Passwords (%): {pwned_passwords:,}% {(pwned_passwords/len(inspected_passwords))*100} \n")
        print("=" * 80)

        #5. Check if CSV has been toggled, if so, create and output CSV file for batch password inspection
        if args.csv:
            csv_writer = csv.writer(sys.stdout)
            csv_writer.writerow([ #Header Row
                "password",
                "score",
                "strong",
                "pwned",
                "breach_count",
                "issues"
            ])

            #Loop that adds rows in the CSV for fields in the header row
            for ip in inspected_passwords:
                csv_writer.writerow([
                    ip['password'],
                    ip['score'],
                    "Yes" if ip['strong'] else "No" or 'No',
                    "Yes" if ip['pwned'] else "No" or 'No',
                    ip['breach_count'],
                    " | \n\n" .join(ip['issues'])
                ])

            print("\n CSV Written to STDOUT")
        else:
            #CSV has not been toggled
            for ip in inspected_passwords:
                print("=" * 80)
                status = "Breached" if ip['pwned'] else "Safe: Not Breached"
                print(f"Password: '{ip['password']}' \n-> Strength Score: {ip['score']} \n-> Status: {status}")
                if status == "Breached":
                    print(f"-> Breach Count: {ip['breach_count']}")
                    print(f"{status} Recommendation: CHANGE PASSWORD AS SOON AS POSSIBLE.")
                print("=" * 80)



    # *** SINGLE PASSWORD / INTERACTIVE MODE ***
    else:
        printGreeting()
        pw_to_inspect = args.input or input("Enter Password to Inspect: ")
        if not pw_to_inspect:
            print("No password provided. Exiting...")
            return

        inspected_pw = inspectPassword(pw_to_inspect)
        print("=" * 80)

        #The entered password
        print(f"Password: {pw_to_inspect} -> Inspection Details Below")
        print(f"Strength Score: {inspected_pw['score']}/100")
        print("=" * 80)

        #Issues
        if inspected_pw['issues']:
            print("Noted the Following Issues that Require Attention: \n\n" + "\n\n" .join(inspected_pw['issues']))
        else:
            print("No issues found. Password meets all criteria.")
        print("=" * 80)

        #Breach Status
        if inspected_pw['pwned']:
            print(f"Password Breached! \nBreach Count: {inspected_pw['breach_count']}")
        else:
            print(f"No breaches found.")

        print("=" * 80)
        print("Privacy: K-anonymity and no passwords are logged.")
        print("=" * 80)

if __name__ == "__main__":
    main()