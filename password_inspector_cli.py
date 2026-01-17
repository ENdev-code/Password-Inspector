"""
Password Inspector v1.3
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
from password_tester import printGreeting, passwordInspector

#Current Password Inspector version: 1.2
__version__ = 1.3

#Function that Inspects Passwords at CLI level
def inspectPassword(password: str) -> dict:
    strength_check = checkStrength(password)
    pwned, breach_count = checkBreached(password)
    return {
        "password": password,
        "score": strength_check['score'],
        "issues": strength_check['issues'],
        "strong": strength_check['strong'],
        "entropy_score": strength_check['entropy_score'],
        "guesses": strength_check['guesses'],
        "entropy_bits": strength_check['entropy_bits'],
        "crack_time": strength_check['crack_time'],
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
        help="Generate CSV file with Password Inspector details about inspected passwords."
    )

    #1.3 Create an argument to output the current version of Password Inspector
    parser.add_argument(
        "--version",
        action="version",
        help=f"Name: Password Inspector\n"
             f"Version: {__version__}\n"
             f"Home Page: https://github.com/ENdev-code/Password-Inspector\n"
             f"Author: Emmanuel Nkhoma\n"
             f"Author-email: emmanuelmnkhoma@gmail\n"
             f"License: MIT"
    )

    #1.4 Argument for creating reports, suitable for security audits
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate Password Inspector report for inspected passwords."
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

        printGreeting()
        print(f"Loading {len(passwords)} passwords from: '{path.name}' ... \n")

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
              f"Weak Passwords (%): {(weak_passwords/len(inspected_passwords)) *100:.2f}% [{weak_passwords:,}/{len(inspected_passwords)}] \n"
              f"Breached Passwords (%): {(pwned_passwords/len(inspected_passwords))*100:.2f}% [{pwned_passwords:,}/{len(inspected_passwords)}] \n")
        print("=" * 80)

        #5. Check if CSV has been toggled, if so, create and output CSV file for batch password inspection
        if args.csv:
            csv_writer = csv.writer(sys.stdout, lineterminator="\n")
            csv_writer.writerow([ #Header Row
                "password",
                "score",
                "strong",
                "entropy_score",
                "crack_time",
                "guesses",
                "entropy_bits",
                "pwned",
                "breach_count",
                "issues"
            ])

            #Loop that adds rows in the CSV for fields in the header row
            for ip in inspected_passwords:
                strong = "Yes" if ip['strong'] else "No" or 'No'
                breached = "Yes" if ip['pwned'] else "No" or 'No'
                breach_count = ip['breach_count'] if ip['pwned'] else 0

                #cleaning up issues, if any are present for that password
                if ip['issues']:
                    clean_issues:str = []
                    for issue in ip['issues']:
                        clean = issue.strip().lstrip("| ").strip()
                        if clean:
                            clean_issues.append(clean)
                    issues = "\n".join(clean_issues)
                else:
                    issues = "None"

                csv_writer.writerow([
                    ip['password'],
                    ip['score'],
                    strong,
                    ip['entropy_score'],
                    ip['crack_time'],
                    ip['guesses'],
                    ip['entropy_bits'],
                    breached,
                    breach_count,
                    issues
                ])

            print("\n CSV Written to STDOUT")
            print("Privacy: K-anonymity and no passwords are logged.")

        #5.1. Report has been toggled
        elif args.report:
            # *** HUMAN READABLE AUDIT REPORT ***
            print("=" * 80)
            print(" " * 25 + "PASSWORD INSPECTOR REPORT")
            print("=" * 80)

            for ip in inspected_passwords:
                password = ip['password']
                score = ip['score']
                strong = ip['strong']
                status = "Breached" if ip['pwned'] else "Safe: No Breach Found"
                breach_count = ip['breach_count'] if ip['pwned'] else 0

                print(f"\nINSPECTED PASSWORD: {password} \n\n"
                      f"SECURITY SCORE:             {score} \n"
                      f"ENTROPY SCORE(zxcvbn):      {ip['entropy_score']}\n"
                      f"NUMBER OF GUESSES:          {ip['guesses']}\n"
                      f"NUMBER OF BITS (ESTIMATE):  {ip['entropy_bits']}\n"
                      f"CRACK TIME:                 {ip['crack_time']}\n"
                      f"BREACH STATUS:              {status} \n"
                      f"BREACH COUNT:               {breach_count}\n"
                      f"STRENGTH LEVEL:             {strong}\n")


                if ip['issues']:
                    print("\nPASSWORD ISSUES & ADVICE:\n")
                    for issue in ip['issues']:
                        print(f" -> {issue}")
                    if ip['pwned']:
                        print(f" -> Breached {breach_count} times: CHANGE PASSWORD IMMEDIATELY!")
                    print("\n")
                    print("="*80)
                else:
                    if ip['pwned']:
                        print("\nPASSWORD ISSUES:\n")
                        print(f" -> Breached {breach_count} times: CHANGE PASSWORD IMMEDIATELY.")
                        print("\n ** Password has no issues (Based on Password Inspecting Criteria)\n")
                    else:
                        print("\n ** Password has no issues (Based on Password Inspecting Criteria)\n")

                    print("="*80)

            #End of report
            print(" " * 25 + "END OF PASSWORD INSPECTOR REPORT\n\n"
                             "      Privacy: K-anonymity and no passwords are logged.")
            print("=" * 80)

        #5.2. Both CSV and report have not been toggled
        else:
            for ip in inspected_passwords:
                print("=" * 80)
                status = "Breached" if ip['pwned'] else "Safe: Not Breached"
                print(f"Password: '{ip['password']}'\n \n-> Strength Score: {ip['score']} \n-> Status: {status}")

                if ip['issues']:
                    print("="*80)
                    print(f"Issues with Password: {ip['password']}: \n")
                    for i, issue in enumerate(ip['issues'], 1):
                        print("->" + issue)
                print("="*80)

                if status == "Breached":
                    print(f"-> Breach Count: {ip['breach_count']}")
                    print(f"{status} Recommendation: CHANGE PASSWORD AS SOON AS POSSIBLE.")
                print("=" * 80)

            #End of Password Inspection
            print(" " * 25 + "END OF PASSWORD INSPECTION\n"
                             "      Privacy: K-anonymity and no passwords are logged.")
            print("=" * 80)

    # *** SINGLE PASSWORD / INTERACTIVE MODE ***
    else:
        printGreeting()
        pw_to_inspect = args.input or input("Enter Password to Inspect: ")
        if not pw_to_inspect:
            print("No password provided. Exiting...")
            return

        inspected_pw = passwordInspector(pw_to_inspect)
        print("=" * 80)



if __name__ == "__main__":
    main()