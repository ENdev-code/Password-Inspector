"""
Password Inspector v2.13
Copyright (c) 2025 Emmanuel Nkhoma
MIT License - See LICENSE file
"""

#dependencies to use
import argparse
from pathlib import Path
import csv
import tkinter as tk
from tkinter import filedialog
import getpass
import sys

#Modules to use
from breach_checker import checkBreached
from strength_checker import checkStrength
from password_tester import printGreeting, passwordInspector

#Current Password Inspector version: 1.3
__version__ = 2.13

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

#Function that handles opening file explorer when needed
def dora() -> str | None:
    """Opens file explorer to allow user to search for .txt file to inspect via GUI window."""
    root = tk.Tk()
    root.withdraw() #closes the empty tkinter window
    root.attributes('-topmost', True) #Makes the file explorer window the highest priority
    file_path = filedialog.askopenfilename(
        title="Open File(.txt) to Inspect.",
        filetypes=[
            ("Text Files", "*.txt"),
            ("All Files", "*.*")
        ]
    )
    root.destroy()#close the window and remove it from memory
    return file_path if file_path else None

#Actual CLI Capability is added here
def main():
    #1. Create parsing instance
    parser = argparse.ArgumentParser(
        description="A privacy-first Python tool for password strength analysis and breach detection.",
        formatter_class=argparse.RawTextHelpFormatter, #helps format version message
        epilog="Privacy: K-anonymity and No Passwords are Logged."
    )

    #1.1. Create argument for parsing: Input - either a password or a path to a wordlist
    parser.add_argument(
        "input",
        nargs="?",
        help="Password or path to wordlist file of passwords to inspect"
    )

    #1.2. Create a --csv argument to allow output of CSV if toggled
    parser.add_argument(
        "--csv",
        action="store_true",
        help="Generates CSV file with Password Inspector details about inspected passwords."
    )

    #1.3 Argument to output the current version of Password Inspector
    parser.add_argument(
        "--version",
        action="version",
        version=(
            f"Name: Password Inspector\n"
            f"Summary: \n"
            f"Version: {__version__}\n"
            f"Home Page: https://github.com/ENdev-code/Password-Inspector\n"
            f"Author: Emmanuel Nkhoma\n"
            f"Author-email: emmanuelmnkhoma@gmail\n"
            f"License: MIT"
        ),
        help="Shows the current version of Password Inspector."
    )

    #1.4 Argument for creating reports, suitable for security audits
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generates Password Inspector report for inspected passwords."
    )

    #2. Parse the arguments in Parser into a variable: args
    args = parser.parse_args()

    # Making sure the main menu shows
    if args.input is None and not args.report and not args.csv:
        show_menu()
        return

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

        print(f"Loading {len(passwords)} passwords from: '{path.name}' ... \n")


        #3.3. Iterate through passwords array and process passwords
        inspected_passwords = []
        total_passwords = len(passwords)
        weak_passwords = pwned_passwords = 0

        for i, pw in enumerate(passwords, 1):
            inspected_pw = inspectPassword(pw)

            inspected_passwords.append(inspected_pw)

            if inspected_pw['strong'] != "Very Strong" and inspected_pw['strong'] != "Strong" and inspected_pw['strong'] != "Fair":
                weak_passwords += 1
            if inspected_pw['pwned']:
                pwned_passwords += 1

            # 3.4. Live Progress Updates
            progress: float = (i / total_passwords) * 100
            print(f"Progress: {progress:.2f}% ({i}/{total_passwords}) passwords inspected ...", end="\r",flush=True)

        #Processing Complete
        #4. Output
        print("=" * 80)
        print(f"\n                  BATCH PASSWORD INSPECTION COMPLETE! \n\n"
              f"Weak Passwords (%): {(weak_passwords/len(inspected_passwords)) *100:.2f}% [{weak_passwords:,}/{len(inspected_passwords)}] \n"
              f"Breached Passwords (%): {(pwned_passwords/len(inspected_passwords))*100:.2f}% [{pwned_passwords:,}/{len(inspected_passwords)}] \n")
        print("=" * 80 + "\n")

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
                    else:
                        print("\n ** Password has no issues (Based on Password Inspector Criteria)\n")

                    print("="*80)

            #End of report
            print(" " * 25 + "END OF PASSWORD INSPECTOR REPORT\n\n"
                             "      Privacy: K-anonymity and no passwords are logged.")
            print("=" * 80 + "\n")

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
            print("=" * 80 + "\n")

    # *** SINGLE PASSWORD / INTERACTIVE MODE ***
    else:
        pw_to_inspect = args.input or input("Enter Password to Inspect: ")
        if not pw_to_inspect:
            print("No password provided. Exiting...")
            return

        inspected_pw = passwordInspector(pw_to_inspect)
        print("=" * 80 + "\n")

def show_menu():
    """This function will show the greeting menu and will abstract the logic of the underlying processes"""
    inspecting = True
    while inspecting:
        print("--" * 40)
        print("                          PASSWORD INSPECTOR")
        print("--" * 40)
        print("What would you like to do?\n"
              " [0] How I work.\n"
              " [1] Single Password Check.\n"
              " [2] Password Batch Check (Report).\n"
              " [3] Password Batch Check (CSV).\n"
              " [4] Version.\n"
              " [5] Help.\n"
              " [6] Exit.")
        print("--" * 40 + "\n")

        choice = input("Enter Your Choice: ")

        #What to do when the user chooses an option
        #if they want to know more about Password Inspector
        if choice == "0":
            printGreeting()
        #if they want to check one password
        elif choice == "1":
            password = getpass.getpass("Enter Password to Inspect(input is hidden): ")
            if password:
                original_argv = sys.argv[:] #Snapshot of current arguments
                sys.argv = [sys.argv[0], password] #simulation of actual command
                try:
                    main() #send arguments to the main function
                finally:
                    sys.argv = original_argv #clearing memory
        #if they want to check multiple passwords in batchmode::report or ::csv
        elif choice == "2" or choice == "3":
            file_path = dora()
            mode = None
            if choice =="2":
                mode = "--report"
            elif choice =="3":
                mode = "--csv"

            if file_path:
                original_argv = sys.argv[:]
                sys.argv = [sys.argv[0], file_path, mode]
                try:
                    main()
                finally:
                    sys.argv = original_argv
        #if they want to see what version Password Inspector is currently running at
        elif choice == "4":
            original_argv = sys.argv[:]
            sys.argv = [sys.argv[0], "--version"]
            try:
                main()
            finally:
                sys.argv = original_argv
        #if they want to see what else can be done with Password Inspector
        elif choice == "5":
            original_argv = sys.argv[:]
            sys.argv = [sys.argv[0], "--help"]
            try:
                main()
            finally:
                sys.argv = original_argv
        #They want to exit
        elif choice == "6":
            print("Thank you for using Password Inspector. Goodbye & Stay Safe!")
            inspecting = False
        else:
            print("Invalid choice. Please make sure your choice is any number from 0 to 6.")


if __name__ == "__main__":
    main()