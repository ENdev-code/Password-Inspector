"""
Password Inspector v2.24
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
from rich.panel import Panel
from rich.console import Console, Group
from rich.tree import Tree
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich import box
from rich.progress import Progress, SpinnerColumn, BarColumn, MofNCompleteColumn, TimeElapsedColumn, TimeRemainingColumn, TextColumn
from rich.prompt import Prompt
from rich.rule import Rule

#Modules to use
from breach_checker import checkBreached
from strength_checker import checkStrength
from password_tester import printGreeting, passwordInspector

#Current Password Inspector version: 2.24
__version__ = 2.24
__APP_NAME__ = "PASSWORD INSPECTOR"

#initializing console
console = Console()

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

#Create a Strength leLevel Styler
def strength_stylist(strong: str) -> str:
    """Gets strength level of a password and returns the color it will be styled with. If input is unrecognized, a white line is returned"""
    styles = {
        "Very Strong":"bold green1",
        "Strong":"bold bright_green",
        "Fair":"bold light_cyan1",
        "Weak":"bold bright_red",
        "Very Weak":"bold red"
    }

    return styles.get(strong, "bright_white")

#Create ability to show password issues
def show_issues(issues, pwned, breach_count):
    """Creates tree of password issues and displays them within report. If password is breached, adds breach warning and recommendation to tree as well."""

    if not issues:
        tree = Tree("All Good! This Password has No Faults")

    tree = Tree("Issues & Advice for Password:", style="bold bright_red")
    for issue in issues:
        tree.add(f"-> {issue}")

    if pwned:
        tree.add(f"Password Breached (Breach Count: {breach_count}.\nDO NOT USE THIS PASSWORD", style="bold white on red")

    return tree

# create formatted report table
def make_report(ip):
    """Creates a formatted table that shows the results of an inspected password when Report mode is toggled"""

    s_level_style = strength_stylist(ip['strong'])
    breach_style = "bold bright_red" if ip['pwned'] else "bold bright_green"

    password = ip['password']
    p_score = Text(f"{ip['score']}", style=s_level_style)
    entropy_score = Text(f"{ip['entropy_score']}")
    guess_number = Text(f"{ip['guesses']}")
    bit_number = Text(f"{ip['entropy_bits']}")
    crack_time = Text(f"{ip['crack_time']}")
    breach_status = Text(f"BREACHED", style=breach_style) if ip['pwned'] else Text(f"SAFE! No Breaches Found.", style=breach_style)
    breaches = Text(f"{ip['breach_count']}", style=breach_style) if ip['pwned'] else Text(f"0 Breaches", style=breach_style)
    strength_level = Text(f"{ip['strong']}", style=s_level_style)
    p_issues = show_issues(ip['issues'], ip['pwned'], ip['breach_count'])

    results = Table(show_header=False, box=box.SIMPLE_HEAVY)
    results.add_column("Category", justify="left")
    results.add_column("Value", justify="left")
    results.add_row("Security Score:", p_score)
    results.add_row("Entropy Score:", entropy_score)
    results.add_row("Number of Guesses:", guess_number)
    results.add_row("Number of Bits (ESTIMATE):", bit_number)
    results.add_row("Crack Time:", crack_time)
    results.add_row("Breach Status:", breach_status)
    results.add_row("Breach Count:", breaches)
    results.add_row("Strength Level:", strength_level)

    report = Table(show_header=False, padding=(1, 0, 0, 0))
    report.add_column(" ")
    report.add_row(results)
    report.add_row(p_issues)

    return Panel(
            Align.center(report),
            title=f"Password Inspected: {password}",
            title_align="center",
            border_style=s_level_style,
            box=box.ROUNDED
        )

#Function that asks for a file path
def pathfinder():
    path = input("Enter path to .txt file: ").strip()
    return path or None

#Function that handles opening file explorer when needed
def dora() -> str | None:
    """Opens file explorer to allow user to search for .txt file to inspect via GUI window."""
    try:
        root = tk.Tk()
        root.withdraw() #closes the empty tkinter window
        root.attributes('-topmost', True) #Makes the file explorer window the highest priority

    except ImportError as i: #tkinter missing
        console.print(Text(f"Error: tkinter not installed. Try running: sudo apt install python3-tk\n({i})", style="red"))
        return pathfinder()

    except tk.TclError as e:  # tkinter missing, or no display available
        console.print(Text(f"Error: File picker unavailable.\n({e})", style="red"))
        return pathfinder()

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
            f"Name: {__APP_NAME__}\n"
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

        #Progressbar logic
        with Progress(#initialize the progressbar with its parameters safely
            SpinnerColumn(),
            TextColumn("[light_cyan1]Inspecting Passwords"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("inspecting", total=total_passwords)
            for i, pw in enumerate(passwords, 1):
                inspected_pw = inspectPassword(pw)

                inspected_passwords.append(inspected_pw)

                if inspected_pw['strong'] != "Very Strong" and inspected_pw['strong'] != "Strong" and inspected_pw[
                    'strong'] != "Fair":
                    weak_passwords += 1
                if inspected_pw['pwned']:
                    pwned_passwords += 1

                progress.advance(task)




        weak = Text(f"Weak Passwords (%): {(weak_passwords/len(inspected_passwords)) *100:.2f}% [{weak_passwords:,}/{len(inspected_passwords)}] \n", style="bold bright_red")
        breached = Text(f"Breached Passwords (%): {(pwned_passwords/len(inspected_passwords))*100:.2f}% [{pwned_passwords:,}/{len(inspected_passwords)}] \n", style="bold bright_red")
        panel = Group(weak, breached)
        #Processing Complete
        #4. Output

        console.print(Panel(
            Align.center(panel),
            title="BATCH PASSWORD INSPECTION COMPLETE!",
            title_align="center",
            padding=(1,2),
            box=box.ROUNDED,
            border_style="light_cyan1"
        ))

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
            report_title = "PASSWORD INSPECTOR REPORT"
            ip_panels = [make_report(ip) for ip in inspected_passwords]
            all_ip = Group(*ip_panels)

            console.print(
                Panel(
                    Align.center(all_ip),
                    title=report_title,
                    title_align="center",
                    subtitle="Privacy: K-anonymity Used & No Passwords Are Logged",
                    subtitle_align="center",
                    style="bold light_cyan1",
                    box=box.DOUBLE_EDGE,
                    padding=(1,2)
                )
            )

            rule = Rule()
            console.print(rule)

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

    title = __APP_NAME__
    feature = "MENU"
    inspecting = True

    while inspecting:

        menu = Table(title=feature, title_justify="center", style="bold light_cyan1", box=box.SIMPLE_HEAD)
        menu.add_column("Option")
        menu.add_column("Description")

        menu.add_row("[0]", "How I Work.")
        menu.add_row("[1]", "Single Password Check.")
        menu.add_row("[2]", "Batch Check: Password Report.")
        menu.add_row("[3]", "Batch Check: Password CSV.")
        menu.add_row("[4]", "Version.")
        menu.add_row("[5]", "Help.")
        menu.add_row("[6]", "Exit.")

        console.print(Panel(
            Align.center(menu),
            padding=(2,5),
            title=title,
            title_align="center",
            style="bold light_cyan1",
            subtitle="Privacy: K-anonymity and no passwords are logged.",
            subtitle_align="center",
            box=box.ROUNDED,
            expand=True
        ))

        prompt = Prompt()
        message = Text("Enter your choice", style="green_yellow")
        choice = prompt.ask(message, case_sensitive=False, )

        #What to do when the user chooses an option
        #if they want to know more about Password Inspector
        if choice == "0":
            printGreeting()

        #if they want to check one password
        elif choice == "1":
            pass_message = Text("Enter Password to Inspect Below (input is hidden) ", style="green_yellow")
            console.print(pass_message)
            password = getpass.getpass("PW: ")
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
            except SystemExit: #Argparse boots you out of runtime if you don't add this for --version and --help
                pass
            finally:
                sys.argv = original_argv

        #if they want to see what else can be done with Password Inspector
        elif choice == "5":
            original_argv = sys.argv[:]
            sys.argv = [sys.argv[0], "--help"]
            try:
                main()
            except SystemExit:
                pass
            finally:
                sys.argv = original_argv

        #They want to exit
        elif choice == "6":
            goodbye = Text("Thank you for using Password Inspector. Goodbye & Stay Safe!\n", style="green_yellow")
            console.print(Align.center(goodbye))
            inspecting = False
        else:
            invalid = Text("Invalid choice. Please make sure your choice is any number from 0 to 6.\n", style="green_yellow")
            console.print(Align.center(invalid))


if __name__ == "__main__":
    main()