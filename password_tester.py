"""
Password Inspector v2.13
Copyright (c) 2025 Emmanuel Nkhoma
MIT License - See LICENSE file
"""

from breach_checker import checkBreached
from strength_checker import checkStrength
from rich.panel import Panel
from rich.console import Console, Group
from rich.tree import Tree
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich import box
from rich.rule import Rule

console = Console()

def printGreeting():
    """Prints a greeting to the user and the user manual for Password Inspector"""
    # Greeting and Manual

    tasks = Tree("WHAT I DO:\n\n", style="bold light_cyan1")
    tasks.add("1. Receive a password or password.txt file as input \n")
    tasks.add("2. Evaluate a password's strength and check if it has been breached \n")
    tasks.add("3. Output neat results\n")
    console.print(Panel(Align.center(tasks),title="PASSWORD INSPECTOR", style="bold bright_white", box=box.DOUBLE, title_align="center"))
    console.print()

    #Password Strength Criteria
    criteria = Table(show_header=True, box=box.SIMPLE_HEAVY)
    criteria.add_column("I Receive Password With", style="bold bright_yellow")
    criteria.add_column("You Get (Points)", style="bold bright_yellow")

    criteria.add_row(Text("8+ Characters", style="bright_yellow"), Text("10", style="bright_blue"))
    criteria.add_row(Text("12+ Characters", style="bright_yellow"), Text("10", style="bright_blue"))
    criteria.add_row(Text("16+ Characters", style="bright_yellow"), Text("15", style="bright_blue"))
    criteria.add_row(Text("20+ Characters", style="bright_yellow"), Text("15", style="bright_blue"))
    criteria.add_row(Text("No Character Repeats", style="bright_yellow"), Text("10", style="bright_blue"))
    criteria.add_row(Text("Entropy Score Points", style="bright_yellow"), Text("2-40", style="bright_blue"))
    criteria.add_row("", Text("Total = 100", style="bright_blue"))
    console.print(Panel(Align.center(criteria),title="PASSWORD INSPECTING CRITERIA", style="bold bright_white", box=box.DOUBLE, title_align="center"))
    console.print()

    #Entropy Score Criteria
    entropy = Table(show_header=True, box=box.SIMPLE_HEAVY)
    entropy.add_column("Entropy Score (ZXCVBN)")
    entropy.add_column("Translation")
    entropy.add_column("PI Score")

    entropy.add_row(Text("0", style="bold red1"), Text("Too Guessable", style="bold red1"), Text("2", style="bold red1"))
    entropy.add_row(Text("1", style="bold bright_red"), Text("Very Guessable", style="bold bright_red"), Text("6", style="bold bright_red"))
    entropy.add_row(Text("2", style="bold light_cyan1"), Text("Somewhat Guessable", style="bold light_cyan1"), Text("12", style="bold light_cyan1"))
    entropy.add_row(Text("3", style="bold bright_green"), Text("Safely Unguessable", style="bold bright_green"), Text("24", style="bold bright_green"))
    entropy.add_row(Text("4", style="bold green1"), Text("Somewhat Guessable", style="bold green1"), Text("40", style="bold green1"))

    desc = Text("\nThis is my scoring criteria in relation to entropy.")
    pi_entropy = Group(desc, Align.center(entropy))
    console.print(Panel(pi_entropy, title="ENTROPY SCORE TRANSLATOR", title_align="center", box=box.DOUBLE, style="bold bright_white"))
    console.print()

    footer = Text()
    footer.append("\n[Privacy: Password processed in memory only. No logs.]\n")
    footer.append("[K-Anonymity: Password matched locally with retrieved breached passwords.]\n")

    console.print(Panel(Align.center(footer), style="bold light_cyan1", box=box.ROUNDED))


def passwordInspector(password:str):
    """
    Does 2 checks:
        a. Strength Check using strength_checker's checkStrength function
        b. Breach Check using breach_checker's checkBreached function

    Outputs:
        a. Strength level and issues if present
        b. Breach status
    """

    console.print(f"\nBeginning Inspection ...\n")


    #1. Strength Check via checkStrength

    result = checkStrength(password)

    evaluation = Table(show_header=True, box=box.SIMPLE_HEAVY)
    evaluation.add_column("Category", justify="left")
    evaluation.add_column("Value", justify="left")

    evaluation.add_row("Password Strength", f"{result['score']}", style="light_cyan1")
    evaluation.add_row("Entropy Score (zxcvbn)", f"{result['entropy_score']}", style="light_cyan1")
    evaluation.add_row("Crack Time", f"{result['crack_time']}", style="light_cyan1")
    evaluation.add_row("Number of Guesses", f"{result['guesses']}", style="light_cyan1")

    if result['issues']:
        issues = Tree("PASSWORD ISSUES FOUND:", style="bright_red")
        for issue in result['issues']:
            issues.add(issue)

        group = Group(Align.center(evaluation), issues)
        console.print(Panel(Align.center(group),title="STRENGTH CHECK", style="bold bright_white", box=box.DOUBLE, title_align="center"))

    else:
        message = Text("\n\nNo issues found. All checks passed!\n", style="chartreuse3")
        console.print(Panel(Align.center(message), box=box.ROUNDED, style="bold light_cyan1"))


    status = f"{result['score']}% [{result['strong']}]" if result['strong'] else "Areas to fix shown above."
    console.print()
    #2. Breach Check


    pwned, count = checkBreached(password)

    if pwned:

        breached = Tree("\nPASSWORD BREACHED!\n\n", style="bold bright_red")
        breached.add(Text(f"Password has been breached {count} times.\n"))
        breached.add(Text("CHANGE PASSWORD AS SOON AS POSSIBLE!\nPassword Unsafe to use by Password Inspector Standard.\n"))
        console.print(Panel(Align.center(breached), title="BREACH CHECK", style="bold bright_white", box=box.DOUBLE, title_align="center"))

    else:

        safe = Tree("\nPASSWORD SAFE!", style="bold bright_green")
        safe.add(Text("All good! No breaches found.\n"))
        safe.add(Text("Password is safe to use by Password Inspector Standard.\n"))
        console.print(Panel(Align.center(safe), title="BREACH CHECK", style="bold bright_white", box=box.DOUBLE, title_align="center"))

    console.print()
    footer = Text()
    footer.append("\n[Privacy: Password processed in memory only. No logs.]\n")
    footer.append("[K-Anonymity: Password matched locally with retrieved breached passwords.]\n")
    console.print(Panel(Align.center(footer), style="bold light_cyan1", box=box.ROUNDED))

    rule = Rule()
    console.print(rule)

if __name__ == "__main__":
    printGreeting()
    check_password = input("Enter password to inspect: ")
    if not check_password:
        print("No password entered.")
        exit()

    #execute
    passwordInspector(check_password)