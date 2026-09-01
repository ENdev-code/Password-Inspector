1
"""
Password Inspector v2.13
Copyright (c) 2025 Emmanuel Nkhoma
MIT License - See LICENSE file
"""

import argparse
import csv
import getpass
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from breach_checker import checkBreached
from strength_checker import checkStrength
from password_tester import printGreeting, passwordInspector


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

__version__ = "2.13"

console = Console()

APP_NAME = "PASSWORD INSPECTOR"
APP_DESCRIPTION = (
    "Privacy-first password strength analysis and breach detection"
)


# ---------------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------------

def print_banner() -> None:
    """Display the main application banner."""

    banner = Text()
    banner.append("PASSWORD ", style="bold white")
    banner.append("INSPECTOR", style="bold cyan")
    banner.append(f"  v{__version__}", style="dim")

    console.print()
    console.print(
        Panel(
            banner,
            subtitle="[dim]Security • Privacy • Analysis[/dim]",
            border_style="cyan",
            box=box.DOUBLE,
            padding=(1, 4),
        )
    )


def print_section(title: str) -> None:
    """Display a section heading."""

    console.print()
    console.print(
        Panel(
            f"[bold cyan]{title}[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )


def print_success(message: str) -> None:
    console.print(f"[bold green]✓[/bold green] {message}")


def print_warning(message: str) -> None:
    console.print(f"[bold yellow]![/bold yellow] {message}")


def print_error(message: str) -> None:
    console.print(f"[bold red]✗[/bold red] {message}")


def print_privacy_notice() -> None:
    console.print(
        Panel(
            "[bold green]Privacy:[/bold green] "
            "K-anonymity is used and passwords are not logged.",
            border_style="green",
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )


# ---------------------------------------------------------------------------
# Password inspection
# ---------------------------------------------------------------------------

def inspectPassword(password: str) -> dict:
    """Inspect a password and return all analysis results."""

    strength_check = checkStrength(password)
    pwned, breach_count = checkBreached(password)

    return {
        "password": password,
        "score": strength_check["score"],
        "issues": strength_check["issues"],
        "strong": strength_check["strong"],
        "entropy_score": strength_check["entropy_score"],
        "guesses": strength_check["guesses"],
        "entropy_bits": strength_check["entropy_bits"],
        "crack_time": strength_check["crack_time"],
        "pwned": pwned,
        "breach_count": breach_count or 0,
    }


# ---------------------------------------------------------------------------
# File picker
# ---------------------------------------------------------------------------

def dora() -> str | None:
    """Open a file explorer to select a .txt wordlist."""

    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)

    file_path = filedialog.askopenfilename(
        title="Open File (.txt) to Inspect",
        filetypes=[
            ("Text Files", "*.txt"),
            ("All Files", "*.*"),
        ],
    )

    root.destroy()

    return file_path if file_path else None


# ---------------------------------------------------------------------------
# Result formatting
# ---------------------------------------------------------------------------

def strength_style(strength) -> str:
    """Return Rich styling for a password strength level."""

    value = str(strength).lower()

    if "very strong" in value:
        return f"[bold green]{strength}[/bold green]"

    if value == "strong":
        return f"[green]{strength}[/green]"

    if value == "fair":
        return f"[yellow]{strength}[/yellow]"

    if "weak" in value:
        return f"[red]{strength}[/red]"

    return f"[dim]{strength}[/dim]"


def breach_style(breached: bool) -> str:
    """Return Rich styling for breach status."""

    if breached:
        return "[bold red]BREACHED[/bold red]"

    return "[bold green]SAFE[/bold green]"


def create_result_table(ip: dict) -> Table:
    """Create a formatted password analysis table."""

    table = Table(
        show_header=False,
        box=box.SIMPLE_HEAVY,
        padding=(0, 2),
        expand=True,
    )

    table.add_column("Property", style="bold cyan", width=28)
    table.add_column("Value")

    status = breach_style(ip["pwned"])

    table.add_row(
        "Security Score",
        f"[bold white]{ip['score']}[/bold white]",
    )

    table.add_row(
        "Strength",
        strength_style(ip["strong"]),
    )

    table.add_row(
        "Entropy Score",
        str(ip["entropy_score"]),
    )

    table.add_row(
        "Entropy Bits",
        f"{ip['entropy_bits']}",
    )

    table.add_row(
        "Estimated Guesses",
        f"{ip['guesses']:,}",
    )

    table.add_row(
        "Estimated Crack Time",
        str(ip["crack_time"]),
    )

    table.add_row(
        "Breach Status",
        status,
    )

    table.add_row(
        "Breach Count",
        f"{ip['breach_count']:,}",
    )

    return table


def display_password_result(ip: dict) -> None:
    """Display a single password result."""

    # Never display the actual password in the report.
    title = Text("PASSWORD ANALYSIS", style="bold white")

    console.print(
        Panel(
            create_result_table(ip),
            title=title,
            border_style="cyan",
            box=box.ROUNDED,
            padding=(1, 2),
        )
    )

    if ip["pwned"]:
        console.print(
            Panel(
                "[bold red]This password has appeared in known breaches.[/bold red]\n"
                "[red]Change it immediately and avoid reusing it elsewhere.[/red]",
                title="[bold red]SECURITY WARNING[/bold red]",
                border_style="red",
                box=box.HEAVY,
            )
        )

    if ip["issues"]:
        issues_table = Table(
            title="Password Issues & Advice",
            box=box.ROUNDED,
            border_style="yellow",
            expand=True,
        )

        issues_table.add_column("#", style="bold yellow", width=5)
        issues_table.add_column("Issue / Recommendation")

        for index, issue in enumerate(ip["issues"], 1):
            clean = issue.strip().lstrip("| ").strip()

            if clean:
                issues_table.add_row(
                    str(index),
                    clean,
                )

        console.print(issues_table)


# ---------------------------------------------------------------------------
# Batch mode
# ---------------------------------------------------------------------------

def inspect_batch(
    passwords: list[str],
) -> list[dict]:
    """Inspect a list of passwords with a Rich progress bar."""

    inspected_passwords = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>6.2f}%"),
        TextColumn("({task.completed}/{task.total})"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:

        task = progress.add_task(
            "Inspecting passwords...",
            total=len(passwords),
        )

        for password in passwords:
            inspected_pw = inspectPassword(password)
            inspected_passwords.append(inspected_pw)

            progress.advance(task)

    return inspected_passwords


def display_batch_summary(
    inspected_passwords: list[dict],
) -> tuple[int, int]:
    """Display a clean summary of a batch inspection."""

    total = len(inspected_passwords)

    weak_passwords = sum(
        1
        for password in inspected_passwords
        if password["strong"]
        not in ("Very Strong", "Strong", "Fair")
    )

    pwned_passwords = sum(
        1
        for password in inspected_passwords
        if password["pwned"]
    )

    weak_percentage = (weak_passwords / total) * 100
    breached_percentage = (pwned_passwords / total) * 100

    summary = Table(
        title="Batch Inspection Summary",
        box=box.DOUBLE,
        border_style="cyan",
        expand=True,
    )

    summary.add_column(
        "Metric",
        style="bold cyan",
    )

    summary.add_column(
        "Count",
        justify="right",
    )

    summary.add_column(
        "Percentage",
        justify="right",
    )

    summary.add_row(
        "Passwords Inspected",
        f"{total:,}",
        "100%",
    )

    summary.add_row(
        "Weak Passwords",
        f"[yellow]{weak_passwords:,}[/yellow]",
        f"[yellow]{weak_percentage:.2f}%[/yellow]",
    )

    summary.add_row(
        "Breached Passwords",
        f"[red]{pwned_passwords:,}[/red]",
        f"[red]{breached_percentage:.2f}%[/red]",
    )

    console.print()
    console.print(
        Panel(
            summary,
            title="[bold cyan]BATCH PASSWORD INSPECTION COMPLETE[/bold cyan]",
            border_style="cyan",
            box=box.DOUBLE,
            padding=(1, 2),
        )
    )

    return weak_passwords, pwned_passwords


# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------

def output_csv(inspected_passwords: list[dict]) -> None:
    """Output batch results as CSV."""

    csv_writer = csv.writer(
        sys.stdout,
        lineterminator="\n",
    )

    csv_writer.writerow(
        [
            "password",
            "score",
            "strong",
            "entropy_score",
            "crack_time",
            "guesses",
            "entropy_bits",
            "pwned",
            "breach_count",
            "issues",
        ]
    )

    for ip in inspected_passwords:

        strong = "Yes" if ip["strong"] else "No"
        breached = "Yes" if ip["pwned"] else "No"

        breach_count = (
            ip["breach_count"]
            if ip["pwned"]
            else 0
        )

        if ip["issues"]:
            clean_issues = []

            for issue in ip["issues"]:
                clean = issue.strip().lstrip("| ").strip()

                if clean:
                    clean_issues.append(clean)

            issues = "\n".join(clean_issues)

        else:
            issues = "None"

        csv_writer.writerow(
            [
                ip["password"],
                ip["score"],
                strong,
                ip["entropy_score"],
                ip["crack_time"],
                ip["guesses"],
                ip["entropy_bits"],
                breached,
                breach_count,
                issues,
            ]
        )


# ---------------------------------------------------------------------------
# Human-readable report
# ---------------------------------------------------------------------------

def output_report(inspected_passwords: list[dict]) -> None:
    """Display a human-readable security audit report."""

    print_section("PASSWORD INSPECTOR REPORT")

    for index, ip in enumerate(inspected_passwords, 1):

        console.print(
            f"\n[bold cyan]Password #{index}[/bold cyan]"
        )

        display_password_result(ip)

    console.print()
    print_privacy_notice()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    """Main CLI entry point."""

    parser = argparse.ArgumentParser(
        description=APP_DESCRIPTION,
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Privacy: K-anonymity and no passwords are logged."
        ),
    )

    parser.add_argument(
        "input",
        nargs="?",
        help=(
            "Password or path to wordlist file "
            "of passwords to inspect"
        ),
    )

    parser.add_argument(
        "--csv",
        action="store_true",
        help=(
            "Generate CSV output containing "
            "Password Inspector details."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=(
            f"Name: Password Inspector\n"
            f"Summary: Privacy-first password analysis tool\n"
            f"Version: {__version__}\n"
            f"Home Page: https://github.com/ENdev-code/Password-Inspector\n"
            f"Author: Emmanuel Nkhoma\n"
            f"Author-email: emmanuelmnkhoma@gmail\n"
            f"License: MIT"
        ),
        help="Show the current version.",
    )

    parser.add_argument(
        "--report",
        action="store_true",
        help=(
            "Generate a human-readable "
            "Password Inspector report."
        ),
    )

    args = parser.parse_args()

    # -----------------------------------------------------------------------
    # Interactive menu
    # -----------------------------------------------------------------------

    if (
        args.input is None
        and not args.report
        and not args.csv
    ):
        show_menu()
        return

    # -----------------------------------------------------------------------
    # Batch mode
    # -----------------------------------------------------------------------

    if args.input and Path(args.input).exists():

        path = Path(args.input)

        passwords = [
            line.strip()
            for line in path.read_text().splitlines()
            if line.strip()
        ]

        if not passwords:
            print_error(
                f"No passwords found in '{path.name}'."
            )
            return

        print_banner()

        console.print(
            f"\n[bold]Wordlist:[/bold] {path.name}"
        )
        console.print(
            f"[bold]Passwords:[/bold] {len(passwords):,}"
        )

        inspected_passwords = inspect_batch(passwords)

        display_batch_summary(inspected_passwords)

        # CSV takes priority over report, matching the original behaviour.
        if args.csv:

            output_csv(inspected_passwords)

            console.print()
            print_success("CSV written to STDOUT.")
            print_privacy_notice()

        elif args.report:

            output_report(inspected_passwords)

        else:

            for ip in inspected_passwords:
                display_password_result(ip)

        return

    # -----------------------------------------------------------------------
    # Single password / interactive mode
    # -----------------------------------------------------------------------

    pw_to_inspect = args.input

    if pw_to_inspect is None:
        pw_to_inspect = getpass.getpass(
            "Enter Password to Inspect: "
        )

    if not pw_to_inspect:
        print_error("No password provided. Exiting...")
        return

    # Keep your existing passwordInspector functionality.
    passwordInspector(pw_to_inspect)

    console.print()
    print_privacy_notice()


# ---------------------------------------------------------------------------
# Interactive menu
# ---------------------------------------------------------------------------

def show_menu():
    """Display the interactive Password Inspector menu."""

    inspecting = True

    while inspecting:

        console.clear()
        print_banner()

        menu = Table(
            show_header=False,
            box=box.ROUNDED,
            border_style="cyan",
            padding=(0, 2),
            expand=True,
        )

        menu.add_column(
            "Option",
            style="bold cyan",
            width=10,
        )

        menu.add_column(
            "Action",
            style="white",
        )

        menu.add_row(
            "[0]",
            "How Password Inspector works",
        )

        menu.add_row(
            "[1]",
            "Single password check",
        )

        menu.add_row(
            "[2]",
            "Batch password check — Report",
        )

        menu.add_row(
            "[3]",
            "Batch password check — CSV",
        )

        menu.add_row(
            "[4]",
            "Version information",
        )

        menu.add_row(
            "[5]",
            "Help",
        )

        menu.add_row(
            "[6]",
            "Exit",
        )

        console.print(menu)

        console.print()
        choice = console.input(
            "[bold cyan]Enter your choice › [/bold cyan]"
        ).strip()

        # -------------------------------------------------------------------
        # How it works
        # -------------------------------------------------------------------

        if choice == "0":

            console.clear()
            print_banner()
            print_section("HOW IT WORKS")

            printGreeting()

            console.input(
                "\n[dim]Press Enter to return to the menu...[/dim]"
            )

        # -------------------------------------------------------------------
        # Single password
        # -------------------------------------------------------------------

        elif choice == "1":

            console.clear()
            print_banner()
            print_section("SINGLE PASSWORD CHECK")

            password = getpass.getpass(
                "Enter Password to Inspect (input hidden): "
            )

            if password:

                inspected_pw = inspectPassword(password)

                display_password_result(inspected_pw)

                print_privacy_notice()

            else:

                print_error(
                    "No password entered."
                )

            console.input(
                "\n[dim]Press Enter to return to the menu...[/dim]"
            )

        # -------------------------------------------------------------------
        # Batch report / CSV
        # -------------------------------------------------------------------

        elif choice in ("2", "3"):

            console.clear()
            print_banner()

            print_section(
                "SELECT WORDLIST"
            )

            file_path = dora()

            if file_path:

                path = Path(file_path)

                passwords = [
                    line.strip()
                    for line in path.read_text().splitlines()
                    if line.strip()
                ]

                if not passwords:

                    print_error(
                        f"No passwords found in '{path.name}'."
                    )

                else:

                    console.print(
                        f"Loaded [bold cyan]{len(passwords):,}[/bold cyan] "
                        f"passwords from "
                        f"[bold]{path.name}[/bold]."
                    )

                    inspected_passwords = inspect_batch(
                        passwords
                    )

                    display_batch_summary(
                        inspected_passwords
                    )

                    if choice == "2":

                        output_report(
                            inspected_passwords
                        )

                    else:

                        output_csv(
                            inspected_passwords
                        )

                        console.print()
                        print_success(
                            "CSV written to STDOUT."
                        )

            else:

                print_warning(
                    "No file selected."
                )

            console.input(
                "\n[dim]Press Enter to return to the menu...[/dim]"
            )

        # -------------------------------------------------------------------
        # Version
        # -------------------------------------------------------------------

        elif choice == "4":

            console.clear()
            print_banner()

            version_table = Table(
                show_header=False,
                box=box.ROUNDED,
                border_style="cyan",
                padding=(0, 2),
            )

            version_table.add_column(
                "Property",
                style="bold cyan",
            )

            version_table.add_column(
                "Value"
            )

            version_table.add_row(
                "Name",
                "Password Inspector",
            )

            version_table.add_row(
                "Version",
                __version__,
            )

            version_table.add_row(
                "Author",
                "Emmanuel Nkhoma",
            )

            version_table.add_row(
                "License",
                "MIT",
            )

            version_table.add_row(
                "Privacy",
                "K-anonymity / No password logging",
            )

            console.print(version_table)

            console.input(
                "\n[dim]Press Enter to return to the menu...[/dim]"
            )

        # -------------------------------------------------------------------
        # Help
        # -------------------------------------------------------------------

        elif choice == "5":

            console.clear()
            print_banner()

            print_section("CLI HELP")

            console.print(
                "[bold]Single password:[/bold]\n"
                "  python password_inspector.py MyPassword\n\n"

                "[bold]Wordlist:[/bold]\n"
                "  python password_inspector.py passwords.txt\n\n"

                "[bold]Human-readable report:[/bold]\n"
                "  python password_inspector.py passwords.txt --report\n\n"

                "[bold]CSV output:[/bold]\n"
                "  python password_inspector.py passwords.txt --csv\n\n"

                "[bold]Version:[/bold]\n"
                "  python password_inspector.py --version\n\n"

                "[bold]Help:[/bold]\n"
                "  python password_inspector.py --help"
            )

            console.print()
            print_privacy_notice()

            console.input(
                "\n[dim]Press Enter to return to the menu...[/dim]"
            )

        # -------------------------------------------------------------------
        # Exit
        # -------------------------------------------------------------------

        elif choice == "6":

            console.clear()

            console.print(
                Panel(
                    "[bold cyan]PASSWORD INSPECTOR[/bold cyan]\n\n"
                    "[green]Thank you for using Password Inspector.[/green]\n"
                    "[dim]Stay safe.[/dim]",
                    border_style="cyan",
                    box=box.ROUNDED,
                    padding=(1, 4),
                )
            )

            inspecting = False

        # -------------------------------------------------------------------
        # Invalid choice
        # -------------------------------------------------------------------

        else:

            print_error(
                "Invalid choice. Select a number from 0 to 6."
            )

            console.input(
                "\n[dim]Press Enter to continue...[/dim]"
            )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()

