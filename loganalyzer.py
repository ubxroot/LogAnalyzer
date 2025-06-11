import re
import os
import json
import sys # Added for sys.platform in edit_patterns
import subprocess # Added for subprocess.run in edit_patterns
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text
import pyfiglet # Added for the banner

# Initialize the Typer application and Console for rich output
app = typer.Typer(help="Log Analyzer: Scans log files for suspicious activities and presents findings in a table.")
console = Console()

# --- Configuration for default patterns and remedies ---
# These regular expressions are used to detect common suspicious activities in log files.
DEFAULT_PATTERNS = {
    "malware_signature": r"(trojan|worm|virus|ransomware|exploit|malicious|backdoor|rootkit)",
    "unauthorized_access": r"(failed password|authentication failure|invalid user|unauthorized access|access denied|permission denied)",
    "phishing_attempt": r"(phish|scam|suspicious link|verify account|urgent action required|click here to verify)",
    "file_tampering": r"(file integrity|checksum mismatch|file modified|deleted file|unexpected file change)",
    "security_breach": r"(breach|compromised|data exfiltration|intrusion detected|vulnerability exploited)",
    "ssh_bruteforce": r"(Failed password for|Invalid user|authentication failure).*from\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})",
    "port_scan": r"(Nmap|masscan|zmap|scan report for|port scan detected)",
    "sql_injection": r"(SELECT\s+.*FROM|UNION\s+SELECT|INSERT\s+INTO|OR\s+\d+=\d+|'or'\d+='|\d+'\s+OR\s+)",
    "buffer_overflow": r"(buffer overflow|segmentation fault|stack smashing detected)",
    "privilege_escalation": r"(privilege escalation|sudo:|su:|root access granted)"
}

# These are recommended actions for each detected event type.
DEFAULT_REMEDIES = {
    "malware_signature": "Isolate the affected system, run full antivirus scan, restore from clean backup.",
    "unauthorized_access": "Block source IP, reset affected user passwords, enforce MFA, review access logs for similar activity.",
    "phishing_attempt": "Report email, block sender, educate users, enhance email filtering and DMARC/SPF/DKIM policies.",
    "file_tampering": "Verify file integrity, restore from backup, investigate source of modification, strengthen access controls.",
    "security_breach": "Activate incident response plan, contain the breach, eradicate threat, recover systems, conduct forensic analysis.",
    "ssh_bruteforce": "Block the source IP address in firewall, consider fail2ban. Review user accounts for compromise.",
    "port_scan": "Investigate the scanning source. Block if malicious. Review exposed services and firewall rules.",
    "sql_injection": "Review web application logs, sanitize input, update web application firewall (WAF) rules, patch vulnerable applications.",
    "buffer_overflow": "Patch vulnerable software, implement DEP/ASLR, review code for insecure functions and bounds checking.",
    "privilege_escalation": "Review user permissions, audit recent system changes, patch vulnerable software, investigate user activity."
}

# Path to the custom configuration file for user-defined patterns and remedies
# This file will be located in the user's home directory.
CUSTOM_CONFIG_PATH = Path.home() / ".log_analyzer_custom_patterns.json"

def load_custom_config():
    """
    Loads custom patterns and remedies from the user's home directory.
    The file is expected to be ~/.log_analyzer_custom_patterns.json.
    """
    if CUSTOM_CONFIG_PATH.exists():
        try:
            with open(CUSTOM_CONFIG_PATH, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            console.print(f"[bold red]Error:[/] Could not parse custom config file: {CUSTOM_CONFIG_PATH}. Please check its JSON format.", style="bold red")
            return {}
    return {}

def get_all_patterns_and_remedies():
    """
    Combines default and custom patterns/remedies into single dictionaries.
    Custom patterns/remedies will override default ones if keys conflict.
    """
    custom_config = load_custom_config()
    all_patterns = DEFAULT_PATTERNS.copy()
    all_remedies = DEFAULT_REMEDIES.copy()

    if "patterns" in custom_config:
        all_patterns.update(custom_config["patterns"])
    if "remedies" in custom_config:
        all_remedies.update(custom_config["remedies"])

    return all_patterns, all_remedies

# --- Analysis Command ---

@app.command(name="analyze", help="Analyzes a log file for suspicious activities and outputs results in a table.")
def analyze_log(log_file: Path = typer.Argument(..., help="Path to the log file to analyze.")):
    """
    Analyzes a given log file for predefined and custom security events.
    It reads the file line by line and checks for matches against known patterns.
    The results are then displayed in a formatted table.
    """
    if not log_file.is_file():
        console.print(f"[bold red]Error:[/] Log file not found: {log_file}", style="bold red")
        raise typer.Exit(code=1)

    console.print(f"[bold blue]Analyzing log file:[/][cyan] {log_file}[/]\n", style="bold blue")

    all_patterns, all_remedies = get_all_patterns_and_remedies()
    detected_events = {}

    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                for event_type, pattern in all_patterns.items():
                    # Search for the pattern in each line (case-insensitive)
                    if re.search(pattern, line, re.IGNORECASE):
                        # If detected, increment count for the event type
                        detected_events.setdefault(event_type, {"count": 0})
                        detected_events[event_type]["count"] += 1
    except IOError as e:
        console.print(f"[bold red]Error:[/] Could not read log file: {e}", style="bold red")
        raise typer.Exit(code=1)

    # Prepare and display results in a rich Table
    table = Table(title=f"Log Analysis Results for {log_file.name}", show_header=True, header_style="bold magenta")
    table.add_column("Event Type", style="bold green")
    table.add_column("Occurrences", style="bold blue", justify="right")
    table.add_column("Recommended Remedy", style="white")

    if detected_events:
        # Sort events by occurrence count in descending order
        sorted_events = sorted(detected_events.items(), key=lambda item: item[1]["count"], reverse=True)
        for event_type, data in sorted_events:
            remedy = all_remedies.get(event_type, "No specific remedy provided.")
            table.add_row(
                Text(event_type.replace('_', ' ').title(), style="bold yellow"),
                str(data["count"]),
                remedy
            )
        console.print(table)
    else:
        console.print("[bold green]No suspicious activities found in the log file. Stay secure![/]", style="bold green")

# --- Custom Patterns Management Command ---
@app.command(name="edit-patterns", help="Opens the custom patterns JSON file for editing.")
def edit_patterns():
    """
    Opens the custom patterns and remedies JSON file in the default text editor.
    If the file doesn't exist, it creates a template.
    """
    if not CUSTOM_CONFIG_PATH.exists():
        initial_content = {"patterns": {}, "remedies": {}}
        try:
            with open(CUSTOM_CONFIG_PATH, 'w') as f:
                json.dump(initial_content, f, indent=2)
            console.print(f"[bold green]Created new custom patterns file:[/][cyan] {CUSTOM_CONFIG_PATH}[/]", style="bold green")
            console.print("[bold yellow]Please add your patterns and remedies in JSON format.[/]", style="bold yellow")
        except IOError as e:
            console.print(f"[bold red]Error:[/] Could not create custom config file: {e}", style="bold red")
            raise typer.Exit(code=1)
    
    # Open the file with the default system editor
    try:
        if sys.platform == "win32":
            os.startfile(CUSTOM_CONFIG_PATH)
        elif sys.platform == "darwin":
            subprocess.run(["open", str(CUSTOM_CONFIG_PATH)])
        else: # Linux/Unix
            subprocess.run(["xdg-open", str(CUSTOM_CONFIG_PATH)])
        console.print(f"[bold blue]Opening custom patterns file:[/][cyan] {CUSTOM_CONFIG_PATH}[/]", style="bold blue")
    except FileNotFoundError:
        console.print("[bold red]Error:[/] Could not open file. No default editor found or file association missing.", style="bold red")
        console.print(f"You can manually edit the file at: [cyan]{CUSTOM_CONFIG_PATH}[/]", style="bold red")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]Error opening file:[/] {e}", style="bold red")
        raise typer.Exit(code=1)

# --- Banner Function ---
def show_banner():
    """Displays a stylized banner for the Log Analyzer tool."""
    banner = pyfiglet.figlet_format("UBXROOT", font="slant")
    console.print(f"[bright_cyan]{banner}[/bright_cyan]")
    console.print("[bright_yellow]Log Analyzer – Blue Team Log Analyzer v1.0[/bright_yellow]\n")

# --- Entry point for the command-line application ---
if __name__ == "__main__":
    show_banner() # Display the banner when the script starts
    app()
