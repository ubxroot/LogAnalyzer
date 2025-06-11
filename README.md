# LogAnalyzer - Blue Team Security Analyzer

![LogAnalyzer Logo/Banner (Optional - you can add an image here)](https://img.shields.io/badge/Blue%20Team-Security-blue?style=for-the-badge&logo=shield)
![Python Version](https://img.shields.io/badge/Python-3.8%2B-green?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)

LogAnalyzer is a powerful Python-based application designed to empower blue teams in analyzing logs and various file types for security events and misconfigurations. It features a user-friendly GUI and a robust command-line interface. LogAnalyzer aims to provide quick, actionable insights into potential threats and insecure settings, significantly reducing the time to detection and mitigation for your security operations.

## ✨ Features
## 🔍 Binary File Scanning
* Analyze various binary formats: Supports scanning of .exe, .dll, .bin, .elf, and other executable and binary file formats.
* Extract forensic data: Automatically pulls out critical information such as headers, strings, and calculates essential cryptographic hashes (MD5, SHA1, SHA256) for forensic analysis.
* Threat intelligence enrichment (Optional): Integrates with external sources like VirusTotal for comprehensive reputation checks, leverages YARA rules for pattern matching, and cross-references against known malware signatures for enhanced detection capabilities.

## 📁 Log Analysis Engine
* Broad log format support: Capable of understanding and parsing common log formats including syslog, auth.log, Windows Event Logs (EVTX), Apache/Nginx access logs, and adaptable to custom JSON log structures.
* Flexible parsing: Utilizes robust Regex and advanced rule-based parsing techniques for accurate and efficient event identification.
* Customizable detection rules: Comes with a set of built-in rules and allows users to define custom rules for detecting specific patterns like brute force attacks, privilege escalation attempts, and other suspicious behaviors tailored to your environment.

## 🚨 Threat Intelligence Correlation
* Integrated threat feeds: Connects with popular and reliable threat intelligence sources such as AbuseIPDB, AlienVault OTX, and provides flexibility for custom Threat Intelligence (TI) source integration.
* Automated IOC correlation: Automatically correlates Indicators of Compromise (IOCs) like IP addresses, file hashes, and domain names found within analyzed logs and binaries against integrated threat intelligence.
* Offline IOC hunting: Features a local cache for frequently used IOCs, enabling effective and rapid threat hunting even when an active internet connection is unavailable.

## 🛡️ Real-time Monitoring
* Live log tailing: Provides real-time tailing and continuous monitoring of specified log files, ensuring immediate detection of unfolding events.
* Instant CLI alerts: Delivers immediate, color-coded alerts directly in your command-line interface for quick visual identification of critical issues.
* Notification integration: Offers optional webhook and Slack notification integration for critical alerts, ensuring your team is informed instantly regardless of their current activity.

## 🔐 File Integrity and IOC Scanner
* Recursive directory monitoring: Continuously monitors specified directories and their subdirectories for file changes and suspicious modifications.
* Signature mismatch detection: Intelligently detects newly added or modified binaries by identifying signature mismatches and anomalies.
* Custom scan policies: Supports defining custom scan policies for granular file integrity checks, allowing you to focus on critical assets and sensitive data.

## 📊 Output and Reporting
* Multiple output formats: Presents analysis results in various versatile formats including a structured table (for CLI output), JSON, CSV, and interactive HTML reports.
* Session summary reports: Generates comprehensive summary reports for each analysis session, providing an executive overview of findings.
* PDF export: Provides an option to export detailed reports to PDF directly via a CLI flag, facilitating easy sharing, archival, and compliance documentation.

## **🚀 Installation**
**Clone the repository:**
```bash
git clone https://github.com/ubxroot/LogAnalyzer.git
cd LogAnalyzer
```

**Install dependencies:**
```bash
pip install -r requirements.txt
(This command will install typer, rich, pyfiglet, matplotlib, numpy, Pillow, and any other necessary libraries listed in requirements.txt to support all features.)
```

## 💡 Usage
## LogAnalyzer offers both a graphical user interface (GUI) and a command-line interface (CLI) for flexibility.

# Start the GUI application:
python log_analyzer.py # Assuming log_analyzer.py is your main GUI script

# Click on "Select Log File and Scan" to choose a log file.

**The analysis results will be displayed, and a report/graph will be saved in the same directory as the log file.**

# Run a log analysis via CLI:
python log_analyzer_cli.py analyze /path/to/logfile.log

# Audit an SSH configuration file via CLI:
python log_analyzer_cli.py audit /etc/ssh/sshd_config ssh

*(The audit command currently supports ssh configurations. More types may be added in future enhancements.)*

# Manage custom detection patterns:
python log_analyzer_cli.py edit-patterns

*(This command will open the custom patterns JSON file in your default editor, allowing you to add your own regex patterns and remedies.)*

# Update LogAnalyzer to the latest version:
python log_analyzer_cli.py update

*(This command pulls the latest changes from the Git repository, ensuring you have the most recent features and bug fixes.)*

# Development & Contributions
LogAnalyzer is actively developed, and contributions are highly encouraged! Feel free to open issues for bug reports or feature requests, or submit pull requests with improvements and new functionalities. Your input helps make LogAnalyzer an even more valuable tool for the blue team community.
