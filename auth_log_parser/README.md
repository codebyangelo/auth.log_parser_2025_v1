# auth.log_parser_2025_v1

**A minimalist, practical, and scalable script that parses `/var/log/auth.log` and extracts security-relevant events for triage and analysis in a SOC environment.**

## What is it?

This tool is a command-line utility designed to help security analysts, system administrators, and developers quickly make sense of Linux authentication logs. It reads the often-chaotic `auth.log` file and transforms it into structured, readable, and actionable information. By highlighting anomalies and categorizing events, it allows you to spot potential security threats, debug login issues, or audit user activity with ease.

## Why Use This Tool?

*   **Save Time and Effort:** Instead of manually sifting through thousands of log lines, get a clear summary of important events in seconds.
*   **Scalable by Design:** Handles log files of any size with ease. The tool processes logs as a memory-efficient stream by default, allowing it to analyze massive files without crashing.
*   **Enhance Security Visibility:** Instantly spot critical security events like failed logins, unauthorized `sudo` attempts, and brute-force attacks.
*   **Gain Deeper Insights:** Stateful tagging connects related events, revealing patterns like repeated login failures from the same IP or unusual activity outside of working hours (see note on stateful tagging below).
*   **Integrate with Your Workflow:** Output to JSON for easy integration with other tools, or get a simple plain-text report for quick viewing.

## Getting Started

To get started, you can run the tool from the command line. The most basic usage is to point it at a log file.

```bash
python3 auth_log_parser/main.py --logfile /path/to/your/auth.log
```

For example, to analyze the test log file included in this project with tags and a summary, you would run:

```bash
python3 auth_log_parser/main.py --logfile test_auth.log --tagged --summary
```

## How It Works

The tool operates in one of two modes, depending on the output you request.

### 1. Streaming Mode (Default)
For most outputs (plain text, tagged, JSON), the tool operates in a highly memory-efficient streaming mode.
1.  **Stream & Parse (`utils/parser.py`):** The tool reads the log file line-by-line, never loading the entire file into memory. Each line is immediately parsed into a structured event.
2.  **Filter (`utils/filters.py`):** The stream of events passes through a filtering generator, which yields only the events that match your criteria (e.g., `--user <username>`).
3.  **Format (`output_formatter.py`):** Each filtered event is formatted and printed to the console one at a time.

### 2. Batch Mode (`--summary` or `--report`)
For outputs that require a complete view of all events (like `--summary` or `--report`), the tool first streams all events into a list in memory.
1.  **Collect:** All events from the log file are parsed and collected into a list.
2.  **Stateful Tagging (`tagging.py`):** The complete list of events is passed to the tagging module, which applies advanced tags by analyzing relationships between events (e.g., `[MULTI_FAIL]` a`[TIMING_ANOMALY]`.).
3.  **Filter & Format:** The full, tagged list is then filtered and formatted into the final summary or report.

## Features

*   **Scalable Log Ingestion**: Reads log files of any size using a streaming-by-default architecture.
*   **Event Classification**: Categorizes events such as SSH logins, `sudo` usage, `su` sessions, and failed logins.
*   **Stateful & Stateless Tagging**: Applies simple, stateless tags in all modes, and advanced stateful tags in batch-processing modes.
*   **Powerful Filtering**: Allows for flag-based event selection by event type, user, time range, and hour range.
*   **Flexible Output**: Display results in plain text, tagged text, JSON, a summary report, or a detailed triage report.
*   **Multiline Log Awareness**: Correctly parse log entries that span multiple lines.

## Available Flags

*   **`--tagged`**: Displays symbolic tags like `[FAILED_AUTH]`, `[PRIV_ESC]` in the output for enhanced clarity.
*   **`--summary`**: Shows aggregated counts per event type, user, or daemon. **(Uses Batch Mode)**
*   **`--report`**: Generates a detailed triage report for all events. **(Uses Batch Mode)**
*   **`--group-by IP`**: Organizes output by originating IP to help identify hotspots or attackers.
*   **`--time-range`**: Filters events within specific timestamps (e.g., `--time-range "2025-07-01:2025-07-09"`).
*   **`--raw`**: Dumps raw lines with no filtering—useful for baseline comparison.
*   **`--verbose`**: Shows parser decisions per line—useful for development or false positive tracing.
*   **`--ethos`**: Prints the human-in-the-loop philosophy banner at the top.

## Tagging Dictionary

**Note on Tagging Modes:** Most tags are applied in all modes. However, some **stateful tags** require analyzing the entire log file at once. These more advanced tags are only applied when using `--summary` or `--report`, which activate Batch Mode.

*   **`[FAILED_AUTH]`**: Failed password attempts, incorrect logins, invalid usernames.
*   **`[INVALID_USER]`**: Login attempts using non-existent or disabled users.
*   **`[REMOTE_LOGIN]`**: SSH or remote access attempts, especially from external IPs.
*   **`[SUDO_COMMAND]`**: Specific sudo commands executed.
*   **`[SUDO_SESSION_OPEN]`**: A sudo session has been opened.
*   **`[SESSION_OPEN]`**: Session starts via PAM (cron, sudo, ssh).
*   **`[SESSION_CLOSE]`**: Session terminations (session closed from PAM).
*   **`[UID_MISMATCH]`**: When a lower-privileged UID initiates privileged activity.
*   **`[TIMING_ANOMALY]`**: Logins outside working hours (e.g., 02:00 AM by admin).
*   **`[MULTI_FAIL]`**: **(Batch Mode Only)** Multiple failed attempts in short succession.
*   **`[PAM_LOCKOUT]`**: Account lockout messages from PAM modules.
*   **`[RECURSIVE_SUDO]`**: **(Batch Mode Only)** Sudo used within a sudo session or repeated escalation.

## Design Ethos

*   **Minimalism**: No GUI, no fancy dashboards—just raw clarity.
*   **Practicality**: Analyst-first. Results should be visible in under 5 seconds.
*   **Efficiency**: Scalable and memory-light by default, easy to embed in a pipeline.
