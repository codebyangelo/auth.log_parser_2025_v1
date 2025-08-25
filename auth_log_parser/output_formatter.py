import json


def format_output(filtered_events, args):
    """
    Formats a list of log events into various output formats.

    Args:
        filtered_events (list): A list of dictionaries, where each
                                dictionary represents a log event.
        args (argparse.Namespace): The command-line arguments.

    Returns:
        str: A string representing the formatted output.
    """
    if args.summary:
        event_type_counts = {}
        user_counts = {}
        daemon_counts = {}

        for event in filtered_events:
            event_type = event.get('event_type', 'unknown')
            event_type_counts[event_type] = event_type_counts.get(
                event_type, 0) + 1
            if 'user' in event:  # Some events might not have a user
                user = event['user']
                user_counts[user] = user_counts.get(user, 0) + 1
            # Some events might not have a process/daemon
            if 'process' in event:
                daemon = event['process']
                daemon_counts[daemon] = daemon_counts.get(daemon, 0) + 1

        summary_output = ["--- Summary Report ---", "Event Type Counts:"]
        for event_type, count in event_type_counts.items():
            summary_output.append(f"  {event_type}: {count}")

        if user_counts:
            summary_output.append("\nUser Activity:")
            for user, count in user_counts.items():
                summary_output.append(f"  {user}: {count}")

        if daemon_counts:
            summary_output.append("\nDaemon Activity:")
            for daemon, count in daemon_counts.items():
                summary_output.append(f"  {daemon}: {count}")
        return "\n".join(summary_output)

    elif args.group_by == 'IP':
        ip_grouped_events = {}
        for event in filtered_events:
            ip = event.get('ip_address', 'N/A')
            if ip not in ip_grouped_events:
                ip_grouped_events[ip] = []
            ip_grouped_events[ip].append(event)

        grouped_output = []
        for ip, events in ip_grouped_events.items():
            grouped_output.append(f"--- IP: {ip} ---")
            for event in events:
                log_line = event.get('raw_log')
                if args.tagged and 'tag' in event:
                    log_line = f"{event['tag']} {log_line}"
                grouped_output.append(log_line)
            grouped_output.append("")  # Add a blank line for separation
        return "\n".join(grouped_output)

    elif args.report:
        report_output = ["--- Triage Report ---"]

        # Add a summary section
        event_type_counts = {}
        for event in filtered_events:
            event_type = event.get('event_type', 'unknown')
            event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1

        report_output.append("\n## Event Summary")
        for event_type, count in sorted(event_type_counts.items()):
            report_output.append(f"- {event_type.replace('_', ' ').title()}: {count}")

        report_output.append("\n## Detailed Events")
        for event in filtered_events:
            who = event.get('user', 'N/A')
            uid = event.get('uid', 'N/A')
            tags = ', '.join(event.get('tag', '').split(', '))

            # Infer probable motive
            why = "N/A"
            for tag in tags.split(', '):
                if tag == '[CRON_TASK]':
                    why = "Scheduled CRON task"
                    break
                elif tag == '[BRUTE_FORCE]':
                    why = "Probable brute force attempt"
                    break
                elif tag == '[TIMING_ANOMALY]':
                    why = "Activity at off-peak time"
                    break
                elif tag == '[FAILED_AUTH]':
                    why = "Failed authentication attempt"
                    break
                elif tag == '[INVALID_USER]':
                    why = "Attempt to login with invalid user"
                    break
                elif tag == '[PRIV_ESC]':
                    why = "Privilege escalation attempt"
                    break
                elif tag == '[PAM_LOCKOUT]':
                    why = "Account locked due to too many failed attempts"
                    break
                elif tag == '[MULTI_FAIL]':
                    why = "Multiple failed authentication attempts"
                    break
                elif tag == '[RECURSIVE_SUDO]':
                    why = "Recursive sudo command execution"
                    break
                elif tag == '[SUDO_COMMAND]':
                    why = "Sudo command executed"
                    break
                elif tag == '[REMOTE_LOGIN]':
                    why = "Successful remote login"
                    break
                elif tag == '[SUDO_SESSION_OPEN]':
                    why = "Sudo session opened"
                    break
                elif tag == '[SESSION_OPEN]':
                    why = "User session opened"
                    break
                elif tag == '[SESSION_CLOSE]':
                    why = "User session closed"
                    break
                elif tag == '[UID_MISMATCH]':
                    why = "User not in sudoers file"
                    break
                elif tag == '[INFO]':
                    why = "Informational event"
                    break

            # Map event_type to action verbs
            action_verb_map = {
                'failed_password': 'Failed Login',
                'accepted_password': 'Successful Login',
                'invalid_user': 'Invalid User Login Attempt',
                'sudo_session_open': 'Sudo Session Open',
                'sudo_command_executed': 'Sudo Command Executed',
                'session_opened': 'Session Opened',
                'session_closed': 'Session Closed',
                'not_in_sudoers': 'User Not in Sudoers',
                'root_session_open': 'Root Session Open',
                'pam_account_locked': 'PAM Account Locked'
            }
            event_type = event.get('event_type', 'N/A')
            what_action = action_verb_map.get(
                event_type, event_type.replace('_', ' ').title())

            report_output.append(f"\n### Event: {what_action}")
            report_output.append(f"- **Who**: {who} (UID={uid})")
            report_output.append(f"- **What**: {what_action}")
            ts = event.get('parsed_timestamp')
            when = ts.isoformat() if ts else 'N/A'
            report_output.append(f"- **When**: {when}")
            host = event.get('hostname', 'N/A')
            ip = event.get('ip_address', 'N/A')
            report_output.append(f"- **Where**: Host {host} (IP: {ip})")
            report_output.append(f"- **Why**: {why}")
            report_output.append(
                f"- **How**: {event.get('method_of_access', 'N/A')}")
            report_output.append(f"- **Tags**: {tags}")
        return "\n".join(report_output)

    elif args.json:
        # Prepare events for JSON serialization
        json_compatible_events = []
        for event in filtered_events:
            # Create a copy to avoid modifying the original event object
            event_copy = event.copy()
            if 'parsed_timestamp' in event_copy and \
               event_copy['parsed_timestamp']:
                event_copy['parsed_timestamp'] = event_copy[
                    'parsed_timestamp'].isoformat()
            json_compatible_events.append(event_copy)
        return json.dumps(json_compatible_events, indent=4)

    else:
        plain_text_output = []
        for event in filtered_events:
            log_line = event.get('raw_log')
            if args.tagged and 'tag' in event:
                log_line = f"{event['tag']} {log_line}"
            plain_text_output.append(log_line)
        return "\n".join(plain_text_output)
