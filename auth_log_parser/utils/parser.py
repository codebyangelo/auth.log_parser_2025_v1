# Import the regular expressions module
import re
from datetime import datetime

# --- Regex Definitions ---

# A list of possible timestamp formats the parser can recognize.
# This allows the parser to be flexible with different log configurations.
TIMESTAMP_PATTERNS = [
    # Traditional Syslog: e.g., "Jul  9 17:52:01"
    r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
    # ISO 8601 / systemd: e.g., "2025-07-09T17:52:01.123456+02:00"
    r'\d{4}-\d{2}-\d{2}T[\d:.]+\S*'
]

# Dynamically create a single, combined regex pattern for capturing any of the
# above timestamps. This uses the OR `|` operator to create a pattern like:
# ((pattern1)|(pattern2))
COMBINED_TIMESTAMP_REGEX = f"(?P<timestamp>({'|'.join(TIMESTAMP_PATTERNS)}))"

# A list of tuples containing event types and their corresponding compiled
# regex patterns. The combined timestamp regex is used in each rule.
EVENT_REGEX = [
    ('sudo_session_open', re.compile(
        COMBINED_TIMESTAMP_REGEX + r'\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>sudo\[\d+\]):\s+'
        r'\s*(?P<user>\S+)\s+:\s+.*?session opened for user '
        r'(?P<target_user>\S+)',
        re.DOTALL
    )),
    ('failed_password', re.compile(
        COMBINED_TIMESTAMP_REGEX + r'\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>sshd\[\d+\]):\s+'
        r'Failed password for (?P<invalid_user>invalid user )?'
        r'(?P<user>\S+)\s+'
        r'from\s+(?P<ip_address>\S+)\s+'
        r'port\s+(?P<port>\d+)'
    )),
    ('accepted_password', re.compile(
        COMBINED_TIMESTAMP_REGEX + r'\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>sshd\[\d+\]):\s+'
        r'Accepted password for (?P<user>\S+)\s+'
        r'from\s+(?P<ip_address>\S+)\s+'
        r'port\s+(?P<port>\d+)'
    )),
    ('invalid_user', re.compile(
        COMBINED_TIMESTAMP_REGEX + r'\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>sshd\[\d+\]):\s+'
        r'Invalid user (?P<user>\S+)\s+'
        r'from\s+(?P<ip_address>\S+)'
    )),
    ('not_in_sudoers', re.compile(
        COMBINED_TIMESTAMP_REGEX + r'\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>sudo\[\d+\]):\s+'
        r'\s*(?P<user>\S+)\s+is not in the sudoers file'
    )),
    ('root_session_open', re.compile(
        COMBINED_TIMESTAMP_REGEX + r'\s+'
        r'(?P<hostname>\S+)\s+'
        r'.*session opened for user (?P<user>root)'
    )),
    ('sudo_command_executed', re.compile(
        COMBINED_TIMESTAMP_REGEX + r'\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>sudo\[\d+\]):\s+'
        r'\s*(?P<user>\S+)\s+:\s+TTY=(?P<tty>\S+)\s+;\s+'
        r'PWD=(?P<pwd>\S+)\s+;\s+USER=(?P<target_user>\S+)\s+;\s+'
        r'COMMAND=(?P<command>.*)'
    )),
    ('session_opened', re.compile(
        COMBINED_TIMESTAMP_REGEX + r'\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>\S+):\s+'
        r'.*session opened for user (?P<user>\S+)'
    )),
    ('session_closed', re.compile(
        COMBINED_TIMESTAMP_REGEX + r'\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>\S+):\s+'
        r'.*session closed for user (?P<user>\S+)'
    )),
    ('pam_account_locked', re.compile(
        COMBINED_TIMESTAMP_REGEX + r'\s+'
        r'(?P<hostname>\S+)\s+'
        r'(?P<process>pam_unix|sshd|login):\s+'
        r'.*(?P<message>account locked|authentication failure|too many '
        r'authentication failures)'
    ))]

# --- Core Parsing Function ---


def stream_log_events(logfile_path, verbose=False):
    """
    Reads a log file line-by-line, yielding parsed events as a generator.
    This is an intermediate refactoring step.
    """
    line_buffer = []
    log_start_pattern = re.compile(f"^(?:{'|'.join(TIMESTAMP_PATTERNS)})")

    try:
        with open(logfile_path, 'r') as f:
            for line in f:
                if log_start_pattern.match(line):
                    if line_buffer:
                        full_entry = ''.join(line_buffer)
                        # Use a temporary list to capture the output of the old function
                        temp_list = []
                        _parse_entry(full_entry, temp_list, verbose)
                        if temp_list:
                            yield temp_list[0]
                    line_buffer = [line]
                else:
                    if line_buffer:
                        line_buffer.append(line)

            if line_buffer:
                full_entry = ''.join(line_buffer)
                temp_list = []
                _parse_entry(full_entry, temp_list, verbose)
                if temp_list:
                    yield temp_list[0]

    except FileNotFoundError:
        print(f"Error: Log file not found at {logfile_path}")
        return
    except PermissionError:
        print(f"Error: Permission denied to read the log file at "
              f"{logfile_path}")
        return


def _parse_entry(log_entry, parsed_events, verbose=False):
    """
    Helper function to parse a single log entry against the regex list.
    """
    matched = False
    for event_type, regex in EVENT_REGEX:
        match = regex.search(log_entry)
        if match:
            event_data = {
                'event_type': event_type,
                'raw_log': log_entry.strip(),
                'uid': 'N/A',  # Placeholder for UID
                'method_of_access': 'N/A'  # Placeholder for method of access
            }
            event_data.update(match.groupdict())

            # Infer method of access
            process = event_data.get('process', '').lower()
            event_type_lower = event_type.lower()

            if "sshd" in process:
                event_data['method_of_access'] = 'SSH'
            elif "sudo" in process:
                event_data['method_of_access'] = 'SUDO'
            elif "cron" in process:
                event_data['method_of_access'] = 'CRON'
            elif "su" in process:
                event_data['method_of_access'] = 'SU'
            elif "login" in event_type_lower:
                event_data['method_of_access'] = 'Login'
            elif "session" in event_type_lower:
                event_data['method_of_access'] = 'Session'

            # Add symbolic tags for --tagged flag
            if event_type == 'failed_password':
                event_data['tag'] = '[FAILED_AUTH]'
            elif event_type == 'invalid_user':
                event_data['tag'] = '[INVALID_USER]'
            elif event_type == 'accepted_password':
                if 'ip_address' in event_data:
                    event_data['tag'] = '[REMOTE_LOGIN]'
                else:
                    # Local login
                    event_data['tag'] = '[SESSION_OPEN]'
            elif event_type == 'sudo_command_executed':
                event_data['tag'] = '[SUDO_COMMAND]'
            elif event_type == 'sudo_session_open':
                event_data['tag'] = '[SUDO_SESSION_OPEN]'
            elif (event_type == 'session_opened' or
                  event_type == 'root_session_open'):
                event_data['tag'] = '[SESSION_OPEN]'
            elif event_type == 'session_closed':
                event_data['tag'] = '[SESSION_CLOSE]'
            elif event_type == 'pam_account_locked':
                event_data['tag'] = '[PAM_LOCKOUT]'
            elif event_type == 'not_in_sudoers':
                event_data['tag'] = '[UID_MISMATCH]'
            else:
                # Default tag for other events
                event_data['tag'] = '[INFO]'

            # Parse timestamp string into datetime object
            event_timestamp_str = event_data.get('timestamp')
            if event_timestamp_str:
                parsed_event_time = None
                try:
                    # Try traditional syslog format (assuming current year)
                    current_year = datetime.now().year
                    parsed_event_time = datetime.strptime(
                        f"{current_year} {event_timestamp_str}",
                        "%Y %b %d %H:%M:%S")
                except ValueError:
                    try:
                        # Try ISO 8601 format
                        parsed_event_time = datetime.fromisoformat(
                            event_timestamp_str.replace('Z', '+00:00'))
                    except ValueError:
                        pass  # Could not parse timestamp
                event_data['parsed_timestamp'] = parsed_event_time

            parsed_events.append(event_data)
            matched = True
            if verbose:
                print(f"[VERBOSE] Matched '{event_type}' for log entry: "
                      f"{log_entry.strip()}")
            break
    if verbose and not matched:
        print(f"[VERBOSE] No regex matched for log entry: "
              f"{log_entry.strip()}")
