import argparse


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="A lightweight parser for Linux /var/log/auth.log files.",
        epilog="Example: python3 auth.log_parser.py --logfile "
               "/path/to/auth.log --failed --json"
    )

    parser.add_argument(
        '--logfile',
        type=str,
        default='/var/log/auth.log',
        help='Path to the auth.log file to parse. Defaults to '
             '/var/log/auth.log'
    )

    parser.add_argument(
        '--failed',
        action='store_true',
        help='Filter to show only failed events (failed passwords, '
             'invalid users, etc.)'
    )

    parser.add_argument(
        '--sudo',
        action='store_true',
        help='Filter to show only sudo-related activity.'
    )

    parser.add_argument(
        '--user',
        type=str,
        help='Filter events for a specific username.'
    )

    parser.add_argument(
        '--output',
        type=str,
        help='Path to a file to write the output to.'
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='Output the results in JSON format.'
    )

    parser.add_argument(
        '--tagged',
        action='store_true',
        help='Adds symbolic tags like [FAILED_AUTH], [PRIV_ESC] to matched '
             'entries.'
    )

    parser.add_argument(
        '--summary',
        action='store_true',
        help='Shows counts per event type, user, or daemon.'
    )

    parser.add_argument(
        '--group-by',
        type=str,
        choices=['IP'],
        help='Organizes output by a specified field (e.g., IP).',
        metavar='FIELD'
    )

    parser.add_argument(
        '--time-range',
        type=str,
        help='Filter events within specific timestamps '
             '(e.g., "YYYY-MM-DD:YYYY-MM-DD").'
    )

    parser.add_argument(
        '--raw',
        action='store_true',
        help='Dumps raw lines with no filtering—useful for baseline '
             'comparison.'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Shows parser decisions per line—useful for development or '
             'false positive tracing.'
    )

    parser.add_argument(
        '--ethos',
        action='store_true',
        help='Prints the human-in-the-loop philosophy banner.'
    )

    parser.add_argument(
        '--report',
        action='store_true',
        help='Enable enhanced structured report mode (5W+How).'
    )

    parser.add_argument(
        '--hour-range',
        type=str,
        help='Filter events within specific hour range (e.g., "00:00-06:00").'
    )

    return parser.parse_args()
