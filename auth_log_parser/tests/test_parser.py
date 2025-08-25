import os
import sys
import unittest

from utils.parser import parse_log_file

parent_dir = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')
)
sys.path.insert(0, parent_dir)


class TestAuthLogParser(unittest.TestCase):
    """
    Test suite for the auth log parser.
    """

    def setUp(self):
        """
        Set up a temporary log file for testing before each test method.
        """
        self.test_logfile_path = "test_auth.log"
        log_line_1 = (
            "Jul 9 10:01:01 my-host sshd[1234]: Accepted password "
            "for angelo from 192.168.1.100 port 12345 ssh2\n"
        )
        log_line_2 = (
            "Jul 9 10:02:02 my-host sshd[5678]: Failed password for "
            "invalid user guest from 10.0.0.5 port 54321 ssh2\n"
        )
        log_line_3 = (
            "Jul 9 10:03:03 my-host sudo[9999]:   angelo : TTY=pts/0 ; "
            "PWD=/home/angelo ; USER=root ; COMMAND=/usr/bin/apt update\n"
        )
        log_line_4 = (
            "    pam_unix(sudo:session): session opened for user root "
            "by (uid=1000)\n"
        )
        log_line_5 = (
            "Jul 9 10:04:04 my-host sshd[1111]: Invalid user admin "
            "from 1.2.3.4\n"
        )
        log_line_6 = (
            "Jul 9 10:05:05 my-host sudo[2222]: baduser is not in the "
            "sudoers file ; TTY=pts/1 ; PWD=/home/baduser ; USER=root ; "
            "COMMAND=/bin/ls\n"
        )
        log_line_7 = (
            "Jul 9 10:06:06 my-host CRON[3333]: A non-security-related "
            "cron job log\n"
        )

        self.log_content = (
            log_line_1 + log_line_2 + log_line_3 + log_line_4 +
            log_line_5 + log_line_6 + log_line_7
        )

        with open(self.test_logfile_path, 'w') as f:
            f.write(self.log_content)

    def tearDown(self):
        """
        Clean up: Remove the temporary log file after each test.
        """
        if os.path.exists(self.test_logfile_path):
            os.remove(self.test_logfile_path)

    def test_parsing_events(self):
        """
        Test that the log file is parsed and the correct number of
        security-related events are extracted.
        """
        events = parse_log_file(self.test_logfile_path)
        self.assertEqual(len(events), 5)

    def test_accepted_password(self):
        """
        Test parsing of an 'accepted password' event.
        """
        events = parse_log_file(self.test_logfile_path)
        accepted_event = events[0]
        self.assertEqual(accepted_event['event_type'], 'accepted_password')
        self.assertEqual(accepted_event['user'], 'angelo')
        self.assertEqual(accepted_event['ip_address'], '192.168.1.100')

    def test_failed_password(self):
        """
        Test parsing of a 'failed password' event.
        """
        events = parse_log_file(self.test_logfile_path)
        failed_event = events[1]
        self.assertEqual(failed_event['event_type'], 'failed_password')
        self.assertEqual(failed_event['user'], 'guest')
        self.assertIn('invalid user', failed_event['raw_log'])

    def test_multiline_sudo_session(self):
        """
        Test parsing of a multi-line sudo session open event.
        """
        events = parse_log_file(self.test_logfile_path)
        sudo_event = events[2]
        self.assertEqual(sudo_event['event_type'], 'sudo_session_open')
        self.assertEqual(sudo_event['user'], 'angelo')
        self.assertEqual(sudo_event['target_user'], 'root')
        self.assertIn("session opened for user root", sudo_event['raw_log'])

    def test_file_not_found(self):
        """
        Test handling of a non-existent log file.
        """
        events = parse_log_file("non_existent_file.log")
        self.assertEqual(len(events), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
