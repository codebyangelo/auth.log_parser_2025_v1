from datetime import timedelta


def is_working_hours(event_time):
    # Define working hours (e.g., 8 AM to 6 PM)
    start_hour = 8
    end_hour = 18
    return start_hour <= event_time.hour < end_hour


def apply_stateful_tags(events):
    # For [MULTI_FAIL]
    failed_attempts = {}
    # For [RECURSIVE_SUDO]
    sudo_sessions = {}

    for event in events:
        # --- [TIMING_ANOMALY] ---
        # Assuming 'timestamp' in event is in a format parsable by
        # datetime.strptime This needs to be robust to handle both syslog and
        # ISO formats
        parsed_event_time = event.get('parsed_timestamp')
        if parsed_event_time:
            if not is_working_hours(parsed_event_time):
                # Only add if not already tagged with something more specific
                if 'tag' in event and event['tag'] == '[INFO]':
                    event['tag'] = '[TIMING_ANOMALY]'
                elif 'tag' in event and event['tag'] != '[INFO]':
                    event['tag'] += ', [TIMING_ANOMALY]'
                else:
                    event['tag'] = '[TIMING_ANOMALY]'

        # --- [MULTI_FAIL] and [BRUTE_FORCE] ---
        if event.get('event_type') in ['failed_password', 'invalid_user']:
            user_ip = (f"{event.get('user', 'N/A')}-"
                       f"{event.get('ip_address', 'N/A')}")
            if user_ip not in failed_attempts:
                failed_attempts[user_ip] = []
            if parsed_event_time:
                failed_attempts[user_ip].append(parsed_event_time)

            # Check for multiple failures in a short window
            # (e.g., 3 failures in 60 seconds)
            threshold_count_multi_fail = 3
            time_window_multi_fail = timedelta(seconds=60)

            recent_failures = [
                t for t in failed_attempts[user_ip] if parsed_event_time and
                parsed_event_time - t <= time_window_multi_fail
            ]
            if len(recent_failures) >= threshold_count_multi_fail:
                if 'tag' in event and event['tag'] == '[INFO]':
                    event['tag'] = '[MULTI_FAIL]'
                elif 'tag' in event and event['tag'] != '[INFO]':
                    event['tag'] += ', [MULTI_FAIL]'
                else:
                    event['tag'] = '[MULTI_FAIL]'

            # Check for brute force (e.g., 10 failures in 5 minutes)
            threshold_count_brute_force = 10
            time_window_brute_force = timedelta(minutes=5)
            recent_failures_brute_force = [
                t for t in failed_attempts[user_ip] if parsed_event_time and
                parsed_event_time - t <= time_window_brute_force
            ]
            if len(recent_failures_brute_force) >= threshold_count_brute_force:
                if 'tag' in event and event['tag'] == '[INFO]':
                    event['tag'] = '[BRUTE_FORCE]'
                elif 'tag' in event and event['tag'] != '[INFO]':
                    event['tag'] += ', [BRUTE_FORCE]'
                else:
                    event['tag'] = '[BRUTE_FORCE]'

        # --- [RECURSIVE_SUDO] ---
        if event.get('event_type') == 'sudo_command_executed':
            user = event.get('user')
            if user:
                # Check if user is already in a sudo session
                if (user in sudo_sessions and parsed_event_time and
                   (parsed_event_time - sudo_sessions[user]) <
                   timedelta(minutes=5)):
                    if 'tag' in event and event['tag'] == '[INFO]':
                        event['tag'] = '[RECURSIVE_SUDO]'
                    elif 'tag' in event and event['tag'] != '[INFO]':
                        event['tag'] += ', [RECURSIVE_SUDO]'
                    else:
                        event['tag'] = '[RECURSIVE_SUDO]'
                if parsed_event_time:
                    # Update last sudo time
                    sudo_sessions[user] = parsed_event_time

        # --- [CRON_TASK] ---
        if event.get('process') == 'CRON':
            if 'tag' in event and event['tag'] == '[INFO]':
                event['tag'] = '[CRON_TASK]'
            elif 'tag' in event and event['tag'] != '[INFO]':
                event['tag'] += ', [CRON_TASK]'
            else:
                event['tag'] = '[CRON_TASK]'

    return events
