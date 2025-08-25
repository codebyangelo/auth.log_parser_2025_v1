import datetime
import sys


def filter_events(events, failed=False, sudo=False, user_filter=None,
                  time_range=None, hour_range=None):
    """
    Filters a stream of parsed log events based on specified criteria,
    yielding events that match.

    Args:
        events (iterable): An iterator/generator of event dictionaries.
        failed (bool): If True, filters for failed attempts.
        sudo (bool): If True, filters for sudo-related activity.
        user_filter (str): Filters for a specific username.
        time_range (str): Filters events within a YYYY-MM-DD:YYYY-MM-DD range.
        hour_range (str): Filters events within an HH:MM-HH:MM range.

    Yields:
        dict: Event dictionaries that match the filter criteria.
    """
    # Prepare filter sets and time ranges once before the loop
    active_filter_types = set()
    if failed:
        active_filter_types.update(['failed_password', 'invalid_user', 'not_in_sudoers'])
    if sudo:
        active_filter_types.update(['sudo_session_open', 'not_in_sudoers'])

    start_time = None
    end_time = None
    if time_range:
        try:
            start_str, end_str = time_range.split(':')
            start_time = datetime.datetime.strptime(start_str, "%Y-%m-%d")
            end_time = datetime.datetime.strptime(end_str, "%Y-%m-%d").replace(hour=23, minute=59, second=59)
            local_tz = datetime.datetime.now().astimezone().tzinfo
            start_time = start_time.replace(tzinfo=local_tz)
            end_time = end_time.replace(tzinfo=local_tz)
        except ValueError:
            print(f"Error: Invalid time range format: {time_range}", file=sys.stderr)
            return

    start_hour = None
    end_hour = None
    if hour_range:
        try:
            start_hour_str, end_hour_str = hour_range.split('-')
            start_hour = datetime.datetime.strptime(start_hour_str, "%H:%M").time()
            end_hour = datetime.datetime.strptime(end_hour_str, "%H:%M").time()
        except ValueError:
            print(f"Error: Invalid hour range format: {hour_range}", file=sys.stderr)
            return

    for event in events:
        # Chain all filter conditions with 'and'.
        # If a filter is not active, its condition is True.

        type_match = not active_filter_types or event.get('event_type') in active_filter_types
        
        user_match = not user_filter or event.get('user') == user_filter
        
        time_match = not time_range or (event.get('parsed_timestamp') and start_time <= event['parsed_timestamp'] <= end_time)

        hour_match = not hour_range or (event.get('parsed_timestamp') and start_hour <= event['parsed_timestamp'].time() <= end_hour)

        if type_match and user_match and time_match and hour_match:
            yield event
