import sys
from cli import parse_arguments
from utils.parser import stream_log_events
from utils.filters import filter_events
from tagging import apply_stateful_tags
from output_formatter import format_output

def main():
    """
    Main function to run the auth.log parser.
    """
    args = parse_arguments()

    if args.ethos:
        print("""
        =======================================================================
        |                 Human-in-the-Loop Philosophy                      |
        =======================================================================
        | This tool is designed to augment, not replace, the security         |
        | analyst. It automates the tedious task of parsing and               |
        | highlighting events, but the final judgment, correlation, and       |
        | interpretation require human expertise. Always treat the output     |
        | as a starting point for investigation, not a definitive conclusion. |
        =======================================================================
        """)
        sys.exit(0)

    event_stream = stream_log_events(args.logfile, verbose=args.verbose)

    # --- Batch Processing for Summary/Report Modes ---
    if args.summary or args.report:
        # These modes require the full list of events for aggregation.
        # This is a trade-off: not memory-efficient for huge files.
        if args.verbose:
            print("# Switching to batch processing for summary/report", file=sys.stderr)
        
        events = list(event_stream)
        if not events:
            print("No events parsed. Exiting.")
            sys.exit(0)
        
        tagged_events = apply_stateful_tags(events)
        
        filtered_events = filter_events(
            tagged_events,
            failed=args.failed,
            sudo=args.sudo,
            user_filter=args.user,
            time_range=args.time_range,
            hour_range=args.hour_range
        )

        if not filtered_events:
            print("No matching events found.")
            sys.exit(0)

        output = format_output(filtered_events, args)
        
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    f.write(output)
                print(f"Output successfully written to {args.output}")
            except IOError as e:
                print(f"Error writing to file {args.output}: {e}", file=sys.stderr)
        else:
            print(output)

    # --- True Streaming for all other modes ---
    else:
        if args.verbose:
            print("# Processing log in memory-efficient streaming mode", file=sys.stderr)

        # Note: Stateful tagging is not yet implemented for streaming mode.
        
        filtered_stream = filter_events(
            event_stream,
            failed=args.failed,
            sudo=args.sudo,
            user_filter=args.user,
            time_range=args.time_range,
            hour_range=args.hour_range
        )

        events_found = False
        # Handle JSON streaming output
        if args.json:
            import json
            print('[')
            first = True
            for event in filtered_stream:
                events_found = True
                if not first:
                    print(',')
                
                event_copy = event.copy()
                if 'parsed_timestamp' in event_copy and event_copy['parsed_timestamp']:
                    event_copy['parsed_timestamp'] = event_copy['parsed_timestamp'].isoformat()
                
                print(json.dumps(event_copy, indent=4), end='')
                first = False
            print('\n]')
        # Handle plain-text and tagged streaming output
        else:
            for event in filtered_stream:
                events_found = True
                log_line = event.get('raw_log', '')
                if args.tagged and 'tag' in event:
                    log_line = f"{event['tag']} {log_line}"
                print(log_line)

        if not events_found:
            print("No matching events found.")

if __name__ == "__main__":
    main()
