import argparse
import re
from collections import Counter

__version__ = "1.0.0"

DEFAULT_THRESHOLD = 5
DEFAULT_FORMAT = "text"

TIMESTAMP_PATTERN = r"\d{4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{2}\.\d{6}"
IP_PATTERN = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
USER_PATTERN = r"for (?:invalid user )?(\S+) from"

class Event:
    def __init__(self, timestamp, ip, target_users):
        self.timestamp = timestamp
        self.ip = ip
        self.target_users = target_users

def failed_auth_log_summary(logfile, threshold, output_format):
    with open (logfile, "r") as file:
        logfile_lines = file.read().splitlines()

    keyword = "failed"
    logfile_failed_lines = [l for l in logfile_lines if keyword in l.lower()]

    events = []
    for log_line in logfile_failed_lines:
        timestamps_found = re.findall(TIMESTAMP_PATTERN, log_line)
        timestamp = "" if not timestamps_found else timestamps_found[0]

        ips_found = re.findall(IP_PATTERN, log_line)
        ip = "" if not ips_found else ips_found[0]

        target_users_found = re.findall(USER_PATTERN, log_line)
        target_users = "" if not target_users_found else target_users_found[0]

        event = Event(timestamp, ip, target_users)
        events.append(event)

    num_tot_fails = len(logfile_failed_lines)

    ip_failed_counter = Counter(event.ip for event in events)
    num_ip_failed = len({ev.ip for ev in events})

    user_failed_counter = Counter(event.target_users for event in events)

    #grouped: ip > users > timestamp
    grouped_events = {}
    for ev in events:
        if ev.ip not in grouped_events:
            grouped_events[ev.ip] = {}
        if ev.target_users not in grouped_events[ev.ip]:
            grouped_events[ev.ip][ev.target_users] = []
        grouped_events[ev.ip][ev.target_users].append(ev.timestamp)

    if output_format == "text":
        SEP = "=" * 82
        SUB = "-" * 82

        print(SEP)
        print("FAILED AUTHENTICATION ATTEMPTS SUMMARY")
        print(SEP)
        print(f"Analyzed file   : {logfile}")
        print(f"Total lines     : {len(logfile_lines)}")
        print(f"Failed attempts : {num_tot_fails}")
        print(f"Unique source IPs: {num_ip_failed}")
        print(f"Alert threshold : >= {threshold} attempts")

        print("\n" + SUB)
        print("TOP SOURCE IPs")
        print(SUB)
        for ip, cnt in ip_failed_counter.most_common():
            marker = "!!" if cnt >= threshold else "  "
            flag = f"[ALERT >= {threshold}]" if cnt >= threshold else "[OK]"
            print(f"{marker} {ip:<18} {cnt:>6} attempts  {flag}")

        print("\n" + SUB)
        print("TOP TARGET USERNAMES")
        print(SUB)
        for user, cnt in user_failed_counter.most_common():
            print(f"   {user:<15} {cnt:>6} attempts")

        print("\n" + SUB)
        print("TIMELINE DETAIL BY IP")
        print(SUB)
        for ip, cnt in ip_failed_counter.most_common():
            general_flag = f"[ALERT >= {threshold}]" if cnt >= threshold else "[OK]"
            print(f"{ip}  ({cnt} attempts) {general_flag}")
            for user, tms in grouped_events[ip].items():
                num_attempts_per_user = len(tms)
                print(f"   {user:<15} {num_attempts_per_user:>4}x  "
                      f"{tms[0]} -> {tms[-1]}")

    elif output_format == "json":
        print("TBD")


def main():
    parser = argparse.ArgumentParser(
        prog="failed_auth_log_summary",
        description=(
            "Summarize failed authentication attempts in an auth-style log file. Extracts timestamps, source IPs and target usernames from failed attempts, aggregates them, and flags IPs that exceed the threshold."
        ),
        epilog=(
            "Examples:\n"
            "  %(prog)s data/sample/sample_auth.log\n"
            "  %(prog)s data/sample/sample_auth.log --threshold 10 --format text"
        ),
    )
    parser.add_argument(
        "logfile",
        help="Path to the log file to analyze.",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_THRESHOLD,
        metavar="N",
        help="Minimum number of failed attempts per source IP to flag it as suspicious (default: %(default)s).",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default=DEFAULT_FORMAT,
        dest="output_format",
        help="Output format (default: %(default)s).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    args = parser.parse_args()

    failed_auth_log_summary(args.logfile, args.threshold, args.output_format)

if __name__ == "__main__":
    main()

