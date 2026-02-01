from collections import defaultdict
from datetime import datetime

LOG_FILE = "sample.log"
ALERT_FILE = "alerts.log"
FAIL_THRESHOLD = 3


def parse_log_line(line: str):
    """
    Parse a single log line into components.
    """
    parts = line.strip().split()
    timestamp = f"{parts[0]} {parts[1]}"
    status = parts[2]
    user = parts[3].split("=")[1]
    ip = parts[4].split("=")[1]

    return timestamp, status, user, ip


def analyze_logs():
    failed_attempts = defaultdict(int)
    alerts = []

    with open(LOG_FILE, "r") as log:
        for line in log:
            timestamp, status, user, ip = parse_log_line(line)

            if status == "LOGIN_FAIL":
                failed_attempts[ip] += 1

                if failed_attempts[ip] == FAIL_THRESHOLD:
                    alert = (
                        f"[{timestamp}] ALERT: "
                        f"Possible brute-force attack from IP {ip} "
                        f"(user={user}, failures={FAIL_THRESHOLD})"
                    )
                    alerts.append(alert)

    return alerts


def write_alerts(alerts):
    if not alerts:
        print("No threats detected.")
        return

    with open(ALERT_FILE, "a") as file:
        for alert in alerts:
            file.write(alert + "\n")

    print(f"{len(alerts)} security alert(s) written to {ALERT_FILE}")


def main():
    print("=== Security Log Analyzer ===")
    alerts = analyze_logs()
    write_alerts(alerts)


if __name__ == "__main__":
    main()