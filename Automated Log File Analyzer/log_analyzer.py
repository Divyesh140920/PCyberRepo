import re
from collections import defaultdict

# Sample alert rules - regex patterns mapped to alert descriptions
ALERT_RULES = {
    r'failed password for invalid user': 'Failed login attempt with invalid user',
    r'authentication failure': 'Authentication failure detected',
    r'error.*access denied': 'Access denied error',
    r'error.*denied': 'Denied error',
    r'failed login': 'Failed login attempt',
    r'root login': 'Root user login detected',
    r'unauthorized access': 'Unauthorized access attempt',
    r'error.*sql injection': 'Possible SQL Injection detected',
    r'xss attack detected': 'Possible XSS attack detected',
    # Add or customize more patterns here
}

def analyze_log_file(file_path):
    alerts = defaultdict(int)
    lines_with_alerts = defaultdict(list)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line_lower = line.lower()
                for pattern, alert_desc in ALERT_RULES.items():
                    if re.search(pattern, line_lower):
                        alerts[alert_desc] += 1
                        lines_with_alerts[alert_desc].append((line_num, line.strip()))
    except FileNotFoundError:
        print(f"Log file not found: {file_path}")
        return
    except Exception as e:
        print(f"Error reading log file: {e}")
        return

    if alerts:
        print(f"\nSecurity Alerts Summary for '{file_path}':\n")
        for alert_desc, count in alerts.items():
            print(f"- {alert_desc}: {count} occurrence(s)")
            print(f"  Sample lines:")
            for ln, text in lines_with_alerts[alert_desc][:3]:  # show up to 3 sample lines
                print(f"    Line {ln}: {text}")
            print()
    else:
        print(f"No suspicious patterns found in '{file_path}'.")

def main():
    log_file = "system.log"  # change to your log file path
    print(f"Analyzing log file: {log_file}")
    analyze_log_file(log_file)

if __name__ == "__main__":
    main()
