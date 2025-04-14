import re
from collections import defaultdict
from datetime import datetime

log_file_path = 'data/example_logs/openssh.log'
alert_file_path = 'reports/alerts.txt'
suspicious_threshold = 5

failures_by_ip = defaultdict(int)
pattern = re.compile(r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)')

# Parse failed login attempts
with open(log_file_path, 'r') as file:
    for line in file:
        match = pattern.search(line)
        if match:
            ip = match.group(1)
            failures_by_ip[ip] += 1

# Generate alerts
with open(alert_file_path, 'w') as alert_file:
    alert_file.write(f"ALERTS LOG - {datetime.now()}\n\n")
    for ip, count in failures_by_ip.items():
        if count >= suspicious_threshold:
            alert_file.write(f"[ALERT] Brute-force risk detected from IP {ip} with {count} failed login attempts.\n")

print(f"Alerts saved to: {alert_file_path}")