import re
from collections import defaultdict
from datetime import datetime

log_file_path = 'data/example_logs/openssh.log'
report_file_path = 'reports/failed_login_report.txt'

# Threshold for suspicious activity
suspicious_threshold = 5

failures_by_ip = defaultdict(int)
timestamps_by_ip = defaultdict(list)
successful_ips = set()

# Regex patterns
failed_pattern = re.compile(r'(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}).*Failed password for .* from (\d+\.\d+\.\d+\.\d+)')
success_pattern = re.compile(r'Accepted password for .* from (\d+\.\d+\.\d+\.\d+)')

# Current year assumption (OpenSSH logs usually don’t include year)
current_year = datetime.now().year

# Parse the log for both failed and successful login attempts
with open(log_file_path, 'r') as file:
    for line in file:
        fail_match = failed_pattern.search(line)
        if fail_match:
            time_str, ip = fail_match.groups()
            log_time = datetime.strptime(f"{current_year} {time_str}", "%Y %b %d %H:%M:%S")
            failures_by_ip[ip] += 1
            timestamps_by_ip[ip].append(log_time)

        success_match = success_pattern.search(line)
        if success_match:
            ip = success_match.group(1)
            successful_ips.add(ip)

# Identify suspicious IPs (5 or more failures)
suspicious_ips = sorted([(ip, failures_by_ip[ip]) for ip in failures_by_ip if failures_by_ip[ip] >= suspicious_threshold], 
	key=lambda x: x[1],
	reverse=True
	)

# Write report
with open(report_file_path, 'w') as report:
    report.write(f"Suspicious Login Activity Report\nGenerated: {datetime.now()}\n\n")

    report.write("IPs with 5 or more failed login attempts:\n")
    for ip, count in suspicious_ips:
        report.write(f"{ip}: {count} failed attempts")

        # Calculate average time between attempts
        times = sorted(timestamps_by_ip[ip])
        if len(times) > 1:
            deltas = [(t2 - t1).total_seconds() for t1, t2 in zip(times, times[1:])]
            avg_delta = sum(deltas) / len(deltas)
            report.write(f" | Avg time between attempts: {avg_delta:.2f} seconds\n")
        else:
            report.write("\n")

    report.write("\nSuspicious IPs That Later Logged In Successfully:\n")
    found = False
    for ip, count in suspicious_ips:
        if ip in successful_ips:
            report.write(f"{ip}: {count} failed attempts, then successful login\n")
            found = True

    if not found:
        report.write("No suspicious IPs were later successful.\n")

print(f"\nReport saved to: {report_file_path}")