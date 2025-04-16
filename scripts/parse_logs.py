import re
from collections import defaultdict
from datetime import datetime

log_file_path = 'data/example_logs/openssh.log'
report_file_path = 'reports/failed_login_report.txt'

# Settings
suspicious_threshold = 5
current_year = datetime.now().year

# Trackers
failures_by_ip = defaultdict(int)
timestamps_by_ip = defaultdict(list)
successful_ips = set()
usernames_targeted = defaultdict(int)

# Regex patterns
failed_pattern = re.compile(r'(\w{3} \d{1,2} \d{2}:\d{2}:\d{2}).*Failed password for (invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+)')
success_pattern = re.compile(r'Accepted password for .* from (\d+\.\d+\.\d+\.\d+)')

# Parse log file
with open(log_file_path, 'r') as file:
    for line in file:
        fail_match = failed_pattern.search(line)
        if fail_match:
            time_str, _, username, ip = fail_match.groups()
            log_time = datetime.strptime(f"{current_year} {time_str}", "%Y %b %d %H:%M:%S")
            failures_by_ip[ip] += 1
            timestamps_by_ip[ip].append(log_time)
            usernames_targeted[username] += 1

        success_match = success_pattern.search(line)
        if success_match:
            ip = success_match.group(1)
            successful_ips.add(ip)

# Sort suspicious IPs by count descending
suspicious_ips = sorted(
    [(ip, failures_by_ip[ip]) for ip in failures_by_ip if failures_by_ip[ip] >= suspicious_threshold],
    key=lambda x: x[1],
    reverse=True
)

# Write report
with open(report_file_path, 'w') as report:
    # Executive summary
    report.write(f"Suspicious Login Activity Report\nGenerated: {datetime.now()}\n\n")
    report.write(f"Total suspicious IPs (>= {suspicious_threshold} failures): {len(suspicious_ips)}\n")
    report.write(f"Suspicious IPs that later succeeded: {len([ip for ip, _ in suspicious_ips if ip in successful_ips])}\n")
    
    if usernames_targeted:
        top_user = max(usernames_targeted.items(), key=lambda x: x[1])
        report.write(f"Most targeted username: {top_user[0]} ({top_user[1]} attempts)\n")

    report.write("\n---\n\n")

    # Suspicious IP breakdown
    report.write("Suspicious IPs Details:\n")
    for ip, count in suspicious_ips:
        times = sorted(timestamps_by_ip[ip])
        first_seen = times[0].strftime("%Y-%m-%d %H:%M:%S")
        last_seen = times[-1].strftime("%Y-%m-%d %H:%M:%S")
        if len(times) > 1:
            deltas = [(t2 - t1).total_seconds() for t1, t2 in zip(times, times[1:])]
            avg_delta = sum(deltas) / len(deltas)
            report.write(f"{ip}: {count} failures | Avg time: {avg_delta:.2f}s | Time Range: {first_seen} to {last_seen}\n")
        else:
            report.write(f"{ip}: {count} failures | Time: {first_seen}\n")

    # Successful intrusion matches
    report.write("\nSuspicious IPs That Later Logged In Successfully:\n")
    found = False
    for ip, count in suspicious_ips:
        if ip in successful_ips:
            report.write(f"{ip}: {count} failed attempts, then successful login\n")
            found = True
    if not found:
        report.write("No suspicious IPs were later successful.\n")

    # Targeted usernames
    report.write("\nMost Targeted Usernames:\n")
    for uname, count in sorted(usernames_targeted.items(), key=lambda x: x[1], reverse=True):
        report.write(f"{uname}: {count}\n")

print(f"\nReport saved to: {report_file_path}")