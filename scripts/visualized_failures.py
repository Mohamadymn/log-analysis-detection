import matplotlib.pyplot as plt
import re
from collections import defaultdict

log_file_path = 'data/example_logs/openssh.log'
suspicious_threshold = 5

# Track failed attempts
failures_by_ip = defaultdict(int)
pattern = re.compile(r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)')

# Parse the log
with open(log_file_path, 'r') as file:
    for line in file:
        match = pattern.search(line)
        if match:
            ip = match.group(1)
            failures_by_ip[ip] += 1

# Filter only suspicious IPs
suspicious = {ip: count for ip, count in failures_by_ip.items() if count >= suspicious_threshold}

# Plot
if suspicious:
    plt.figure(figsize=(10, 6))
    plt.bar(suspicious.keys(), suspicious.values())
    plt.xticks(rotation=45, ha='right')
    plt.title('Suspicious IPs with 5+ Failed Login Attempts')
    plt.xlabel('IP Address')
    plt.ylabel('Number of Failed Attempts')
    plt.tight_layout()
    plt.show()
else:
    print("No suspicious IPs to visualize.")