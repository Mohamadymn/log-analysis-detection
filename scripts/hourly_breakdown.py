
import re
from collections import defaultdict
from datetime import datetime
import matplotlib.pyplot as plt

log_file_path = 'data/example_logs/openssh.log'
current_year = datetime.now().year

# Track failed login hours
hourly_counts = defaultdict(int)
pattern = re.compile(r'(\w{3} \d{1,2} \d{2}):\d{2}:\d{2}.*Failed password for .* from (\d+\.\d+\.\d+\.\d+)')

with open(log_file_path, 'r') as file:
    for line in file:
        match = pattern.search(line)
        if match:
            time_str, _ = match.groups()
            log_time = datetime.strptime(f"{current_year} {time_str}", "%Y %b %d %H")
            hour = log_time.hour
            hourly_counts[hour] += 1

# Plot results
hours = list(range(24))
counts = [hourly_counts.get(h, 0) for h in hours]

plt.figure(figsize=(10, 6))
plt.bar(hours, counts)
plt.xticks(hours)
plt.xlabel('Hour of Day (0-23)')
plt.ylabel('Failed Login Attempts')
plt.title('Failed Login Attempts by Hour')
plt.grid(axis='y', linestyle='--', alpha=0.5)
plt.tight_layout()
plt.show()