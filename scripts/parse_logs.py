log_file_path = 'C:/Users/mhd_y/OneDrive/Desktop/cybersecurity/log-analysis-detection/data/example_logs/openssh.log'

with open(log_file_path, 'r') as file:
    lines = file.readlines()

for i, line in enumerate(lines[:10]):
    print(f"{i+1}: {line.strip()}")