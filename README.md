# Log Analysis & Detection Project 

Simulation for real-world security log analysis.

## Tools Used

- Python
- Regular Expressions (`re`)
- `matplotlib` for visualization
- `datetime` for log timestamp analysis


## Features

- Parses raw OpenSSH log files
- Detects failed login attempts
- Flags suspicious IPs with 5 or more failures
- Tracks IPs that later logged in successfully
- Calculates average time between failed attempts (to identify brute-force behavior)
- Generates readable reports in `/reports/`
- Visualizes login failure counts via bar chart


## Results found in reports folder




