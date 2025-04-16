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
- Added Time range of Activity
- Included most targeted users
- Generates readable reports in `/reports/`
- Visualizes login failure counts via bar chart
- Visualizes time range of activities


## Results found in reports folder




