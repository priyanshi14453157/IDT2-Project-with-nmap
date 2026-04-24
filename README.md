Features

Network Scanning (Nmap Integration)
Detects open ports and running services
Supports version detection and vulnerability scripts
SSL/TLS Analysis
Checks certificate validity and expiry
Identifies weak configurations
Security Headers Check
Detects missing headers like CSP, HSTS, X-Frame-Options
Cookie Security Analysis
Checks Secure, HttpOnly, and SameSite flags
DNS & WHOIS Lookup
Retrieves domain and DNS information
Sensitive File Detection
Checks for exposed files like .env, .git, config.php
Parallel Execution
Uses multithreading to speed up scanning
Risk Scoring System
Generates overall risk score and level (LOW / MEDIUM / HIGH)

Technologies Used
Python
Nmap (via python-nmap)
Requests
SSL & Socket
DNS Resolver
WHOIS
Concurrent Futures (Multithreading)

How It Works
Takes a domain as input
Performs multiple security checks in parallel
Aggregates results into a structured report
Calculates a risk score based on findings
Usage
python scanner.py example.com
Example Nmap Configuration
nm.scan(ip_address, arguments='-sV -sC --script vuln --script-args=mincvss=7.0 -T4 --host-timeout 120s')
-sV → Service/version detection
-sC → Default scripts
--script vuln → Vulnerability detection
-T4 → Faster execution
--host-timeout → Limits scan time per host

Disclaimer

This tool is intended for educational purposes and authorized testing only.
Do not scan systems without proper permission.

📈 Future Improvements
Web-based dashboard for visualization
More advanced vulnerability detection
