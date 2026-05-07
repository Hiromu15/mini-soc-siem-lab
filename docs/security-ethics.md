# Security and Ethics

This project is for defense, learning, and local validation only.

Do not use this repository to attack, scan, test, or probe third-party systems.
The included demo scripts are constrained to local targets such as
`http://localhost:8080` and are intended only to generate logs for detection
testing inside the Docker Compose lab.

## Allowed Use

- Learning how SOC/SIEM-style detection pipelines work.
- Testing log parsing and alerting against dummy data.
- Demonstrating defensive engineering in a portfolio.
- Extending local detection rules with safe sample logs.

## Prohibited Use

- Sending test traffic to systems you do not own or lack permission to test.
- Automating attacks against real environments.
- Using this lab to bypass authentication, exploit vulnerabilities, or assist
  unauthorized access.
- Publishing real customer, company, or personal logs as sample data.

## Sample Data Policy

All sample IPs are documentation ranges such as `192.0.2.0/24`,
`198.51.100.0/24`, and `203.0.113.0/24`. Keep new examples fully synthetic.

