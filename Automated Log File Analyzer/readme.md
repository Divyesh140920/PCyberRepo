# Automated Log File Analyzer for Security Events

## Description
A Python script that parses system or application log files to detect suspicious patterns indicative of potential security incidents. 

The tool uses customizable regular expression rules to identify alerts such as failed login attempts, authentication failures, access denials, and possible attack indicators (e.g., SQL injection or XSS attempts). It summarizes the findings and shows sample log lines for quick review.

## Features
- Parses plain text log files line-by-line.
- Matches lines against user-defined regex alert rules.
- Generates summary counts for each alert type.
- Displays sample log entries to aid investigation.
- Easily customizable alert rules for different environments.

## Requirements
- Python 3.x

## Usage
1. Customize the `ALERT_RULES` dictionary in `log_analyzer.py` to add or modify alert patterns.
2. Set the path to the log file in the `log_file` variable.
3. Run the script:
4. Review the summary of suspicious patterns and sample log lines output to the console.