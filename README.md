# SecOps CLI Toolkit
A lightweight, native Python and Bash CLI toolkit designed to assist with rapid SOC log triage, indicator extraction, and host posture checks without heavy virtualization overhead.

## Authentication Log Triage

### Failed Authentication Summary
`failed_auth_log_summary.py` summarizes failed authentication attempts in a log file, grouped by source IP address and target username. Source IPs that meet or exceed the configured threshold are flagged.

```bash
python failed_auth_log_summary.py path/to/file.log
python failed_auth_log_summary.py path/to/file.log --threshold 10 --format text
```

JSON output is available as an option but is not yet implemented.

### Accepted Authentication Summary
`accepted_auth_log_summary.py` summarizes successful authentication events in a log file, grouped by source IP address and authenticated username. Useful for verifying legitimate sessions, spotting unexpected source IPs, or correlating successful logins following brute-force activity.

```bash
python accepted_auth_log_summary.py path/to/file.log
python accepted_auth_log_summary.py path/to/file.log --format text
```

JSON output is available as an option but is not yet implemented.
