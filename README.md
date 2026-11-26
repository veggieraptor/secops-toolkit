# SecOps CLI Toolkit
A lightweight, native Python and Bash CLI toolkit designed to assist with rapid SOC log triage, indicator extraction, and host posture checks without heavy virtualization overhead.

All tools print their results to stdout, one record per line, following the Unix philosophy: they can be redirected (`>`, `>>`) or piped to other tools (eg. `grep`).
## Failed Authentication Summary
`failed_auth_log_summary.py` summarizes failed authentication attempts in a log file, grouped by source IP address and target username. Source IPs that meet or exceed the configured threshold are flagged.

```bash
python failed_auth_log_summary.py path/to/file.log
python failed_auth_log_summary.py path/to/file.log --threshold 10 --format text
```

JSON output is available as an option but is not yet implemented.

## Accepted Authentication Summary
`accepted_auth_log_summary.py` summarizes successful authentication events in a log file, grouped by source IP address and authenticated username. Useful for verifying legitimate sessions, spotting unexpected source IPs, or correlating successful logins following brute-force activity.

```bash
python accepted_auth_log_summary.py path/to/file.log
python accepted_auth_log_summary.py path/to/file.log --format text
```

JSON output is available as an option but is not yet implemented.

## IOC Extractor
`ioc_extractor.py` extracts IPv4 addresses, domains, URLs, and hashes (MD5/SHA-256) from a text or log file, removing duplicates. Optional `--defang ` mode defangs the indicators (eg. `hxxp://`, `1.2.3[.]4`) so they are safe to share to reports.
    
```bash
python ioc_extractor.py path/to/file
python ioc_extractor.py path/to/file.log --defang
```

Defanged indicators are also printed to stdout; the defanging happens before printing, so saved files are already safe to share.
