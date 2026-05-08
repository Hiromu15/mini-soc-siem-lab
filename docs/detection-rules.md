# Detection Rules

The first MVP uses transparent, deterministic rules. The goal is to make the
logic easy to read, test, and extend, not to claim production-grade coverage.

| Alert type | Severity | Logic | Recommendation |
| --- | --- | --- | --- |
| `brute_force_suspicion` | High | 10 or more failed logins from the same IP in 5 minutes | Rate limit login attempts, enable MFA, review logs |
| `sqli_suspicion` | High | Request path or query contains SQLi-like patterns such as `UNION SELECT`, boolean tautologies, comment tokens, or `sqlmap` | Validate input, use parameterized queries, check WAF rules |
| `xss_suspicion` | Medium | Request path or query contains strings such as `<script>`, `onerror=`, or `javascript:` | Validate input, encode output, review CSP |
| `path_traversal_suspicion` | High | Request path contains `../`, encoded traversal, `/etc/passwd`, or similar sensitive path indicators | Normalize paths, restrict file access, check WAF rules |
| `directory_scan_suspicion` | Low | 20 or more 404 responses from the same IP in 5 minutes | Review access logs, restrict admin paths, block if necessary |
| `suspicious_user_agent` | Medium | User-Agent contains strings such as `sqlmap`, `nikto`, `nmap`, `masscan`, `gobuster`, or `ffuf` | Review logs, check WAF rules, block if necessary |

## Rule Storage

Rules are seeded into the `detection_rules` table at API startup. Each rule has
an `enabled` flag so future versions can add rule management without changing
the detection engine interface.

## Scheduled Detection

`detector-api` can run detection automatically in the background. Docker Compose
enables this by default:

```env
DETECTION_SCHEDULER_ENABLED=true
DETECTION_INTERVAL_SECONDS=30
```

Manual execution is still available through:

```bash
curl -X POST http://localhost:8001/detect/run
```

The scheduler checks events already ingested into the database. It does not scan
external systems, and it does not automatically attack or probe any target.

## Limitations

- Rules are signature and threshold based.
- The MVP does not correlate across many data sources.
- Alerts are deduplicated by alert type, IP, path, and open status.
- The lab intentionally avoids exploit execution and external scanning.
