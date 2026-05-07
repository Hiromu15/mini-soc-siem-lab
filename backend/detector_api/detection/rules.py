BRUTE_FORCE_WINDOW_MINUTES = 5
BRUTE_FORCE_THRESHOLD = 10
DIRECTORY_SCAN_WINDOW_MINUTES = 5
DIRECTORY_SCAN_THRESHOLD = 20

SQLI_PATTERNS = [
    r"(?i)(\bunion\s+select\b)",
    r"(?i)(\bor\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
    r"(?i)(\band\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
    r"(?i)(--|%2d%2d|#|%23)",
    r"(?i)(/\*|\*/|%2f%2a)",
    r"(?i)(\bsqlmap\b|\binformation_schema\b|\bsleep\s*\()",
]

XSS_PATTERNS = [
    r"(?i)(<\s*script|%3c\s*script)",
    r"(?i)(onerror\s*=|onload\s*=|onclick\s*=)",
    r"(?i)(javascript\s*:)",
    r"(?i)(<\s*img|%3c\s*img|<\s*svg|%3c\s*svg)",
]

PATH_TRAVERSAL_PATTERNS = [
    r"(?i)(\.\./|\.\.\\)",
    r"(?i)(\.\.%2f|%2e%2e%2f|%252e%252e%252f)",
    r"(?i)(/etc/passwd|/etc/shadow|boot\.ini|win\.ini)",
]

SUSPICIOUS_USER_AGENTS = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "gobuster",
    "ffuf",
    "dirbuster",
    "wpscan",
]

DEFAULT_RULES = [
    {
        "name": "Brute force login failure threshold",
        "alert_type": "brute_force_suspicion",
        "severity": "high",
        "description": "Detects many failed login events from the same IP in a short window.",
    },
    {
        "name": "SQL injection pattern in request path",
        "alert_type": "sqli_suspicion",
        "severity": "high",
        "description": "Detects common SQL Injection indicators in URL paths and query strings.",
    },
    {
        "name": "XSS pattern in request path",
        "alert_type": "xss_suspicion",
        "severity": "medium",
        "description": (
            "Detects common Cross-Site Scripting indicators in URL paths and query strings."
        ),
    },
    {
        "name": "Path traversal pattern in request path",
        "alert_type": "path_traversal_suspicion",
        "severity": "high",
        "description": (
            "Detects directory traversal indicators such as ../ and sensitive file paths."
        ),
    },
    {
        "name": "HTTP 404 directory discovery threshold",
        "alert_type": "directory_scan_suspicion",
        "severity": "low",
        "description": "Detects many 404 responses from the same IP in a short window.",
    },
    {
        "name": "Suspicious security tool user-agent",
        "alert_type": "suspicious_user_agent",
        "severity": "medium",
        "description": "Detects user-agent strings commonly used by scanners and testing tools.",
    },
]

RECOMMENDATIONS = {
    "brute_force_suspicion": (
        "Rate limit login attempts. Enable MFA. Review access logs and block suspicious IP "
        "if necessary."
    ),
    "sqli_suspicion": (
        "Validate and sanitize user input. Use parameterized queries. Check WAF rules."
    ),
    "xss_suspicion": (
        "Validate and sanitize user input. Encode output and review Content Security Policy."
    ),
    "path_traversal_suspicion": (
        "Restrict file path access. Normalize paths safely. Check WAF rules and review access logs."
    ),
    "directory_scan_suspicion": (
        "Review access logs. Restrict access to admin paths and block suspicious IP if necessary."
    ),
    "suspicious_user_agent": (
        "Review access logs. Check WAF rules and block suspicious IP if necessary."
    ),
}
