"""Detection rules shared by the Spark job and the unit tests."""
import os

BRUTE_FORCE_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", "10"))  # failed logins / IP / minute
PORT_SCAN_THRESHOLD = int(os.getenv("PORT_SCAN_THRESHOLD", "20"))  # distinct ports / IP / minute

# Case-insensitive patterns for classic SQL injection probes (valid in Java and Python regex).
SQLI_PATTERN = r"(?i)('\s*or\s*'?1'?\s*=\s*'?1|union\s+select|--|;\s*drop\s+table)"

VALID_SOURCES = ["auth", "firewall", "web"]


def brute_force_severity(failed_attempts: int, threshold: int = BRUTE_FORCE_THRESHOLD) -> str:
    return "critical" if failed_attempts >= 3 * threshold else "high"


def port_scan_severity(distinct_ports: int, threshold: int = PORT_SCAN_THRESHOLD) -> str:
    return "high" if distinct_ports >= 2 * threshold else "medium"


def sqli_severity(http_status: int | None) -> str:
    # A 200 response to an injection probe may mean the payload worked.
    return "high" if http_status == 200 else "medium"
