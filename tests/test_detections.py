import re

import pytest

import detections as rules
from log_generator import NORMAL_PATHS, SQLI_PAYLOADS

SQLI = re.compile(rules.SQLI_PATTERN)


@pytest.mark.parametrize("path", SQLI_PAYLOADS)
def test_sqli_payloads_are_detected(path):
    assert SQLI.search(path)


@pytest.mark.parametrize("path", NORMAL_PATHS + ["/api/orders?id=42", "/search?q=union+station"])
def test_normal_paths_are_not_flagged(path):
    assert not SQLI.search(path)


def test_brute_force_severity_escalates():
    assert rules.brute_force_severity(10, threshold=10) == "high"
    assert rules.brute_force_severity(30, threshold=10) == "critical"


def test_port_scan_severity_escalates():
    assert rules.port_scan_severity(20, threshold=20) == "medium"
    assert rules.port_scan_severity(40, threshold=20) == "high"


def test_sqli_success_is_high_severity():
    assert rules.sqli_severity(200) == "high"
    assert rules.sqli_severity(403) == "medium"
