import random
from datetime import datetime

import pytest

from log_generator import (
    EVENT_FIELDS,
    LogGenerator,
    brute_force,
    malformed,
    port_scan,
    sql_injection,
)


@pytest.fixture
def rng():
    return random.Random(42)


def test_every_event_has_the_full_schema():
    gen = LogGenerator(seed=1, attack_rate=0.2, malformed_rate=0.0)
    for _ in range(500):
        for event in gen.next_batch():
            assert set(event) == set(EVENT_FIELDS)
            assert event["source"] in {"auth", "firewall", "web"}
            datetime.fromisoformat(event["ts"])


def test_brute_force_comes_from_one_ip_and_is_mostly_failures(rng):
    events = brute_force(rng, attempts=25)
    assert len({e["src_ip"] for e in events}) == 1
    assert sum(e["outcome"] == "failure" for e in events) == 25


def test_port_scan_hits_distinct_ports_on_one_host(rng):
    events = port_scan(rng, ports=40)
    assert len({e["dst_port"] for e in events}) == 40
    assert len({e["dst_ip"] for e in events}) == 1


def test_sql_injection_uses_attack_tooling(rng):
    assert all(e["user_agent"] == "sqlmap/1.7" for e in sql_injection(rng))


def test_malformed_records_break_exactly_one_rule(rng):
    for _ in range(50):
        e = malformed(rng)
        defects = [e["src_ip"] is None, e["ts"] == "not-a-timestamp", e["source"] == "printer"]
        assert sum(defects) == 1


def test_attack_rate_controls_injection():
    quiet = LogGenerator(seed=3, attack_rate=0.0, malformed_rate=0.0)
    assert all(len(quiet.next_batch()) == 1 for _ in range(1000))
