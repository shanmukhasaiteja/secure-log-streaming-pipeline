"""Synthetic security log generator with injectable attack scenarios.

Produces a unified event schema for three log sources (auth, firewall, web)
and occasionally injects realistic attack bursts and malformed records so the
downstream pipeline has something meaningful to detect and quarantine.
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone

USERS = ["alice", "bob", "carol", "dave", "erin", "svc_backup", "admin"]
HOSTS = ["web-01", "web-02", "auth-01", "db-01", "vpn-gw"]
COMMON_PORTS = [22, 53, 80, 443, 3306, 5432, 8080]
NORMAL_PATHS = ["/", "/login", "/api/orders", "/api/products", "/static/app.js", "/health"]
SQLI_PAYLOADS = [
    "/api/products?id=1' OR '1'='1",
    "/login?user=admin'--",
    "/api/orders?id=1 UNION SELECT username,password FROM users",
    "/search?q=1;DROP TABLE users",
]
NORMAL_AGENTS = ["Mozilla/5.0", "curl/8.4.0", "python-requests/2.31"]

EVENT_FIELDS = [
    "event_id", "ts", "source", "host", "src_ip", "dst_ip", "dst_port", "user",
    "outcome", "http_method", "http_path", "http_status", "user_agent", "bytes",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def external_ip(rng: random.Random) -> str:
    return f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def internal_ip(rng: random.Random) -> str:
    return f"10.0.{rng.randint(0, 10)}.{rng.randint(2, 254)}"


def base_event(source: str, rng: random.Random, **fields) -> dict:
    event = {name: None for name in EVENT_FIELDS}
    event.update(event_id=str(uuid.uuid4()), ts=_now(), source=source, host=rng.choice(HOSTS))
    event.update(fields)
    return event


# ---------- normal traffic ----------
def normal_auth(rng: random.Random) -> dict:
    return base_event(
        "auth", rng, src_ip=internal_ip(rng), dst_port=22, user=rng.choice(USERS),
        outcome="success" if rng.random() < 0.92 else "failure",
    )


def normal_firewall(rng: random.Random) -> dict:
    return base_event(
        "firewall", rng, src_ip=rng.choice([internal_ip(rng), external_ip(rng)]),
        dst_ip=internal_ip(rng), dst_port=rng.choice(COMMON_PORTS),
        outcome="allow" if rng.random() < 0.85 else "deny", bytes=rng.randint(64, 50_000),
    )


def normal_web(rng: random.Random) -> dict:
    return base_event(
        "web", rng, src_ip=external_ip(rng), dst_port=443, http_method=rng.choice(["GET", "GET", "POST"]),
        http_path=rng.choice(NORMAL_PATHS), http_status=rng.choice([200, 200, 200, 301, 404]),
        user_agent=rng.choice(NORMAL_AGENTS), bytes=rng.randint(200, 20_000),
    )


# ---------- attack scenarios ----------
def brute_force(rng: random.Random, attempts: int = 25) -> list[dict]:
    """Many failed SSH logins from one IP, optionally ending in a success."""
    attacker, target = external_ip(rng), rng.choice(USERS)
    events = [
        base_event("auth", rng, src_ip=attacker, dst_port=22, user=target, outcome="failure")
        for _ in range(attempts)
    ]
    if rng.random() < 0.3:  # the scary case: the attacker eventually gets in
        events.append(base_event("auth", rng, src_ip=attacker, dst_port=22, user=target, outcome="success"))
    return events


def port_scan(rng: random.Random, ports: int = 40) -> list[dict]:
    """One IP probing many distinct ports on a single internal host."""
    attacker, victim = external_ip(rng), internal_ip(rng)
    return [
        base_event("firewall", rng, src_ip=attacker, dst_ip=victim, dst_port=port, outcome="deny", bytes=60)
        for port in rng.sample(range(1, 1025), ports)
    ]


def sql_injection(rng: random.Random, requests: int = 5) -> list[dict]:
    attacker = external_ip(rng)
    return [
        base_event(
            "web", rng, src_ip=attacker, dst_port=443, http_method="GET", http_path=rng.choice(SQLI_PAYLOADS),
            http_status=rng.choice([200, 500, 403]), user_agent="sqlmap/1.7", bytes=rng.randint(100, 5_000),
        )
        for _ in range(requests)
    ]


def malformed(rng: random.Random) -> dict:
    """Broken records the pipeline must quarantine rather than silently drop."""
    event = normal_web(rng)
    defect = rng.choice(["missing_ip", "bad_ts", "unknown_source"])
    if defect == "missing_ip":
        event["src_ip"] = None
    elif defect == "bad_ts":
        event["ts"] = "not-a-timestamp"
    else:
        event["source"] = "printer"
    return event


SCENARIOS = {"brute_force": brute_force, "port_scan": port_scan, "sql_injection": sql_injection}


class LogGenerator:
    def __init__(self, seed: int | None = None, attack_rate: float = 0.02, malformed_rate: float = 0.01):
        self.rng = random.Random(seed)
        self.attack_rate = attack_rate
        self.malformed_rate = malformed_rate

    def next_batch(self) -> list[dict]:
        roll = self.rng.random()
        if roll < self.attack_rate:
            return SCENARIOS[self.rng.choice(list(SCENARIOS))](self.rng)
        if roll < self.attack_rate + self.malformed_rate:
            return [malformed(self.rng)]
        return [self.rng.choice([normal_auth, normal_firewall, normal_web, normal_web])(self.rng)]
