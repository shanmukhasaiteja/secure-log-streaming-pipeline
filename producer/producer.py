"""Streams synthetic security logs into Kafka."""
import json
import logging
import os
import time

from confluent_kafka import KafkaException, Producer
from confluent_kafka.admin import AdminClient

from log_generator import LogGenerator

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("producer")

BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
TOPIC = os.getenv("KAFKA_TOPIC", "security-logs")
EVENTS_PER_SEC = float(os.getenv("EVENTS_PER_SEC", "50"))
ATTACK_RATE = float(os.getenv("ATTACK_RATE", "0.02"))


def wait_for_kafka(retries: int = 30) -> None:
    admin = AdminClient({"bootstrap.servers": BOOTSTRAP})
    for attempt in range(1, retries + 1):
        try:
            admin.list_topics(timeout=5)
            return
        except KafkaException:
            log.info("Kafka not ready (attempt %d/%d)", attempt, retries)
            time.sleep(2)
    raise RuntimeError("Kafka never became available")


def on_delivery(err, msg):
    if err:
        log.error("Delivery failed: %s", err)


def main() -> None:
    wait_for_kafka()
    producer = Producer({"bootstrap.servers": BOOTSTRAP, "linger.ms": 50, "acks": "all", "enable.idempotence": True})
    generator = LogGenerator(attack_rate=ATTACK_RATE)
    sent, started = 0, time.time()
    log.info("Producing to %s at ~%.0f events/sec", TOPIC, EVENTS_PER_SEC)
    while True:
        for event in generator.next_batch():
            producer.produce(TOPIC, key=event.get("src_ip") or "unknown", value=json.dumps(event), callback=on_delivery)
            sent += 1
        producer.poll(0)
        if sent % 1000 == 0:
            log.info("Sent %d events (%.1f/sec)", sent, sent / (time.time() - started))
        time.sleep(1 / EVENTS_PER_SEC)


if __name__ == "__main__":
    main()
