"""Spark Structured Streaming job: Kafka -> Delta Lake medallion layers + detections.

bronze/raw_events          every message exactly as received (replayable audit trail)
silver/events              parsed, typed, validated and de-duplicated events
silver/quarantine          records that failed data-quality checks, with the reason
gold/alerts_bruteforce     failed-login bursts per source IP
gold/alerts_portscan       many distinct ports probed by one source IP
gold/alerts_sqli           web requests matching SQL injection signatures
"""
import os

import detections as rules
from pyspark.sql import Column, DataFrame, SparkSession
from pyspark.sql import functions as F
from pyspark.sql import types as T

KAFKA = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
TOPIC = os.getenv("KAFKA_TOPIC", "security-logs")
LAKE = os.getenv("LAKE_PATH", "/data/lake")
CHECKPOINTS = os.getenv("CHECKPOINT_PATH", "/data/checkpoints")
TRIGGER = os.getenv("TRIGGER_INTERVAL", "10 seconds")

EVENT_SCHEMA = T.StructType([
    T.StructField("event_id", T.StringType()),
    T.StructField("ts", T.StringType()),
    T.StructField("source", T.StringType()),
    T.StructField("host", T.StringType()),
    T.StructField("src_ip", T.StringType()),
    T.StructField("dst_ip", T.StringType()),
    T.StructField("dst_port", T.IntegerType()),
    T.StructField("user", T.StringType()),
    T.StructField("outcome", T.StringType()),
    T.StructField("http_method", T.StringType()),
    T.StructField("http_path", T.StringType()),
    T.StructField("http_status", T.IntegerType()),
    T.StructField("user_agent", T.StringType()),
    T.StructField("bytes", T.LongType()),
])


def build_spark() -> SparkSession:
    return (
        SparkSession.builder.appName("secure-log-streaming-pipeline")
        .config("spark.sql.extensions", "io.delta.sql.DeltaSparkSessionExtension")
        .config("spark.sql.catalog.spark_catalog", "org.apache.spark.sql.delta.catalog.DeltaCatalog")
        .config("spark.sql.shuffle.partitions", "4")
        .getOrCreate()
    )


def sink(df: DataFrame, layer: str, name: str, partition_by: list[str] | None = None):
    writer = (
        df.writeStream.format("delta").outputMode("append")
        .option("checkpointLocation", f"{CHECKPOINTS}/{layer}_{name}")
        .trigger(processingTime=TRIGGER)
        .queryName(f"{layer}_{name}")
    )
    if partition_by:
        writer = writer.partitionBy(*partition_by)
    return writer.start(f"{LAKE}/{layer}/{name}")


def quality_checks(df: DataFrame) -> tuple[Column, Column]:
    """Returns (is_valid, rejection_reason) columns. Nulls are treated as failures."""
    reason = (
        F.when(F.col("event_id").isNull(), "missing_event_id")
        .when(F.col("event_ts").isNull(), "unparseable_timestamp")
        .when(F.col("src_ip").isNull(), "missing_src_ip")
        .when(~F.coalesce(F.col("source").isin(rules.VALID_SOURCES), F.lit(False)), "unknown_source")
    )
    return reason.isNull(), reason


def main() -> None:
    spark = build_spark()
    spark.sparkContext.setLogLevel("WARN")

    raw = (
        spark.readStream.format("kafka")
        .option("kafka.bootstrap.servers", KAFKA)
        .option("subscribe", TOPIC)
        .option("startingOffsets", "earliest")
        .option("failOnDataLoss", "false")
        .load()
    )

    # ---------- BRONZE: land everything untouched ----------
    bronze = raw.select(
        F.col("key").cast("string").alias("kafka_key"),
        F.col("value").cast("string").alias("raw_json"),
        "topic", "partition", "offset",
        F.col("timestamp").alias("kafka_ts"),
        F.current_timestamp().alias("ingested_at"),
    )
    sink(bronze, "bronze", "raw_events")

    # ---------- SILVER: parse, validate, quarantine, de-duplicate ----------
    parsed = (
        bronze.withColumn("e", F.from_json("raw_json", EVENT_SCHEMA))
        .select("raw_json", "kafka_ts", "ingested_at", "e.*")
        .withColumn("event_ts", F.to_timestamp("ts"))
    )
    is_valid, reason = quality_checks(parsed)

    quarantine = parsed.filter(~is_valid).select(
        "raw_json", "kafka_ts", "ingested_at", reason.alias("rejection_reason")
    )
    sink(quarantine, "silver", "quarantine")

    valid = parsed.filter(is_valid).drop("raw_json", "ts")
    silver = (
        valid.withWatermark("event_ts", "10 minutes")
        .dropDuplicatesWithinWatermark(["event_id"])
        .withColumn("event_date", F.to_date("event_ts"))
    )
    sink(silver, "silver", "events", partition_by=["event_date", "source"])

    # ---------- GOLD: real-time detections ----------
    events = valid.withWatermark("event_ts", "2 minutes")

    brute = (
        events.filter((F.col("source") == "auth") & (F.col("outcome") == "failure"))
        .groupBy(F.window("event_ts", "1 minute"), "src_ip")
        .agg(
            F.count("*").alias("failed_attempts"),
            F.approx_count_distinct("user").alias("distinct_users"),
            F.collect_set("user").alias("targeted_users"),
        )
        .filter(F.col("failed_attempts") >= rules.BRUTE_FORCE_THRESHOLD)
        .select(
            F.col("window.start").alias("window_start"), F.col("window.end").alias("window_end"),
            "src_ip", "failed_attempts", "distinct_users", "targeted_users",
            F.lit("brute_force").alias("alert_type"),
            F.when(F.col("failed_attempts") >= 3 * rules.BRUTE_FORCE_THRESHOLD, "critical")
            .otherwise("high").alias("severity"),
        )
    )
    sink(brute, "gold", "alerts_bruteforce")

    scan = (
        events.filter(F.col("source") == "firewall")
        .groupBy(F.window("event_ts", "1 minute"), "src_ip")
        .agg(
            F.approx_count_distinct("dst_port").alias("distinct_ports"),
            F.collect_set("dst_ip").alias("target_hosts"),
            F.count("*").alias("connection_attempts"),
        )
        .filter(F.col("distinct_ports") >= rules.PORT_SCAN_THRESHOLD)
        .select(
            F.col("window.start").alias("window_start"), F.col("window.end").alias("window_end"),
            "src_ip", "distinct_ports", "connection_attempts", "target_hosts",
            F.lit("port_scan").alias("alert_type"),
            F.when(F.col("distinct_ports") >= 2 * rules.PORT_SCAN_THRESHOLD, "high")
            .otherwise("medium").alias("severity"),
        )
    )
    sink(scan, "gold", "alerts_portscan")

    sqli = (
        events.filter((F.col("source") == "web") & F.col("http_path").rlike(rules.SQLI_PATTERN))
        .select(
            "event_ts", "src_ip", "host", "http_method", "http_path", "http_status", "user_agent",
            F.lit("sql_injection").alias("alert_type"),
            F.when(F.col("http_status") == 200, "high").otherwise("medium").alias("severity"),
        )
    )
    sink(sqli, "gold", "alerts_sqli")

    spark.streams.awaitAnyTermination()


if __name__ == "__main__":
    main()
