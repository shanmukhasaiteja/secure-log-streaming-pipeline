"""Hourly batch layer on top of the streaming pipeline.

check_freshness -> dbt_run -> dbt_test -> report_critical_alerts
"""
import logging
import os
from datetime import datetime, timedelta, timezone

from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.operators.python import PythonOperator

LAKE = os.getenv("LAKE_PATH", "/data/lake")
WAREHOUSE = os.getenv("DUCKDB_PATH", "/data/warehouse/security.duckdb")
DBT_DIR = "/opt/airflow/dbt"
MAX_LAG_MINUTES = 15

log = logging.getLogger(__name__)


def check_freshness() -> None:
    """Fail fast if the streaming job has stopped writing to the silver layer."""
    import duckdb

    con = duckdb.connect()
    con.execute("INSTALL delta; LOAD delta;")
    lag = con.execute(
        f"select date_diff('minute', max(event_ts), now()) from delta_scan('{LAKE}/silver/events')"
    ).fetchone()[0]
    log.info("Silver layer lag: %s minutes", lag)
    if lag is None or lag > MAX_LAG_MINUTES:
        raise ValueError(f"Silver layer is stale (lag={lag} min). Is the Spark job running?")


def report_critical_alerts() -> None:
    import duckdb

    con = duckdb.connect(WAREHOUSE, read_only=True)
    rows = con.execute(
        """
        select alert_type, src_ip, evidence, detected_at
        from fct_security_alerts
        where severity = 'critical' and detected_at >= now() - interval 1 hour
        order by detected_at desc
        """
    ).fetchall()
    log.info("%d critical alerts in the last hour", len(rows))
    for row in rows:
        log.warning("CRITICAL %s from %s | %s | %s", *row)


with DAG(
    dag_id="security_lakehouse_hourly",
    start_date=datetime(2026, 1, 1, tzinfo=timezone.utc),
    schedule="@hourly",
    catchup=False,
    default_args={"retries": 2, "retry_delay": timedelta(minutes=2)},
    tags=["security", "dbt", "data-quality"],
) as dag:
    freshness = PythonOperator(task_id="check_freshness", python_callable=check_freshness)
    dbt_run = BashOperator(task_id="dbt_run", bash_command=f"cd {DBT_DIR} && dbt run --profiles-dir .")
    dbt_test = BashOperator(task_id="dbt_test", bash_command=f"cd {DBT_DIR} && dbt test --profiles-dir .")
    report = PythonOperator(task_id="report_critical_alerts", python_callable=report_critical_alerts)

    freshness >> dbt_run >> dbt_test >> report
