"""Live security dashboard reading the Delta Lake tables directly via DuckDB."""
import os

import duckdb
import pandas as pd
import streamlit as st

LAKE = os.getenv("LAKE_PATH", "/data/lake")

st.set_page_config(page_title="Security Lakehouse", page_icon="🛡️", layout="wide")


@st.cache_resource
def connection():
    con = duckdb.connect()
    con.execute("INSTALL delta; LOAD delta;")
    return con


def query(sql: str) -> pd.DataFrame:
    try:
        return connection().execute(sql).df()
    except duckdb.Error:  # table not created yet: the stream is still warming up
        return pd.DataFrame()


def table(layer: str, name: str) -> str:
    return f"delta_scan('{LAKE}/{layer}/{name}')"


st.title("🛡️ Security Lakehouse: live detections")
st.caption("Kafka → Spark Structured Streaming → Delta Lake (bronze / silver / gold)")

volume = query(f"select count(*) as events, count(distinct src_ip) as ips from {table('silver', 'events')}")
quarantined = query(f"select count(*) as n from {table('silver', 'quarantine')}")
alerts = query(
    f"""
    select window_start as detected_at, src_ip, alert_type, severity from {table('gold', 'alerts_bruteforce')}
    union all
    select window_start, src_ip, alert_type, severity from {table('gold', 'alerts_portscan')}
    union all
    select event_ts, src_ip, alert_type, severity from {table('gold', 'alerts_sqli')}
    """
)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events processed", int(volume["events"][0]) if not volume.empty else 0)
c2.metric("Unique source IPs", int(volume["ips"][0]) if not volume.empty else 0)
c3.metric("Alerts raised", len(alerts))
c4.metric("Records quarantined", int(quarantined["n"][0]) if not quarantined.empty else 0)

if alerts.empty:
    st.info("No alerts yet. Attacks are injected randomly; give the stream a minute.")
else:
    left, right = st.columns(2)
    left.subheader("Alerts by type")
    left.bar_chart(alerts["alert_type"].value_counts())
    right.subheader("Alerts by severity")
    right.bar_chart(alerts["severity"].value_counts())
    st.subheader("Latest alerts")
    st.dataframe(alerts.sort_values("detected_at", ascending=False).head(50), use_container_width=True)

st.subheader("Event volume by source (per minute)")
trend = query(
    f"""
    select date_trunc('minute', event_ts) as minute, source, count(*) as events
    from {table('silver', 'events')} group by 1, 2 order by 1
    """
)
if not trend.empty:
    st.line_chart(trend.pivot(index="minute", columns="source", values="events"))

if st.button("🔄 Refresh"):
    st.rerun()
