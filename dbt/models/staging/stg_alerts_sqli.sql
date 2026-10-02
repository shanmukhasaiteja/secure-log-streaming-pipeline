select
    event_ts                                        as detected_at,
    src_ip,
    alert_type,
    severity,
    1                                               as event_count,
    http_method || ' ' || http_path
      || ' -> ' || http_status                      as evidence
from delta_scan('{{ var("lake_path") }}/gold/alerts_sqli')
