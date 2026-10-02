select
    window_start                                    as detected_at,
    src_ip,
    alert_type,
    severity,
    connection_attempts                             as event_count,
    'distinct ports probed: ' || distinct_ports     as evidence
from delta_scan('{{ var("lake_path") }}/gold/alerts_portscan')
