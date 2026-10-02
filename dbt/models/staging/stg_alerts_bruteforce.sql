select
    window_start                                    as detected_at,
    src_ip,
    alert_type,
    severity,
    failed_attempts                                 as event_count,
    'failed logins: ' || failed_attempts
      || ', users targeted: ' || distinct_users     as evidence
from delta_scan('{{ var("lake_path") }}/gold/alerts_bruteforce')
