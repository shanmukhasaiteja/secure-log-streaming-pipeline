select
    cast(detected_at as date)       as alert_date,
    alert_type,
    severity,
    count(*)                        as alert_count,
    count(distinct src_ip)          as distinct_attackers
from {{ ref('fct_security_alerts') }}
group by 1, 2, 3
