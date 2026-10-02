-- Risk-ranked view of every source IP that triggered at least one alert.
select
    src_ip,
    count(*)                                   as total_alerts,
    count(distinct alert_type)                 as attack_techniques,
    list_distinct(list(alert_type))            as alert_types,
    min(detected_at)                           as first_seen,
    max(detected_at)                           as last_seen,
    sum(severity_rank) * count(distinct alert_type) as risk_score
from {{ ref('fct_security_alerts') }}
group by src_ip
order by risk_score desc
