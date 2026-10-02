-- One row per alert across all detection types.
with unioned as (
    select * from {{ ref('stg_alerts_bruteforce') }}
    union all
    select * from {{ ref('stg_alerts_portscan') }}
    union all
    select * from {{ ref('stg_alerts_sqli') }}
)

select
    md5(alert_type || src_ip || cast(detected_at as varchar) || evidence) as alert_id,
    *,
    case severity when 'critical' then 4 when 'high' then 3 when 'medium' then 2 else 1 end as severity_rank
from unioned
