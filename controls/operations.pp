benchmark "operations" {
  title       = "5. Operations"
  description = "Operational posture: unmaintained data, oversized blast radii, and namespace sprawl."
  children = [
    control.ops_stale_namespaces,
    control.ops_index_lag,
    control.ops_oversized_namespaces,
    control.ops_namespace_sprawl,
  ]
  tags = merge(local.common_tags, { category = "operations" })
}

control "ops_stale_namespaces" {
  title       = "Namespaces receive writes within the staleness window"
  description = "A namespace with no writes for months is usually a namespace with no owner. Unowned data is unreviewed risk: nobody rotates its keys, nobody answers for its contents in an audit, nobody notices its exfiltration. Uses updated_at from the metadata API."
  severity    = "medium"
  tags        = merge(local.common_tags, { category = "operations" })

  param "stale_days" {
    description = "Days without a write after which a namespace is flagged as stale."
    default = var.stale_days
  }

  sql = <<-EOQ
    select
      id as resource,
      case
        when updated_at >= now() - ($1::int || ' days')::interval then 'ok'
        else 'alarm'
      end as status,
      case
        when updated_at >= now() - ($1::int || ' days')::interval
          then id || ' last written ' || to_char(updated_at, 'YYYY-MM-DD') || '.'
        else id || ' has had no writes since ' || to_char(updated_at, 'YYYY-MM-DD') || ' — confirm ownership or decommission.'
      end as reason,
      region
    from turbopuffer_namespace;
  EOQ
}

control "ops_index_lag" {
  title       = "Namespace indexes are up to date"
  description = "turbopuffer indexes writes asynchronously; bytes sitting in the write-ahead log but not yet indexed are not fully searchable. For a security posture this is an integrity gap — a canary seeded moments ago, or a tenant's freshly written data, can be silently missed by retrieval until the index catches up. Uses index_unindexed_bytes from the metadata API."
  severity    = "medium"
  tags        = merge(local.common_tags, { category = "operations" })

  param "max_unindexed_bytes" {
    description = "Unindexed WAL bytes a namespace may have before it is flagged."
    default = var.max_unindexed_bytes
  }

  sql = <<-EOQ
    select
      id as resource,
      case
        when coalesce(index_unindexed_bytes, 0) <= $1 then 'ok'
        else 'alarm'
      end as status,
      case
        when coalesce(index_unindexed_bytes, 0) <= $1
          then id || ' index is up to date (' || coalesce(index_status, 'unknown') || ').'
        else id || ' has ' || index_unindexed_bytes || ' unindexed bytes (status: ' || coalesce(index_status, 'unknown') || ') — recent writes are not yet searchable.'
      end as reason,
      region
    from turbopuffer_namespace;
  EOQ
}

control "ops_oversized_namespaces" {
  title       = "No single namespace exceeds the blast-radius threshold"
  description = "One giant namespace means one leaked key or one missing filter exposes everything at once. Above the threshold, consider namespace-per-tenant or per-corpus partitioning — turbopuffer namespaces are cheap and copy-on-write branching makes splits practical."
  severity    = "medium"
  tags        = merge(local.common_tags, { category = "operations" })

  param "max_namespace_gb" {
    description = "Logical-size threshold (GB) above which a namespace is flagged for blast-radius review."
    default = var.max_namespace_gb
  }

    # Threshold is expressed in GB (the config unit); the comparison is exact
    # bigint math and is safe to PB scale. The displayed size auto-scales up
    # through PB so the reason stays readable for petabyte namespaces.
  sql = <<-EOQ
    select
      id as resource,
      case
        when approx_logical_bytes <= $1::bigint * 1073741824 then 'ok'
        else 'alarm'
      end as status,
      case
        when approx_logical_bytes <= $1::bigint * 1073741824
          then id || ' is ' || (
            case
              when approx_logical_bytes >= 1125899906842624 then round(approx_logical_bytes / 1125899906842624.0, 2) || ' PB'
              when approx_logical_bytes >= 1099511627776    then round(approx_logical_bytes / 1099511627776.0, 2) || ' TB'
              else round(approx_logical_bytes / 1073741824.0, 1) || ' GB'
            end
          ) || '.'
        else id || ' is ' || (
            case
              when approx_logical_bytes >= 1125899906842624 then round(approx_logical_bytes / 1125899906842624.0, 2) || ' PB'
              when approx_logical_bytes >= 1099511627776    then round(approx_logical_bytes / 1099511627776.0, 2) || ' TB'
              else round(approx_logical_bytes / 1073741824.0, 1) || ' GB'
            end
          ) || ' (threshold ' || $1 || ' GB) — review blast radius.'
      end as reason,
      region
    from turbopuffer_namespace;
  EOQ
}

control "ops_namespace_sprawl" {
  title       = "Namespace count is within budget"
  description = "A soft inventory-review trigger: past the budget, namespaces tend to outrun the naming conventions and ownership records the rest of this benchmark depends on."
  severity    = "low"
  tags        = merge(local.common_tags, { category = "operations" })

  param "namespace_count_budget" {
    description = "Soft budget for total namespace count before sprawl is flagged."
    default = var.namespace_count_budget
  }

  sql = <<-EOQ
    select
      'organization' as resource,
      case when count(*) <= $1::int then 'ok' else 'info' end as status,
      count(*)::text || ' namespaces across ' || count(distinct region)::text ||
        ' region(s); budget is ' || $1 || '.' as reason
    from turbopuffer_namespace;
  EOQ
}
