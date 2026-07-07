benchmark "schema_hygiene" {
  title       = "4. Schema & Data Hygiene"
  description = "What is stored next to the vectors matters as much as the vectors. These controls audit attribute schemas for sensitive-data smells, exposure-amplifying index config, cross-environment drift, and dead weight."
  children = [
    control.hygiene_sensitive_attribute_names,
    control.hygiene_sensitive_attributes_not_search_indexed,
    control.hygiene_schema_drift_across_environments,
    control.hygiene_empty_namespaces,
  ]
  tags = merge(local.common_tags, { category = "schema_hygiene" })
}

control "hygiene_sensitive_attribute_names" {
  title       = "No sensitive-data attribute names in schemas"
  description = "Attribute names like ssn, card_number or api_key are a strong signal that regulated or secret data is being stored alongside embeddings. Each hit deserves a data-classification review: should this live in a vector search index at all?"
  severity    = "high"
  tags        = merge(local.common_tags, { category = "schema_hygiene" })

  param "sensitive_attribute_pattern" {
    description = "Case-insensitive regex flagging sensitive attribute names."
    default = var.sensitive_attribute_pattern
  }

  sql = <<-EOQ
    select
      a.namespace || '/' || a.name as resource,
      case when a.name ~* $1 then 'alarm' else 'ok' end as status,
      case
        when a.name ~* $1 then a.namespace || ': attribute "' || a.name || '" (' || a.type || ') matches the sensitive-name pattern — review data classification.'
        else a.namespace || ': attribute "' || a.name || '" looks fine.'
      end as reason,
      a.region
    from turbopuffer_namespace_attribute a;
  EOQ
}

control "hygiene_sensitive_attributes_not_search_indexed" {
  title       = "Sensitive attributes are not search-amplified"
  description = "Full-text, regex, glob or fuzzy indexing on a sensitive attribute makes it dramatically easier to mine with a leaked key ('regex every card number in the corpus'). Sensitive fields should be exact-filter only — or better, not stored here."
  severity    = "high"
  tags        = merge(local.common_tags, { category = "schema_hygiene" })

  param "sensitive_attribute_pattern" {
    description = "Case-insensitive regex flagging sensitive attribute names."
    default = var.sensitive_attribute_pattern
  }

  sql = <<-EOQ
    select
      a.namespace || '/' || a.name as resource,
      case
        when a.full_text_search or a.regex or a.glob or a.fuzzy then 'alarm'
        else 'ok'
      end as status,
      case
        when a.full_text_search or a.regex or a.glob or a.fuzzy
          then a.namespace || ': sensitive attribute "' || a.name || '" has ' ||
               concat_ws(', ',
                 case when a.full_text_search then 'BM25 full-text' end,
                 case when a.regex then 'regex' end,
                 case when a.glob then 'glob' end,
                 case when a.fuzzy then 'fuzzy' end
               ) || ' indexing enabled — exposure-amplifying.'
        else a.namespace || ': sensitive attribute "' || a.name || '" is exact-filter only.'
      end as reason,
      a.region
    from turbopuffer_namespace_attribute a
    where a.name ~* $1;
  EOQ
}

control "hygiene_schema_drift_across_environments" {
  title       = "No schema drift between environments"
  description = "For namespaces named '<env>-<name>', the attribute schema should be identical across environments. Drift usually means an ACL or classification attribute was added in staging and never promoted — i.e. isolation tested is not isolation shipped."
  severity    = "medium"
  tags        = merge(local.common_tags, { category = "schema_hygiene" })

  param "environment_prefixes" {
    description = "Environment prefixes compared by the schema-drift control."
    default = var.environment_prefixes
  }

  sql = <<-EOQ
    -- env/base is derived in the same scan as the attribute join, and the env
    -- filter uses = any(array(...)) rather than IN (select from a
    -- set-returning CTE): the latter trips a Steampipe FDW planner bug
    -- (SQLSTATE 42804: "attribute N has wrong type") on the hydrated table.
    with sigs as (
      select split_part(n.id, '-', 1) as env,
             substring(n.id from length(split_part(n.id, '-', 1)) + 2) as base,
             n.id, n.region,
             coalesce(string_agg(a.name || ':' || a.type, ',' order by a.name), '<empty>') as signature
      from turbopuffer_namespace n
      left join turbopuffer_namespace_attribute a
        on a.namespace = n.id and a.region = n.region
      where position('-' in n.id) > 0
        and split_part(n.id, '-', 1) = any(array(select jsonb_array_elements_text($1::jsonb)))
      group by n.id, n.region
    ),
    compared as (
      select base, region,
             count(distinct signature) as variants,
             string_agg(env, ', ' order by env) as members
      from sigs
      group by base, region
      having count(*) > 1
    )
    select
      base as resource,
      case when variants = 1 then 'ok' else 'alarm' end as status,
      case
        when variants = 1 then base || ': schema matches across environments (' || members || ').'
        else base || ': schema drift between environments (' || members || ') — diff the schemas before the next release.'
      end as reason,
      region
    from compared;
  EOQ
}

control "hygiene_empty_namespaces" {
  title       = "No abandoned empty namespaces"
  description = "Empty namespaces older than the grace period are attack surface and audit noise with zero value — delete them. Fresh empties are informational (probably mid-provisioning)."
  severity    = "low"
  tags        = merge(local.common_tags, { category = "schema_hygiene" })

  param "empty_namespace_min_age_days" {
    description = "Age (days) above which an empty namespace is flagged for cleanup."
    default = var.empty_namespace_min_age_days
  }

  sql = <<-EOQ
    select
      id as resource,
      case
        when approx_row_count > 0 then 'ok'
        when created_at > now() - ($1::int || ' days')::interval then 'info'
        else 'alarm'
      end as status,
      case
        when approx_row_count > 0 then id || ' has ' || approx_row_count || ' rows.'
        when created_at > now() - ($1::int || ' days')::interval
          then id || ' is empty but only ' || extract(day from now() - created_at)::int || ' days old.'
        else id || ' has been empty for ' || extract(day from now() - created_at)::int || ' days — delete it.'
      end as reason,
      region
    from turbopuffer_namespace;
  EOQ
}
