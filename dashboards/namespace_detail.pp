dashboard "turbopuffer_namespace_detail" {
  title         = "turbopuffer: Namespace Detail"
  documentation = file("./docs/turbopuffer_namespace_detail.md")
  tags          = merge(local.common_tags, { type = "Detail" })

  container {
    input "namespace_id" {
      title       = "Select a namespace"
      width       = 4
      type        = "select"
      placeholder = "choose a namespace"
      query       = query.tpuf_namespace_input
    }
  }

  container {
    card {
      width = 2
      icon  = "table_rows"
      query = query.tpuf_detail_rows
      args  = { ns = self.input.namespace_id.value }
    }
    card {
      width = 2
      icon  = "scale"
      query = query.tpuf_detail_size
      args  = { ns = self.input.namespace_id.value }
    }
    card {
      width = 2
      icon  = "history"
      query = query.tpuf_detail_last_write
      args  = { ns = self.input.namespace_id.value }
    }
    card {
      width = 3
      icon  = "encrypted"
      query = query.tpuf_detail_encryption
      args  = { ns = self.input.namespace_id.value }
    }
    card {
      width = 3
      icon  = "shield_person"
      query = query.tpuf_detail_isolation
      args = {
        ns  = self.input.namespace_id.value
        acl = var.required_acl_attributes
      }
    }
  }

  container {
    text {
      width = 12
      value = <<-EOM
```
┌ Schema ── every attribute, its type, and how it can be reached ─────────────┐
│  filterable = can enforce ACLs · fts/regex/glob/fuzzy = search-amplified    │
└──────────────────────────────────────────────────────────────────────────────┘
```
      EOM
    }

    table {
      width = 12
      query = query.tpuf_detail_attributes
      args  = { ns = self.input.namespace_id.value }
    }
  }
}

# ── Queries ──────────────────────────────────────────────────────────────

query "tpuf_namespace_input" {
  sql = <<-EOQ
    select
      id || '  [' || region || ']' as label,
      id as value
    from turbopuffer_namespace
    order by id;
  EOQ
}

query "tpuf_detail_rows" {
  sql = <<-EOQ
    select approx_row_count as "Rows"
    from turbopuffer_namespace
    where id = $1;
  EOQ
  param "ns" {}
}

query "tpuf_detail_size" {
  # Auto-scale up through PB so large namespaces read correctly.
  sql = <<-EOQ
    select
      case
        when approx_logical_bytes >= 1125899906842624 then round(approx_logical_bytes / 1125899906842624.0, 2) || ' PB'
        when approx_logical_bytes >= 1099511627776    then round(approx_logical_bytes / 1099511627776.0, 2) || ' TB'
        when approx_logical_bytes >= 1073741824       then round(approx_logical_bytes / 1073741824.0, 2) || ' GB'
        when approx_logical_bytes >= 1048576          then round(approx_logical_bytes / 1048576.0, 2) || ' MB'
        else coalesce(approx_logical_bytes, 0) || ' B'
      end as "Logical Size"
    from turbopuffer_namespace
    where id = $1;
  EOQ
  param "ns" {}
}

query "tpuf_detail_last_write" {
  sql = <<-EOQ
    select
      to_char(updated_at, 'YYYY-MM-DD') as value,
      'Last Write' as label,
      case
        when updated_at >= now() - interval '90 days' then 'ok'
        else 'alert'
      end as type
    from turbopuffer_namespace
    where id = $1;
  EOQ
  param "ns" {}
}

query "tpuf_detail_encryption" {
  sql = <<-EOQ
    select
      case when coalesce(encryption_key_name, '') <> ''
        then 'CMEK: ' || encryption_key_name
        else 'provider default'
      end as value,
      'Encryption' as label,
      case when coalesce(encryption_key_name, '') <> '' then 'ok' else 'info' end as type
    from turbopuffer_namespace
    where id = $1;
  EOQ
  param "ns" {}
}

# Isolation readiness: are all required ACL attributes present AND filterable?
query "tpuf_detail_isolation" {
  sql = <<-EOQ
    with required as (
      select jsonb_array_elements_text($2::jsonb) as attr
    ),
    have as (
      select r.attr,
             bool_or(a.filterable) as filterable
      from required r
      left join turbopuffer_namespace_attribute a
        on a.namespace = $1 and a.name = r.attr
      group by r.attr
    )
    select
      case
        when count(*) filter (where filterable is not true) = 0 then 'ready'
        else 'NOT enforceable'
      end as value,
      'Tenant Isolation' as label,
      case
        when count(*) filter (where filterable is not true) = 0 then 'ok'
        else 'alert'
      end as type
    from have;
  EOQ
  param "ns" {}
  param "acl" {}
}

query "tpuf_detail_attributes" {
  sql = <<-EOQ
    select
      name as "Attribute",
      type as "Type",
      case when filterable then '✓' else '·' end as "Filterable",
      case when full_text_search then '✓' else '·' end as "BM25",
      case when regex then '✓' else '·' end as "Regex",
      case when glob then '✓' else '·' end as "Glob",
      case when fuzzy then '✓' else '·' end as "Fuzzy",
      case when sparse_vector_index then '✓' else '·' end as "Sparse",
      case when vector_index then '✓' else '·' end as "ANN"
    from turbopuffer_namespace_attribute
    where namespace = $1
    order by name;
  EOQ
  param "ns" {}
}
