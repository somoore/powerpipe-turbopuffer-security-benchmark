dashboard "turbopuffer_home" {
  title         = "turbopuffer: Security Posture"
  documentation = file("./docs/turbopuffer_home.md")
  tags          = merge(local.common_tags, { type = "Dashboard" })

  # ── Hero ──────────────────────────────────────────────────────────────
  container {
    text {
      width = 12
      value = <<-EOM
```
┌ turbopuffer ─ security posture ──────────────────────────────────────────────┐
│                                                                              │
│    ><(((·>     Ready to start puffin'? Here's how your namespaces           │
│                are holding up.                                               │
│                                                                              │
│    tenant isolation · data residency · encryption · schema hygiene · ops     │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```
      EOM
    }
  }

  # ── Posture cards (amber when fine, coral-alert when not) ─────────────
  container {
    card {
      width = 2
      icon  = "database"
      query = query.tpuf_card_namespaces
    }
    card {
      width = 2
      icon  = "public"
      query = query.tpuf_card_regions
    }
    card {
      width = 2
      icon  = "table_rows"
      query = query.tpuf_card_rows
    }
    card {
      width = 2
      icon  = "scale"
      query = query.tpuf_card_size
    }
    card {
      width = 2
      icon  = "encrypted"
      query = query.tpuf_card_cmek
    }
    card {
      width = 2
      icon  = "history"
      query = query.tpuf_card_stale
    }
  }

  # ── Step panels, echoing the onboarding page ──────────────────────────
  container {
    text {
      width = 4
      value = <<-EOM
```
┌ Step 1 ────────────────────────┐
│                                │
│  Run the benchmark:            │
│                                │
│  powerpipe benchmark run \     │
│    turbopuffer_security        │
│                                │
└────────────────────────────────┘
```
      EOM
    }
    text {
      width = 4
      value = <<-EOM
```
┌ Step 2 ────────────────────────┐
│                                │
│  Fix the criticals first:      │
│  ACL attributes present        │
│  and filterable in every       │
│  tenant namespace.             │
│                                │
└────────────────────────────────┘
```
      EOM
    }
    text {
      width = 4
      value = <<-EOM
```
┌ Step 3 ────────────────────────┐
│                                │
│  Automate: snapshot in CI,     │
│  alert on canary-document      │
│  retrieval in your app logs.   │
│                                │
└────────────────────────────────┘
```
      EOM
    }
  }

  # ── Charts, in brand ──────────────────────────────────────────────────
  container {
    chart {
      title = "Encryption"
      type  = "donut"
      width = 4
      query = query.tpuf_encryption_mix

      series "namespaces" {
        point "customer-managed (CMEK)" {
          color = local.puffer_amber
        }
        point "provider default" {
          color = local.puffer_mist
        }
      }
    }

    chart {
      title = "Freshness"
      type  = "donut"
      width = 4
      query = query.tpuf_freshness_mix

      series "namespaces" {
        point "updated in last 90d" {
          color = local.puffer_amber
        }
        point "stale (90d+)" {
          color = local.puffer_coral
        }
      }
    }

    chart {
      title = "Namespaces by Region"
      type  = "column"
      width = 4
      query = query.tpuf_by_region

      series "namespaces" {
        color = local.puffer_deep
      }
    }
  }

  container {
    chart {
      title = "Sensitive-Named Attributes by Namespace"
      type  = "bar"
      width = 6
      query = query.tpuf_sensitive_by_namespace

      series "sensitive_attributes" {
        color = local.puffer_brown
      }
    }

    table {
      title = "Largest Namespaces"
      width = 6
      query = query.tpuf_largest_namespaces

      column "Namespace" {
        href = "${dashboard.turbopuffer_namespace_detail.url_path}?input.namespace_id={{.'Namespace' | @uri}}"
      }
    }
  }

  # ── Footer, in the site's header voice ────────────────────────────────
  container {
    text {
      width = 12
      value = <<-EOM
[Overview](https://turbopuffer.com/docs) · [Namespaces](https://turbopuffer.com/docs/api-overview) · [Powerpipe Hub](https://hub.powerpipe.io) — unofficial community mod, not affiliated with turbopuffer inc. Managed by you; audited by this mod.
      EOM
    }
  }
}

# ── Queries ──────────────────────────────────────────────────────────────

query "tpuf_card_namespaces" {
  sql = <<-EOQ
    select count(*) as "Namespaces" from turbopuffer_namespace;
  EOQ
}

query "tpuf_card_regions" {
  sql = <<-EOQ
    select count(distinct region) as "Regions" from turbopuffer_namespace;
  EOQ
}

query "tpuf_card_rows" {
  sql = <<-EOQ
    select coalesce(sum(approx_row_count), 0) as "Total Rows" from turbopuffer_namespace;
  EOQ
}

query "tpuf_card_size" {
  # Auto-scale the total logical size to the largest fitting unit up through PB,
  # so a petabyte-scale estate reads "1.34 PB", not "1340.00 TB".
  sql = <<-EOQ
    with total as (
      select coalesce(sum(approx_logical_bytes), 0)::numeric as bytes
      from turbopuffer_namespace
    )
    select
      case
        when bytes >= 1125899906842624 then round(bytes / 1125899906842624, 2) || ' PB'
        when bytes >= 1099511627776    then round(bytes / 1099511627776, 2) || ' TB'
        when bytes >= 1073741824       then round(bytes / 1073741824, 2) || ' GB'
        when bytes >= 1048576          then round(bytes / 1048576, 2) || ' MB'
        else bytes || ' B'
      end as "Logical Size"
    from total;
  EOQ
}

query "tpuf_card_cmek" {
  sql = <<-EOQ
    select
      case when count(*) = 0 then 0
           else round(100.0 * count(*) filter (where coalesce(encryption_key_name, '') <> '') / count(*), 0)
      end as value,
      'CMEK Coverage %' as label,
      case
        when count(*) = 0 then 'info'
        when count(*) filter (where coalesce(encryption_key_name, '') <> '') = count(*) then 'ok'
        else 'info'
      end as type
    from turbopuffer_namespace;
  EOQ
}

query "tpuf_card_stale" {
  sql = <<-EOQ
    select
      count(*) filter (where updated_at < now() - interval '90 days') as value,
      'Stale (90d+)' as label,
      case
        when count(*) filter (where updated_at < now() - interval '90 days') = 0 then 'ok'
        else 'alert'
      end as type
    from turbopuffer_namespace;
  EOQ
}

query "tpuf_encryption_mix" {
  sql = <<-EOQ
    select
      case when coalesce(encryption_key_name, '') <> ''
        then 'customer-managed (CMEK)'
        else 'provider default'
      end as "Encryption",
      count(*) as namespaces
    from turbopuffer_namespace
    group by 1;
  EOQ
}

query "tpuf_freshness_mix" {
  sql = <<-EOQ
    select
      case when updated_at >= now() - interval '90 days'
        then 'updated in last 90d'
        else 'stale (90d+)'
      end as "Freshness",
      count(*) as namespaces
    from turbopuffer_namespace
    group by 1;
  EOQ
}

query "tpuf_by_region" {
  sql = <<-EOQ
    select region as "Region", count(*) as namespaces
    from turbopuffer_namespace
    group by region
    order by namespaces desc;
  EOQ
}

query "tpuf_sensitive_by_namespace" {
  sql = <<-EOQ
    select namespace as "Namespace", count(*) as sensitive_attributes
    from turbopuffer_namespace_attribute
    where name ~* '(ssn|credit_card|card_number|password|secret|token|api_key|medical|dob)'
    group by namespace
    order by sensitive_attributes desc
    limit 10;
  EOQ
}

query "tpuf_largest_namespaces" {
  sql = <<-EOQ
    select
      id as "Namespace",
      region as "Region",
      approx_row_count as "Rows",
      case
        when approx_logical_bytes >= 1125899906842624 then round(approx_logical_bytes / 1125899906842624.0, 2) || ' PB'
        when approx_logical_bytes >= 1099511627776    then round(approx_logical_bytes / 1099511627776.0, 2) || ' TB'
        when approx_logical_bytes >= 1073741824       then round(approx_logical_bytes / 1073741824.0, 2) || ' GB'
        when approx_logical_bytes >= 1048576          then round(approx_logical_bytes / 1048576.0, 2) || ' MB'
        else coalesce(approx_logical_bytes, 0) || ' B'
      end as "Size",
      case when coalesce(encryption_key_name, '') <> '' then 'CMEK' else 'default' end as "Encryption",
      to_char(updated_at, 'YYYY-MM-DD') as "Last Updated"
    from turbopuffer_namespace
    order by approx_logical_bytes desc nulls last
    limit 10;
  EOQ
}
