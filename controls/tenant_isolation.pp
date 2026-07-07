benchmark "tenant_isolation" {
  title       = "1. Tenant Isolation"
  description = "turbopuffer's own permissions docs state that row/document-level access control is the application's job, implemented via attribute filters. These controls verify the schema-level preconditions for that model to actually hold."
  children = [
    control.tenant_isolation_acl_attributes_present,
    control.tenant_isolation_acl_attributes_filterable,
    control.tenant_isolation_namespace_naming,
    control.tenant_isolation_canary_document_present,
  ]
  tags = merge(local.common_tags, { category = "tenant_isolation" })
}

control "tenant_isolation_acl_attributes_present" {
  title       = "Tenant namespaces define all required ACL attributes"
  description = "If the ACL attribute is not in the schema, no query filter can reference it and every query returns cross-tenant data. This is the single most dangerous misconfiguration in a multi-tenant turbopuffer deployment."
  severity    = "critical"
  tags        = merge(local.common_tags, { category = "tenant_isolation" })

  param "required_acl_attributes" {
    description = "Attributes every multi-tenant namespace must define and keep filterable."
    default = var.required_acl_attributes
  }
  param "tenant_namespace_pattern" {
    description = "Regex selecting namespaces subject to tenant-isolation controls."
    default = var.tenant_namespace_pattern
  }

  sql = <<-EOQ
    with target_ns as (
      select id, region
      from turbopuffer_namespace
      where id ~ $2
    ),
    required as (
      select jsonb_array_elements_text($1::jsonb) as attr
    ),
    missing as (
      select n.id, n.region,
             string_agg(r.attr, ', ' order by r.attr) as missing_attrs
      from target_ns n
      cross join required r
      left join turbopuffer_namespace_attribute a
        on a.namespace = n.id
       and a.region    = n.region
       and a.name      = r.attr
      where a.name is null
      group by n.id, n.region
    )
    select
      n.id as resource,
      case when m.id is null then 'ok' else 'alarm' end as status,
      case
        when m.id is null then n.id || ' defines all required ACL attributes.'
        else n.id || ' is missing ACL attribute(s): ' || m.missing_attrs || ' — queries cannot be tenant-scoped.'
      end as reason,
      n.region
    from target_ns n
    left join missing m
      on m.id = n.id and m.region = n.region;
  EOQ
}

control "tenant_isolation_acl_attributes_filterable" {
  title       = "ACL attributes are filterable"
  description = "In turbopuffer, attributes can opt out of filterability (and BM25-enabled attributes are non-filterable by default). An ACL attribute that exists but is not filterable gives a false sense of security: the isolation filter silently cannot be applied."
  severity    = "critical"
  tags        = merge(local.common_tags, { category = "tenant_isolation" })

  param "required_acl_attributes" {
    description = "Attributes every multi-tenant namespace must define and keep filterable."
    default = var.required_acl_attributes
  }
  param "tenant_namespace_pattern" {
    description = "Regex selecting namespaces subject to tenant-isolation controls."
    default = var.tenant_namespace_pattern
  }

  sql = <<-EOQ
    with required as (
      select jsonb_array_elements_text($1::jsonb) as attr
    )
    select
      a.namespace || '/' || a.name as resource,
      case when a.filterable then 'ok' else 'alarm' end as status,
      case
        when a.filterable then a.namespace || ': ACL attribute "' || a.name || '" is filterable.'
        else a.namespace || ': ACL attribute "' || a.name || '" is NOT filterable — authorization filters on it are impossible.'
      end as reason,
      a.region
    from turbopuffer_namespace_attribute a
    join required r on r.attr = a.name
    where a.namespace ~ $2;
  EOQ
}

control "tenant_isolation_namespace_naming" {
  title       = "Namespaces follow the naming convention"
  description = "Naming conventions are load-bearing here: residency, CMEK and isolation controls all select namespaces by pattern. A namespace outside the convention is a namespace outside the guardrails."
  severity    = "medium"
  tags        = merge(local.common_tags, { category = "tenant_isolation" })

  param "namespace_naming_pattern" {
    description = "Regex namespaces must match as a naming-convention control."
    default = var.namespace_naming_pattern
  }

  sql = <<-EOQ
    select
      id as resource,
      case when id ~ $1 then 'ok' else 'alarm' end as status,
      case
        when id ~ $1 then id || ' matches the naming convention.'
        else id || ' does not match naming convention ' || $1 || ' and is invisible to pattern-scoped controls.'
      end as reason,
      region
    from turbopuffer_namespace;
  EOQ
}

control "tenant_isolation_canary_document_present" {
  title       = "Canary document is seeded in every tenant namespace"
  description = "A honeytoken row per namespace turns your data plane into a tripwire: any retrieval of the canary ID (alert on it in your app or gateway logs) means a leaked key, a missing tenant filter, or an isolation failure. This control verifies the canaries exist; alerting on their retrieval is the data-path half."
  severity    = "high"
  tags        = merge(local.common_tags, { category = "tenant_isolation" })

  param "canary_document_id" {
    description = "ID of a honeytoken document expected in every tenant namespace."
    default = var.canary_document_id
  }
  param "tenant_namespace_pattern" {
    description = "Regex selecting namespaces subject to tenant-isolation controls."
    default = var.tenant_namespace_pattern
  }

  sql = <<-EOQ
    select
      n.id as resource,
      case
        when $1 = '' then 'skip'
        when d.id is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when $1 = '' then 'Skipped: set var.canary_document_id to enable canary checks.'
        when d.id is not null then n.id || ' contains the canary document.'
        else n.id || ' is missing the canary document — seeding gap or unexpected deletion.'
      end as reason,
      n.region
    from turbopuffer_namespace n
    left join turbopuffer_document d
      on  d.namespace = n.id
      and d.region    = n.region
      and d.id        = $1
      and $1 <> ''
    where n.id ~ $2;
  EOQ
}
