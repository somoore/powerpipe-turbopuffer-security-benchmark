benchmark "data_residency" {
  title       = "2. Data Residency"
  description = "turbopuffer regions are hard boundaries — each is a separate endpoint. These controls verify namespaces live only where policy says they may."
  children = [
    control.residency_approved_regions_only,
    control.residency_eu_namespaces_in_eu_regions,
  ]
  tags = merge(local.common_tags, { category = "data_residency" })
}

control "residency_approved_regions_only" {
  title       = "Namespaces exist only in approved regions"
  description = "Every namespace must live in a region on the organization's approved list. Note: this control can only see regions listed in the plugin connection config — keep `regions` in turbopuffer.spc equal to ALL regions your org can write to, not just the approved ones, or shadow regions stay invisible."
  severity    = "high"
  tags        = merge(local.common_tags, { category = "data_residency" })

  param "approved_regions" {
    description = "turbopuffer regions approved for any data."
    default = var.approved_regions
  }

  sql = <<-EOQ
    select
      id as resource,
      case
        when region in (select jsonb_array_elements_text($1::jsonb)) then 'ok'
        else 'alarm'
      end as status,
      case
        when region in (select jsonb_array_elements_text($1::jsonb))
          then id || ' is in approved region ' || region || '.'
        else id || ' is in UNAPPROVED region ' || region || '.'
      end as reason,
      region
    from turbopuffer_namespace;
  EOQ
}

control "residency_eu_namespaces_in_eu_regions" {
  title       = "EU-tagged namespaces are hosted in EU regions"
  description = "Namespaces whose names mark them as holding EU-resident data must be hosted in an EU region. GDPR exposure otherwise; embeddings of personal data are personal data — inversion attacks can recover approximate source text from vectors."
  severity    = "critical"
  tags        = merge(local.common_tags, { category = "data_residency" })

  param "eu_namespace_pattern" {
    description = "Regex identifying namespaces that hold EU-resident data."
    default = var.eu_namespace_pattern
  }
  param "eu_region_pattern" {
    description = "Regex a region ID must match to count as an EU region."
    default = var.eu_region_pattern
  }

  sql = <<-EOQ
    select
      id as resource,
      case when region ~* $2 then 'ok' else 'alarm' end as status,
      case
        when region ~* $2 then id || ' (EU-tagged) is correctly hosted in ' || region || '.'
        else id || ' is EU-tagged but hosted in non-EU region ' || region || '.'
      end as reason,
      region
    from turbopuffer_namespace
    where id ~* $1;
  EOQ
}
