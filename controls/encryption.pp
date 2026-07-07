benchmark "encryption" {
  title       = "3. Encryption"
  description = "The namespace metadata API exposes each namespace's encryption configuration, including customer-managed keys (CMEK). These controls turn that into enforceable policy."
  children = [
    control.encryption_cmek_on_sensitive_namespaces,
    control.encryption_cmek_keys_approved,
  ]
  tags = merge(local.common_tags, { category = "encryption" })
}

control "encryption_cmek_on_sensitive_namespaces" {
  title       = "Sensitive namespaces use customer-managed encryption keys"
  description = "Namespaces matching the CMEK-required pattern (production / PII / customer data by convention) must be configured with a customer-managed key rather than provider-default encryption, so key rotation and revocation stay under your control."
  severity    = "high"
  tags        = merge(local.common_tags, { category = "encryption" })

  param "cmek_required_pattern" {
    description = "Regex selecting namespaces that must use customer-managed encryption keys."
    default = var.cmek_required_pattern
  }

  sql = <<-EOQ
    select
      id as resource,
      case
        when coalesce(encryption_key_name, '') <> '' then 'ok'
        else 'alarm'
      end as status,
      case
        when coalesce(encryption_key_name, '') <> ''
          then id || ' uses customer-managed key ' || encryption_key_name || '.'
        else id || ' matches the CMEK-required pattern but uses provider-default encryption.'
      end as reason,
      region
    from turbopuffer_namespace
    where id ~* $1;
  EOQ
}

control "encryption_cmek_keys_approved" {
  title       = "CMEK namespaces use keys from the approved list"
  description = "Where CMEK is in use, the key must come from the organization's approved key inventory — an unapproved key is unmanaged key material (no rotation policy, unknown custodian). Skips when var.approved_cmek_keys is empty."
  severity    = "medium"
  tags        = merge(local.common_tags, { category = "encryption" })

  param "approved_cmek_keys" {
    description = "Allow-list of approved CMEK key resource names."
    default = var.approved_cmek_keys
  }

  # Powerpipe binds a list(string) param as a JSON array string, so $1::jsonb
  # is the correct cast (verified: residency/isolation controls use the same
  # pattern and run clean).
  sql = <<-EOQ
    select
      id as resource,
      case
        when jsonb_array_length($1::jsonb) = 0 then 'skip'
        when encryption_key_name in (select jsonb_array_elements_text($1::jsonb)) then 'ok'
        else 'alarm'
      end as status,
      case
        when jsonb_array_length($1::jsonb) = 0
          then 'Skipped: populate var.approved_cmek_keys to enable the key allow-list.'
        when encryption_key_name in (select jsonb_array_elements_text($1::jsonb))
          then id || ' uses approved key ' || encryption_key_name || '.'
        else id || ' uses key ' || encryption_key_name || ' which is not on the approved list.'
      end as reason,
      region
    from turbopuffer_namespace
    where coalesce(encryption_key_name, '') <> '';
  EOQ
}
