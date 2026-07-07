locals {
  common_tags = {
    project = "turbopuffer_security"
    plugin  = "turbopuffer"
  }
}

benchmark "turbopuffer_security" {
  title       = "turbopuffer Security Benchmark v0.1"
  description = "The full posture scan: tenant isolation, data residency, encryption, schema hygiene, and operations. Run with: powerpipe benchmark run turbopuffer_security"
  children = [
    benchmark.tenant_isolation,
    benchmark.data_residency,
    benchmark.encryption,
    benchmark.schema_hygiene,
    benchmark.operations,
  ]
  tags = local.common_tags
}
