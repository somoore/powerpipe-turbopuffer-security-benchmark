mod "turbopuffer_security" {
  database    = var.database
  title       = "turbopuffer Security & Compliance Benchmark"
  description = "Security posture, tenant-isolation, data-residency, encryption and hygiene checks for turbopuffer namespaces. Runs against the steampipe-plugin-turbopuffer tables. Unofficial community project; not affiliated with turbopuffer inc."
  color       = "#FB915F"
  categories  = ["security", "compliance", "turbopuffer"]

  opengraph {
    title       = "turbopuffer Security & Compliance Mod for Powerpipe"
    description = "16 posture controls and turbopuffer-branded dashboards: tenant isolation, data residency, CMEK, schema hygiene, and operations."
  }

  require {
    plugin "turbopuffer" {
      min_version = "0.1.0"
    }
  }
}
