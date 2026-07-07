# ------------------------------------------------------------------
# Database
# ------------------------------------------------------------------

variable "database" {
  type        = connection.steampipe
  default     = connection.steampipe.default
  description = "The Steampipe database this mod queries. Defaults to the local Steampipe service."
}

# ------------------------------------------------------------------
# Tenant isolation
# ------------------------------------------------------------------

variable "required_acl_attributes" {
  type        = list(string)
  default     = ["tenant_id"]
  description = "Attributes every multi-tenant namespace must define AND keep filterable, because turbopuffer has no built-in row-level RBAC — isolation is only as strong as the filters your app applies on these attributes."
}

variable "tenant_namespace_pattern" {
  type        = string
  default     = "."
  description = "Regex selecting namespaces subject to tenant-isolation controls. Default '.' matches everything; narrow it to e.g. '^prod-' once conventions exist."
}

variable "namespace_naming_pattern" {
  type        = string
  default     = "^[a-z0-9]+(-[a-z0-9]+)*$"
  description = "Regex namespaces must match. Naming conventions are a security control here: they are what residency and isolation checks key off."
}

variable "canary_document_id" {
  type        = string
  default     = ""
  description = "ID of a honeytoken document expected to exist in every tenant namespace. Empty string skips the control. Pair with data-path alerting on retrieval of this ID for leak detection."
}

# ------------------------------------------------------------------
# Data residency
# ------------------------------------------------------------------

variable "approved_regions" {
  type        = list(string)
  default     = ["gcp-us-central1"]
  description = "turbopuffer regions your organization has approved for any data."
}

variable "eu_namespace_pattern" {
  type        = string
  default     = "(^|[-_])eu([-_]|$)"
  description = "Regex identifying namespaces that hold EU-resident data (by naming convention)."
}

variable "eu_region_pattern" {
  type        = string
  default     = "(eu|europe)"
  description = "Regex a region ID must match to count as an EU region (matches e.g. aws-eu-central-1, gcp-europe-west3)."
}

# ------------------------------------------------------------------
# Encryption
# ------------------------------------------------------------------

variable "cmek_required_pattern" {
  type        = string
  default     = "(prod|pii|phi|sensitive|customer)"
  description = "Regex selecting namespaces that must use customer-managed encryption keys (CMEK) rather than provider-default encryption."
}

variable "approved_cmek_keys" {
  type        = list(string)
  default     = []
  description = "Allow-list of CMEK key resource names. Empty list skips the key allow-list control."
}

# ------------------------------------------------------------------
# Schema hygiene
# ------------------------------------------------------------------

variable "sensitive_attribute_pattern" {
  type        = string
  default     = "(ssn|social_security|passport|national_id|credit_card|card_number|cvv|iban|routing|password|secret|token|api_key|private_key|access_key|dob|date_of_birth|salary|medical|diagnosis|health)"
  description = "Case-insensitive regex flagging attribute names that suggest sensitive content stored alongside vectors."
}

variable "environment_prefixes" {
  type        = list(string)
  default     = ["prod", "staging"]
  description = "Environment prefixes (in '<env>-<name>' namespaces) compared by the schema-drift control."
}

variable "empty_namespace_min_age_days" {
  type        = number
  default     = 14
  description = "Empty namespaces older than this are flagged for cleanup; younger ones are informational."
}

# ------------------------------------------------------------------
# Operations
# ------------------------------------------------------------------

variable "stale_days" {
  type        = number
  default     = 90
  description = "Namespaces with no writes for this many days are flagged: unmaintained data is unowned risk."
}

variable "max_namespace_gb" {
  type        = number
  default     = 250
  description = "Logical-size threshold (GB) above which a single namespace is flagged for blast-radius review — consider splitting per tenant or per corpus."
}

variable "namespace_count_budget" {
  type        = number
  default     = 500
  description = "Soft budget for total namespace count; exceeding it signals sprawl worth an inventory review."
}

variable "max_unindexed_bytes" {
  type        = number
  default     = 0
  description = "Bytes a namespace may have written but not yet indexed before it is flagged. Default 0 flags any lag; raise it to tolerate steady write throughput. A lagging index means recent writes are not yet searchable — retrieval silently misses fresh data."
}
