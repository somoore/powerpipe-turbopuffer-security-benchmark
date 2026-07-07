# turbopuffer Security Benchmark

Security posture management for [turbopuffer](https://turbopuffer.com) — a Steampipe plugin that turns your namespaces into SQL, and a Powerpipe mod that runs 16 security controls over them.

> Unofficial community project. Not affiliated with or endorsed by turbopuffer inc. All read-only.

```
┌─────────────────────┐     GET /v1/namespaces            ┌──────────────────┐
│  Powerpipe          │     GET /v2/namespaces/:ns/meta   │  turbopuffer     │
│  benchmark + dash   │──▶ Steampipe plugin ─────────────▶│  (per region)    │
│  (16 controls, HCL) │     POST /v2/namespaces/:ns/query │                  │
└─────────────────────┘     (canary lookups only)         └──────────────────┘
```

## Why

turbopuffer's own permissions documentation is explicit: row/document-level access control is the **application's** responsibility, implemented via attribute filters. There is no built-in RBAC below the API-key level. That's a reasonable architectural choice — and it means every turbopuffer customer is one missing schema attribute or one non-filterable field away from cross-tenant retrieval. Nothing audits that today. This does.

## What gets checked

| # | Control | Severity | Signal |
|---|---------|----------|--------|
| 1 | `tenant_isolation_acl_attributes_present` | critical | Tenant namespaces define the ACL attributes your filters depend on |
| 2 | `tenant_isolation_acl_attributes_filterable` | critical | …and those attributes are actually `filterable` (BM25 fields aren't, by default) |
| 3 | `tenant_isolation_namespace_naming` | medium | Namespaces match the naming convention other controls key off |
| 4 | `tenant_isolation_canary_document_present` | high | Honeytoken doc seeded per namespace (alert on its retrieval in your app logs) |
| 5 | `residency_approved_regions_only` | high | Namespaces only in approved regions |
| 6 | `residency_eu_namespaces_in_eu_regions` | critical | EU-tagged namespaces hosted in EU regions |
| 7 | `encryption_cmek_on_sensitive_namespaces` | high | Prod/PII namespaces use customer-managed keys |
| 8 | `encryption_cmek_keys_approved` | medium | CMEK keys come from the approved key inventory |
| 9 | `hygiene_sensitive_attribute_names` | high | No `ssn`/`card_number`/`api_key`-style attributes next to your vectors |
| 10 | `hygiene_sensitive_attributes_not_search_indexed` | high | Sensitive attrs aren't FTS/regex/glob/fuzzy-indexed (exposure amplification) |
| 11 | `hygiene_schema_drift_across_environments` | medium | `prod-x` and `staging-x` schemas match |
| 12 | `hygiene_empty_namespaces` | low | No abandoned empty namespaces |
| 13 | `ops_stale_namespaces` | medium | Every namespace has an owner writing to it (`updated_at` recency) |
| 14 | `ops_index_lag` | medium | No unindexed WAL bytes — recent writes are searchable, not silently missed |
| 15 | `ops_oversized_namespaces` | medium | Single-namespace blast radius under threshold |
| 16 | `ops_namespace_sprawl` | low | Total namespace count within budget |

Everything is tunable in `powerpipe-turbopuffer-security-benchmark/variables.pp`.

## Quick start

```bash
# 1. Build and install the plugin locally
cd steampipe-plugin-turbopuffer
go mod tidy && make install   # or: go build -o ~/.steampipe/plugins/local/turbopuffer/turbopuffer.plugin

# 2. Configure the connection
cp config/turbopuffer.spc ~/.steampipe/config/
$EDITOR ~/.steampipe/config/turbopuffer.spc   # api_key + regions

# 3. Kick the tires
steampipe query "select id, region, approx_row_count, encryption_mode from turbopuffer_namespace"

# 4. Run the benchmark
cd ../powerpipe-turbopuffer-security-benchmark
powerpipe benchmark run turbopuffer_security \
  --var 'required_acl_attributes=["tenant_id","user_id"]' \
  --var 'approved_regions=["gcp-us-central1","aws-eu-central-1"]'

# 5. Or the live dashboard
powerpipe server   # open http://localhost:9033
```

## Tables

| Table | One row per | Notable columns |
|-------|-------------|-----------------|
| `turbopuffer_namespace` | namespace × region | `approx_row_count`, `approx_logical_bytes`, `created_at`, `updated_at`, `encryption_mode`, `encryption_key_name`, `schema` |
| `turbopuffer_namespace_attribute` | schema attribute | `type`, `filterable`, `full_text_search`, `regex`, `glob`, `fuzzy`, `vector_index`, `sparse_vector_index` |
| `turbopuffer_document` | document (requires `namespace` qual) | `id`, `attributes` — vectors always excluded; built for canary lookups and small samples, not export |
| `turbopuffer_namespace_recall` | recall evaluation (requires `namespace` qual) | `avg_recall`, `avg_ann_count`, `avg_exhaustive_count` — index-integrity signal; runs real searches, costs money |
| `turbopuffer_region` | configured region | `region`, `endpoint` — join anchor for residency queries |

The plugin follows full Steampipe Hub conventions: `docs/index.md` + per-table example docs (what the Hub renders), Apache-2.0 `LICENSE`, `.goreleaser.yml` for cross-platform release builds, and resilience defaults (404s ignored as skips, 429/5xx retried with backoff). Standards conformance (naming, descriptions, column order, docs, coding) is enforced by `make test` and a pre-commit hook.

Because it's all SQL in Steampipe, these join against the other 150+ plugins: put turbopuffer residency next to `aws_s3_bucket` residency in one compliance report, or join namespaces against a `tenants.csv` (CSV plugin) to catch orphaned tenants.

## Dashboards (in turbopuffer's visual language)

Powerpipe mods can't inject CSS or custom fonts — but turbopuffer's aesthetic is monospace frames, and code fences render true monospace. So the branding is real, not cosplay:

- **turbopuffer: Security Posture** (`turbopuffer_home`) — box-drawn hero and "Step 1/2/3" panels echoing the onboarding page, posture cards that flip coral on alert, amber/sand/ink palette on every chart, and a Largest Namespaces table that drills into…
- **turbopuffer: Namespace Detail** (`turbopuffer_namespace_detail`) — a select input, size/freshness/encryption cards, a **Tenant Isolation: ready / NOT enforceable** verdict card (required ACL attributes present *and* filterable), and the full attribute schema with search-amplification flags.

For a pixel-faithful branded artifact (their cream background, their exact type), the path is `powerpipe benchmark run --export html` with a custom template — on the roadmap below.

## Grounding & honesty notes

- Endpoint paths and response fields were **verified against the official `turbopuffer-go/v2` client and the [turbopuffer OpenAPI spec](https://github.com/turbopuffer/turbopuffer-openapi)**, then confirmed against a live account (`GET /v1/namespaces`, `GET /v2/namespaces/:ns/metadata` → `approx_row_count`, `approx_logical_bytes`, `created_at`, `updated_at`, `encryption{mode,key_name}`, `index{status,unindexed_bytes}`, `schema`; `POST /v2/namespaces/:ns/query`). The metadata response is what makes CMEK, staleness, and index-lag controls real rather than aspirational.
- **Compiled, tested, and run against a live account.** The plugin builds clean, passes its standards test suite, and the benchmark runs end-to-end (0 errors) against seeded live data.
- **The control-plane gap**: turbopuffer's public API is data-plane only. API keys, their permissions, org membership and billing are dashboard-only. That's why there's no `turbopuffer_api_key` table — and it's the partnership conversation to have with turbopuffer ("give us a management API"). Track what you can't check; that list is the roadmap.
- Metadata is fetched once per namespace (concurrency-capped, cached by Steampipe across a benchmark run). A 1,000-namespace org costs ~1,001 GET requests per scan.

## Roadmap

1. **Now (this repo):** read-only posture scan — the ten-minute scary report.
2. **Next:** companion content scanner (PII / secrets / stored-prompt-injection detection over sampled documents) writing findings into a table this mod benchmarks alongside live data.
3. **Then:** retrospective detection over audit logs (Tailpipe) when/if log export lands; alerting on canary-document retrieval.
4. **The product:** the data-path gateway — per-user filter injection, short-lived scoped credentials, tenant-isolation probes, exfiltration-shaped-query detection. The plugin audits the preconditions; the gateway enforces them.
