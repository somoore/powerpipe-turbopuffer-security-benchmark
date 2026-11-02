#!/usr/bin/env python3
"""Golden-test the turbopuffer Powerpipe controls without a live turbopuffer account.

Extracts each `sql = <<-EOQ ... EOQ` block from controls/*.pp, binds the
Powerpipe `$n` params to literal values, runs it against a Postgres fixture
schema, and asserts expected `status` values per `resource`.

Usage:
  python3 run_controls.py --dsn postgresql://... [--schema tpuf_qa]
"""
import argparse
import glob
import json
import re
import subprocess
import sys

PARAMS = {
    "required_acl_attributes": ["tenant_id"],
    "tenant_namespace_pattern": ".",
    "namespace_naming_pattern": "^[a-z0-9]+(-[a-z0-9]+)*$",
    "canary_document_id": "canary-1",
    "approved_regions": ["gcp-us-central1"],
    "eu_namespace_pattern": "(^|[-_])eu([-_]|$)",
    "eu_region_pattern": "(eu|europe)",
    "cmek_required_pattern": "(prod|pii|phi|sensitive|customer)",
    "approved_cmek_keys": ["projects/x/locations/y/keyRings/z/cryptoKeys/approved"],
    "sensitive_attribute_pattern": "(ssn|social_security|passport|national_id|credit_card|card_number|cvv|iban|routing|password|secret|token|api_key|private_key|access_key|dob|date_of_birth|salary|medical|diagnosis|health)",
    "environment_prefixes": ["prod", "staging"],
    "empty_namespace_min_age_days": 14,
    "stale_days": 90,
    "max_namespace_gb": 250,
    "namespace_count_budget": 500,
    "max_unindexed_bytes": 0,
}

# param name -> position used in the control's SQL
PARAM_POS = {
    "tenant_isolation_acl_attributes_present": {1: "required_acl_attributes", 2: "tenant_namespace_pattern"},
    "tenant_isolation_acl_attributes_filterable": {1: "required_acl_attributes", 2: "tenant_namespace_pattern"},
    "tenant_isolation_namespace_naming": {1: "namespace_naming_pattern"},
    "tenant_isolation_canary_document_present": {1: "canary_document_id", 2: "tenant_namespace_pattern"},
    "residency_approved_regions_only": {1: "approved_regions"},
    "residency_eu_namespaces_in_eu_regions": {1: "eu_namespace_pattern", 2: "eu_region_pattern"},
    "encryption_cmek_on_sensitive_namespaces": {1: "cmek_required_pattern"},
    "encryption_cmek_keys_approved": {1: "approved_cmek_keys"},
    "hygiene_sensitive_attribute_names": {1: "sensitive_attribute_pattern"},
    "hygiene_sensitive_attributes_not_search_indexed": {1: "sensitive_attribute_pattern"},
    "hygiene_schema_drift_across_environments": {1: "environment_prefixes"},
    "hygiene_empty_namespaces": {1: "empty_namespace_min_age_days"},
    "ops_stale_namespaces": {1: "stale_days"},
    "ops_index_lag": {1: "max_unindexed_bytes"},
    "ops_oversized_namespaces": {1: "max_namespace_gb"},
    "ops_namespace_sprawl": {1: "namespace_count_budget"},
}

# Expected status per resource. Unlisted resources are not asserted.
EXPECTED = {
    "tenant_isolation_acl_attributes_present": {"prod-tenant-a": "ok", "prod-noacl": "alarm", "prod-tenant-b": "ok"},
    "tenant_isolation_acl_attributes_filterable": {"prod-tenant-a/tenant_id": "ok", "prod-tenant-b/tenant_id": "alarm"},
    "tenant_isolation_namespace_naming": {"prod-tenant-a": "ok", "Bad_Name": "alarm"},
    "tenant_isolation_canary_document_present": {"prod-tenant-a": "ok", "prod-tenant-b": "alarm"},
    "residency_approved_regions_only": {"prod-tenant-a": "ok", "empty-old": "alarm"},
    "residency_eu_namespaces_in_eu_regions": {"pub-eu-data": "alarm"},
    "encryption_cmek_on_sensitive_namespaces": {"prod-tenant-b": "alarm", "prod-enc": "ok"},
    "encryption_cmek_keys_approved": {"prod-enc": "alarm"},
    "hygiene_sensitive_attribute_names": {"prod-tenant-b/card_number": "alarm", "prod-tenant-a/body": "ok"},
    "hygiene_sensitive_attributes_not_search_indexed": {"prod-tenant-b/card_number": "alarm"},
    "hygiene_schema_drift_across_environments": {"drift": "alarm", "same": "ok"},
    "hygiene_empty_namespaces": {"empty-old": "alarm", "prod-tenant-a": "ok"},
    "ops_stale_namespaces": {"stale-1": "alarm", "prod-tenant-a": "ok"},
    "ops_index_lag": {"lagging": "alarm", "prod-tenant-a": "ok"},
    "ops_oversized_namespaces": {"big-ns": "alarm", "prod-tenant-a": "ok"},
    "ops_namespace_sprawl": {"organization": "ok"},
}

CTRL_RE = re.compile(r'control\s+"([^"]+)"\s*\{(.*?)\n\}', re.S)
SQL_RE = re.compile(r'sql\s*=\s*<<-EOQ\n(.*?)\n\s*EOQ', re.S)


def sql_literal(v):
    if isinstance(v, list):
        return "'" + json.dumps(v).replace("'", "''") + "'"
    if isinstance(v, (int, float)):
        return "'" + str(v) + "'"
    return "'" + str(v).replace("'", "''") + "'"


def bind(sql, ctrl):
    def sub(m):
        pos = int(m.group(1))
        name = PARAM_POS[ctrl][pos]
        return sql_literal(PARAMS[name])
    return re.sub(r"\$(\d+)", sub, sql)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--mod", default=".")
    ap.add_argument("--schema", default=None)
    args = ap.parse_args()

    controls = {}
    for path in sorted(glob.glob(f"{args.mod}/controls/*.pp")):
        text = open(path).read()
        for name, body in CTRL_RE.findall(text):
            m = SQL_RE.search(body)
            if not m:
                continue
            controls[name] = bind(m.group(1), name)

    failures, checked = [], 0
    for name in sorted(controls):
        sql = controls[name]
        if args.schema:
            sql = f"set search_path to {args.schema}; {sql}"
        out = subprocess.run(
            ["psql", args.dsn, "-X", "-q", "-A", "-F", "\t", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql],
            capture_output=True, text=True,
        )
        if out.returncode != 0:
            failures.append(f"{name}: SQL ERROR: {out.stderr.strip().splitlines()[0]}")
            continue
        got = {}
        for line in out.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                got[parts[0]] = parts[1]
        for resource, want in EXPECTED.get(name, {}).items():
            checked += 1
            if got.get(resource) != want:
                failures.append(f"{name}: {resource} expected {want}, got {got.get(resource)!r}")

    print(f"controls run: {len(controls)}  assertions: {checked}  failures: {len(failures)}")
    for f in failures:
        print("FAIL " + f)
    return 1 if failures or len(controls) != 16 else 0


if __name__ == "__main__":
    sys.exit(main())
