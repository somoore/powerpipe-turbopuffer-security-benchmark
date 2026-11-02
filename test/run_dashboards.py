#!/usr/bin/env python3
"""Golden-test the namespace-detail dashboard queries without a live account.

Regression guard for the multi-region identity bug: a namespace is identified
by (id, region), so a query that filters on id alone merges rows from two
regions and can report "Tenant Isolation: ready" for a region where the ACL
attribute is not filterable.

Creates an isolated `qa_dash` schema (the control fixture is untouched), runs
every query in dashboards/namespace_detail.pp against it, and asserts the
region-scoped answers.

Usage:
  python3 run_dashboards.py --mod . --dsn postgresql://...
"""
import argparse
import glob
import json
import re
import subprocess
import sys

SCHEMA = "qa_dash"

DDL = f"""
drop schema if exists {SCHEMA} cascade;
create schema {SCHEMA};

create table {SCHEMA}.turbopuffer_namespace (
  id                    text,
  region                text,
  approx_row_count      bigint,
  approx_logical_bytes  bigint,
  created_at            timestamptz,
  updated_at            timestamptz,
  index_unindexed_bytes bigint,
  index_status          text,
  encryption_key_name   text
);

create table {SCHEMA}.turbopuffer_namespace_attribute (
  namespace          text,
  region             text,
  name               text,
  type               text,
  filterable         boolean,
  full_text_search   boolean,
  regex              boolean,
  glob               boolean,
  fuzzy              boolean,
  sparse_vector_index boolean,
  vector_index       boolean
);

-- Same namespace id in two regions with different schemas and sizes: the
-- ACL attribute is filterable only in gcp-us-central1.
insert into {SCHEMA}.turbopuffer_namespace
  (id, region, approx_row_count, approx_logical_bytes, created_at, updated_at,
   index_unindexed_bytes, index_status, encryption_key_name)
values
  ('dup-ns', 'gcp-us-central1', 10, 1073741824, now(), now(), 0, 'up-to-date', null),
  ('dup-ns', 'aws-eu-central-1', 20, 2147483648, now(), now(), 0, 'up-to-date', null);

insert into {SCHEMA}.turbopuffer_namespace_attribute
  (namespace, region, name, type, filterable, full_text_search, regex, glob,
   fuzzy, sparse_vector_index, vector_index)
values
  ('dup-ns', 'gcp-us-central1', 'tenant_id', 'string', true , false, false, false, false, false, false),
  ('dup-ns', 'gcp-us-central1', 'body',      'string', false, true , false, false, false, false, false),
  ('dup-ns', 'aws-eu-central-1', 'tenant_id', 'string', false, false, false, false, false, false, false);
"""

QUERY_RE = re.compile(r'query\s+"([^"]+)"\s*\{(.*?)\n\}', re.S)
SQL_RE = re.compile(r'sql\s*=\s*<<-EOQ\n(.*?)\n\s*EOQ', re.S)

# query -> ordered param values ("" means: skip, use the selector output)
PARAMS = {
    "tpuf_namespace_input": [],
    "tpuf_detail_rows": ["dup-ns|aws-eu-central-1"],
    "tpuf_detail_size": ["dup-ns|aws-eu-central-1"],
    "tpuf_detail_last_write": ["dup-ns|aws-eu-central-1"],
    "tpuf_detail_encryption": ["dup-ns|aws-eu-central-1"],
    "tpuf_detail_isolation": ["dup-ns|aws-eu-central-1", json.dumps(["tenant_id"])],
    "tpuf_detail_attributes": ["dup-ns|aws-eu-central-1"],
}


def sql_literal(v):
    return "'" + str(v).replace("'", "''") + "'"


def bind(sql, values):
    return re.sub(r"\$(\d+)", lambda m: sql_literal(values[int(m.group(1)) - 1]), sql)


def run(dsn, sql):
    out = subprocess.run(
        ["psql", dsn, "-X", "-q", "-A", "-F", "\t", "-t",
         "-v", "ON_ERROR_STOP=1", "-c", f"set search_path to {SCHEMA}; {sql}"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip().splitlines()[0] if out.stderr else "psql failed")
    return [line.split("\t") for line in out.stdout.splitlines() if line]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--mod", default=".")
    args = ap.parse_args()

    ddl = subprocess.run(
        ["psql", args.dsn, "-X", "-q", "-v", "ON_ERROR_STOP=1", "-c", DDL],
        capture_output=True, text=True,
    )
    if ddl.returncode != 0:
        print("FAIL fixture setup: " + ddl.stderr.strip().splitlines()[0])
        return 1

    queries = {}
    for path in sorted(glob.glob(f"{args.mod}/dashboards/*.pp")):
        text = open(path).read()
        for name, body in QUERY_RE.findall(text):
            m = SQL_RE.search(body)
            if m:
                queries[name] = m.group(1)
    for name in PARAMS:
        if name not in queries:
            print(f"FAIL query {name} not found")
            return 1

    failures, checked = [], 0

    def check(desc, got, want):
        nonlocal checked
        checked += 1
        if got != want:
            failures.append(f"{desc}: expected {want!r}, got {got!r}")

    def one(name, values, col=0):
        if isinstance(values, str):
            values = [values]
        rows = run(args.dsn, bind(queries[name], values))
        return rows[0][col] if rows else None

    # 1. The selector must offer one option per (id, region), not per id.
    sel = run(args.dsn, queries["tpuf_namespace_input"])
    check("selector options", sorted(r[1] for r in sel),
          ["dup-ns|aws-eu-central-1", "dup-ns|gcp-us-central1"])

    # 2. The regression: each region gets its own verdict. Before the fix the
    #    EU (non-filterable) region reported 'ready' because the US row merged in.
    check("isolation us-central1", one("tpuf_detail_isolation", ["dup-ns|gcp-us-central1", json.dumps(["tenant_id"])]), "ready")
    check("isolation eu-central1", one("tpuf_detail_isolation", ["dup-ns|aws-eu-central-1", json.dumps(["tenant_id"])]), "NOT enforceable")
    # A bare id must not produce a green verdict: filtering on id alone is what
    # merged the two regions. Post-fix it matches nothing (empty, not "ready").
    check("isolation bare id not ready", one("tpuf_detail_isolation", ["dup-ns", json.dumps(["tenant_id"])]), "NOT enforceable")

    # 3. Cards must not mix regions (row counts and sizes differ per region).
    check("rows eu-central1", one("tpuf_detail_rows", "dup-ns|aws-eu-central-1"), "20")
    check("rows us-central1", one("tpuf_detail_rows", "dup-ns|gcp-us-central1"), "10")
    check("size eu-central1", one("tpuf_detail_size", "dup-ns|aws-eu-central-1"), "2.00 GB")

    # 4. The attribute table must show only the selected region's schema.
    check("attributes eu-central1", len(run(args.dsn, bind(queries["tpuf_detail_attributes"], ["dup-ns|aws-eu-central-1"]))), 1)
    check("attributes us-central1", len(run(args.dsn, bind(queries["tpuf_detail_attributes"], ["dup-ns|gcp-us-central1"]))), 2)

    print(f"dashboard queries run: {len(queries)}  assertions: {checked}  failures: {len(failures)}")
    for f in failures:
        print("FAIL " + f)
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as e:
        print("FAIL SQL ERROR: " + str(e))
        sys.exit(1)
