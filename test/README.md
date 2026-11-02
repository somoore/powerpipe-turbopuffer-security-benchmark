# Offline test fixtures

Proves the mod's SQL parses and returns the intended results against a fixture
schema, with **no** turbopuffer credentials and no calls to the turbopuffer API.

| File | What it does |
|------|--------------|
| `fixture.sql` | Minimal tables/columns the controls reference, plus a row for each branch of every control. |
| `run_controls.py` | Extracts each `sql = <<-EOQ … EOQ` from `controls/*.pp`, binds the `$n` params from `variables.pp`, runs it, asserts expected statuses. |
| `run_dashboards.py` | Runs every query in `dashboards/namespace_detail.pp` in an isolated `qa_dash` schema and asserts the multi-region identity fix (same id in two regions → per-region verdicts). |
| `checks-guard.sh` | Self-test for `ci/checks.sh`: both key shapes detected, identifiers not flagged, fails closed outside a work tree, key never echoed. |
| `run.sh` | Disposable `postgres:16` container + the two python suites. |

## Run

```bash
./test/run.sh          # docker + python3; expect 16 controls / 29 assertions / 0 failures
./test/checks-guard.sh # no dependencies beyond git + bash
```

CI runs the same commands (a `postgres:16` service job plus the guard test).

## Why

`powerpipe mod list` does **not** load or execute control SQL, so it passes on
broken HCL and broken SQL alike. `powerpipe benchmark list` (the CI gate) catches
bad HCL; only these fixtures catch a wrong table/column name, a broken `$n`
binding, or a status-logic regression.

## Extending

Add a row to `fixture.sql`, then an expectation in `EXPECTED` in
`run_controls.py`. Verify each new assertion **fails before** the fix and passes
after — otherwise the test proves nothing.
