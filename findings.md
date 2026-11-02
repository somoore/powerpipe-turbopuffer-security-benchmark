# Security findings — powerpipe-turbopuffer-security-benchmark

| | |
|---|---|
| **Scanned** | `powerpipe-turbopuffer-security-benchmark` @ `7188c2e` (26 tracked files: Powerpipe HCL mod of 16 controls + 2 dashboards, 2 GitHub Actions workflows, bash guard/hooks, docs) |
| **Date** | 2026-11-02 |
| **Tools** | semgrep, trivy (+config), shellcheck 0.11.0, gitleaks 8.30.1, trufflehog 3.95.8, actionlint, `powerpipe` 1.5.2 / `steampipe` 2.4.4, docker `postgres:16`, `gh` |
| **Team roles** | `01-pm` (scope/threat model), `02-appsec` (breadth), `03-pentest` (exploitability), `04-devil` (adjudication/fix risk), `05-qa` (verification harness) |

Repo shape drives every verdict: there is no service, no listener, no parser and no credential in
the tree. The attack surface is the GitHub Actions workflows, the developer gate (`ci/checks.sh`,
hooks), and the read-only SQL the mod runs in a consumer's Steampipe database. No finding is
CRITICAL or HIGH; the check that gates auto-merge was a no-op, which is why that one mattered.

Status key: `FIXED` (verification below actually passes), `MITIGATED` (partial), `ACCEPTED RISK`,
`FALSE POSITIVE`, `DEFERRED`.

| ID | Severity | Status | Location | Issue | Fix | Verification |
|---|---|---|---|---|---|---|
| F-01 | MEDIUM | FIXED | `.github/workflows/dependabot-auto-merge.yml:9-25`, `.github/workflows/ci.yml` | Dependabot PRs auto-merge patch/minor while `dependabot/fetch-metadata@v3` is a mutable tag, the job holds `contents: write` + `pull-requests: write`, and the token is handed to the third-party action. Upstream tag repoint → merge/push authority. (DA-03, APP-SEC-02/03, PT-SEC-01/02, semgrep ×2) | Pin `fetch-metadata` to `25dd0e3…` (`v3.1.0`); `permissions: {}` at workflow level, job gets `contents: read` + `pull-requests: write` only; drop the explicit `github-token` input (defaults to `GITHUB_TOKEN`). `gh pr merge --auto` needs no `contents: write` — GitHub performs the merge server-side. | `grep -rnE 'uses:[[:space:]]*[^#]+@(v[0-9]+\|main\|master)' .github/workflows` → no matches; `grep -rhoE 'uses:[^#]*@[0-9a-f]{40}' .github/workflows \| wc -l` → 3; `actionlint` → exit 0; YAML parse → OK |
| F-02 | MEDIUM | FIXED | `.github/workflows/ci.yml:19-30` | `curl -sSL https://powerpipe.io/install/powerpipe.sh \| sudo -E bash`: unpinned remote script executed as root on every run, no checksum, no `--fail`, caller env carried into the root shell. (DA-06, APP-SEC-01, PT-SEC-03) | Download a pinned release archive with `curl --fail --proto '=https' --tlsv1.2`, verify a pinned SHA-256, extract to `$HOME/.local/bin`, no `sudo`. Same pattern for a pinned `gitleaks` so CI's secret scan is real. | Install step run verbatim with `HOME`/`RUNNER_TEMP` redirected: `powerpipe.linux.amd64.tar.gz: OK`, binary extracted, `GITHUB_PATH` updated; a tampered digest exits 1. Checksums re-derived from each release's published checksums file. `grep -rn 'curl .*\|.*sudo' .github/workflows` → none |
| F-03 | MEDIUM | FIXED | `.github/workflows/ci.yml:70-75` | The only *required* check ran `powerpipe mod list`, which lists the mod and exits 0 on invalid HCL. Any broken PR got a green "mod validation". (QA-01) | Run `powerpipe benchmark list` (loads/validates every `.pp`) after `mod list`. | Clean tree: both exit 0. Copy with `control "broken" { title =`: `mod list` exit 0, `benchmark list` exit **255** with file/line — the job now fails |
| F-04 | MEDIUM | FIXED | `dashboards/namespace_detail.pp:74-193`, `dashboards/home.pp:171` | Selector value was the bare namespace `id`; every detail query filtered on `namespace`/`id` without `region`. A namespace present in two regions merged attribute rows, so `bool_or(a.filterable)` reported "Tenant Isolation: ready" for a region where the ACL attribute is not filterable. (APP-SEC-04, QA-03, PM R4) | Selector value is `id \|\| '\|' \|\| region`; all seven queries split it (`split_part($1,'\|',1/2)`) and filter `region`/`a.region`; drill-through href passes the region too (`…\|@uri}}%7C{{.'Region' \| @uri}}`). Param count and `args` contract unchanged. | `./test/run.sh` → `dashboard queries run: 18  assertions: 9  failures: 0`. Same test on the pre-fix dashboards → **8 failures**, including `isolation bare id not ready: expected 'NOT enforceable', got 'ready'` |
| F-05 | LOW | FIXED | `.github/workflows/ci.yml:36,110` | `actions/checkout@v7` mutable tag (semgrep `github-actions-mutable-action-tag`; DA-02) | Pin to `3d3c42e…` (`v7.0.1`) in both jobs. | Same pin checks as F-01; Dependabot keeps SHA pins current |
| F-06 | LOW | FIXED | `.github/dependabot.yml` | No `cooldown`, no PR limit: an action release published minutes ago could be proposed and auto-merged. (semgrep `dependabot-missing-cooldown`; DA-01, APP-SEC-08) | `cooldown.default-days: 7`, `open-pull-requests-limit: 5`. | `grep -A2 cooldown .github/dependabot.yml` → `default-days: 7`; YAML parses |
| F-07 | LOW | FIXED | `ci/checks.sh:8-18`, `ci/hooks/pre-commit:6`, `ci/hooks/pre-push:7` | Guard failed open: `set -uo pipefail` without `-e`, and `cd "$(git rev-parse --show-toplevel)"` — outside a work tree `cd ""` **succeeds** in bash, so every check ran inert and the script printed "all checks passed", exit 0. The naive `cd … \|\| exit 1` fix does not fire. (DA-04, QA-05, PT-SEC-05, APP-SEC-07a, shellcheck SC2164) | Capture the root, reject an empty result explicitly, then `cd`; same idiom in both hooks. A CI run with no secret scanner now fails instead of warning. | `cd $(mktemp -d) && PATH=/usr/bin:/bin bash …/ci/checks.sh` → `not a git work tree — nothing was checked`, exit **1**. In-repo `./ci/checks.sh` → exit 0. Hook test: planted key → commit aborted |
| F-08 | LOW | FIXED | `ci/checks.sh:30-36,79-88`, `.github/workflows/ci.yml:87-92` | Secret gate matched only `tpuf_[A-Za-z0-9]{20,}`, so a segmented key (`tpuf_staging_<payload>`, the shape the project's own docs use) slipped through; CI re-implemented a *narrower* file-shape check by hand, and the guard echoed the matching line (the key) to the terminal. (QA-04, PT-SEC-04, DA-08, APP-SEC-07b) | Pattern is now `tpuf_[A-Za-z0-9]{20,}\|tpuf_[A-Za-z0-9]+_[A-Za-z0-9]{16,}` in one place; hits are reported as `file:line` only; CI calls `./ci/checks.sh` instead of a divergent copy, and installs pinned `gitleaks` so a real scanner runs. | `./test/checks-guard.sh` → 8/8 ok: segmented + flat keys detected, `tpuf_encryption_mix`/`tpuf_sensitive_by_namespace`/`tpuf_detail_attributes` not flagged, fail-closed, key **not** echoed. Guard on the repo → clean |
| F-09 | LOW | FIXED | `controls/*.pp`, `ci/` | Nothing executed control SQL; a dropped plugin column or bad cast passed every gate and only failed for a user on a live account. (QA-02) | Add the offline fixture harness (`test/`: `fixture.sql`, `run_controls.py`, `run_dashboards.py`, `run.sh`) and a CI job with a `postgres:16` service. No credentials, no network to turbopuffer. | `./test/run.sh` → `controls run: 16  assertions: 29  failures: 0` (+ 9 dashboard assertions). Negative: renaming a table in a scratch copy makes the harness exit 1 |
| F-10 | LOW | MITIGATED | `README.md:59-95` | Install docs pulled an unsigned plugin binary from `…/releases/latest`, pulled `turbopuffer.spc` from plugin `main`, and `powerpipe mod install` tracks `main`; a compromised upstream swaps the config a user pastes an API key into. (DA-09, APP-SEC-09) | Pin plugin version `v0.0.6`, verify the release's `SHA256SUMS` before `gunzip`, fetch the sample `.spc` from the same tag, add an explicit "read `api_key`/`regions` before saving" warning. Residual: this repo has no release tag, so `mod install` still tracks `main` (documented in README). | Checksum re-derived from the v0.0.6 `SHA256SUMS` and verified against the downloaded asset (`shasum -a 256` match); config file at that tag reviewed (keys: `api_key`, `regions`) |
| F-11 | INFO | FIXED | `ci/hooks/*`, `README.md` | Hooks only run after `git config core.hooksPath ci/hooks`, which is not shipped; a fresh clone silently had no local gate and the README never said so. (DA-10, PT-SEC-06) | README section with the bootstrap command, the standalone `./ci/checks.sh` / `./test/checks-guard.sh` commands, and an explicit note that CI + branch protection are the real gates. | `grep -n core.hooksPath README.md` → documented; fresh-clone hook test: planted key → commit aborted |
| F-12 | INFO | ACCEPTED RISK | GitHub repo settings | Auto-merge trusts branch protection that is not expressible in git; if `mod validation` were not required, `--auto` would merge immediately. (DA-07) | Not fixable in-repo. QA verified live settings: `mod validation` required (strict), force-push/deletion blocked. Owner action after merge: enable "Require actions to be pinned to a full-length commit SHA" (`sha_pinning_required` is still `false`). | `gh api repos/…/branches/main/protection` (QA, 2026-11-02); re-check post-merge |
| F-13 | LOW | DEFERRED | `controls/tenant_isolation.pp:53-54,86-87,112-113`, `encryption.pp:31,67`, `schema_hygiene.pp:29,57-63,112-113`, `dashboards/namespace_detail.pp:129` | API-sourced identifiers are concatenated raw into `reason`/`value`; a name containing ANSI/CR/LF could forge a green line in CLI/log output. (APP-SEC-06) | Not applied: every fix is inside control SQL, which the review team (DA, QA) fenced off because it changes reported status/reason text and the `ok/alarm/info/skip` contract. Compensating control: Powerpipe HTML-escapes dashboard output; identifiers are API-constrained. | Current behaviour unchanged; see Residual risk |
| F-14 | LOW | ACCEPTED RISK | `controls/*.pp` (`~`/`~*` on `var.*` patterns), `variables.pp` | Operator-supplied regexes are bound as `$n` (not injectable) but a pathological pattern can pin the Steampipe/Postgres backend. Trusted input only. (APP-SEC-05) | None. Postgres ARE is non-backtracking; patterns are set by the person running the audit. Documented here; do not silently cap them. | Static review: all 16 SQL blocks bind `$1..$n`, no interpolation |
| F-15 | INFO | ACCEPTED RISK | `ci/checks.sh`, `ci/hooks/pre-push` | `trufflehog --only-verified` sends credential-shaped candidates to issuing providers from a developer machine. (APP-SEC-10) | None — that is how verification works, and the hooks are opt-in. CI now uses pinned `gitleaks` (offline) as well. | n/a |
| F-16 | INFO | FIXED | `ci/checks.sh:55`, `.github/workflows/ci.yml:78-79` | ShellCheck exited 1 on the repo's own script (SC2164 + SC2001) so a lint gate could not be added. (QA-06) | SC2164 fixed by F-07; SC2001 removed by replacing `sed` with a read loop. Added a `shellcheck` step (preinstalled on `ubuntu-latest`). `actionlint` verified locally but not added to CI (not preinstalled). | `shellcheck ci/checks.sh ci/hooks/* test/*.sh` → exit **0**; `actionlint` → exit 0 |
| F-17 | LOW | MITIGATED | `mod.pp:13-17`, `README.md` | Toolchain/plugin versions were unpinned, so "validated" meant "validated against whatever is latest today". (QA-07) | CI now pins `powerpipe` 1.5.7 and `gitleaks` 8.30.1 by version + SHA-256. Plugin floor (`min_version = "0.0.1"`) left as-is per review instruction; README pins the documented install to a release tag. | `grep -nE 'POWERPIPE_VERSION\|GITLEAKS_VERSION' .github/workflows/ci.yml`; install dry-run verified (F-02) |
| F-18 | INFO | FALSE POSITIVE | `ci/checks.sh:55` | ShellCheck SC2001 (`sed` → `${var//}`) is style only; the input is `git ls-files` output, not attacker-controlled. (DA-05) | None required; the `sed` was replaced with a `while read` loop while editing the block, so the warning is gone anyway. | `shellcheck` exit 0 |
| F-19 | INFO | FALSE POSITIVE | `README.md`, `CLAUDE.md`, `controls/*.pp` descriptions | Marketing/assurance wording ("all read-only", "tested against a live account", "no PII") is not a vulnerability. The substantive over-claims (residency sees only configured regions; `…_filterable` emits no row for a missing attribute; drift compares same-region pairs only; `max_unindexed_bytes=0` alarms on any lag; sensitive-data detection is name-only) are documented design limits. (DA-11 + over-claims 1-5) | Not "fixed": changing these changes reported statuses and breaks the `ok/alarm/info/skip` contract consumers rely on. Recorded as residual risk instead. | Reviewed against `controls/` + `variables.pp`; no code change |
| F-20 | INFO | FALSE POSITIVE | `trivy*.json`, `semgrep.json` | Zero trivy results are vacuous (no lockfile, no IaC) and semgrep loaded no HCL rules (`rules_selected_ratio ≈ 0.097`); scanner silence here is not evidence of absence. | No finding to fix; treated as coverage limits in this report. | Report metadata (QA/DA) |
| F-21 | INFO | FALSE POSITIVE | `dashboards/home.pp:171`, `controls/*.pp` | Reported SQL injection / ReDoS / path traversal / XSS / fork-PR secret exposure: all values reach SQL as `$n` binds, `file()` paths are literals, the href is `@uri`-encoded, and the workflow uses `pull_request` (not `pull_request_target`) with a server-set actor gate. | None — verified absent; "hardening" these would create the bug. | Static review of all 16 SQL blocks and the workflow trigger (APP-SEC/PT/QA agree) |

## Verification commands (run from the repo root on 2026-11-02)

| Command | Result |
|---|---|
| `powerpipe mod list && powerpipe benchmark list && powerpipe control list && powerpipe dashboard list` | exit 0; 1 benchmark, 16 controls, 2 dashboards |
| `./ci/checks.sh` | exit 0, `all checks passed` |
| `cd "$(mktemp -d)" && bash <repo>/ci/checks.sh` | exit **1**, `not a git work tree — nothing was checked` |
| `./test/checks-guard.sh` | exit 0, `secret guard self-test passed` (8 checks) |
| `./test/run.sh` | exit 0, `controls run: 16  assertions: 29  failures: 0`; `dashboard queries run: 18  assertions: 9  failures: 0` |
| pre-fix `run_dashboards.py` against `git show HEAD:dashboards/…` | exit 1, **8 failures**, incl. `bare id … expected 'NOT enforceable', got 'ready'` |
| `shellcheck ci/checks.sh ci/hooks/pre-commit ci/hooks/pre-push test/checks-guard.sh test/run.sh` | exit 0 |
| `actionlint` | exit 0 |
| `ruby -ryaml -e 'ARGV.each{\|f\| YAML.load_file(f)}' .github/workflows/*.yml .github/dependabot.yml` | exit 0 |
| `gitleaks detect --source . --no-banner` | `no leaks found` (12 commits) |
| `grep -rnE 'uses:.*@(v[0-9]+\|main\|master)' .github/workflows` | no matches (3/3 `uses:` are 40-hex pins) |
| CI install step, verbatim, with `RUNNER_TEMP`/`HOME` redirected | `OK` + binary extracted; tampered digest → exit 1 |
| Hook test in a scratch clone (`core.hooksPath ci/hooks`), planted segmented key | commit aborted, `leak.txt:1` reported, key not echoed |
| Invalid-HCL copy: `powerpipe benchmark list` | exit **255** (the CI gate now fails as required) |

## Residual risk

- **F-13 (deferred):** identifiers from the turbopuffer API are still concatenated raw into control
  `reason`/`value`. Impact is CLI/log spoofing only (dashboards are HTML-escaped), and the fix lives
  inside control SQL that the review team fenced off. Owner note: the one-expression fix is
  `regexp_replace(<id>, '[[:cntrl:]]', '', 'g')` at the listed sites, if the contract change is accepted.
- **F-14 (accepted):** operator-supplied regexes can still cost a lot of Postgres time. Mitigate in the
  Steampipe connection with `statement_timeout`; no code change, because the input is the auditor's own.
- **F-15 (accepted):** local `trufflehog --only-verified` performs live verification against providers.
  Use `--no-verification` if that egress is not acceptable; CI uses offline `gitleaks`.
- **F-12 / repo settings (owner action):** branch protection is real (required `mod validation`, strict)
  but lives outside git. After merge, enable "Require actions to be pinned to a full-length commit SHA".
  A functional check of the auto-merge job on a real Dependabot PR is only possible post-merge.
- **F-10 (partial):** the mod itself has no release tag, so `powerpipe mod install` still tracks `main`;
  the README says so. Plugin dependency is still a floor (`min_version = "0.0.1"`), deliberately not
  tightened (it would change install behaviour for existing users).
- **F-19 (not fixed):** the controls cannot see namespaces/regions outside the configured connection, the
  `…_filterable` control emits no row for a namespace missing the ACL attribute entirely, schema-drift
  compares only same-region pairs, `max_unindexed_bytes = 0` alarms on any WAL lag, and sensitive-data
  detection is attribute-name-only. A green benchmark is not proof of "no PII" or "approved regions only";
  do not present it as such.
- **No secret was found** in the tree or in 12 commits of history (`gitleaks`, `trufflehog`, manual
  `git log --all -p` grep), so there is nothing to rotate and no history rewrite is proposed.
- **Not changed on purpose:** `controls/**` SQL semantics, `variables.pp` defaults, `mod.pp`
  `min_version`, `pull_request` (not `pull_request_target`) on the auto-merge workflow.
