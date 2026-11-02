#!/usr/bin/env bash
# Pre-commit safety checks for the turbopuffer Powerpipe mod:
#   1. Mod parses (powerpipe can load benchmarks/controls without error)
#   2. No secrets committed (trufflehog / gitleaks, whichever is installed)
#   3. No .env / credential files in the tree
#
# Blocking checks exit non-zero. Run standalone with: ./ci/checks.sh
set -uo pipefail

# Fail closed: without a work tree every check below would silently run in the
# caller's directory and report success. Note `cd ""` succeeds in bash, so the
# empty result has to be tested explicitly — a plain `cd "$(...)" || exit` does
# not fire.
top=$(git rev-parse --show-toplevel 2>/dev/null) || top=""
if [ -z "$top" ]; then
  echo "not a git work tree — nothing was checked" >&2
  exit 1
fi
cd "$top" || {
  echo "cannot enter repository root: $top" >&2
  exit 1
}
fail=0

say()  { printf '\n\033[1m== %s\033[0m\n' "$1"; }
bad()  { printf '\033[31m  FAIL: %s\033[0m\n' "$1"; fail=1; }
ok()   { printf '\033[32m  ok: %s\033[0m\n' "$1"; }
warn() { printf '\033[33m  warn: %s\033[0m\n' "$1"; }

# A turbopuffer key is either a flat `tpuf_<payload>` token or a segmented key
# such as `tpuf_prod_<payload>`. Both shapes must match; identifiers like
# `tpuf_encryption_mix` (short trailing segment, no long payload) must not.
KEY_RE='tpuf_[A-Za-z0-9]{20,}|tpuf_[A-Za-z0-9]+_[A-Za-z0-9]{16,}'

#### 1. Mod parses #############################################################
say "mod parses"
if command -v powerpipe >/dev/null 2>&1; then
  # `benchmark list` forces powerpipe to load and validate every .pp file.
  # (`mod list` merely lists the mod and passes on invalid HCL.)
  if powerpipe benchmark list >/dev/null 2>&1; then
    ok "powerpipe loads the mod (benchmarks/controls/dashboards valid)"
  else
    bad "powerpipe failed to load the mod — run: powerpipe benchmark list"
  fi
else
  warn "powerpipe not installed — skipping mod-parse check"
fi

#### 2. No secrets committed ###################################################
say "secret scan"
if command -v trufflehog >/dev/null 2>&1; then
  if trufflehog filesystem . --no-update --only-verified --fail >/dev/null 2>&1; then
    ok "trufflehog: no verified secrets"
  else
    bad "trufflehog found verified secret(s) — run: trufflehog filesystem . --only-verified"
  fi
elif command -v gitleaks >/dev/null 2>&1; then
  if gitleaks detect --source . --no-git --no-banner >/dev/null 2>&1; then
    ok "gitleaks: no leaks"
  else
    bad "gitleaks found secret(s) — run: gitleaks detect --source ."
  fi
elif [ -n "${CI:-}" ]; then
  # A CI run that cannot scan must not report a green secret check.
  bad "neither trufflehog nor gitleaks installed — refusing to pass the secret scan in CI"
else
  warn "neither trufflehog nor gitleaks installed — skipping secret scan (brew install trufflehog)"
fi

#### 3. No .env / credential files #############################################
say "no credential files in tree"
env_hits=$(git ls-files -co --exclude-standard \
  | grep -E '(^|/)\.env($|\.)|(^|/).*\.spc$|(^|/)credentials(\.|$)|\.pem$|\.p12$|id_rsa' || true)
if [ -n "$env_hits" ]; then
  bad "credential-shaped files present (add to .gitignore or remove):"
  while IFS= read -r hit; do printf '    %s\n' "$hit"; done <<< "$env_hits"
else
  ok "no .env / key / credential files"
fi
# Belt and suspenders: reject the turbopuffer key pattern anywhere in tracked
# text. Report file:line only — echoing the match would print the key.
key_hits=$(git grep -nIE "$KEY_RE" -- . | cut -d: -f1,2 || true)
if [ -n "$key_hits" ]; then
  bad "a turbopuffer API key (tpuf_...) appears in the tree:"
  while IFS= read -r hit; do printf '    %s\n' "$hit"; done <<< "$key_hits"
fi

echo
if [ "$fail" -ne 0 ]; then
  printf '\033[31mCHECKS FAILED\033[0m\n'
  exit 1
fi
printf '\033[32mall checks passed\033[0m\n'
