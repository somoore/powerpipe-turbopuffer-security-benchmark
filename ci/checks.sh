#!/usr/bin/env bash
# Pre-commit safety checks for the turbopuffer Powerpipe mod:
#   1. Mod parses (powerpipe can load benchmarks/controls without error)
#   2. No secrets committed (trufflehog / gitleaks, whichever is installed)
#   3. No .env / credential files in the tree
#
# Blocking checks exit non-zero. Run standalone with: ./ci/checks.sh
set -uo pipefail

cd "$(git rev-parse --show-toplevel)"
fail=0

say()  { printf '\n\033[1m== %s\033[0m\n' "$1"; }
bad()  { printf '\033[31m  FAIL: %s\033[0m\n' "$1"; fail=1; }
ok()   { printf '\033[32m  ok: %s\033[0m\n' "$1"; }
warn() { printf '\033[33m  warn: %s\033[0m\n' "$1"; }

#### 1. Mod parses #############################################################
say "mod parses"
if command -v powerpipe >/dev/null 2>&1; then
  # `benchmark list` forces powerpipe to load and validate every .pp file.
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
else
  warn "neither trufflehog nor gitleaks installed — skipping secret scan (brew install trufflehog)"
fi

#### 3. No .env / credential files #############################################
say "no credential files in tree"
env_hits=$(git ls-files -co --exclude-standard \
  | grep -E '(^|/)\.env($|\.)|(^|/).*\.spc$|(^|/)credentials(\.|$)|\.pem$|\.p12$|id_rsa' || true)
if [ -n "$env_hits" ]; then
  bad "credential-shaped files present (add to .gitignore or remove):"
  echo "$env_hits" | sed 's/^/    /'
else
  ok "no .env / key / credential files"
fi
# Belt and suspenders: reject the turbopuffer key pattern anywhere in tracked text.
if git grep -nI 'tpuf_[A-Za-z0-9]\{20,\}' -- . >/dev/null 2>&1; then
  bad "a turbopuffer API key (tpuf_...) appears in the tree:"
  git grep -nI 'tpuf_[A-Za-z0-9]\{20,\}' -- . | sed 's/^/    /'
fi

echo
if [ "$fail" -ne 0 ]; then
  printf '\033[31mCHECKS FAILED\033[0m\n'
  exit 1
fi
printf '\033[32mall checks passed\033[0m\n'
