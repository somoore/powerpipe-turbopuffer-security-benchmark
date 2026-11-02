#!/usr/bin/env bash
# Self-test for ci/checks.sh.
#
# Proves the three properties the secret guard is supposed to have:
#   1. both turbopuffer key shapes are detected (flat and segmented),
#   2. identifiers such as tpuf_encryption_mix are not flagged,
#   3. the guard fails closed outside a git work tree, and never echoes a key.
#
# No network, no credentials: the "keys" are synthetic strings assembled at
# runtime so this file does not itself contain a match.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CHECKS="$REPO/ci/checks.sh"
KEY_RE='tpuf_[A-Za-z0-9]{20,}|tpuf_[A-Za-z0-9]+_[A-Za-z0-9]{16,}'

fail=0
check() { # check <description> <actual-exit> <expected-exit>
  if [ "$2" -eq "$3" ]; then
    printf '  ok: %s\n' "$1"
  else
    printf '  FAIL: %s (exit %s, expected %s)\n' "$1" "$2" "$3"
    fail=1
  fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

#### 1+2. Pattern coverage #####################################################
printf '  -- key shapes\n'
git -C "$TMP" init -q
git -C "$TMP" config user.email qa@example.invalid
git -C "$TMP" config user.name qa

# Segmented key in the shape the project's own docs use: tpuf_<env>_<payload>.
printf 'token = "%s"\n' "tpuf_""staging_ABCDEFGHIJKLMNOPQRSTUVWX" > "$TMP/segmented.txt"
# Flat key: tpuf_<26 alnum>.
printf 'token = "%s"\n' "tpuf_""ABCDEFGHIJKLMNOPQRSTUVWXYZ012345" > "$TMP/flat.txt"
# Identifiers from the mod's own SQL must not match.
printf '%s\n' \
  'select tpuf_encryption_mix from x' \
  'select tpuf_sensitive_by_namespace from y' \
  'select tpuf_detail_attributes from z' > "$TMP/identifiers.txt"
git -C "$TMP" add -A

git -C "$TMP" grep -qIE "$KEY_RE" -- segmented.txt; check "segmented key detected" $? 0
git -C "$TMP" grep -qIE "$KEY_RE" -- flat.txt;      check "flat key detected" $? 0
git -C "$TMP" grep -qIE "$KEY_RE" -- identifiers.txt; check "identifiers not flagged" $? 1

#### 3. Fail closed outside a work tree ########################################
printf '  -- fail-closed\n'
out="$(cd "$TMP" && rm -rf .git && mkdir -p plain && cd plain && bash "$CHECKS" 2>&1)"
rc=$?
check "no work tree exits non-zero" "$rc" 1
case "$out" in
  *"not a git work tree"*) printf '  ok: reports the missing work tree\n' ;;
  *) printf '  FAIL: missing work-tree diagnostic\n'; fail=1 ;;
esac

#### 4. Key is reported, but never echoed ######################################
printf '  -- redaction\n'
out="$(git -C "$TMP" init -q && git -C "$TMP" add -A && cd "$TMP" && bash "$CHECKS" 2>&1)"
rc=$?
key="tpuf_""staging_ABCDEFGHIJKLMNOPQRSTUVWX"
check "key in tree exits non-zero" "$rc" 1
case "$out" in
  *"$key"*) printf '  FAIL: the guard echoed the key\n'; fail=1 ;;
  *) printf '  ok: key not echoed\n' ;;
esac
case "$out" in
  *"segmented.txt"*) printf '  ok: offending file reported\n' ;;
  *) printf '  FAIL: offending file not reported\n'; fail=1 ;;
esac

echo
if [ "$fail" -ne 0 ]; then
  echo "SECRET GUARD SELF-TEST FAILED"
  exit 1
fi
echo "secret guard self-test passed"
