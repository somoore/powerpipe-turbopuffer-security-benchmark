#!/usr/bin/env bash
# Run the offline fixtures: all 16 controls + the namespace-detail dashboard
# queries against a disposable Postgres container.
#
# No turbopuffer account, no credentials, no production contact.
#
# Requires: docker, python3.  Usage:
#   ./test/run.sh            # test the repo this script lives in
#   ./test/run.sh <mod-dir>  # test another checkout
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
MOD="${1:-$(cd "$HERE/.." && pwd)}"
CTR=qa-tpuf-pg
WORK="$(mktemp -d)"
trap 'docker rm -f "$CTR" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 2; }

# psql wrapper: run the client inside the fixture container.
cat > "$WORK/psql" <<EOF
#!/bin/sh
exec docker exec -i $CTR psql "\$@"
EOF
chmod +x "$WORK/psql"

docker rm -f "$CTR" >/dev/null 2>&1 || true
docker run -d --name "$CTR" \
  -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_PASSWORD=x -e POSTGRES_DB=qa \
  postgres:16 >/dev/null

for _ in $(seq 1 30); do
  docker exec "$CTR" pg_isready -U postgres -d qa >/dev/null 2>&1 && break
  sleep 1
done

docker exec -i "$CTR" psql -U postgres -d qa -q -v ON_ERROR_STOP=1 < "$HERE/fixture.sql"
PATH="$WORK:$PATH" python3 "$HERE/run_controls.py" --mod "$MOD" --dsn "postgresql://postgres@localhost/qa"
PATH="$WORK:$PATH" python3 "$HERE/run_dashboards.py" --mod "$MOD" --dsn "postgresql://postgres@localhost/qa"
