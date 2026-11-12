#!/usr/bin/env bash
# Backup and restore drill, run locally (wrangler dev, local D1 and R2):
#   drills/restore-drill.sh            (from control-plane/, after npm ci)
# 1. a Worker on fresh storage gets a tenant, a policy and an audit chain;
# 2. D1 is exported to SQL and the R2 data copied: the backup;
# 3. a second Worker starts on a new database restored from that SQL;
# 4. drill.mjs verify checks everything came back and still works.
# The production procedure (D1 Time Travel, R2 copies) is in docs/runbooks.md;
# this proves the parts that do not need Cloudflare: a restored database runs
# the Worker, its encrypted signing keys still decrypt, and evidence still
# verifies against heads recorded before the backup.
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
stop() { pkill -f "wrangler dev --env local --ip 127.0.0.1 --port $1" 2>/dev/null || true; sleep 1; }
trap 'stop 8791; stop 8792; rm -rf "$work"' EXIT
export CI=1 NO_PROXY='*' no_proxy='*'
kek=$(openssl rand -base64 32)
printf 'PLATFORM_ADMIN_TOKEN="drill-platform"\nKEY_ENCRYPTION_KEY="%s"\n' "$kek" > "$work/dev.vars"

# Each store is its own directory holding a copy of the wrangler config, so
# wrangler's local D1 commands (which take --cwd, not --persist-to) and
# wrangler dev (--persist-to) both use <dir>/.wrangler/state.
store() {
  mkdir -p "$work/$1"
  cp wrangler.jsonc "$work/$1/"
  cp -R migrations "$work/$1/"
}

serve() { # store, port
  if curl -s "http://127.0.0.1:$2/healthz" > /dev/null; then echo "port $2 is already in use"; exit 1; fi
  npx wrangler dev --env local --ip 127.0.0.1 --port "$2" --persist-to "$work/$1/.wrangler/state" \
    --env-file "$work/dev.vars" --log-level warn > "$work/wrangler-$2.log" 2>&1 &
  for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$2/healthz" > /dev/null && return; sleep 1; done
  cat "$work/wrangler-$2.log"; exit 1
}

echo "== source: fresh storage"
store source
npx wrangler d1 migrations apply DB --local --env local --cwd "$work/source" > /dev/null
serve source 8791
node drills/drill.mjs seed http://127.0.0.1:8791 drill-platform "$work/state.json"
stop 8791

echo "== backup: D1 exported to SQL, R2 objects copied"
npx wrangler d1 export DB --local --env local --cwd "$work/source" --output "$work/d1.sql" > /dev/null
echo "   $(grep -c '^INSERT' "$work/d1.sql") rows in the export"
store restored
mkdir -p "$work/restored/.wrangler/state/v3"
cp -R "$work/source/.wrangler/state/v3/r2" "$work/restored/.wrangler/state/v3/r2"

echo "== restore: a new, empty database loaded from the SQL alone"
npx wrangler d1 execute DB --local --env local --cwd "$work/restored" --file "$work/d1.sql" --yes > /dev/null
serve restored 8792
node drills/drill.mjs verify http://127.0.0.1:8792 "$work/state.json"
