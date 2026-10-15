#!/bin/sh
# Run from any directory; docker build also runs --local inside the final image.
set -eu
if [ "${1:-}" != --local ]; then
    exec docker build --progress=plain -t nanosiem-web:cache-check "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
fi

scratch=$(mktemp -d)
nginx -g 'daemon off;' >"$scratch/nginx.log" 2>&1 &
nginx_pid=$!
cleanup() {
    kill "$nginx_pid" 2>/dev/null || true
    wait "$nginx_pid" 2>/dev/null || true
    rm -rf "$scratch"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
base=http://127.0.0.1:5173
ready=false
for attempt in 1 2 3 4 5; do
    if curl -fsS "$base/index.html" -o "$scratch/index.html" 2>/dev/null; then
        ready=true
        break
    fi
    sleep 1
done
if [ "$ready" != true ]; then cat "$scratch/nginx.log"; exit 1; fi

check() {
    path=$1 expected=$2 status=${3:-200}
    actual_status=$(curl -sS --max-time 10 -D "$scratch/headers" -o "$scratch/body" -w '%{http_code}' "$base$path")
    actual=$(awk 'tolower($1) == "cache-control:" {sub(/^[^:]*: */, ""); sub(/\r$/, ""); print}' "$scratch/headers")
    if [ "$actual_status" != "$status" ] || [ "$actual" != "$expected" ]; then
        echo "FAIL $path: status=$actual_status Cache-Control='$actual' (expected $status '$expected')" >&2
        exit 1
    fi
    echo "PASS $path: $status Cache-Control: ${actual:-<absent>}"
}
for path in / /index.html /cache-check/deep/route; do
    check "$path" no-cache
    cmp "$scratch/index.html" "$scratch/body"
done
# Check every shipped non-hashed entry (includes manifest / service worker if added).
find /usr/share/nginx/html -type f ! -path '*/assets/*' | while IFS= read -r file; do
    check "${file#/usr/share/nginx/html}" no-cache
done
asset=$(find /usr/share/nginx/html/assets -type f -name '*.js' | head -n 1)
[ -n "$asset" ] || { echo 'No built JavaScript asset found' >&2; exit 1; }
check "${asset#/usr/share/nginx/html}" 'public, max-age=31536000, immutable'
# A removed chunk must be a 404, never immutable HTML from the SPA fallback.
check /assets/cache-check-missing.js '' 404
etag=$(curl -sSI "$base/index.html" | awk 'tolower($1) == "etag:" {sub(/^[^:]*: */, ""); sub(/\r$/, ""); print}')
[ -n "$etag" ]
status=$(curl -sS --max-time 10 -D "$scratch/headers" -o /dev/null -w '%{http_code}' -H "If-None-Match: $etag" "$base/index.html")
[ "$status" = 304 ]
awk 'tolower($0) == "cache-control: no-cache\r" {found=1} END {exit !found}' "$scratch/headers"
echo 'PASS /index.html: 304 Cache-Control: no-cache'
