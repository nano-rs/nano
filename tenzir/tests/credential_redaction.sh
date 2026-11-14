#!/usr/bin/env bash
# NAN-5352: run the CREDENTIAL REDACTION block of tenzir/pipeline.tql on the
# fixture events in Tenzir itself (the image docker-compose pins), and check
# that no fake credential survives and raw_data keeps its context.
#
#   tenzir/tests/credential_redaction.sh [image]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
image=${1:-$(sed -n 's/^ *image: \(tenzir\/tenzir:[^ ]*\)/\1/p' "$here/../../docker-compose.opensource.yml" | head -1)}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
awk '/CREDENTIAL REDACTION \(NAN-5352/{on=1} on{print} on&&/^drop _nano_j$/{exit}' "$here/../pipeline.tql" > "$work/block.tql"
grep -q '^drop _nano_j' "$work/block.tql" || { echo "redaction block not found in pipeline.tql" >&2; exit 1; }
cp "$here/credential_redaction.ndjson" "$work/in.ndjson"
{ printf 'from_file "/t/in.ndjson" {\n  read_ndjson\n}\n'; cat "$work/block.tql"; printf 'write_ndjson\n'; } > "$work/run.tql"
docker run --rm --network none -v "$work:/t:ro" --entrypoint tenzir "$image" -f /t/run.tql > "$work/out.ndjson"
python3 -I - "$work/out.ndjson" "$work/in.ndjson" <<'PY'
import json, sys
out = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
n_in = sum(1 for l in open(sys.argv[2]) if l.strip())
assert len(out) == n_in, f"{len(out)} events out of {n_in}"
for row in out:
    text = json.dumps(row["event"])
    assert "FAKE-" not in text, f"credential survived: {text}"
    assert row["event"].get("raw_data") == row["want_raw_data"], f"raw_data {row['event'].get('raw_data')!r} != {row['want_raw_data']!r}"
    if row["keep"]:
        assert row["keep"] in text, f"context lost: {text}"
print(f"ok: {len(out)} events, no fake credential, raw_data as expected")
PY
