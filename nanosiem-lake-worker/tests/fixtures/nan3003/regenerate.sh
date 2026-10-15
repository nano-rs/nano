#!/usr/bin/env bash
# NAN-3003 fixtures: run a platform base's REAL `ocsf_lake_storage_prepare` VRL
# (the lake sink stage) in the pinned cell Vector image on two fixture events.
#   regenerate.sh <extracted-base-dir> <out.jsonl>   (BUNDLE_SHA= for an unpinned cell)
# Bases: nanosiem-core/src/parsers/tenant_bundle/testdata/platform-base*.tar.gz.
set -euo pipefail
base=$1 out=$2
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
awk '/^\[transforms.ocsf_lake_storage_prepare\]/{p=1} /^\[sinks\./{p=0} p' "$base/sources/parsers/_ocsf_sink.toml" \
  | sed 's/^inputs = .*/inputs = ["stamp_meta"]/; s/^reroute_dropped = true/reroute_dropped = false/' > "$work/sink.toml"
cat > "$work/harness.toml" <<'T'
[sources.in]
type = "stdin"
decoding.codec = "json"

# Stand-in for the ingress lanes + generic_ocsf_prepare: event metadata the
# lanes set, and the `{source_type, event}` envelope the sink lifts `.event` from.
[transforms.stamp_meta]
type = "remap"
inputs = ["in"]
source = '''
%nano_ingest_id = to_string(.ingest_id) ?? ""
if exists(.credential) { %nano_credential_id = .credential }
del(.ingest_id)
del(.credential)
# stdin-source bookkeeping a real cell never has
del(.host)
del(.timestamp)
del(.source_type)
. = {"source_type": "windows_event", "event": .}
'''

[sinks.out]
type = "console"
inputs = ["ocsf_lake_storage_prepare"]
encoding.codec = "json"
encoding.except_fields = ["_nano_bronze_partition"]
T
cat > "$work/in.jsonl" <<'J'
{"ingest_id":"nan3003-a","credential":"0b7f7a5e-3c1d-4f7e-9a2b-1c2d3e4f5a6b","activity_id":1,"category_uid":6,"class_uid":6003,"type_uid":600301,"severity_id":1,"time":1786437600123,"message":"fixture","api":{"operation":"test"},"actor":{"user":{"name":"TESTER"}},"src_endpoint":{"ip":"10.1.2.3"},"metadata":{"product":{"name":"fixture","vendor_name":"nano"}}}
{"ingest_id":"nan3003-b","activity_id":1,"category_uid":6,"class_uid":6003,"type_uid":600301,"severity_id":1,"time":1786437600456,"message":"fixture-2","api":{"operation":"test"},"actor":{"user":{"name":"TESTER"}},"src_endpoint":{"ip":"10.1.2.4"},"metadata":{"product":{"name":"fixture","vendor_name":"nano"}}}
J
docker run --rm -i --network none -e NANO_TENANT_ID=6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00 -e NANO_LAKE_BRONZE_SHARDS=1 \
  -e VECTOR_CONFIG_GZIP_SHA256="${BUNDLE_SHA-b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c}" \
  -v "$work:/h:ro" timberio/vector@sha256:ed2134fa8f9844c1ca6405260903c2c2c52f94af9e16bc8fa9de9655134e0b39 \
  --quiet --dangerously-allow-env-var-interpolation --config /h/harness.toml --config /h/sink.toml \
  < "$work/in.jsonl" > "$out"
