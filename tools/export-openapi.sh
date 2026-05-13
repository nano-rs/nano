#!/usr/bin/env bash
set -euo pipefail

# Export the merged OpenAPI spec to docs/api/openapi.json and produce a
# compact markdown summary at docs/api/openapi-summary.md. The summary is
# the input to tools/generate-docs.sh for the api-reference topic — small
# enough to fit in a Claude context window while preserving every
# endpoint, its tags, security, and brief schema shape.
#
# Run after meaningful API changes (new endpoint, renamed handler, auth
# change). The output is committed so downstream RAG / doc generators
# never need to start a server.

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$REPO_ROOT/docs/api"
SPEC="$OUT_DIR/openapi.json"
SUMMARY="$OUT_DIR/openapi-summary.md"

mkdir -p "$OUT_DIR"

echo "▶ Building export_openapi binary..."
cargo build --bin export_openapi --quiet

echo "▶ Writing $SPEC..."
cargo run --bin export_openapi --quiet > "$SPEC"
echo "  $(wc -c < "$SPEC" | tr -d ' ') bytes"

echo "▶ Writing compact markdown summary $SUMMARY..."
python3 - "$SPEC" "$SUMMARY" <<'PY'
import json, sys
from collections import defaultdict

spec_path, out_path = sys.argv[1], sys.argv[2]
spec = json.load(open(spec_path))

info = spec.get("info", {})
schemes = spec.get("components", {}).get("securitySchemes", {})

# Group endpoints by tag
by_tag = defaultdict(list)
for path, methods in spec.get("paths", {}).items():
    for method, op in methods.items():
        if method.startswith("x-") or not isinstance(op, dict):
            continue
        tags = op.get("tags") or ["untagged"]
        for tag in tags:
            by_tag[tag].append((method.upper(), path, op))

# Sort: tags alphabetically, endpoints by path
for tag in by_tag:
    by_tag[tag].sort(key=lambda e: (e[1], e[0]))


def fmt_schema_ref(s):
    """Render a schema as a compact one-line summary."""
    if not isinstance(s, dict):
        return ""
    if "$ref" in s:
        return s["$ref"].split("/")[-1]
    t = s.get("type")
    if t == "array":
        return f"[{fmt_schema_ref(s.get('items', {}))}]"
    if t == "object":
        props = s.get("properties", {})
        if not props:
            return "object"
        items = []
        for k, v in list(props.items())[:8]:
            inner = fmt_schema_ref(v)
            items.append(f"{k}: {inner}" if inner else k)
        more = "" if len(props) <= 8 else f", +{len(props)-8} more"
        return "{" + ", ".join(items) + more + "}"
    if "enum" in s:
        return "enum(" + "|".join(str(v) for v in s["enum"][:6]) + (")" if len(s["enum"]) <= 6 else "...)")
    return t or "any"


def fmt_security(op):
    """Render the security requirement(s) as 'api_key | bearer_auth' style."""
    sec = op.get("security")
    if sec is None:
        return "(default)"
    if not sec:
        return "public"
    names = []
    for entry in sec:
        names.append(" + ".join(entry.keys()))
    return " | ".join(names)


lines = [
    f"# {info.get('title', 'API')} — endpoint summary",
    "",
    f"Generated from `openapi.json` (version {info.get('version', '?')}). "
    "One line per endpoint, grouped by tag. For full schemas see "
    "`openapi.json`. **Auth header conventions**: prefer `X-API-Key: nsk_…` "
    "for programmatic access (`api_key` scheme); use `Authorization: Bearer "
    "<jwt>` only on the login/session flow (`bearer_auth` scheme).",
    "",
    "## Security schemes",
    "",
]
for name, scheme in schemes.items():
    if scheme.get("type") == "apiKey":
        lines.append(
            f"- `{name}` — apiKey in {scheme.get('in')} header `{scheme.get('name')}`"
        )
    elif scheme.get("type") == "http":
        lines.append(
            f"- `{name}` — http {scheme.get('scheme')} ({scheme.get('bearerFormat', '')})"
        )
    else:
        lines.append(f"- `{name}` — {scheme.get('type')}")
lines.append("")

for tag in sorted(by_tag):
    lines.append(f"## {tag}")
    lines.append("")
    for method, path, op in by_tag[tag]:
        raw_summary = (op.get("summary") or op.get("description") or "").strip()
        summary = raw_summary.splitlines()[0].strip() if raw_summary else "(no summary)"
        sec = fmt_security(op)
        body_schema = ""
        rb = op.get("requestBody", {})
        if rb:
            content = rb.get("content", {})
            for ct, ct_obj in content.items():
                schema = ct_obj.get("schema", {})
                body_schema = f" body=`{fmt_schema_ref(schema)}` ({ct})"
                break
        # response: pick 2xx
        resps = op.get("responses", {})
        ok = None
        for code in ("200", "201", "204"):
            if code in resps:
                ok = (code, resps[code])
                break
        resp_schema = ""
        if ok:
            code, resp = ok
            content = resp.get("content", {})
            for ct, ct_obj in content.items():
                schema = ct_obj.get("schema", {})
                shape = fmt_schema_ref(schema)
                resp_schema = f" → {code} `{shape}`"
                break
            if not resp_schema:
                resp_schema = f" → {code}"
        line = f"- **{method} {path}** — {summary} · security: {sec}{body_schema}{resp_schema}"
        lines.append(line)
    lines.append("")

with open(out_path, "w") as f:
    f.write("\n".join(lines))

import os
print(f"  {os.path.getsize(out_path)} bytes")
PY

echo "✅ Done."
echo "   - $SPEC ($(wc -c < "$SPEC" | tr -d ' ') bytes, full source of truth)"
echo "   - $SUMMARY ($(wc -c < "$SUMMARY" | tr -d ' ') bytes, LLM-ready)"
