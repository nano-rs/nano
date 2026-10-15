-- NAN-2370: ship the OTLP LogRecord parser out of the box.
--
-- WHY THIS IS A DEFECT FIX, NOT A NEW FEATURE
-- -------------------------------------------
-- Migration 214 seeds the OTLP listener as a SYSTEM-LEVEL, ALWAYS-ENABLED source
-- (gRPC :4317 / HTTP :4318, platform-managed). Every deployment therefore accepts
-- OTLP logs by default. `otlp_logs_prep` tags them `source_type="otlp_log"` and
-- feeds `source_router` directly.
--
-- Without a parser whose `match_values` claims `otlp_log`, the router has no
-- matching route, the events fall through to the `generic` output, and
-- `placeholder_combiner` (`type = "filter"`, `condition = "false"`) DISCARDS
-- them. No error, no metric, no counter. Measured before this seed existed:
-- ~2,000 OTLP log records ingested, zero rows landed, nothing logged.
--
-- An always-on listener that silently drops what it accepts is a data-loss path
-- in the default configuration, so the parser must be as out-of-the-box as the
-- listener it serves. Spans and metrics already have first-class homes
-- (`/v1/otlp/spans`, `/v1/otlp/metrics` + their Iceberg datasets); logs were the
-- only OTLP signal without one.
--
-- MODELLING DECISIONS worth revisiting (documented, not hidden)
-- ------------------------------------------------------------
-- 1. class_uid 6003 (API Activity) for EVERY LogRecord. Forced, not ideal: only
--    two OCSF 1.9 classes define the `trace` object at all -- 4002 http_activity
--    and 6003 api_activity -- and Base Event (class 0) never can. A plain
--    application log is not really "API activity"; per-service class selection
--    would be more faithful and is the natural follow-up.
-- 2. `actor.app_name` falls back to the emitting service (or "OpenTelemetry").
--    OCSF requires `actor` with at least one identifying sub-field, and many
--    LogRecords carry no principal. This value is SYNTHESISED, not observed.
-- 3. `unmapped` keys have "." rewritten to "_" (`service.name` -> `service_name`).
--    Forced: a dot makes Iceberg read the key as a nested-struct path and the
--    additive-schema step rejects the batch ("Cannot add column with ambiguous
--    name"), which retries forever on a durable batch and stalls publication for
--    EVERY source. This is a user-visible departure from OTLP naming and must be
--    documented for anyone searching for the dotted form.
--
-- The row is seeded enabled but NOT deployed: writing Vector config is the
-- deploy path's job, not a migration's. It goes live on the next deploy /
-- publication cycle. Idempotent via the UNIQUE (name) constraint.

INSERT INTO log_sources (
    name,
    description,
    source_type,
    match_values,
    parser_vrl,
    category,
    vendor,
    product,
    namespace,
    timezone,
    kind,
    lifecycle_status,
    enabled,
    deployed,
    validated
) VALUES (
    'OpenTelemetry Logs (OCSF)',
    'OTLP LogRecords normalised to OCSF 1.9 API Activity with the Trace profile, so OTLP logs are searchable in the same lane as SIEM events and joinable by trace id (trace.uid, with unmapped.trace_id as the declared fallback).',
    'routed',
    ARRAY['otlp_log'],
$otlp_vrl$# OpenTelemetry LogRecord -> OCSF 1.9.0 API Activity (6003) + Trace profile
#
# WHY API Activity (6003) and NOT Base Event (0): Base Event is the schema's
# designated home for undefined events and passes OCSF validation, but the lake
# sink computes `%class_uid = to_int(.class_uid) ?? 0`, so a real class_uid of 0
# is indistinguishable from "attribute absent" and the row never lands. 6003 is
# the closest OCSF class for service/application telemetry and carries the
# required actor / api / src_endpoint, which OTLP resource+attributes supply.
#
# WHY trace.* and not unmapped.*: OCSF 1.9 defines the Trace profile — `trace`
# carries a REQUIRED `uid` and a nested `span` whose `uid` is likewise required.
# Emitting the canonical paths means hunts read `trace.uid="..."` rather than
# `unmapped.trace_id="..."`. The lake's field validator is data-driven
# (schema/ocsf.rs:902-911), so writing these makes them queryable with no alias
# and no validator change. `unmapped.trace_id`/`unmapped.span_id` remain the
# documented fallback for foreign producers that do not emit the profile
# (source manifest fields 37/38, roles trace_fallback/span_fallback).
#
# Input shape is whatever `otlp_logs_prep` (config/vector/03-otlp-source.toml)
# leaves on the event: .message (body), .severity / .severity_number,
# .trace_id / .span_id (already downcased), .resources, .attributes.

body = to_string(.message) ?? ""

# ---- severity: OTLP SeverityNumber -> OCSF severity_id ----
# OCSF: 0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical,
# 6 Fatal, 99 Other. otlp_logs_prep already banded the text; keep it as the
# human-facing `severity` string and derive the id from the numeric when present.
sev_text = to_string(.severity) ?? ""
sev_num = to_int(.severity_number) ?? 0

severity_id = 0
if sev_num >= 21 {
    severity_id = 6
} else if sev_num >= 17 {
    severity_id = 4
} else if sev_num >= 13 {
    severity_id = 3
} else if sev_num >= 5 {
    severity_id = 1
} else if sev_num >= 1 {
    severity_id = 1
}

# No numeric SeverityNumber: fall back to the text band otlp_logs_prep computed.
if severity_id == 0 {
    if sev_text == "Fatal" {
        severity_id = 6
    } else if sev_text == "Error" {
        severity_id = 4
    } else if sev_text == "Warn" {
        severity_id = 3
    } else if sev_text != "" {
        severity_id = 1
    }
}

if sev_text == "" {
    sev_text = "Unknown"
}

# ---- time: the LOG timestamp, never ingest time ----
# The OTLP LogRecord time must win: stamping ingest time would silently
# back-date/forward-date every OTLP row and corrupt time-ordered hunts.
# `.timestamp` arrives as a real timestamp from Vector's OTLP source, but can be
# an RFC3339 string or raw epoch (OTLP carries unix NANOS) depending on the
# producer, so handle all three rather than letting a type mismatch fall through
# to now(). `to_unix_timestamp` errors on a non-timestamp, which is exactly how
# the first draft of this parser silently stamped ingest time.
resolve_ms = {
    ms = null
    candidate = .timestamp
    if candidate == null { candidate = .observed_timestamp }

    if is_timestamp(candidate) {
        ms = to_unix_timestamp(timestamp!(candidate), unit: "milliseconds")
    } else if is_string(candidate) {
        parsed_ts, parse_err = parse_timestamp(string!(candidate), "%+")
        if parse_err == null {
            ms = to_unix_timestamp(parsed_ts, unit: "milliseconds")
        }
    } else if is_integer(candidate) || is_float(candidate) {
        # A large epoch (OTLP nanos) decodes as a float in some JSON paths, so
        # accept both and normalise through float before truncating back.
        raw = to_float(candidate) ?? 0.0
        # Disambiguate by magnitude: OTLP emits nanoseconds; tolerate micros,
        # millis and seconds from looser producers. Thresholds are year-2001-ish
        # in each unit, so a plausible event time never lands in the wrong band.
        # NOTE: VRL division always yields a float — truncate explicitly, or the
        # downstream int coercion aborts the whole program ("expected integer,
        # got float") and the row is dropped with no row and no error surface.
        if raw > 100000000000000000.0 {
            ms = to_int(floor(raw / 1000000.0))
        } else if raw > 100000000000000.0 {
            ms = to_int(floor(raw / 1000.0))
        } else if raw > 100000000000.0 {
            ms = to_int(floor(raw))
        } else if raw > 0.0 {
            ms = to_int(floor(raw * 1000.0))
        }
    }
    ms
}

time_ms = 0
time_from_record = true
if resolve_ms != null {
    time_ms = to_int(resolve_ms)
} else {
    time_from_record = false
    # No usable record time. Fall back to the routing stamp (still ingest-side,
    # but at least explicit) and record that the time is not authoritative.
    rts, rts_err = to_unix_timestamp(.routing_timestamp, unit: "milliseconds")
    if rts_err == null {
        time_ms = rts
    } else {
        time_ms = to_unix_timestamp(now(), unit: "milliseconds")
    }
}

# ---- trace context (OCSF Trace profile) ----
trace_uid = downcase(to_string(.trace_id) ?? "")
span_uid = downcase(to_string(.span_id) ?? "")

# ---- resource / log-record attributes ----
resources = {}
if is_object(.resources) {
    resources = object!(.resources)
}
attributes = {}
if is_object(.attributes) {
    attributes = object!(.attributes)
}

service_name = to_string(resources."service.name") ?? ""

# Non-OCSF residue rides `unmapped` (the OCSF spill), resource attrs first so a
# same-named log attribute wins — same precedence otlp_logs_prep used for `ext`.
#
# CRITICAL: keys must not contain dots. OTLP semantic conventions are dotted
# almost everywhere (`service.name`, `client.address`, `http.method`), but the
# Iceberg additive-schema step reads a dot as a nested-struct path and refuses
# the whole batch:
#   PreconditionFailed => Cannot add column with ambiguous name: client.address
# That error is retried forever on a durable batch, which wedges publication for
# EVERY source, not just this one. Flatten the separator to `_` so each OTLP
# attribute becomes an unambiguous leaf.
unmapped = map_keys(merge(resources, attributes), recursive: true) -> |key| {
    replace(key, ".", "_")
}

# ---- required attributes for 6003, sourced from OTLP where available ----
operation = to_string(attributes."http.request.method") ?? to_string(attributes."http.method") ?? ""
url_path = to_string(attributes."url.path") ?? to_string(attributes."http.target") ?? ""
if operation == "" { operation = "log" }
api = {"operation": operation}
if service_name != "" { api = merge(api, {"service": {"name": service_name}}) }
if url_path != "" { api = merge(api, {"request": {"uid": url_path}}) }

# `actor` is REQUIRED and must carry at least one of
# [process, user, iam_role, invoked_by, session, application, app_name, app_uid].
# A LogRecord often has no principal at all, so fall back to naming the emitting
# application — an OCSF-valid actor beats dropping the row.
user_name = to_string(attributes."enduser.id") ?? ""
actor = {}
if user_name != "" { actor = {"user": {"name": user_name}} }
if actor == {} {
    if service_name != "" {
        actor = {"app_name": service_name}
    } else {
        actor = {"app_name": "OpenTelemetry"}
    }
}

client_ip = to_string(attributes."client.address") ?? to_string(attributes."net.peer.ip") ?? ""
src_endpoint = {}
if client_ip != "" { src_endpoint = {"ip": client_ip} }
host_name = to_string(resources."host.name") ?? ""
if host_name != "" { src_endpoint = merge(src_endpoint, {"hostname": host_name}) }
if service_name != "" { src_endpoint = merge(src_endpoint, {"svc_name": service_name}) }
# Same contract as `actor`: at least one identifying attribute is REQUIRED.
if src_endpoint == {} { src_endpoint = {"svc_name": "unknown"} }

# ---- assemble the OCSF record on the root ----
. = {
    "class_uid": 6003,
    "class_name": "API Activity",
    "category_uid": 6,
    "category_name": "Application Activity",
    "activity_id": 0,
    "activity_name": "Unknown",
    "type_uid": 600300,
    "actor": actor,
    "api": api,
    "src_endpoint": src_endpoint,
    "severity_id": severity_id,
    "severity": sev_text,
    "time": time_ms,
    "message": body,
    "metadata": {
        "version": "1.9.0",
        "uid": uuid_v4(),
        # REQUIRED for the `trace` object to be admitted. OCSF binds `trace` to
        # the "trace" profile, and the strict admission validator
        # (nanosiem-core/src/parsers/ocsf_validation.rs, `attribute_allowed`)
        # only permits a profile-bound attribute when the event DECLARES that
        # profile here. Without this, every bronze object carrying one of these
        # rows is rejected wholesale as `strict_admission_failed`
        # ("attribute \"trace\" is not defined for this OCSF class/profile") --
        # taking any co-located rows from other sources down with it.
        "profiles": ["trace"],
        "product": {
            "name": "OpenTelemetry",
            "vendor_name": "OpenTelemetry"
        },
        "log_provider": "OTLP"
    },
    "unmapped": unmapped
}

# OCSF Trace profile — only when the LogRecord actually carried trace context.
# `trace.uid` is REQUIRED by the trace object, so never emit a bare/empty trace.
if trace_uid != "" {
    trace = {"uid": trace_uid}
    # Deliberately NO `trace.span`. OCSF's span object requires `start_time` and
    # `end_time` as well as `uid`, and a LogRecord carries only the span ID from
    # its W3C trace context -- it does not know when that span began or ended.
    # Emitting the object without them is rejected outright
    # ("required OCSF attribute \"trace.span.end_time\""), and inventing the
    # timestamps would put fabricated timing into a security event store. The
    # span identity therefore rides `unmapped.span_id`, which is exactly the
    # `span_fallback` role the source manifest declares (field 38). The span's
    # real timings live on the span row itself, in the spans dataset.
    if service_name != "" {
        trace = merge(trace, {"service": {"name": service_name}})
    }
    .trace = trace

    # Fallback slots the entity manifest declares (fields 37/38) so foreign
    # consumers and the primary-then-fallback query predicate both resolve.
    .unmapped.trace_id = trace_uid
    if span_uid != "" {
        .unmapped.span_id = span_uid
    }
}

# service.name -> OCSF actor.process / src_endpoint has no clean slot for a
# logical service, so keep it on the canonical `metadata.product.feature`
# (a real OCSF path) in addition to trace.service.name above.
if service_name != "" {
    .metadata.product.feature = {"name": service_name}
}

# The LogRecord carried no usable time, so `time` is ingest-side. Say so on the
# row rather than letting a fabricated time read as the event's own.
if !time_from_record {
    .unmapped.nano_time_source = "ingest"
}
$otlp_vrl$,
    'application',
    'OpenTelemetry',
    'OpenTelemetry',
    'default',
    'UTC',
    'log',
    'active',
    true,
    false,
    false
) ON CONFLICT (name) DO NOTHING;
