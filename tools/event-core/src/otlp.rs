//! OTLP (OpenTelemetry) signal generators — NAN-1533.
//!
//! Generates synthetic OTLP traces / metrics / logs in the OTLP/JSON encoding
//! (OTLP 1.x, camelCase field names, 64-bit ints encoded as STRINGS). Each
//! generator emits ONE record at a time as a [`serde_json::Value`]:
//!
//! - a single **span** (`gen_trace` returns a connected tree of spans),
//! - a single metric **data point** (`gen_metrics` returns the per-service set),
//! - a single **log record** (`gen_log`).
//!
//! The per-record JSON shape is the contract consumed by TWO downstream paths,
//! and it is deliberately identical for both:
//!
//! * **Vector** (`Transport::OtlpHttp`) wraps each record in an OTLP export
//!   envelope (`resourceSpans`/`resourceMetrics`/`resourceLogs`) and POSTs it to
//!   the `opentelemetry` receiver's `/v1/{traces,metrics,logs}` endpoints.
//! * **Direct ClickHouse** (`Transport::OtlpClickHouse`) writes each record's
//!   JSON verbatim into the single `event` column of `otel_spans_raw` /
//!   `otel_metrics_raw` (the Null staging tables whose MVs derive the promoted
//!   columns — clickhouse/138_otel_spans.sql, clickhouse/140_otel_metrics.sql).
//!
//! CRITICAL: the field names below are read VERBATIM by the derivation MVs via
//! `JSONExtract*`. The span MV reads `traceId`, `spanId`, `parentSpanId`,
//! `name`, `kind`, `startTimeUnixNano`, `endTimeUnixNano`, `status.code`,
//! `status.message`, `attributes[].key`/`.value.{stringValue,intValue,...}`,
//! and `resource.attributes[...]`. The metrics MV reads `name`, `unit`, `type`,
//! `timeUnixNano`, `asInt`/`asDouble`, `count`, `sum`, `bucketCounts`,
//! `explicitBounds`, plus `attributes`/`resource.attributes`. Do not rename.

use chrono::Utc;
use rand::Rng;
use serde_json::{json, Value};

use crate::entity::Entity;

/// Synthetic services for the generated call graph. The traffic shape is a
/// classic three-tier request: `frontend` (SERVER) calls `checkout` (CLIENT ->
/// SERVER), which calls `db` (CLIENT). `service.name` lands in
/// `resource.attributes` (the MV reads service_name from there).
const SERVICES: &[&str] = &["frontend", "checkout", "db", "payments", "inventory"];

/// HTTP routes used for the root SERVER span name / `url.path` attribute.
const ROUTES: &[&str] = &[
    "/api/cart", "/api/checkout", "/api/products", "/api/orders", "/api/login", "/healthz",
];

const HTTP_METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE"];

/// Random lowercase-hex string of `n_bytes` bytes (so 16 bytes -> 32 hex chars
/// for a trace id, 8 bytes -> 16 hex chars for a span id). Matches the OTLP/JSON
/// hex encoding the MV `lower()`s.
fn hex_id(rng: &mut impl Rng, n_bytes: usize) -> String {
    let mut s = String::with_capacity(n_bytes * 2);
    for _ in 0..n_bytes {
        s.push_str(&format!("{:02x}", rng.random::<u8>()));
    }
    s
}

/// Build one OTLP KeyValue `{key, value:{stringValue: ...}}`.
fn attr_str(key: &str, val: impl Into<String>) -> Value {
    json!({ "key": key, "value": { "stringValue": val.into() } })
}

/// Build one OTLP KeyValue with an int value. OTLP/JSON encodes 64-bit ints as
/// STRINGS — the MV reads them with `JSONExtractString`, so we emit a string.
fn attr_int(key: &str, val: i64) -> Value {
    json!({ "key": key, "value": { "intValue": val.to_string() } })
}

/// Resource-level attribute set for a service. `service.name` is the column the
/// span/metric MVs promote; `host.name` feeds the `host` entity overlay.
fn resource_for(service: &str, host: &str) -> Value {
    json!({
        "attributes": [
            attr_str("service.name", service),
            attr_str("service.namespace", "shop"),
            attr_str("host.name", host),
            attr_str("telemetry.sdk.name", "log-blaster"),
            attr_str("telemetry.sdk.language", "rust"),
        ]
    })
}

/// Resource attribute set for a HOST (no service). The Infra tab keys the
/// host fleet off `resource_attributes['host.name']` and groups by
/// `resource_attributes['host.group']` (falling back to `service.name`). We
/// emit `host.name` + `host.group` + a co-located `service.name` so both the
/// group-by-host.group and the service-fallback paths render.
fn resource_for_host(host: &str, group: &str, service: &str) -> Value {
    json!({
        "attributes": [
            attr_str("host.name", host),
            attr_str("host.group", group),
            attr_str("service.name", service),
            attr_str("telemetry.sdk.name", "log-blaster"),
        ]
    })
}

/// Resource attribute set for a RUM (browser) producer. RUM has no host — the
/// service is the web app; the page / browser live on the data-point attributes.
fn resource_for_rum() -> Value {
    json!({
        "attributes": [
            attr_str("service.name", "web-frontend"),
            attr_str("telemetry.sdk.name", "log-blaster-rum"),
            attr_str("telemetry.sdk.language", "webjs"),
        ]
    })
}

/// Build one OTLP gauge NumberDataPoint (`type: gauge`, `asDouble`) for a metric
/// with the given name/unit/value, data-point attributes, and owning resource.
fn gauge_point(
    name: &str,
    unit: &str,
    value: f64,
    attributes: Vec<Value>,
    resource: Value,
    now_ns: u64,
) -> Value {
    json!({
        "name": name,
        "unit": unit,
        "type": "gauge",
        "timeUnixNano": now_ns.to_string(),
        "asDouble": value,
        "attributes": attributes,
        "resource": resource,
    })
}

/// The synthetic host fleet for the Infra tab. Each entry is
/// `(host.name, host.group, service.name, hot)` — `hot` hosts run high
/// CPU/mem/load so the waffle has a mix of good / warn / bad statuses (the
/// backend derives status from cpu/mem thresholds). Mirrors the design
/// fixture's role-based fleet (api/web/db/cache/worker prod hosts).
const HOST_FLEET: &[(&str, &str, &str, bool)] = &[
    ("api-prod-01", "api", "checkout", true),
    ("api-prod-02", "api", "checkout", true),
    ("api-prod-03", "api", "checkout", false),
    ("web-prod-01", "web", "frontend", false),
    ("web-prod-02", "web", "frontend", false),
    ("db-prod-01", "db", "db", true),
    ("db-prod-02", "db", "db", false),
    ("cache-prod-01", "cache", "inventory", false),
    ("worker-prod-01", "worker", "payments", false),
    ("worker-prod-02", "worker", "payments", false),
];

/// RUM page paths the synthetic browser fleet "navigates". Page-view spans use
/// these for `page.url` + the `pageview <path>` span name; web-vital metrics
/// tag the same `page.url`.
const RUM_PAGES: &[&str] = &["/", "/product/:id", "/cart", "/checkout", "/search", "/login"];

/// Browser labels stamped on RUM data points / spans (`browser` attribute).
const RUM_BROWSERS: &[&str] =
    &["Chrome 126", "Chrome 125", "Safari 17", "Firefox 128", "Edge 126"];

/// JS error class + message pairs for the RUM error spans (`exception.type` +
/// `exception.message`). The RUM tab's recent-errors list reads these.
const RUM_JS_ERRORS: &[(&str, &str)] = &[
    ("TypeError", "Cannot read 'total' of undefined"),
    ("UnhandledRejection", "504 from /v2/pay"),
    ("ChunkLoadError", "loading chunk 42 failed"),
    ("ReferenceError", "gtag is not defined"),
    ("RangeError", "Maximum call stack size exceeded"),
];

/// Generate the host-fleet INFRA metric scrape for one tick — for every host in
/// [`HOST_FLEET`], emit the four OTLP gauge data points the Infra tab consumes:
///
///   * `system.cpu.utilization`     (0..1 fraction; the backend ×100 for cpu_pct)
///   * `system.memory.utilization`  (0..1 fraction; surfaced as mem_pct)
///   * `system.cpu.load_average.1m` (load average, ~0.3..5.2)
///   * `system.network.io`          (bytes/sec; surfaced as net_bytes_per_sec)
///
/// Each point carries `resource_attributes['host.name']` + `['host.group']`
/// (the host-grouping keys) so `argMax(value,timestamp)` per (host, metric)
/// yields a populated fleet. `hot` hosts run high cpu/mem so the waffle shows a
/// mix of statuses. One [`Value`] per data point — ONE-ROW-PER-DATA-POINT.
pub fn gen_host_metrics(rng: &mut impl Rng) -> Vec<Value> {
    let now_ns: u64 = (Utc::now().timestamp_nanos_opt().unwrap_or(0)).max(0) as u64;
    let mut points = Vec::with_capacity(HOST_FLEET.len() * 4);

    for (host, group, service, hot) in HOST_FLEET {
        let resource = resource_for_host(host, group, service);
        // Fractions in [0,1] for the *.utilization gauges (OTel `1` unit). Hot
        // hosts saturate so cpu/mem cross the warn/bad thresholds.
        let cpu = if *hot {
            rng.random_range(0.72..0.98)
        } else {
            rng.random_range(0.18..0.60)
        };
        let mem = if *hot {
            rng.random_range(0.64..0.94)
        } else {
            rng.random_range(0.30..0.70)
        };
        let load = if *hot {
            rng.random_range(2.2..5.2)
        } else {
            rng.random_range(0.3..1.9)
        };
        // Network throughput in bytes/sec (MB/s × 1e6).
        let net_bytes = if *hot {
            rng.random_range(120.0..420.0) * 1.0e6
        } else {
            rng.random_range(10.0..90.0) * 1.0e6
        };

        points.push(gauge_point(
            "system.cpu.utilization",
            "1",
            cpu,
            vec![attr_str("state", "used"), attr_str("host.name", *host)],
            resource.clone(),
            now_ns,
        ));
        points.push(gauge_point(
            "system.memory.utilization",
            "1",
            mem,
            vec![attr_str("state", "used"), attr_str("host.name", *host)],
            resource.clone(),
            now_ns,
        ));
        points.push(gauge_point(
            "system.cpu.load_average.1m",
            "1",
            load,
            vec![attr_str("host.name", *host)],
            resource.clone(),
            now_ns,
        ));
        points.push(gauge_point(
            "system.network.io",
            "By",
            net_bytes,
            vec![attr_str("direction", "receive"), attr_str("host.name", *host)],
            resource,
            now_ns,
        ));
    }

    points
}

/// Generate the RUM (real-user-monitoring) METRIC data points for one tick: a
/// web-vital gauge per Core Web Vital, each tagged with `page.url` + `browser`
/// so the backend can compute p75 per vital. One [`Value`] per data point.
///
///   * `web.vitals.lcp`  (ms, Largest Contentful Paint — typically 1200..4000)
///   * `web.vitals.inp`  (ms, Interaction to Next Paint — typically 80..400)
///   * `web.vitals.cls`  (unitless layout-shift score — typically 0.0..0.25)
pub fn gen_rum_metrics(rng: &mut impl Rng) -> Vec<Value> {
    let now_ns: u64 = (Utc::now().timestamp_nanos_opt().unwrap_or(0)).max(0) as u64;
    let resource = resource_for_rum();
    let page = RUM_PAGES[rng.random_range(0..RUM_PAGES.len())];
    let browser = RUM_BROWSERS[rng.random_range(0..RUM_BROWSERS.len())];
    // `/checkout` is the slow page (matches the design fixture); give it a worse
    // LCP/INP so the top-pages drill-in has a clear offender.
    let slow = page == "/checkout";

    let lcp = if slow {
        rng.random_range(2600.0..4200.0)
    } else {
        rng.random_range(900.0..2400.0)
    };
    let inp = if slow {
        rng.random_range(180.0..360.0)
    } else {
        rng.random_range(60.0..180.0)
    };
    let cls = rng.random_range(0.0..0.22f64);

    let vital_attrs = || vec![attr_str("page.url", page), attr_str("browser", browser)];
    vec![
        gauge_point("web.vitals.lcp", "ms", lcp, vital_attrs(), resource.clone(), now_ns),
        gauge_point("web.vitals.inp", "ms", inp, vital_attrs(), resource.clone(), now_ns),
        gauge_point("web.vitals.cls", "1", cls, vital_attrs(), resource, now_ns),
    ]
}

/// Generate the RUM page-view / JS-error SPANS for one tick. Returns a small
/// batch of OTLP spans (browser-side, SpanKind CLIENT):
///
///   * page-view spans — span_name `pageview <path>` AND `attributes['page.url']`
///     set, so the backend's page-view count matches either signal; OK status.
///   * a fraction (~12%) of error spans — status ERROR (code 2) +
///     `attributes['exception.type']` / `['exception.message']` so the JS-error
///     count + recent-errors list populate.
///
/// Spans are independent root spans (no downstream tree) — RUM page views aren't
/// distributed traces. Each gets its own trace + span id.
pub fn gen_rum_spans(rng: &mut impl Rng) -> Vec<Value> {
    let now_ns: u64 = (Utc::now().timestamp_nanos_opt().unwrap_or(0)).max(0) as u64;
    let resource = resource_for_rum();
    let mut spans = Vec::new();

    // 1–3 page views per tick.
    let n_views = rng.random_range(1..=3);
    for _ in 0..n_views {
        let page = RUM_PAGES[rng.random_range(0..RUM_PAGES.len())];
        let browser = RUM_BROWSERS[rng.random_range(0..RUM_BROWSERS.len())];
        // Page load duration 0.3–4s in nanos.
        let dur_ns: u64 = rng.random_range(300_000_000..4_000_000_000);
        let is_error = rng.random_bool(0.12);
        let (exc_type, exc_msg) = RUM_JS_ERRORS[rng.random_range(0..RUM_JS_ERRORS.len())];

        let mut attrs = vec![
            attr_str("page.url", page),
            attr_str("browser", browser),
            attr_str("http.url", format!("https://shop.example{page}")),
        ];
        if is_error {
            attrs.push(attr_str("exception.type", exc_type));
            attrs.push(attr_str("exception.message", exc_msg));
        }

        spans.push(span(
            &hex_id(rng, 16),
            &hex_id(rng, 8),
            "",
            &format!("pageview {page}"),
            3, // CLIENT (browser-side)
            now_ns,
            now_ns + dur_ns,
            if is_error { 2 } else { 1 }, // ERROR else OK
            if is_error { exc_msg } else { "" },
            attrs,
            resource.clone(),
        ));
    }

    spans
}

/// One generated span in OTLP/JSON shape, WITH its owning `resource` sub-object
/// hoisted alongside (the flattened contract the MV expects — see migration 138).
#[allow(clippy::too_many_arguments)]
fn span(
    trace_id: &str,
    span_id: &str,
    parent_span_id: &str,
    name: &str,
    kind: i64,
    start_ns: u64,
    end_ns: u64,
    status_code: i64,
    status_message: &str,
    attributes: Vec<Value>,
    resource: Value,
) -> Value {
    let mut status = json!({ "code": status_code });
    if !status_message.is_empty() {
        status["message"] = json!(status_message);
    }
    json!({
        "traceId": trace_id,
        "spanId": span_id,
        // OTLP/JSON omits parentSpanId for a root span; emit "" so the MV
        // lower("") = "" yields the DEFAULT-empty parent column.
        "parentSpanId": parent_span_id,
        "name": name,
        // SpanKind int enum: 2 SERVER, 3 CLIENT, 1 INTERNAL.
        "kind": kind,
        // 64-bit nanos encoded as STRINGS (OTLP/JSON) — MV uses toUInt64OrZero(JSONExtractString).
        "startTimeUnixNano": start_ns.to_string(),
        "endTimeUnixNano": end_ns.to_string(),
        "status": status,
        "attributes": attributes,
        "events": [],
        "resource": resource,
    })
}

/// Generate one realistic distributed trace: a root SERVER span on `frontend`
/// plus a small tree of CLIENT/INTERNAL child spans across downstream services.
/// Returns the spans in DAG order (root first). A `~8%` fraction of traces is
/// marked ERROR (status.code = 2) on the leaf + propagated to the root, which
/// is the common error-propagation shape.
///
/// `entity` seeds the client/host/user attributes from the fleet so the entity
/// overlay (src_ip / dest_ip / user / host) populates against real-looking data.
pub fn gen_trace(entity: &Entity, rng: &mut impl Rng) -> Vec<Value> {
    let now_ns: u64 = (Utc::now().timestamp_nanos_opt().unwrap_or(0)).max(0) as u64;
    let trace_id = hex_id(rng, 16);

    let route = ROUTES[rng.random_range(0..ROUTES.len())];
    let method = HTTP_METHODS[rng.random_range(0..HTTP_METHODS.len())];
    let is_error = rng.random_bool(0.08);
    let http_status = if is_error {
        *[500i64, 502, 503].choose_one(rng)
    } else {
        *[200i64, 201, 204, 304].choose_one(rng)
    };

    // Client identity from the fleet entity (semconv attrs the overlay reads).
    let client_ip = entity.ip.clone();
    let user = entity.user.clone();
    let host = entity.hostname.clone();

    let root_span_id = hex_id(rng, 8);
    // Total request duration: 5–250ms, expressed in nanos.
    let root_dur_ns: u64 = rng.random_range(5_000_000..250_000_000);
    let root_start = now_ns;
    let root_end = now_ns + root_dur_ns;

    let frontend_res = resource_for("frontend", &host);
    let root_name = format!("{method} {route}");
    let mut root_attrs = vec![
        attr_str("http.request.method", method),
        attr_int("http.response.status_code", http_status),
        attr_str("url.path", route),
        attr_str("url.scheme", "https"),
        attr_str("server.address", "frontend.shop.svc"),
        attr_str("client.address", &client_ip),
        attr_str("enduser.id", &user),
        attr_str("host.name", &host),
        attr_str("network.protocol.version", "1.1"),
    ];
    if is_error {
        root_attrs.push(attr_str("error.type", "internal_error"));
    }
    let mut spans = vec![span(
        &trace_id,
        &root_span_id,
        "",
        &root_name,
        2, // SERVER
        root_start,
        root_end,
        if is_error { 2 } else { 1 }, // ERROR else OK
        if is_error { "upstream call failed" } else { "" },
        root_attrs,
        frontend_res,
    )];

    // Build a 2–3 hop downstream chain: frontend -> checkout -> db (+ maybe
    // payments/inventory). Each hop is a CLIENT span on the caller plus the
    // callee's SERVER span, parented on the previous span.
    let chain: &[&str] = if rng.random_bool(0.5) {
        &["checkout", "db"]
    } else {
        &["checkout", "payments", "db"]
    };

    let mut parent_id = root_span_id.clone();
    let mut cursor_start = root_start + rng.random_range(100_000..2_000_000);
    let mut remaining = root_dur_ns.saturating_sub(3_000_000);
    for (i, svc) in chain.iter().enumerate() {
        let is_leaf = i == chain.len() - 1;
        // Each child takes a slice of the remaining budget.
        let child_dur = (remaining / (chain.len() - i) as u64).max(200_000);
        remaining = remaining.saturating_sub(child_dur);
        let child_start = cursor_start;
        let child_end = (child_start + child_dur).min(root_end.saturating_sub(50_000));
        cursor_start = child_start + child_dur / 4;

        // CLIENT span on the caller (parent_id) describing the outbound call.
        let client_span_id = hex_id(rng, 8);
        let client_name = if *svc == "db" {
            "SELECT shop.orders".to_string()
        } else {
            format!("{method} {svc}")
        };
        let mut client_attrs = vec![
            attr_str("server.address", format!("{svc}.shop.svc")),
            attr_str("peer.service", *svc),
        ];
        if *svc == "db" {
            client_attrs.push(attr_str("db.system", "postgresql"));
            client_attrs.push(attr_str("db.namespace", "shop"));
            client_attrs.push(attr_str(
                "db.query.text",
                "SELECT * FROM orders WHERE id = $1",
            ));
        } else {
            client_attrs.push(attr_str("http.request.method", method));
            client_attrs.push(attr_int("http.response.status_code", http_status));
        }
        let leaf_error = is_error && is_leaf;
        spans.push(span(
            &trace_id,
            &client_span_id,
            &parent_id,
            &client_name,
            3, // CLIENT
            child_start,
            child_end,
            if leaf_error { 2 } else { 1 },
            if leaf_error { "connection reset" } else { "" },
            client_attrs,
            resource_for(
                // The CLIENT span belongs to the CALLER. For the first hop the
                // caller is frontend; afterward it's the previous service.
                if i == 0 {
                    "frontend"
                } else {
                    chain[i - 1]
                },
                &host,
            ),
        ));
        parent_id = client_span_id;

        // For non-db hops add the callee's INTERNAL work span so the tree has
        // some depth (db is a leaf — the CLIENT span is the bottom).
        if *svc != "db" {
            let internal_span_id = hex_id(rng, 8);
            let internal_start = child_start + child_dur / 8;
            let internal_end = (internal_start + child_dur / 2).min(child_end);
            spans.push(span(
                &trace_id,
                &internal_span_id,
                &parent_id,
                &format!("{svc}.handle"),
                1, // INTERNAL
                internal_start,
                internal_end,
                1,
                "",
                vec![
                    attr_str("code.function", format!("{svc}_handler")),
                    attr_str("host.name", &host),
                ],
                resource_for(svc, &host),
            ));
        }
    }

    spans
}

/// Generate the per-service metric data points for one scrape tick: a monotonic
/// SUM counter, a GAUGE, and an explicit-bucket HISTOGRAM. Returns one
/// [`Value`] per data point (one row each — the MV is ONE-ROW-PER-DATA-POINT).
///
/// `type` is the producer-set discriminator the metrics MV prefers; the bucket
/// fields are only present on the histogram point.
pub fn gen_metrics(rng: &mut impl Rng) -> Vec<Value> {
    let now_ns: u64 = (Utc::now().timestamp_nanos_opt().unwrap_or(0)).max(0) as u64;
    let mut points = Vec::new();

    for svc in SERVICES {
        let resource = resource_for(svc, &format!("{svc}-pod-0"));
        let dp_attrs = vec![attr_str("http.route", ROUTES[rng.random_range(0..ROUTES.len())])];

        // Monotonic SUM counter — request count. asInt is STRING-encoded.
        points.push(json!({
            "name": "http.server.request.count",
            "unit": "{request}",
            "type": "sum",
            "timeUnixNano": now_ns.to_string(),
            "asInt": rng.random_range(1..5000i64).to_string(),
            "attributes": dp_attrs,
            "resource": resource.clone(),
        }));

        // GAUGE — in-flight requests / active connections (asDouble: real JSON number).
        points.push(json!({
            "name": "http.server.active_requests",
            "unit": "{request}",
            "type": "gauge",
            "timeUnixNano": now_ns.to_string(),
            "asDouble": rng.random_range(0.0..64.0f64),
            "attributes": dp_attrs.clone(),
            "resource": resource.clone(),
        }));

        // HISTOGRAM — request duration with explicit buckets (ms). count = sum
        // of bucketCounts; sum is the running total. bucketCounts has one more
        // entry than explicitBounds (the +Inf overflow bucket) per OTLP spec.
        let bounds = [5.0f64, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0];
        let mut buckets = vec![0u64; bounds.len() + 1];
        let n: u64 = rng.random_range(20..500);
        let mut running_sum = 0.0f64;
        for _ in 0..n {
            // Sample a latency, find its bucket, accrue the sum.
            let lat = rng.random_range(1.0..1200.0f64);
            running_sum += lat;
            let idx = bounds.iter().position(|b| lat <= *b).unwrap_or(bounds.len());
            buckets[idx] += 1;
        }
        points.push(json!({
            "name": "http.server.request.duration",
            "unit": "ms",
            "type": "histogram",
            "timeUnixNano": now_ns.to_string(),
            "count": n,
            "sum": running_sum,
            "bucketCounts": buckets.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
            "explicitBounds": bounds,
            "attributes": dp_attrs.clone(),
            "resource": resource,
        }));
    }

    points
}

/// Generate one OTLP LogRecord carrying body + severity + the W3C trace context
/// (`traceId`/`spanId`) so log->trace correlation is testable. Returns the
/// per-record OTLP/JSON shape (Vector's opentelemetry source decodes the body
/// into `.message`, the trace ids into `.trace_id`/`.span_id`).
///
/// If `trace` is `Some((trace_id, span_id))`, the log is correlated to that
/// span — pass a root span from a just-generated trace to make the
/// log<->trace pivot exercisable.
pub fn gen_log(entity: &Entity, trace: Option<(&str, &str)>, rng: &mut impl Rng) -> Value {
    let now_ns: u64 = (Utc::now().timestamp_nanos_opt().unwrap_or(0)).max(0) as u64;
    // OTLP SeverityNumber: 5 DEBUG, 9 INFO, 13 WARN, 17 ERROR.
    let (sev_num, sev_text, body) = match rng.random_range(0..10) {
        0 => (17, "ERROR", "request failed: upstream 503 from payments"),
        1 => (13, "WARN", "slow query detected (>500ms)"),
        2 => (5, "DEBUG", "cache miss for key shop:cart:active"),
        _ => (9, "INFO", "handled request"),
    };
    let route = ROUTES[rng.random_range(0..ROUTES.len())];
    let (trace_id, span_id) = match trace {
        Some((t, s)) => (t.to_string(), s.to_string()),
        None => (hex_id(rng, 16), hex_id(rng, 8)),
    };

    json!({
        "timeUnixNano": now_ns.to_string(),
        "observedTimeUnixNano": now_ns.to_string(),
        "severityNumber": sev_num,
        "severityText": sev_text,
        "body": { "stringValue": format!("{body} ({route})") },
        // W3C trace context for the log->trace pivot. Vector's OTLP-log path
        // lower()s these into .trace_id / .span_id.
        "traceId": trace_id,
        "spanId": span_id,
        "attributes": [
            attr_str("url.path", route),
            attr_str("client.address", &entity.ip),
            attr_str("enduser.id", &entity.user),
            attr_str("host.name", &entity.hostname),
        ],
        "resource": resource_for("frontend", &entity.hostname),
    })
}

/// Tiny `choose` helper so we don't pull `rand::seq` into every call site.
trait ChooseOne<T> {
    fn choose_one(&self, rng: &mut impl Rng) -> &T;
}
impl<T> ChooseOne<T> for [T] {
    fn choose_one(&self, rng: &mut impl Rng) -> &T {
        &self[rng.random_range(0..self.len())]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::WorldState;

    fn one_entity() -> WorldState {
        WorldState::new(50)
    }

    #[test]
    fn trace_ids_are_lowercase_hex_and_linked() {
        let world = one_entity();
        let mut rng = rand::rng();
        let spans = gen_trace(world.random_entity(), &mut rng);
        assert!(spans.len() >= 2, "expected a root + children");

        // Root: 32-hex trace id, 16-hex span id, empty parent.
        let root = &spans[0];
        let trace_id = root["traceId"].as_str().unwrap();
        assert_eq!(trace_id.len(), 32);
        assert!(trace_id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(root["spanId"].as_str().unwrap().len(), 16);
        assert_eq!(root["parentSpanId"], "");
        assert_eq!(root["kind"], 2); // SERVER

        // nanos are string-encoded (OTLP/JSON 64-bit int convention).
        assert!(root["startTimeUnixNano"].is_string());
        assert!(root["endTimeUnixNano"].is_string());
        let start: u64 = root["startTimeUnixNano"].as_str().unwrap().parse().unwrap();
        let end: u64 = root["endTimeUnixNano"].as_str().unwrap().parse().unwrap();
        assert!(end > start);

        // Every span shares the trace id; every non-root has a parent that is
        // some other span's id.
        let ids: std::collections::HashSet<&str> =
            spans.iter().map(|s| s["spanId"].as_str().unwrap()).collect();
        for s in &spans {
            assert_eq!(s["traceId"].as_str().unwrap(), trace_id);
            let parent = s["parentSpanId"].as_str().unwrap();
            if !parent.is_empty() {
                assert!(ids.contains(parent), "dangling parent {parent}");
            }
        }

        // resource.attributes carries service.name (MV reads service_name there).
        let svc = root["resource"]["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|kv| kv["key"] == "service.name");
        assert!(svc.is_some(), "service.name must be a resource attribute");
    }

    #[test]
    fn metrics_have_three_shapes_per_service() {
        let mut rng = rand::rng();
        let points = gen_metrics(&mut rng);
        assert_eq!(points.len(), SERVICES.len() * 3);

        let hist = points
            .iter()
            .find(|p| p["type"] == "histogram")
            .expect("a histogram point");
        // OTLP: bucketCounts has exactly one more entry than explicitBounds.
        let bc = hist["bucketCounts"].as_array().unwrap().len();
        let eb = hist["explicitBounds"].as_array().unwrap().len();
        assert_eq!(bc, eb + 1, "bucketCounts must be explicitBounds + overflow");
        // count equals the sum of bucket counts.
        let count = hist["count"].as_u64().unwrap();
        let bucket_total: u64 = hist["bucketCounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().parse::<u64>().unwrap())
            .sum();
        assert_eq!(count, bucket_total);

        let sum = points.iter().find(|p| p["type"] == "sum").unwrap();
        assert!(sum["asInt"].is_string(), "asInt is string-encoded");
    }

    #[test]
    fn host_metrics_cover_the_fleet_with_four_gauges_each() {
        let mut rng = rand::rng();
        let points = gen_host_metrics(&mut rng);
        // Four gauges per host.
        assert_eq!(points.len(), HOST_FLEET.len() * 4);

        // Every point is a gauge with host.name on the resource (the Infra fleet key).
        for p in &points {
            assert_eq!(p["type"], "gauge");
            assert!(p["asDouble"].is_number(), "gauge uses asDouble: {p}");
            let host = p["resource"]["attributes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|kv| kv["key"] == "host.name")
                .and_then(|kv| kv["value"]["stringValue"].as_str());
            assert!(host.is_some(), "host.name must be a resource attribute: {p}");
            // host.group present for the Infra group-by.
            assert!(p["resource"]["attributes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|kv| kv["key"] == "host.group"));
        }

        // The four expected metric names all appear.
        let names: std::collections::HashSet<&str> =
            points.iter().map(|p| p["name"].as_str().unwrap()).collect();
        for expected in [
            "system.cpu.utilization",
            "system.memory.utilization",
            "system.cpu.load_average.1m",
            "system.network.io",
        ] {
            assert!(names.contains(expected), "missing metric {expected}");
        }

        // *.utilization gauges are fractions in [0,1] (the backend ×100 for pct).
        for p in &points {
            if p["name"].as_str().unwrap().ends_with(".utilization") {
                let v = p["asDouble"].as_f64().unwrap();
                assert!((0.0..=1.0).contains(&v), "utilization must be a fraction: {v}");
            }
        }
    }

    #[test]
    fn rum_metrics_are_three_web_vitals_with_page_and_browser() {
        let mut rng = rand::rng();
        let points = gen_rum_metrics(&mut rng);
        assert_eq!(points.len(), 3);

        let names: std::collections::HashSet<&str> =
            points.iter().map(|p| p["name"].as_str().unwrap()).collect();
        assert!(names.contains("web.vitals.lcp"));
        assert!(names.contains("web.vitals.inp"));
        assert!(names.contains("web.vitals.cls"));

        for p in &points {
            assert_eq!(p["type"], "gauge");
            let attrs = p["attributes"].as_array().unwrap();
            assert!(attrs.iter().any(|kv| kv["key"] == "page.url"));
            assert!(attrs.iter().any(|kv| kv["key"] == "browser"));
        }
    }

    #[test]
    fn rum_spans_are_pageviews_with_some_errors() {
        let mut rng = rand::rng();
        // Run several ticks so the ~12% error fraction is exercised.
        let mut total = 0usize;
        let mut errors = 0usize;
        let mut had_pageurl = false;
        for _ in 0..200 {
            for s in gen_rum_spans(&mut rng) {
                total += 1;
                // Root span (no parent) — RUM views aren't distributed traces.
                assert_eq!(s["parentSpanId"], "");
                // span_name carries the pageview marker.
                assert!(s["name"].as_str().unwrap().starts_with("pageview "));
                let attrs = s["attributes"].as_array().unwrap();
                if attrs.iter().any(|kv| kv["key"] == "page.url") {
                    had_pageurl = true;
                }
                if s["status"]["code"] == 2 {
                    errors += 1;
                    // Error spans carry exception.type for the JS-error count.
                    assert!(attrs.iter().any(|kv| kv["key"] == "exception.type"));
                }
            }
        }
        assert!(total > 0, "expected page-view spans");
        assert!(had_pageurl, "page.url must be set on page-view spans");
        assert!(errors > 0, "expected at least some ERROR spans across 200 ticks");
    }

    #[test]
    fn log_carries_trace_context_and_severity() {
        let world = one_entity();
        let mut rng = rand::rng();
        let log = gen_log(world.random_entity(), Some(("abc123", "def456")), &mut rng);
        assert_eq!(log["traceId"], "abc123");
        assert_eq!(log["spanId"], "def456");
        assert!(log["severityNumber"].as_i64().unwrap() >= 1);
        assert!(log["body"]["stringValue"].is_string());
    }
}
