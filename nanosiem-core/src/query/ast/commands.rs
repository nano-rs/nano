// SPDX-License-Identifier: AGPL-3.0-or-later

//! Command types for piped query language
//!
//! This module defines the `Command` enum and all command-specific supporting types
//! (join, rex, lookup, asset, cloud, inputlookup, etc.).

use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::aggregation::Aggregation;
use super::eval::{EvalAssignment, EvalExpression, RiskScoreExpr};
use super::eval::{SortField, TableField};
use super::lateral::{LateralMethod, LateralSeedType};
use super::prevalence::{PrevalenceCondition, PrevalenceTimeWindow};
use super::types::{BinSpan, Query, SearchExpr, WindowType};

/// Piped commands that transform query results
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Command {
    /// stats command: aggregate results
    Stats {
        aggregations: Vec<Aggregation>,
        group_by: Option<Vec<String>>,
    },
    /// chart command: aggregate results (alias for stats, used for visualization)
    Chart {
        aggregations: Vec<Aggregation>,
        group_by: Option<Vec<String>>,
    },
    /// streamstats command: calculate running/cumulative statistics per event
    /// Unlike stats which aggregates rows, streamstats adds new fields to each event
    /// Syntax: streamstats [current=true|false] [window=N] agg1, agg2, ... [by field1, field2]
    /// Example: streamstats current=false last(timestamp) as prev_ts by dest_host
    /// Example: streamstats window=10 avg(bytes) as rolling_avg by src_ip
    StreamStats {
        /// Aggregation functions to compute (count, sum, avg, min, max, first, last, etc.)
        aggregations: Vec<Aggregation>,
        /// Fields to partition/group by (each group has its own running stats)
        group_by: Option<Vec<String>>,
        /// Whether to include current row in calculation (default: true)
        current: bool,
        /// Number of preceding rows to include (None = all preceding rows)
        window: Option<usize>,
    },
    /// where command: filter results
    Where { condition: SearchExpr },
    /// sort command: order results (supports multiple fields)
    Sort {
        fields: Vec<SortField>,
        limit: Option<usize>,
    },
    /// head command: limit to first N results
    Head { count: usize },
    /// tail command: limit to last N results
    Tail { count: usize },
    /// timechart command: time-based aggregation
    Timechart {
        span: Duration,
        aggregations: Vec<Aggregation>,
        split_by: Vec<String>,
        /// Limit number of split-by series (top N by first aggregation).
        limit: Option<usize>,
        /// Continuous time axis — fill gaps with zeros (default: false).
        cont: bool,
    },
    /// table command: select specific fields (with optional aliases)
    Table { fields: Vec<TableField> },
    /// rename command: rename fields in results
    Rename { mappings: Vec<FieldRename> },
    /// lookup command: enrich results with data from lookup tables
    /// Syntax: lookup <table_name> <key_field> [OUTPUT <field1>, <field2>, ...] [CASE_INSENSITIVE]
    Lookup {
        /// Name of the lookup table
        table_name: String,
        /// Field in the log results to match against the lookup table's key
        key_field: String,
        /// Optional list of fields to output from the lookup table (None = all fields)
        output_fields: Option<Vec<String>>,
        /// Whether to perform case-insensitive matching
        case_insensitive: bool,
    },
    /// eval command: create calculated fields
    /// Syntax: eval field1=expression1, field2=expression2, ...
    Eval { assignments: Vec<EvalAssignment> },
    /// dedup command: remove duplicate events
    /// Syntax: dedup field1, field2, ... [keepfirst=true|false] [keeplast=true|false]
    Dedup {
        /// Fields to use for deduplication
        fields: Vec<String>,
        /// Keep first occurrence (default: true)
        keep_first: bool,
    },
    /// bin command: bucket timestamps or numeric values into bins for aggregation
    /// Syntax: bin span=10m [hop=5m] [field] (time-based) or bin field span=5000 (numeric)
    /// Window types:
    ///   - Tumbling (default): non-overlapping fixed windows
    ///   - Hop: overlapping windows that advance by a specified interval
    ///   - Sliding: window slides with each event
    /// Use with stats for time-windowed detection rules:
    ///   action=login status=failure | bin span=10m | stats count by time_bucket, src_ip | where count > 5
    ///   * | bin span=1h hop=5m | stats count by time_bucket  -- hop window
    ///   * | bin bytes_out span=5000 | stats count by bytes_out
    Bin {
        /// Span for each bucket - either time duration or numeric value
        span: BinSpan,
        /// Field to bin (defaults to "timestamp" for time bins, required for numeric bins)
        field: Option<String>,
        /// Output field name (defaults to field name or "time_bucket")
        alias: Option<String>,
        /// Window type: tumbling (default), hop, or sliding
        window_type: WindowType,
    },
    /// rex command: extract fields using regex capture groups
    /// Syntax: rex field=<field> "(?<name>pattern)"
    Rex {
        /// Source field to extract from (defaults to message)
        field: Option<String>,
        /// Regex pattern with named capture groups
        pattern: String,
        /// Mode: extract (default) or sed for replacement
        mode: RexMode,
    },
    /// fields command: include or exclude specific fields
    /// Syntax: fields [+|-] field1, field2, ...
    Fields {
        /// Fields to include/exclude
        fields: Vec<String>,
        /// Whether to keep (+) or remove (-) the fields
        keep: bool,
    },
    /// top command: find most common values
    /// Syntax: top [limit=N] field [by field2]
    Top {
        /// Field to find top values for
        field: String,
        /// Number of results (default 10)
        limit: usize,
        /// Fields to split by
        by_fields: Vec<String>,
        /// Show count column
        show_count: bool,
        /// Show percent column
        show_percent: bool,
    },
    /// rare command: find least common values
    /// Syntax: rare [limit=N] field [by field1, field2]
    Rare {
        /// Field to find rare values for
        field: String,
        /// Number of results (default 10)
        limit: usize,
        /// Fields to split by
        by_fields: Vec<String>,
        /// Show count column
        show_count: bool,
        /// Show percent column
        show_percent: bool,
    },
    /// transaction command: group related events
    /// Syntax: transaction field [startswith=expr] [endswith=expr] [maxspan=duration]
    Transaction {
        /// Fields to group by
        fields: Vec<String>,
        /// Expression that starts a transaction
        startswith: Option<SearchExpr>,
        /// Expression that ends a transaction
        endswith: Option<SearchExpr>,
        /// Maximum time span for a transaction
        maxspan: Option<Duration>,
        /// Maximum number of events in a transaction
        maxevents: Option<usize>,
    },
    /// fillnull command: replace null values
    /// Syntax: fillnull [value=<string>] [field1, field2, ...]
    Fillnull {
        /// Value to use for nulls (default "NULL")
        value: String,
        /// Fields to fill (None = all fields)
        fields: Option<Vec<String>>,
    },
    /// mvexpand command: expand multi-value fields
    /// Syntax: mvexpand field [limit=N]
    Mvexpand {
        /// Field to expand
        field: String,
        /// Maximum number of values to expand
        limit: Option<usize>,
    },
    /// spath command: extract fields from JSON/XML
    /// Syntax: spath [input=field] [output=field] [path=jsonpath]
    Spath {
        /// Input field containing JSON/XML (default: _raw)
        input: Option<String>,
        /// Output field name
        output: Option<String>,
        /// JSON path to extract
        path: Option<String>,
    },
    /// append command: append results from a subsearch
    /// Syntax: append [maxout=N] [subsearch]
    Append {
        /// The subsearch query to append
        subsearch: Box<Query>,
        /// Maximum total rows the subsearch returns (default: 10,000)
        maxout: Option<usize>,
    },
    /// join command: combine results from main search with subsearch
    /// Syntax: join [type=inner|left|outer] field1, field2 [max=N] [maxout=N] [[dataset=spans] subsearch]
    /// Example: ... | join type=left user [search index=users | fields user, dept]
    /// Cross-dataset example: spans … | join trace_id [dataset=logs search status=500]
    Join {
        /// Type of join to perform
        join_type: JoinType,
        /// Fields to join on
        fields: Vec<String>,
        /// The subsearch query to join with
        subsearch: Box<Query>,
        /// Maximum results from subsearch per key (default: 1)
        max: usize,
        /// Whether to overwrite existing fields from subsearch (default: true)
        overwrite: bool,
        /// Maximum total rows the subsearch returns (default: 10,000)
        maxout: Option<usize>,
        /// Cross-dataset correlation (NAN-1562): the dataset the subsearch runs
        /// against, parsed from a leading `dataset=<logs|spans|metrics>` token
        /// inside the `[ ]` brackets. `None` means the subsearch inherits the
        /// outer query's dataset (the pre-existing, byte-identical behavior).
        subsearch_dataset: Option<crate::query::clickhouse_sql_gen::otel::Dataset>,
    },
    /// format command: format results into a single string
    /// Syntax: format [maxresults=N]
    Format {
        /// Maximum results to format
        maxresults: Option<usize>,
        /// Row separator
        row_sep: String,
        /// Column separator
        col_sep: String,
    },
    /// return command: return field values from subsearch
    /// Syntax: return [count] field1, field2, ...
    Return {
        /// Number of values to return
        count: usize,
        /// Fields to return
        fields: Vec<String>,
    },
    /// risk command: assign risk scores to events for risk-based alerting
    /// Syntax: risk score=N [entity=field] [factor="description" | factor=expr] [weight=0.5]
    /// The score can be a literal integer or a dynamic expression (field reference, arithmetic, conditional)
    /// The factor can be a simple string or a dynamic expression with string concatenation
    Risk {
        /// Risk score to assign (0-100) - can be literal or dynamic expression
        score: RiskScoreExpr,
        /// Field containing the entity to score (optional)
        entity_field: Option<String>,
        /// Risk factor description (optional) - can be a simple string or dynamic expression
        factor: Option<EvalExpression>,
        /// Optional weight override (0.0-1.0) - if not specified, uses global weight
        weight: Option<f64>,
    },
    /// prevalence command: filter or enrich results based on artifact prevalence
    /// Syntax: prevalence hash_prevalence < 5 window=24h
    /// Syntax: prevalence hash_prevalence < 5 domain_first_seen > now()-24h window=24h
    /// Syntax: prevalence enrich=true [window=24h]
    Prevalence {
        /// Filter conditions (can have multiple, all must be satisfied)
        conditions: Vec<PrevalenceCondition>,
        /// Time window for prevalence calculation
        time_window: Option<PrevalenceTimeWindow>,
        /// Whether to enrich results with prevalence data (enrichment mode)
        enrich: bool,
    },
    /// sample command: return random sample of events
    /// Syntax: sample [N] (default: 1000)
    /// Example: * | sample 100
    Sample {
        /// Number of events to sample
        limit: usize,
    },
    /// reverse command: reverse the order of events
    /// Syntax: reverse
    /// Example: * | head 100 | reverse
    Reverse,
    /// eventstats command: calculate statistics while preserving all rows
    /// Unlike stats which aggregates rows, eventstats adds aggregation results to each row
    /// Syntax: eventstats agg1, agg2 [by field1, field2]
    /// Example: * | eventstats count() by src_ip | where count > 10
    EventStats {
        /// Aggregation functions to compute
        aggregations: Vec<Aggregation>,
        /// Fields to partition/group by
        group_by: Option<Vec<String>>,
    },
    /// sequence command: detect ordered event patterns
    /// Syntax: sequence by field1, field2 [maxspan=duration] [fields(f1,f2)] [condition1] [condition2] ...
    /// Example: * | sequence by src_ip maxspan=5m fields(message, url) [action="login_fail"] [action="login_success"]
    Sequence {
        /// Fields to partition/group by (e.g., src_ip, user)
        group_by: Vec<String>,
        /// Maximum time span between first and last event
        maxspan: Option<Duration>,
        /// Ordered list of conditions that must match in sequence
        conditions: Vec<SearchExpr>,
        /// Additional fields to capture from each step's matching event
        capture_fields: Vec<String>,
    },
    /// funnel command: analyze conversion through sequential steps
    /// Syntax: funnel by field1, field2 window=duration step1=cond1 step2=cond2 ...
    /// Example: * | funnel by session_id window=1h step1="initial_access" step2="execution" step3="persistence"
    Funnel {
        /// Fields to partition/group by (e.g., session_id, user)
        group_by: Vec<String>,
        /// Time window for funnel completion
        window: Duration,
        /// Ordered steps with names and conditions
        steps: Vec<(String, SearchExpr)>,
    },
    /// anomaly command: detect statistical outliers
    /// Syntax: anomaly field=field_name [by field1, field2] [threshold=N]
    /// Example: * | anomaly sum(bytes_out) by src_ip, user threshold=3
    Anomaly {
        /// Field to analyze for anomalies
        field: String,
        /// Fields to group by (calculate stats per group)
        by_fields: Vec<String>,
        /// Number of standard deviations for outlier threshold (default: 3)
        threshold: f64,
        /// Detection method (zscore or mad)
        method: AnomalyMethod,
    },
    /// inputlookup command: fetch data from external URLs for enrichment
    /// Syntax: inputlookup url="URL" [format=json|csv] [key=field] [timeout=N] [max_rows=N] [cache_ttl=N]
    /// Data source mode: | inputlookup url="https://feeds.example.com/iocs.csv" format=csv
    /// Enrichment mode: ... | inputlookup url="https://api.ipinfo.io/{src_ip}/json" key=src_ip format=json
    InputLookup {
        /// URL template with optional {field} placeholders
        url: UrlTemplate,
        /// Response format (json or csv)
        format: InputLookupFormat,
        /// Field to join on (enables enrichment mode when set)
        key_field: Option<String>,
        /// Request timeout in seconds (default: 30)
        timeout_secs: u32,
        /// Maximum rows to return (default: 10000)
        max_rows: usize,
        /// Cache TTL in seconds (default: 300, 0 = no cache)
        cache_ttl_secs: u32,
    },
    /// tree command: visualize hierarchical relationships with optional prevalence
    /// Syntax: tree parent=<field> child=<field> label=<field> [detail=<field>] [prevalence=<field>] [root=<pattern>]
    /// Builds a tree structure from flat results based on parent-child relationships
    Tree {
        /// Field containing parent identifier (e.g., parent_process_id, referrer)
        parent_field: String,
        /// Field containing child identifier (e.g., process_id, url)
        child_field: String,
        /// Field to display as node label (e.g., process_name, dest_host)
        label_field: String,
        /// Optional field for detail text (e.g., process, file_name)
        detail_field: Option<String>,
        /// Optional field to enrich with prevalence (e.g., file_hash, domain)
        prevalence_field: Option<String>,
        /// Optional root filter - show only subtree(s) rooted at nodes matching this pattern
        root_filter: Option<String>,
    },
    /// resolve_identity command: enrich events with identity from ASOF JOIN lookup
    /// Supports bidirectional lookups via ASOF JOIN on identity_observations:
    /// - IP fields (src_ip, dest_ip): JOIN on i.ip -> fills src_host, src_mac, user
    /// - User fields (user, dest_user): JOIN on i.user -> fills src_host, src_mac, identity_ip
    /// - Hostname fields (src_host, dest_host): JOIN on i.hostname -> fills src_mac, user, identity_ip
    /// Adds: identity_confidence, identity_observed_at, identity_source, identity_fqdn.
    /// For reverse lookups (user/hostname), also adds identity_ip with the resolved IP.
    /// Syntax: | resolve_identity [field=src_ip] [max_age=24h]
    /// Example: source_type=firewall | resolve_identity | table timestamp src_ip src_host user
    /// Example: user="jsmith" | resolve_identity field=user | table timestamp identity_ip src_host
    ResolveIdentity {
        /// Field to resolve -- IP, user, or hostname (default: src_ip)
        field: String,
        /// Maximum age of identity observation to use (default: 24h)
        max_age: Duration,
    },
    /// asset command: create an asset-centric view with identity resolution and activity aggregation
    /// Similar to Chronicle asset view - shows all activity for a host/IP/user across time
    /// Syntax: | asset [field=src_host|src_ip|user] [sections=network,process,auth,file,dns,alerts] [max_age=14d]
    /// Example: src_host = "workstation-42" | asset
    /// Example: src_ip = "10.1.1.50" | asset field=src_ip
    /// Example: user = "jsmith" | asset sections=auth,process
    Asset {
        /// Field containing the asset identifier (auto-detected if not specified: src_host, src_ip, user, mac)
        identifier_field: Option<String>,
        /// Sections to include in asset details (None = all sections)
        sections: Option<Vec<AssetSection>>,
        /// Maximum age of identity observations to use (default: 14 days)
        max_identity_age: Duration,
    },
    /// cloud command: create a cloud-centric investigation view with faceted summaries
    /// Syntax: | cloud [by=provider|account|region|service|resource] [show_mfa=true]
    ///                 [principal=<id>] [account=<id>]
    /// Example: cloud_provider=aws | cloud
    /// Example: cloud_service=iam | cloud by=account show_mfa=true
    /// Example: | cloud principal=contractor-acme       -- NAN-395 principal dossier
    Cloud {
        /// Primary grouping dimension (default: service)
        group_by: CloudGroupBy,
        /// Whether to include MFA usage analysis panel
        show_mfa: bool,
        /// Scope to a single IAM principal (user / role / service-account) —
        /// switches the Search result pane to the principal dossier view.
        /// When None, renders the org-wide cloud overview.
        principal: Option<String>,
        /// Optional account scope (AWS account id / GCP project id).
        /// Orthogonal to `principal` — can be combined to narrow the dossier
        /// or the overview to a specific account.
        account: Option<String>,
    },
    /// lateral command: trace lateral movement paths across network
    /// Syntax: lateral [seed=user|host] [entity=field] [maxhops=N] [window=duration] [methods=auth,network,process]
    /// Example: user="jsmith" | lateral
    /// Example: src_host="WKS-0142" | lateral seed=host maxhops=3
    Lateral {
        /// How to identify the seed entity (auto-detect, user, or host)
        seed_type: LateralSeedType,
        /// Specific field to use as seed entity (overrides seed_type auto-detection)
        entity_field: Option<String>,
        /// Maximum number of hops to trace (default: 4)
        max_hops: u32,
        /// Time window for lateral movement search (None = use query time range)
        time_window: Option<Duration>,
        /// Categories of lateral movement evidence to search (default: all)
        methods: Vec<LateralMethod>,
    },
    /// ai command: send results to an LLM for inline classification/enrichment
    /// Syntax: ai prompt="<instruction>" [max_rows=N]
    Ai {
        /// Natural language instruction for the LLM
        prompt: String,
        /// Maximum rows to send to LLM (default 100, hard cap 500)
        max_rows: usize,
    },
    /// output command: write results to a named destination (no-op in query execution)
    /// Syntax: output <destination_name>
    Output {
        /// Destination name for the output
        destination: String,
    },
    /// services command (bare): observability services overview page.
    /// Short-circuits to the curated /api/search/services surface — no log scan.
    /// Syntax: | services
    Services,
    /// service command: single-service detail page (RED metrics, endpoints).
    /// Short-circuits to /api/search/services/{service} — no log scan.
    /// Syntax: | service <name>
    Service {
        /// Service name to drill into (e.g. "checkout-api")
        name: String,
    },
    /// trace command: distributed-trace waterfall page.
    /// Short-circuits to /api/search/trace/{id} — no log scan.
    /// Syntax: | trace <trace_id>
    Trace {
        /// Trace id (hex). Lowercased/escaped downstream by the trace fetch.
        trace_id: String,
    },
    /// metric command: metric time-series page.
    /// Short-circuits to /api/search/metrics/timeseries — no log scan.
    /// Syntax: | metric <metric_name> [service=<service_name>]
    /// Service-scoping (`service=<name>`) is carried on the marker and seeds
    /// MetricsExplorer's `service_name` query param (the promoted `otel_metrics`
    /// column — NOT a tag/attribute filter), so the chart opens genuinely scoped
    /// (NAN-1564, fixing the silent-drop concern from NAN-1560).
    Metric {
        /// Metric name (e.g. "http.server.duration")
        name: String,
        /// Optional `otel_metrics.service_name` scope (`service=<name>`). `None`
        /// ⇒ unscoped (all services).
        service: Option<String>,
    },
    /// retro command: IOC retro-hunt over the time range (NAN-1580).
    /// Paired with a leading `ioc=…` / `ioc in […]` / `ioc in feed("arg")`
    /// observable term, it switches the Search result pane to the retro-hunt
    /// surface (summary / list / pivot submodes are derived downstream from the
    /// ioc term and this axis).
    /// Syntax: ioc=<v> | retro [by asset|user]
    /// Example: ioc="1.2.3.4" | retro
    /// Example: ioc in threatfox("apt29") | retro by asset
    Retro {
        /// Pivot axis: `Indicator` (default, no `by`), `Asset` (`by
        /// asset|host|ip|entity|account`), or `User` (`by user`).
        axis: RetroAxis,
    },
}

/// Pivot axis for the retro-hunt command (NAN-1580).
///
/// Surface keywords normalize as: absent ⇒ `Indicator`; `asset`/`host`/`ip`/
/// `entity`/`account` ⇒ `Asset`; `user` ⇒ `User`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RetroAxis {
    /// Indicator-centric (default): summary or rarest-first list.
    #[default]
    Indicator,
    /// Asset-centric pivot (host / ip / entity / account).
    Asset,
    /// User-centric pivot.
    User,
}

impl RetroAxis {
    /// Returns the string representation of the axis.
    pub fn as_str(&self) -> &'static str {
        match self {
            RetroAxis::Indicator => "indicator",
            RetroAxis::Asset => "asset",
            RetroAxis::User => "user",
        }
    }

    /// Parse an axis from a `by <keyword>` token, normalizing aliases.
    /// `host`/`ip`/`entity`/`account` ⇒ `Asset`; `user` ⇒ `User`;
    /// `asset` ⇒ `Asset`. Unknown tokens return `None`.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "asset" | "host" | "ip" | "entity" | "account" => Some(RetroAxis::Asset),
            "user" => Some(RetroAxis::User),
            "indicator" => Some(RetroAxis::Indicator),
            _ => None,
        }
    }
}

/// Method for anomaly detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AnomalyMethod {
    /// Z-score method using mean and standard deviation (default)
    #[default]
    ZScore,
    /// Median Absolute Deviation method (more robust to outliers)
    Mad,
}

/// Sections available in asset view
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssetSection {
    /// Network activity: top destinations, ports, bytes
    Network,
    /// Process activity: executed processes, command lines, hashes
    Process,
    /// Authentication activity: logins, failures, auth types
    Auth,
    /// File activity: file operations, paths, hashes
    File,
    /// DNS queries: queried domains, record types
    Dns,
    /// Alerts: triggered alerts for this asset
    Alerts,
}

impl AssetSection {
    /// Parse section from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "network" => Some(AssetSection::Network),
            "process" => Some(AssetSection::Process),
            "auth" => Some(AssetSection::Auth),
            "file" => Some(AssetSection::File),
            "dns" => Some(AssetSection::Dns),
            "alerts" => Some(AssetSection::Alerts),
            _ => None,
        }
    }

    /// Returns the string representation of the section
    pub fn as_str(&self) -> &'static str {
        match self {
            AssetSection::Network => "network",
            AssetSection::Process => "process",
            AssetSection::Auth => "auth",
            AssetSection::File => "file",
            AssetSection::Dns => "dns",
            AssetSection::Alerts => "alerts",
        }
    }

    /// Get all available sections
    pub fn all() -> Vec<AssetSection> {
        vec![
            AssetSection::Network,
            AssetSection::Process,
            AssetSection::Auth,
            AssetSection::File,
            AssetSection::Dns,
            AssetSection::Alerts,
        ]
    }
}

/// Primary grouping dimension for cloud investigation view
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CloudGroupBy {
    /// Group by cloud provider (aws, gcp, azure)
    Provider,
    /// Group by cloud account ID
    Account,
    /// Group by cloud region
    Region,
    /// Group by cloud service (default)
    #[default]
    Service,
    /// Group by resource (resource_id + resource_name + resource_type)
    Resource,
}

impl CloudGroupBy {
    /// Parse group-by dimension from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "provider" => Some(CloudGroupBy::Provider),
            "account" => Some(CloudGroupBy::Account),
            "region" => Some(CloudGroupBy::Region),
            "service" => Some(CloudGroupBy::Service),
            "resource" => Some(CloudGroupBy::Resource),
            _ => None,
        }
    }

    /// Returns the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            CloudGroupBy::Provider => "provider",
            CloudGroupBy::Account => "account",
            CloudGroupBy::Region => "region",
            CloudGroupBy::Service => "service",
            CloudGroupBy::Resource => "resource",
        }
    }

    /// Returns the ClickHouse column name for this dimension
    pub fn column_name(&self) -> &'static str {
        match self {
            CloudGroupBy::Provider => "cloud_provider",
            CloudGroupBy::Account => "cloud_account_id",
            CloudGroupBy::Region => "cloud_region",
            CloudGroupBy::Service => "cloud_service",
            CloudGroupBy::Resource => "resource_id",
        }
    }
}

/// Format of the URL response data for inputlookup command
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum InputLookupFormat {
    /// JSON response (array of objects or single object)
    #[default]
    Json,
    /// CSV response with headers
    Csv,
}

impl InputLookupFormat {
    /// Returns the string representation of the format
    pub fn as_str(&self) -> &'static str {
        match self {
            InputLookupFormat::Json => "json",
            InputLookupFormat::Csv => "csv",
        }
    }

    /// Parse format from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "json" => Some(InputLookupFormat::Json),
            "csv" => Some(InputLookupFormat::Csv),
            _ => None,
        }
    }
}

/// URL template with optional field placeholders for inputlookup command
///
/// Templates can contain `{field}` placeholders that get substituted
/// with values from the search results during enrichment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UrlTemplate {
    /// The raw template string with optional {field} placeholders
    pub template: String,
    /// Extracted field names from placeholders (e.g., ["src_ip", "user"])
    pub fields: Vec<String>,
}

impl UrlTemplate {
    /// Create a new URL template from a string
    ///
    /// Automatically extracts {field} placeholders from the template.
    pub fn new(template: &str) -> Self {
        let fields = Self::extract_template_fields(template);
        Self {
            template: template.to_string(),
            fields,
        }
    }

    /// Check if this template has any field placeholders
    pub fn has_placeholders(&self) -> bool {
        !self.fields.is_empty()
    }

    /// Substitute field values into the template
    ///
    /// Returns None if any required field is missing from the values map.
    pub fn substitute(&self, values: &std::collections::HashMap<String, String>) -> Option<String> {
        let mut result = self.template.clone();
        for field in &self.fields {
            let value = values.get(field)?;
            // URL-encode the value for safety
            let encoded = urlencoding::encode(value);
            result = result.replace(&format!("{{{}}}", field), &encoded);
        }
        Some(result)
    }

    /// Extract {field} placeholders from a URL template
    fn extract_template_fields(template: &str) -> Vec<String> {
        let mut fields = Vec::new();
        let mut chars = template.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '{' {
                let mut field = String::new();
                while let Some(&nc) = chars.peek() {
                    if nc == '}' {
                        chars.next(); // consume '}'
                        if !field.is_empty() {
                            fields.push(field);
                        }
                        break;
                    }
                    field.push(chars.next().unwrap());
                }
            }
        }

        fields
    }
}

/// Rex command mode
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RexMode {
    /// Extract fields from text (default)
    Extract,
    /// Sed-like replacement mode
    Sed {
        /// Pattern to match (extracted from sed expression)
        pattern: String,
        /// Replacement string
        replacement: String,
    },
}

/// Join type for join command (Join type)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum JoinType {
    /// Inner join - only matching rows from both sides
    #[default]
    Inner,
    /// Left join - all rows from left, matching from right
    Left,
    /// Outer join - all rows from both sides
    Outer,
}

impl JoinType {
    /// Returns the string representation of the join type
    pub fn as_str(&self) -> &'static str {
        match self {
            JoinType::Inner => "inner",
            JoinType::Left => "left",
            JoinType::Outer => "outer",
        }
    }

    /// Parse join type from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "inner" => Some(JoinType::Inner),
            "left" => Some(JoinType::Left),
            "outer" => Some(JoinType::Outer),
            _ => None,
        }
    }
}

/// Field rename mapping (old_name -> new_name)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldRename {
    /// Original field name
    pub from: String,
    /// New field name (alias)
    pub to: String,
}
