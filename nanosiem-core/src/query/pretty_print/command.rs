// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pretty-print implementation for commands.

use super::super::ast::*;
use super::helpers::{dataset_selector_str, format_duration};
use super::PrettyPrint;

impl PrettyPrint for Command {
    fn pretty_print(&self) -> String {
        match self {
            Command::Stats {
                aggregations,
                group_by,
            } => {
                let aggs = aggregations
                    .iter()
                    .map(|a| a.pretty_print())
                    .collect::<Vec<_>>()
                    .join(", ");
                match group_by {
                    Some(fields) => format!("stats {} by {}", aggs, fields.join(", ")),
                    None => format!("stats {}", aggs),
                }
            }
            Command::Chart {
                aggregations,
                group_by,
            } => {
                let aggs = aggregations
                    .iter()
                    .map(|a| a.pretty_print())
                    .collect::<Vec<_>>()
                    .join(", ");
                match group_by {
                    Some(fields) => format!("chart {} by {}", aggs, fields.join(", ")),
                    None => format!("chart {}", aggs),
                }
            }
            Command::StreamStats {
                aggregations,
                group_by,
                current,
                window,
            } => {
                let aggs = aggregations
                    .iter()
                    .map(|a| a.pretty_print())
                    .collect::<Vec<_>>()
                    .join(", ");
                let mut parts = vec!["streamstats".to_string()];
                if !*current {
                    parts.push("current=false".to_string());
                }
                if let Some(w) = window {
                    parts.push(format!("window={}", w));
                }
                parts.push(aggs);
                if let Some(fields) = group_by {
                    parts.push(format!("by {}", fields.join(", ")));
                }
                parts.join(" ")
            }
            Command::Where { condition } => {
                format!("where {}", condition.pretty_print())
            }
            Command::Sort { fields, limit } => {
                let field_strs: Vec<String> = fields
                    .iter()
                    .map(|sf| {
                        if sf.descending {
                            format!("-{}", sf.field)
                        } else {
                            format!("+{}", sf.field)
                        }
                    })
                    .collect();
                match limit {
                    Some(n) => format!("sort {} {}", n, field_strs.join(", ")),
                    None => format!("sort {}", field_strs.join(", ")),
                }
            }
            Command::Head { count } => {
                format!("head {}", count)
            }
            Command::Tail { count } => {
                format!("tail {}", count)
            }
            Command::Timechart {
                span,
                aggregations,
                split_by,
                limit,
                cont,
            } => {
                let aggs = aggregations
                    .iter()
                    .map(|a| a.pretty_print())
                    .collect::<Vec<_>>()
                    .join(", ");
                let span_str = format_duration(*span);
                let mut result = if split_by.is_empty() {
                    format!("timechart span={} {}", span_str, aggs)
                } else {
                    format!(
                        "timechart span={} {} by {}",
                        span_str,
                        aggs,
                        split_by.join(", ")
                    )
                };
                if let Some(n) = limit {
                    result.push_str(&format!(" limit={}", n));
                }
                if *cont {
                    result.push_str(" cont=true");
                }
                result
            }
            Command::Table { fields } => {
                // Handle wildcard efficiently
                if fields.len() == 1 && fields[0].name == "*" {
                    return "table *".to_string();
                }

                let field_strs = fields
                    .iter()
                    .map(|f| match &f.alias {
                        Some(alias) => format!("{} as {}", f.name, alias),
                        None => f.name.clone(),
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("table {}", field_strs)
            }
            Command::Rename { mappings } => {
                let renames = mappings
                    .iter()
                    .map(|m| format!("{} as {}", m.from, m.to))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("rename {}", renames)
            }
            Command::Lookup {
                table_name,
                key_field,
                output_fields,
                case_insensitive,
            } => {
                let mut result = format!("lookup {} {}", table_name, key_field);
                if let Some(fields) = output_fields {
                    result.push_str(&format!(" OUTPUT {}", fields.join(", ")));
                }
                if *case_insensitive {
                    result.push_str(" CASE_INSENSITIVE");
                }
                result
            }
            Command::Eval { assignments } => {
                let assigns = assignments
                    .iter()
                    .map(|a| format!("{} = {}", a.field, a.expression.pretty_print()))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("eval {}", assigns)
            }
            Command::Dedup { fields, keep_first } => {
                let mut result = format!("dedup {}", fields.join(", "));
                if !keep_first {
                    result.push_str(" keeplast=true");
                }
                result
            }
            Command::Bin {
                span,
                field,
                alias,
                window_type,
            } => {
                let span_str = match span {
                    BinSpan::Time(duration) => format_duration(*duration),
                    BinSpan::Numeric(value) => value.to_string(),
                };
                let mut result = format!("bin span={}", span_str);
                // Add window type if not tumbling (default)
                match window_type {
                    WindowType::Tumbling => {}
                    WindowType::Hop { advance } => {
                        result.push_str(&format!(" hop={}", format_duration(*advance)));
                    }
                    WindowType::Sliding => {
                        result.push_str(" sliding");
                    }
                }
                if let Some(f) = field {
                    result.push_str(&format!(" {}", f));
                }
                if let Some(a) = alias {
                    result.push_str(&format!(" as {}", a));
                }
                result
            }
            Command::Rex {
                field,
                pattern,
                mode,
            } => {
                let mut result = "rex".to_string();
                if let Some(f) = field {
                    result.push_str(&format!(" field={}", f));
                }
                result.push_str(&format!(" \"{}\"", pattern));
                if let RexMode::Sed {
                    pattern: sed_pat,
                    replacement,
                } = mode
                {
                    result.push_str(&format!(" mode=sed \"s/{}/{}/\"", sed_pat, replacement));
                }
                result
            }
            Command::Fields { fields, keep } => {
                let prefix = if *keep { "" } else { "- " };
                format!("fields {}{}", prefix, fields.join(", "))
            }
            Command::Top {
                field,
                limit,
                by_fields,
                show_count: _,
                show_percent: _,
                inject_bounds,
            } => {
                let mut result = format!("top limit={} {}", limit, field);
                if !by_fields.is_empty() {
                    result.push_str(&format!(" by {}", by_fields.join(", ")));
                }
                if *inject_bounds {
                    // Internal token (NAN-1711 / audit D15): keeps the detection
                    // enrichment's canonical-window flag alive across the
                    // pretty_print → re-parse round-trip in evaluate_window.
                    result.push_str(" _bounds=true");
                }
                result
            }
            Command::Rare {
                field,
                limit,
                by_fields,
                show_count: _,
                show_percent: _,
                inject_bounds,
            } => {
                let mut result = format!("rare limit={} {}", limit, field);
                if !by_fields.is_empty() {
                    result.push_str(&format!(" by {}", by_fields.join(", ")));
                }
                if *inject_bounds {
                    // Internal token (NAN-1711 / audit D15) — see the `top` arm.
                    result.push_str(" _bounds=true");
                }
                result
            }
            Command::Transaction {
                fields,
                startswith,
                endswith,
                maxspan,
                maxevents,
            } => {
                let mut result = format!("transaction {}", fields.join(", "));
                // Parenthesize startswith/endswith so the round-trip (NAN-1342) re-parses:
                // a bare `startswith=login` lets the parser's greedy `search_expr` swallow the
                // following `endswith=…`/`maxspan=…` params; the `(…)` form is bounded.
                if let Some(expr) = startswith {
                    result.push_str(&format!(" startswith=({})", expr.pretty_print()));
                }
                if let Some(expr) = endswith {
                    result.push_str(&format!(" endswith=({})", expr.pretty_print()));
                }
                if let Some(span) = maxspan {
                    result.push_str(&format!(" maxspan={}", format_duration(*span)));
                }
                if let Some(max) = maxevents {
                    result.push_str(&format!(" maxevents={}", max));
                }
                result
            }
            Command::Fillnull { value, fields } => {
                let mut result = format!("fillnull value=\"{}\"", value);
                if let Some(f) = fields {
                    result.push_str(&format!(" {}", f.join(", ")));
                }
                result
            }
            Command::Mvexpand { field, limit } => {
                let mut result = format!("mvexpand {}", field);
                if let Some(l) = limit {
                    result.push_str(&format!(" limit={}", l));
                }
                result
            }
            Command::Spath {
                input,
                output,
                path,
            } => {
                let mut result = "spath".to_string();
                if let Some(i) = input {
                    result.push_str(&format!(" input={}", i));
                }
                if let Some(o) = output {
                    result.push_str(&format!(" output={}", o));
                }
                if let Some(p) = path {
                    result.push_str(&format!(" path={}", p));
                }
                result
            }
            Command::Append { subsearch, maxout } => {
                let mut result = "append".to_string();
                if let Some(mo) = maxout {
                    result.push_str(&format!(" maxout={}", mo));
                }
                result.push_str(&format!(" [{}]", subsearch.pretty_print()));
                result
            }
            Command::Join {
                join_type,
                fields,
                subsearch,
                max,
                overwrite,
                maxout,
                subsearch_dataset,
            } => {
                let mut result = "join".to_string();
                if *join_type != JoinType::Inner {
                    result.push_str(&format!(" type={}", join_type.as_str()));
                }
                if *max != 1 {
                    result.push_str(&format!(" max={}", max));
                }
                if let Some(mo) = maxout {
                    result.push_str(&format!(" maxout={}", mo));
                }
                if !*overwrite {
                    result.push_str(" overwrite=false");
                }
                // NAN-1562: render the cross-dataset selector inside the brackets.
                let ds_prefix = match subsearch_dataset {
                    Some(ds) => format!("dataset={} ", dataset_selector_str(*ds)),
                    None => String::new(),
                };
                result.push_str(&format!(
                    " {} [{}{}]",
                    fields.join(", "),
                    ds_prefix,
                    subsearch.pretty_print()
                ));
                result
            }
            Command::Format {
                maxresults,
                row_sep: _,
                col_sep: _,
            } => match maxresults {
                Some(n) => format!("format maxresults={}", n),
                None => "format".to_string(),
            },
            Command::Return { count, fields } => {
                format!("return {} {}", count, fields.join(", "))
            }
            Command::Risk {
                score,
                entity_field,
                factor,
                weight,
            } => {
                let score_str = match score {
                    RiskScoreExpr::Literal(s) => s.to_string(),
                    RiskScoreExpr::Dynamic(expr) => expr.pretty_print(),
                };
                let mut result = format!("risk score={}", score_str);
                if let Some(entity) = entity_field {
                    result.push_str(&format!(" entity={}", entity));
                }
                if let Some(f) = factor {
                    result.push_str(&format!(" factor={}", f.pretty_print()));
                }
                if let Some(w) = weight {
                    result.push_str(&format!(" weight={}", w));
                }
                result
            }
            Command::Prevalence {
                conditions,
                time_window,
                enrich,
            } => {
                if *enrich {
                    // Enrichment mode
                    let mut result = "prevalence enrich=true".to_string();
                    if let Some(tw) = time_window {
                        result.push_str(&format!(" window={}", tw.as_str()));
                    }
                    result
                } else {
                    // Filtering mode with one or more conditions
                    let mut result = "prevalence".to_string();
                    for condition in conditions {
                        result.push_str(&format!(
                            " {} {}",
                            condition.field.as_str(),
                            condition.operator.as_str()
                        ));
                        match &condition.threshold {
                            PrevalenceThreshold::Count(n) => result.push_str(&format!(" {}", n)),
                            PrevalenceThreshold::Duration(d) => {
                                result.push_str(&format!(" now() - {}", format_duration(*d)));
                            }
                        }
                    }
                    if let Some(tw) = time_window {
                        result.push_str(&format!(" window={}", tw.as_str()));
                    }
                    result
                }
            }
            Command::Sample { limit } => {
                format!("sample {}", limit)
            }
            Command::Reverse => "reverse".to_string(),
            Command::EventStats {
                aggregations,
                group_by,
            } => {
                let agg_str = aggregations
                    .iter()
                    .map(|a| a.pretty_print())
                    .collect::<Vec<_>>()
                    .join(", ");
                match group_by {
                    Some(fields) => format!("eventstats {} by {}", agg_str, fields.join(", ")),
                    None => format!("eventstats {}", agg_str),
                }
            }
            Command::Sequence {
                group_by,
                maxspan,
                conditions,
                capture_fields,
            } => {
                let mut parts = vec![format!("sequence by {}", group_by.join(", "))];
                if let Some(span) = maxspan {
                    parts.push(format!("maxspan={}s", span.as_secs()));
                }
                if !capture_fields.is_empty() {
                    parts.push(format!("fields({})", capture_fields.join(", ")));
                }
                for condition in conditions {
                    parts.push(format!("[{}]", condition.pretty_print()));
                }
                parts.join(" ")
            }
            Command::Funnel {
                group_by,
                window,
                steps,
            } => {
                let mut parts = vec![
                    format!("funnel by {}", group_by.join(", ")),
                    format!("window={}s", window.as_secs()),
                ];
                // Parenthesize each step condition (NAN-1342). `step1="action="login""`
                // (wrapping the printed condition in quotes) produces broken nested quotes
                // that fail the re-parse; `step1=(action="login")` round-trips cleanly.
                for (name, condition) in steps {
                    parts.push(format!("{}=({})", name, condition.pretty_print()));
                }
                parts.join(" ")
            }
            Command::Anomaly {
                field,
                by_fields,
                threshold,
                method,
            } => {
                // Emit the field bare, not `field={field}` (NAN-1342): the field may be an
                // aggregation expression like `count()` or `sum(bytes)`, which the parser's
                // `field=` branch rejects (it expects a plain name). The bare form is matched
                // by the agg-first and bare-field branches, which accept both.
                let mut parts = vec![format!("anomaly {}", field)];
                if !by_fields.is_empty() {
                    parts.push(format!("by {}", by_fields.join(", ")));
                }
                parts.push(format!("threshold={}", threshold));
                if *method != AnomalyMethod::ZScore {
                    let method_str = match method {
                        AnomalyMethod::ZScore => "zscore",
                        AnomalyMethod::Mad => "mad",
                    };
                    parts.push(format!("method={}", method_str));
                }
                parts.join(" ")
            }
            Command::InputLookup {
                url,
                format,
                key_field,
                timeout_secs,
                max_rows,
                cache_ttl_secs,
            } => {
                let mut parts = vec![format!("inputlookup url=\"{}\"", url.template)];
                if *format != InputLookupFormat::Json {
                    parts.push(format!("format={}", format.as_str()));
                }
                if let Some(key) = key_field {
                    parts.push(format!("key={}", key));
                }
                if *timeout_secs != 30 {
                    parts.push(format!("timeout={}", timeout_secs));
                }
                if *max_rows != 10000 {
                    parts.push(format!("max_rows={}", max_rows));
                }
                if *cache_ttl_secs != 300 {
                    parts.push(format!("cache_ttl={}", cache_ttl_secs));
                }
                parts.join(" ")
            }
            Command::Tree {
                parent_field,
                child_field,
                label_field,
                detail_field,
                prevalence_field,
                root_filter,
            } => {
                // Positional form: the parser's `tree <field>` syntax leaves `parent_field`
                // empty and sets child==label. Emitting the named form with an empty
                // `parent=` produces invalid nPL (`tree parent= child=…`) that fails the
                // round-trip re-parse (NAN-1342); emit the positional form instead.
                if parent_field.is_empty() {
                    let mut parts = vec![format!("tree {}", child_field)];
                    if let Some(root) = root_filter {
                        parts.push(format!("root=\"{}\"", root));
                    }
                    return parts.join(" ");
                }
                let mut parts = vec![
                    "tree".to_string(),
                    format!("parent={}", parent_field),
                    format!("child={}", child_field),
                    format!("label={}", label_field),
                ];
                if let Some(detail) = detail_field {
                    parts.push(format!("detail={}", detail));
                }
                if let Some(prevalence) = prevalence_field {
                    parts.push(format!("prevalence={}", prevalence));
                }
                if let Some(root) = root_filter {
                    parts.push(format!("root=\"{}\"", root));
                }
                parts.join(" ")
            }
            Command::ResolveIdentity { field, max_age } => {
                let mut parts = vec!["resolve_identity".to_string()];
                if field != "src_ip" {
                    parts.push(format!("field={}", field));
                }
                let default_max_age = std::time::Duration::from_secs(24 * 3600);
                if *max_age != default_max_age {
                    let hours = max_age.as_secs() / 3600;
                    if hours > 0 && max_age.as_secs() % 3600 == 0 {
                        parts.push(format!("max_age={}h", hours));
                    } else {
                        parts.push(format!("max_age={}s", max_age.as_secs()));
                    }
                }
                parts.join(" ")
            }
            Command::Asset {
                identifier_field,
                sections,
                max_identity_age,
            } => {
                let mut parts = vec!["asset".to_string()];
                if let Some(field) = identifier_field {
                    parts.push(format!("field={}", field));
                }
                if let Some(sects) = sections {
                    let section_names: Vec<&str> = sects.iter().map(|s| s.as_str()).collect();
                    parts.push(format!("sections={}", section_names.join(",")));
                }
                let default_max_age = std::time::Duration::from_secs(14 * 24 * 3600);
                if *max_identity_age != default_max_age {
                    let days = max_identity_age.as_secs() / 86400;
                    if days > 0 && max_identity_age.as_secs() % 86400 == 0 {
                        parts.push(format!("max_age={}d", days));
                    } else {
                        let hours = max_identity_age.as_secs() / 3600;
                        if hours > 0 && max_identity_age.as_secs() % 3600 == 0 {
                            parts.push(format!("max_age={}h", hours));
                        } else {
                            parts.push(format!("max_age={}s", max_identity_age.as_secs()));
                        }
                    }
                }
                parts.join(" ")
            }
            Command::Cloud {
                group_by,
                show_mfa,
                principal,
                account,
            } => {
                let mut parts = vec!["cloud".to_string()];
                if *group_by != CloudGroupBy::Service {
                    parts.push(format!("by={}", group_by.as_str()));
                }
                if *show_mfa {
                    parts.push("show_mfa=true".to_string());
                }
                if let Some(p) = principal {
                    parts.push(format!("principal=\"{}\"", p));
                }
                if let Some(a) = account {
                    parts.push(format!("account=\"{}\"", a));
                }
                parts.join(" ")
            }
            Command::Lateral {
                seed_type,
                entity_field,
                max_hops,
                time_window,
                methods,
            } => {
                let mut parts = vec!["lateral".to_string()];
                if *seed_type != LateralSeedType::Auto {
                    parts.push(format!("seed={}", seed_type.as_str()));
                }
                if let Some(field) = entity_field {
                    parts.push(format!("entity={}", field));
                }
                if *max_hops != 4 {
                    parts.push(format!("maxhops={}", max_hops));
                }
                if let Some(window) = time_window {
                    parts.push(format!("window={}", format_duration(*window)));
                }
                if *methods != LateralMethod::all() {
                    let method_names: Vec<&str> = methods.iter().map(|m| m.as_str()).collect();
                    parts.push(format!("methods={}", method_names.join(",")));
                }
                parts.join(" ")
            }
            Command::Ai { prompt, max_rows } => {
                let mut parts = vec![format!(r#"ai prompt="{}""#, prompt)];
                if *max_rows != 100 {
                    parts.push(format!("max_rows={}", max_rows));
                }
                parts.join(" ")
            }
            Command::Output { destination } => {
                format!("output {}", destination)
            }
            Command::Services => "services".to_string(),
            Command::Service { name } => format!("service {}", name),
            Command::Trace { trace_id } => format!("trace {}", trace_id),
            Command::Metric { name, service } => match service {
                Some(svc) => format!("metric {} service={}", name, svc),
                None => format!("metric {}", name),
            },
            // NAN-1580: bare `retro` or `retro by <axis>`.
            Command::Retro { axis } => match axis {
                RetroAxis::Indicator => "retro".to_string(),
                other => format!("retro by {}", other.as_str()),
            },
            // NAN-1868: `baseline [host=|user=|ip="X"] [window=Nd] [dims=a,b]`.
            Command::Baseline {
                entity_type,
                entity_value,
                window,
                dims,
            } => {
                let mut parts = vec!["baseline".to_string()];
                if let (Some(t), Some(v)) = (entity_type, entity_value) {
                    parts.push(format!("{}=\"{}\"", t, v));
                }
                let default_window = std::time::Duration::from_secs(7 * 24 * 3600);
                if *window != default_window {
                    parts.push(format!("window={}", format_duration(*window)));
                }
                if let Some(d) = dims {
                    parts.push(format!("dims={}", d.join(",")));
                }
                parts.join(" ")
            }
        }
    }
}
