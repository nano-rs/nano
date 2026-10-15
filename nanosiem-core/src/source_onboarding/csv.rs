// SPDX-License-Identifier: AGPL-3.0-or-later
//! RFC 4180 parsing with optional headers; derived status columns are ignored.
use super::*;
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImportRow {
    pub name: String,
    pub vendor: String,
    pub wave: Option<String>,
    pub wave_id: Option<Uuid>,
    pub new_wave: bool,
    pub priority: i16,
    pub owner: String,
    pub target: Option<NaiveDate>,
    pub notes: String,
    pub expected_type: Option<String>,
    pub duplicate: bool,
}
/// Largest CSV `parse` accepts (file read or paste; no server-side fetch).
pub const MAX_CSV_BYTES: usize = 1024 * 1024;
/// HTTP body cap for the endpoints that carry a CSV (`import-preview` and the
/// `import` action): the CSV cap plus headroom for JSON string escaping.
/// Routes set it explicitly so the bound never depends on a framework default.
pub const IMPORT_BODY_LIMIT_BYTES: usize = 2 * MAX_CSV_BYTES + 64 * 1024;
pub fn parse(
    input: &str,
    waves: &[Wave],
    existing_names: &[String],
) -> Result<Vec<ImportRow>, String> {
    if input.len() > MAX_CSV_BYTES {
        return Err("CSV exceeds 1 MiB".into());
    }
    let mut reader = ::csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .trim(::csv::Trim::All)
        .from_reader(input.as_bytes());
    let mut records = reader.records();
    let Some(first) = records.next() else {
        return Ok(vec![]);
    };
    let first = first.map_err(|e| e.to_string())?;
    let header = first.iter().any(|v| {
        v.trim_start_matches('\u{feff}')
            .eq_ignore_ascii_case("name")
    });
    let fields: Vec<String> = if header {
        first
            .iter()
            .map(|s| s.trim_start_matches('\u{feff}').to_ascii_lowercase())
            .collect()
    } else {
        vec!["name", "vendor", "wave", "priority", "owner", "target"]
            .into_iter()
            .map(String::from)
            .collect()
    };
    let mut all = vec![];
    if !header {
        all.push(first);
    }
    for r in records {
        all.push(r.map_err(|e| e.to_string())?);
        if all.len() > 5000 {
            return Err("CSV exceeds 5000 rows".into());
        }
    }
    let mut have: BTreeSet<_> = existing_names.iter().map(|n| n.to_lowercase()).collect();
    let mut ordered = waves.to_vec();
    ordered.sort_by_key(|w| w.order);
    Ok(all
        .iter()
        .filter_map(|r| {
            // Cells exported by `service::export` carry a `'` formula guard
            // (`crate::csv_safe`); strip exactly that marker so import →
            // export → import round-trips instead of growing `''=…`.
            let get = |name: &str| {
                let raw = fields
                    .iter()
                    .position(|f| f == name)
                    .and_then(|i| r.get(i))
                    .unwrap_or("")
                    .trim()
                    .trim_start_matches('\u{feff}');
                crate::csv_safe::restore_formula(raw).trim()
            };
            let name = get("name");
            if name.is_empty() {
                return None;
            }
            let wave = get("wave");
            let matched = ordered
                .iter()
                .find(|w| {
                    w.name.eq_ignore_ascii_case(wave)
                        || w.name
                            .split(" — ")
                            .next()
                            .unwrap_or("")
                            .eq_ignore_ascii_case(wave)
                })
                .or_else(|| {
                    wave.to_lowercase()
                        .strip_prefix("wave")
                        .and_then(|n| n.trim().parse::<usize>().ok())
                        .and_then(|i| i.checked_sub(1))
                        .and_then(|i| ordered.get(i))
                });
            let target = get("target");
            Some(ImportRow {
                name: name.into(),
                vendor: get("vendor").into(),
                wave: (!wave.is_empty()).then(|| wave.into()),
                wave_id: matched.map(|w| w.id),
                new_wave: !wave.is_empty() && matched.is_none(),
                priority: get("priority")
                    .parse::<i16>()
                    .ok()
                    .filter(|p| (1..=3).contains(p))
                    .unwrap_or(2),
                owner: get("owner").into(),
                target: if target.len() == 10 {
                    NaiveDate::parse_from_str(target, "%Y-%m-%d")
                        .ok()
                        .filter(|d| d.to_string() == target)
                } else {
                    None
                },
                notes: get("notes").into(),
                expected_type: (!get("expectedtype").is_empty())
                    .then(|| get("expectedtype").into()),
                duplicate: !have.insert(name.to_lowercase()),
            })
        })
        .collect())
}
