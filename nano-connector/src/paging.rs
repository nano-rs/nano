//! Page steppers and their registry. A stepper decides the next page inside
//! one request sequence (one window, one fan-out item). Time windows wrap
//! steppers; see `engine::run_windowed`.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

use crate::broker::InboundResponse;

pub enum Step {
    Done,
    /// An absolute URL from the server (Link header). Policy-checked by the
    /// engine like any other hop.
    Url(url::Url),
    /// Query parameters to set on the stream's request template.
    Query(BTreeMap<String, String>),
    /// Offset pagination reached the API's maximum offset while pages were
    /// still full: the window must be narrowed.
    CapReached,
}

#[derive(Debug, Default, Clone)]
pub struct PageState {
    pub offset: u64,
}

pub struct PageCtx<'a> {
    pub resp: &'a InboundResponse,
    pub body: &'a Value,
    pub events: &'a [Value],
}

pub trait Stepper: Send + Sync {
    /// Query for the first page.
    fn first(&self, _st: &mut PageState) -> BTreeMap<String, String> {
        BTreeMap::new()
    }
    fn next(&self, cx: &PageCtx<'_>, st: &mut PageState) -> Result<Step, String>;
}

pub struct StepperRegistration {
    pub name: &'static str,
    pub summary: &'static str,
    pub schema: fn() -> Value,
    pub build: fn(&serde_json::Map<String, Value>) -> Result<Box<dyn Stepper>, String>,
}

fn params<T: for<'de> Deserialize<'de>>(m: &serde_json::Map<String, Value>) -> Result<T, String> {
    serde_json::from_value(Value::Object(m.clone())).map_err(|e| e.to_string())
}

fn schema_of<T: JsonSchema>() -> Value {
    serde_json::to_value(schemars::schema_for!(T)).unwrap_or_default()
}

pub fn registry() -> Vec<StepperRegistration> {
    vec![
        StepperRegistration {
            name: "none",
            summary: "One page",
            schema: schema_of::<Empty>,
            build: |m| {
                params::<Empty>(m)?;
                Ok(Box::new(NoPaging))
            },
        },
        StepperRegistration {
            name: "link_header",
            summary: "Follow Link: <...>; rel=\"next\" (policy-checked)",
            schema: schema_of::<Empty>,
            build: |m| {
                params::<Empty>(m)?;
                Ok(Box::new(LinkHeader))
            },
        },
        StepperRegistration {
            name: "next_url",
            summary: "Follow an absolute next-page URL from the body at a JSON pointer (e.g. /@odata.nextLink; policy-checked)",
            schema: schema_of::<NextUrlParams>,
            build: |m| {
                let p: NextUrlParams = params(m)?;
                if !(p.pointer.is_empty() || p.pointer.starts_with('/')) {
                    return Err("next_url pointer must be a JSON pointer starting with `/`".into());
                }
                Ok(Box::new(NextUrl(p)))
            },
        },
        StepperRegistration {
            name: "cursor",
            summary: "Next cursor from a body field, sent as a query parameter",
            schema: schema_of::<CursorParams>,
            build: |m| Ok(Box::new(CursorStep(params(m)?))),
        },
        StepperRegistration {
            name: "token",
            summary: "Page token from a body field, sent as a query parameter",
            schema: schema_of::<CursorParams>,
            build: |m| Ok(Box::new(CursorStep(params(m)?))),
        },
        StepperRegistration {
            name: "offset",
            summary: "offset/limit; stops on a short page; max_offset triggers window narrowing",
            schema: schema_of::<OffsetParams>,
            build: |m| Ok(Box::new(OffsetStep(params(m)?))),
        },
    ]
}

pub fn build(kind: &str, m: &serde_json::Map<String, Value>) -> Result<Box<dyn Stepper>, String> {
    let r = registry()
        .into_iter()
        .find(|r| r.name == kind)
        .ok_or_else(|| format!("pagination type `{kind}` is not registered"))?;
    (r.build)(m)
}

pub fn registry_schema() -> schemars::Schema {
    let variants: Vec<Value> = registry()
        .into_iter()
        .map(|r| {
            let mut s = (r.schema)();
            if let Some(obj) = s.as_object_mut() {
                obj.remove("$schema");
                obj.insert("description".into(), Value::String(r.summary.into()));
                let props = obj.entry("properties").or_insert_with(|| Value::Object(Default::default()));
                props.as_object_mut().expect("object").insert("type".into(), serde_json::json!({ "const": r.name }));
                let req = obj.entry("required").or_insert_with(|| Value::Array(vec![]));
                req.as_array_mut().expect("array").push(Value::String("type".into()));
            }
            s
        })
        .collect();
    schemars::Schema::try_from(serde_json::json!({ "oneOf": variants })).expect("valid schema")
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Empty {}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CursorParams {
    /// Dotted path of the next cursor in the response body.
    pub from: String,
    /// Query parameter that carries it.
    pub param: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NextUrlParams {
    /// RFC 6901 JSON pointer to the next-page URL in the response body
    /// (`/@odata.nextLink`, `/links/next/href`). Absent, null or empty =
    /// last page.
    pub pointer: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OffsetParams {
    pub param: String,
    #[serde(default)]
    pub limit_param: Option<String>,
    pub page_size: u64,
    /// The API's largest accepted offset. Reaching it with full pages makes
    /// the engine narrow the time window instead of failing.
    #[serde(default)]
    pub max_offset: Option<u64>,
}

pub struct NoPaging;

impl Stepper for NoPaging {
    fn next(&self, _: &PageCtx<'_>, _: &mut PageState) -> Result<Step, String> {
        Ok(Step::Done)
    }
}

/// `rel="next"` target from an RFC 8288 Link header.
pub fn link_next(link: &str) -> Option<String> {
    link.split(',').find_map(|part| {
        let (target, params) = part.split_once(';')?;
        let target = target.trim().strip_prefix('<')?.strip_suffix('>')?;
        params
            .split(';')
            .any(|p| {
                let p = p.trim().to_ascii_lowercase();
                p == "rel=\"next\"" || p == "rel=next"
            })
            .then(|| target.to_string())
    })
}

pub struct LinkHeader;

impl Stepper for LinkHeader {
    fn next(&self, cx: &PageCtx<'_>, _: &mut PageState) -> Result<Step, String> {
        match cx.resp.header("link").and_then(link_next) {
            Some(u) => url::Url::parse(&u).map(Step::Url).map_err(|e| format!("bad Link URL: {e}")),
            None => Ok(Step::Done),
        }
    }
}

/// An absolute next-page URL from the body. The engine checks it against
/// the allow policy like every other hop.
pub struct NextUrl(NextUrlParams);

impl Stepper for NextUrl {
    fn next(&self, cx: &PageCtx<'_>, _: &mut PageState) -> Result<Step, String> {
        match cx.body.pointer(&self.0.pointer) {
            Some(Value::String(u)) if !u.is_empty() => url::Url::parse(u).map(Step::Url).map_err(|e| format!("bad next-page URL: {e}")),
            None | Some(Value::Null) | Some(Value::String(_)) => Ok(Step::Done),
            Some(_) => Err("next-page URL is not a string".into()),
        }
    }
}

pub fn get_path<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() || path == "." {
        return Some(v);
    }
    path.split('.').try_fold(v, |cur, p| match cur {
        Value::Object(m) => m.get(p),
        Value::Array(a) => p.parse::<usize>().ok().and_then(|i| a.get(i)),
        _ => None,
    })
}

pub struct CursorStep(CursorParams);

impl Stepper for CursorStep {
    fn next(&self, cx: &PageCtx<'_>, _: &mut PageState) -> Result<Step, String> {
        match get_path(cx.body, &self.0.from) {
            Some(Value::String(s)) if !s.is_empty() => Ok(Step::Query(BTreeMap::from([(self.0.param.clone(), s.clone())]))),
            Some(Value::Number(n)) => Ok(Step::Query(BTreeMap::from([(self.0.param.clone(), n.to_string())]))),
            _ => Ok(Step::Done),
        }
    }
}

pub struct OffsetStep(OffsetParams);

impl OffsetStep {
    fn query(&self, offset: u64) -> BTreeMap<String, String> {
        let mut q = BTreeMap::from([(self.0.param.clone(), offset.to_string())]);
        if let Some(l) = &self.0.limit_param {
            q.insert(l.clone(), self.0.page_size.to_string());
        }
        q
    }
}

impl Stepper for OffsetStep {
    fn first(&self, st: &mut PageState) -> BTreeMap<String, String> {
        st.offset = 0;
        self.query(0)
    }
    fn next(&self, cx: &PageCtx<'_>, st: &mut PageState) -> Result<Step, String> {
        if (cx.events.len() as u64) < self.0.page_size {
            return Ok(Step::Done);
        }
        let next = st.offset + self.0.page_size;
        if let Some(max) = self.0.max_offset {
            if next > max {
                return Ok(Step::CapReached);
            }
        }
        st.offset = next;
        Ok(Step::Query(self.query(next)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_link_next() {
        let l = r#"<https://a.okta.com/api/v1/logs?after=1>; rel="self", <https://a.okta.com/api/v1/logs?after=2>; rel="next""#;
        assert_eq!(link_next(l).as_deref(), Some("https://a.okta.com/api/v1/logs?after=2"));
        assert_eq!(link_next(r#"<https://x/>; rel="self""#), None);
    }

    #[test]
    fn next_url_follows_a_pointer_with_dots_in_the_key() {
        let s = build("next_url", serde_json::json!({"pointer": "/@odata.nextLink"}).as_object().unwrap()).unwrap();
        let resp = InboundResponse { status: 200, headers: http::HeaderMap::new(), body: bytes::Bytes::new() };
        let body = serde_json::json!({"@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=X", "value": []});
        let cx = PageCtx { resp: &resp, body: &body, events: &[] };
        match s.next(&cx, &mut PageState::default()).unwrap() {
            Step::Url(u) => assert_eq!(u.as_str(), "https://graph.microsoft.com/v1.0/users?$skiptoken=X"),
            _ => panic!("expected a URL"),
        }
        let last = serde_json::json!({"@odata.deltaLink": "https://graph.microsoft.com/x", "value": []});
        let cx = PageCtx { resp: &resp, body: &last, events: &[] };
        assert!(matches!(s.next(&cx, &mut PageState::default()).unwrap(), Step::Done));
        assert!(build("next_url", serde_json::json!({"pointer": "@odata.nextLink"}).as_object().unwrap()).is_err());
    }
}
