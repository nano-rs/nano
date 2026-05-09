// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cybersecurity news feed handlers
//!
//! Fetches and caches RSS feeds from cybersecurity news sources.
//! Provides aggregated news for the dashboard.

use axum::{extract::State, Json};
use chrono::{DateTime, Utc};
use feed_rs::parser;
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use utoipa::ToSchema;

use crate::state::AppState;

/// News feed sources with their RSS URLs
const NEWS_FEEDS: &[(&str, &str, &str)] = &[
    ("CISA Alerts", "https://www.cisa.gov/news.xml", "cisa"),
    (
        "The Hacker News",
        "https://feeds.feedburner.com/TheHackersNews",
        "hackernews",
    ),
    (
        "BleepingComputer",
        "https://www.bleepingcomputer.com/feed/",
        "bleeping",
    ),
    (
        "Krebs on Security",
        "https://krebsonsecurity.com/feed/",
        "krebs",
    ),
];

/// Cache duration in seconds (15 minutes)
const CACHE_DURATION_SECS: u64 = 900;

/// A single news item
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct NewsItem {
    pub title: String,
    pub link: String,
    pub source: String,
    pub source_id: String,
    pub published: Option<DateTime<Utc>>,
    pub summary: Option<String>,
}

/// Response containing aggregated news
#[derive(Debug, Serialize, ToSchema)]
pub struct NewsResponse {
    pub items: Vec<NewsItem>,
    pub last_updated: DateTime<Utc>,
    pub sources: Vec<SourceStatus>,
}

/// Status of a news source
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SourceStatus {
    pub name: String,
    pub id: String,
    pub status: String,
    pub item_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Cached news data
struct NewsCache {
    items: Vec<NewsItem>,
    sources: Vec<SourceStatus>,
    last_updated: DateTime<Utc>,
    last_fetch: Instant,
}

/// Global news cache
static NEWS_CACHE: once_cell::sync::Lazy<Arc<RwLock<Option<NewsCache>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(None)));

/// Fetch a single RSS feed
async fn fetch_feed(name: &str, url: &str, source_id: &str) -> (Vec<NewsItem>, SourceStatus) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("NanoSIEM/1.0")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return (
                vec![],
                SourceStatus {
                    name: name.to_string(),
                    id: source_id.to_string(),
                    status: "error".to_string(),
                    item_count: 0,
                    error: Some(format!("Client error: {}", e)),
                },
            );
        }
    };

    let response = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                vec![],
                SourceStatus {
                    name: name.to_string(),
                    id: source_id.to_string(),
                    status: "error".to_string(),
                    item_count: 0,
                    error: Some(format!("Fetch error: {}", e)),
                },
            );
        }
    };

    let bytes = match response.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return (
                vec![],
                SourceStatus {
                    name: name.to_string(),
                    id: source_id.to_string(),
                    status: "error".to_string(),
                    item_count: 0,
                    error: Some(format!("Read error: {}", e)),
                },
            );
        }
    };

    let feed = match parser::parse(&bytes[..]) {
        Ok(f) => f,
        Err(e) => {
            return (
                vec![],
                SourceStatus {
                    name: name.to_string(),
                    id: source_id.to_string(),
                    status: "error".to_string(),
                    item_count: 0,
                    error: Some(format!("Parse error: {}", e)),
                },
            );
        }
    };

    let items: Vec<NewsItem> = feed
        .entries
        .into_iter()
        .take(10) // Limit to 10 items per source
        .map(|entry| {
            let link = entry
                .links
                .first()
                .map(|l| l.href.clone())
                .unwrap_or_default();

            let summary = entry.summary.map(|s| {
                // Strip HTML and truncate
                let text = strip_html(&s.content);
                if text.len() > 200 {
                    format!("{}...", &text[..200])
                } else {
                    text
                }
            });

            NewsItem {
                title: entry.title.map(|t| t.content).unwrap_or_default(),
                link,
                source: name.to_string(),
                source_id: source_id.to_string(),
                published: entry.published.map(|d| d.into()),
                summary,
            }
        })
        .collect();

    let item_count = items.len();
    (
        items,
        SourceStatus {
            name: name.to_string(),
            id: source_id.to_string(),
            status: "ok".to_string(),
            item_count,
            error: None,
        },
    )
}

/// Strip HTML tags from text
fn strip_html(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut in_tag = false;
    let mut in_entity = false;
    let mut entity = String::new();

    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            '&' if !in_tag => {
                in_entity = true;
                entity.clear();
            }
            ';' if in_entity => {
                in_entity = false;
                // Convert common HTML entities
                match entity.as_str() {
                    "amp" => result.push('&'),
                    "lt" => result.push('<'),
                    "gt" => result.push('>'),
                    "quot" => result.push('"'),
                    "nbsp" => result.push(' '),
                    "apos" => result.push('\''),
                    _ => {} // Skip unknown entities
                }
            }
            _ if in_entity => entity.push(c),
            _ if !in_tag => result.push(c),
            _ => {}
        }
    }

    // Clean up whitespace
    result.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Fetch all news feeds and cache the results
async fn fetch_all_feeds() -> NewsCache {
    let futures: Vec<_> = NEWS_FEEDS
        .iter()
        .map(|(name, url, id)| fetch_feed(name, url, id))
        .collect();

    let results: Vec<_> = futures::future::join_all(futures).await;

    let mut all_items: Vec<NewsItem> = Vec::new();
    let mut sources: Vec<SourceStatus> = Vec::new();

    for (items, status) in results {
        all_items.extend(items);
        sources.push(status);
    }

    // Sort by publish date (newest first)
    all_items.sort_by(|a, b| {
        let a_time = a.published.unwrap_or_else(|| DateTime::<Utc>::MIN_UTC);
        let b_time = b.published.unwrap_or_else(|| DateTime::<Utc>::MIN_UTC);
        b_time.cmp(&a_time)
    });

    // Limit total items
    all_items.truncate(30);

    NewsCache {
        items: all_items,
        sources,
        last_updated: Utc::now(),
        last_fetch: Instant::now(),
    }
}

/// Get cybersecurity news feed
///
/// Returns aggregated news from multiple cybersecurity sources.
/// Results are cached for 15 minutes to reduce load on source sites.
#[utoipa::path(
    get,
    path = "/api/news",
    tag = "news",
    responses(
        (status = 200, description = "News feed retrieved successfully", body = NewsResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_news(State(_state): State<AppState>) -> Json<NewsResponse> {
    // Check cache first
    {
        let cache = NEWS_CACHE.read().await;
        if let Some(ref cached) = *cache {
            if cached.last_fetch.elapsed() < Duration::from_secs(CACHE_DURATION_SECS) {
                return Json(NewsResponse {
                    items: cached.items.clone(),
                    last_updated: cached.last_updated,
                    sources: cached.sources.clone(),
                });
            }
        }
    }

    // Cache miss or expired - fetch fresh data
    let new_cache = fetch_all_feeds().await;

    let response = NewsResponse {
        items: new_cache.items.clone(),
        last_updated: new_cache.last_updated,
        sources: new_cache.sources.clone(),
    };

    // Update cache
    {
        let mut cache = NEWS_CACHE.write().await;
        *cache = Some(new_cache);
    }

    Json(response)
}

/// OpenAPI documentation for news endpoints
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_news),
    components(schemas(NewsItem, NewsResponse, SourceStatus))
)]
pub struct NewsApiDoc;
