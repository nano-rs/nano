// SPDX-License-Identifier: AGPL-3.0-or-later

use super::MarketplaceRepository;
use crate::marketplace::MarketplaceCatalogEntry;

#[test]
fn catalog_api_hydration_declares_platform_feed_ownership() {
    for (slug, feed_id) in [
        ("ipinfo_lite", "ipinfo_lite"),
        ("threatfox", "threatfox"),
        ("tor-exit-nodes", "tor_exit_nodes"),
    ] {
        let entry = MarketplaceRepository::hydrate(MarketplaceCatalogEntry {
            slug: slug.to_string(),
            ..Default::default()
        });
        let json = serde_json::to_value(entry).expect("serialize catalog entry");
        assert_eq!(json["platform_feed_id"], feed_id, "{slug}");
    }

    let other = MarketplaceRepository::hydrate(MarketplaceCatalogEntry {
        slug: "urlhaus".to_string(),
        ..Default::default()
    });
    let json = serde_json::to_value(other).expect("serialize catalog entry");
    assert!(json.get("platform_feed_id").is_none());
}
