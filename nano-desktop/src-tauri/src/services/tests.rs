/// The Info.plist and the Objective-C selector are two halves of one contract,
/// and nothing checks them against each other at build time. If `NSMessage` says
/// `searchInNano` and the method is named anything else, the menu item still
/// appears in every app on the Mac — and silently does nothing when clicked.
/// That is the worst possible failure for this feature, so it is pinned here.
#[test]
fn the_plist_message_matches_the_selector_we_implement() {
    let plist = include_str!("../../Info.plist");

    // The selector in services.rs is `searchInNano:userData:error:`, which AppKit
    // derives from this NSMessage.
    assert!(
        plist.contains("<key>NSMessage</key>"),
        "the service declares no NSMessage"
    );
    assert!(
        plist.contains("<string>searchInNano</string>"),
        "NSMessage no longer matches the `searchInNano:userData:error:` selector \
         implemented in services.rs — the menu item would appear and do nothing"
    );

    // We only ever read text off the pasteboard.
    assert!(
        plist.contains("<key>NSSendTypes</key>"),
        "a service with no NSSendTypes is offered for nothing and never appears"
    );
    assert!(plist.contains("public.utf8-plain-text"));

    // The menu item the analyst actually right-clicks.
    assert!(plist.contains("<string>Search in nano</string>"));
}
