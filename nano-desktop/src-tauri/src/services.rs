//! "Search in nano", from any app on the Mac.
//!
//! Select an IP, a hash, or a domain anywhere — a browser, Slack, Mail, a PDF —
//! right-click, and nano answers. This is the macOS **Services** mechanism: the
//! app declares an `NSServices` entry in its `Info.plist`, the system puts it in
//! every app's Services menu, and when it's chosen the system hands us the
//! selected text on a pasteboard.
//!
//! It reuses the Quick Search window as the answer surface, which is exactly what
//! the mock's "verdict peek" is: the same indicator classification, the same live
//! peek, the same ↩/⌘↩ handoffs. A second, near-identical popover would have been
//! a second thing to keep correct.
//!
//! ONLY WORKS FROM A REAL BUNDLE. `tauri dev` produces a binary macOS won't
//! register a service for — the Services registry is keyed off the `.app`'s
//! Info.plist. Build with `npx tauri build --debug --bundles app`, launch the
//! `.app`, and the item appears (the system may take a beat, or need
//! `/System/Library/CoreServices/pbs -flush`).

#![cfg(target_os = "macos")]

use objc2::rc::Retained;
use objc2::runtime::NSObject;
use objc2::{define_class, msg_send, AllocAnyThread, DefinedClass, MainThreadMarker};
use objc2_app_kit::{NSApplication, NSPasteboard, NSPasteboardTypeString};
use objc2_foundation::NSString;
use tauri::AppHandle;

define_class!(
    // SAFETY: NSObject imposes no subclassing requirements, and this type has no
    // Drop impl.
    #[unsafe(super(NSObject))]
    // The name the Objective-C runtime knows it by. It doesn't have to match
    // anything in the plist — NSMessage names the METHOD, not the class — but a
    // recognisable name makes a crash report readable.
    #[name = "NanoServiceProvider"]
    #[ivars = AppHandle]
    struct ServiceProvider;

    impl ServiceProvider {
        /// The `NSMessage` in Info.plist is `searchInNano`; AppKit turns that into
        /// this three-part selector. If the two ever disagree, the menu item
        /// appears and silently does nothing — which is why they are tested
        /// together (`services/tests.rs` asserts the plist against this name).
        #[unsafe(method(searchInNano:userData:error:))]
        fn search_in_nano(
            &self,
            pasteboard: &NSPasteboard,
            _user_data: *mut NSString,
            _error: *mut *mut NSString,
        ) {
            let Some(text) = read_string(pasteboard) else {
                return;
            };
            crate::quick::show_with_selection(self.ivars(), &text);
        }
    }
);

impl ServiceProvider {
    fn new(app: AppHandle) -> Retained<Self> {
        let this = Self::alloc().set_ivars(app);
        unsafe { msg_send![super(this), init] }
    }
}

/// The selection, as plain text. The system only offers us the types we declared
/// in `NSSendTypes`, so this is a string or nothing.
fn read_string(pasteboard: &NSPasteboard) -> Option<String> {
    let value = unsafe { pasteboard.stringForType(NSPasteboardTypeString) }?;
    let text = value.to_string();
    let line = text.trim().lines().next()?.trim();

    // A whole paragraph is not an indicator. The same ceiling the ⌥Space capture
    // uses, for the same reason: what comes back is whatever the user had
    // highlighted, and that can be a page.
    (!line.is_empty() && line.len() <= 512).then(|| line.to_string())
}

/// Offer the service to the system. Non-fatal: a Mac that won't register it still
/// has ⌥Space, and the app must launch regardless.
pub fn setup(app: &AppHandle) {
    let Some(mtm) = MainThreadMarker::new() else {
        log::warn!("Services provider must be registered on the main thread; skipping.");
        return;
    };

    // Leaked deliberately: AppKit holds the services provider unretained for the
    // life of the process, so this must outlive the setup call. It is one object,
    // once, for the lifetime of the app — not a leak that grows.
    let provider = ServiceProvider::new(app.clone());
    let provider = Retained::into_raw(provider);

    let ns_app = NSApplication::sharedApplication(mtm);
    unsafe {
        ns_app.setServicesProvider(Some(&*provider.cast::<NSObject>()));
    }
}

#[cfg(test)]
mod tests;
