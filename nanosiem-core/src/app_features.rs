// SPDX-License-Identifier: AGPL-3.0-or-later
//! `--print-features`: the capabilities an app image's own binary reports
//! (NAN-3531 N2a). `scripts/build-publish-staging-apps.sh` records them as
//! the image label `nanosiem.io/app-features` and as `features` in the build
//! receipt; the platform refuses to render a template that needs a capability
//! the deployed image does not report.

/// The flag. It must be the only argument.
pub const PRINT_FEATURES_FLAG: &str = "--print-features";

/// The comma list printed for `features` (empty when there are none).
pub fn render(features: &[&str]) -> String {
    features.join(",")
}

/// When the process was started as `<bin> --print-features`, print
/// `features` and return `true`; the caller then exits before any tracing,
/// configuration or database setup. Any other argument list returns `false`.
pub fn print_if_requested(features: &[&str]) -> bool {
    let mut args = std::env::args_os().skip(1);
    if args
        .next()
        .is_some_and(|first| first == PRINT_FEATURES_FLAG)
        && args.next().is_none()
    {
        println!("{}", render(features));
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    #[test]
    fn renders_a_comma_list() {
        assert_eq!(super::render(&[]), "");
        assert_eq!(
            super::render(&["hosted_config_dir_v1"]),
            "hosted_config_dir_v1"
        );
        assert_eq!(super::render(&["a", "b"]), "a,b");
    }
}
