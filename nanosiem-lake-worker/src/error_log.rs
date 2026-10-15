// SPDX-License-Identifier: AGPL-3.0-or-later

/// Preserve cause chains without exposing SDK response bodies containing OAuth tokens.
pub fn error_chain(error: &anyhow::Error) -> String {
    let contains_response_body = error.chain().any(|cause| {
        cause.downcast_ref::<iceberg::Error>().is_some_and(|sdk| {
            sdk.message().starts_with("Failed to parse response from rest catalog server")
                || sdk.message() == "Received unexpected response"
        })
    });
    if contains_response_body {
        // SDK Display recursively includes its sources, so stop before any SDK
        // wrapper rather than copying a wrapper that embeds the unsafe body.
        let mut context: Vec<String> = error.chain()
            .take_while(|cause| !cause.is::<iceberg::Error>())
            .map(ToString::to_string)
            .collect();
        context.push("Iceberg REST response decoding failed (response body omitted)".into());
        return context.join(": ");
    }
    format!("{error:#}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_oauth_response_does_not_disclose_tokens() {
        let sdk = iceberg::Error::new(
            iceberg::ErrorKind::Unexpected,
            "Failed to parse response from rest catalog server!",
        )
        .with_context("json", r#"{"access_token":"fixture-secret","expires_in":"invalid"}"#);
        let error = anyhow::Error::new(sdk).context("load Iceberg REST catalog");
        let rendered = error_chain(&error);
        assert!(rendered.starts_with("load Iceberg REST catalog: "));
        assert!(rendered.contains("response body omitted"));
        assert!(!rendered.contains("fixture-secret"));
        assert!(!rendered.contains("access_token"));
    }
}
