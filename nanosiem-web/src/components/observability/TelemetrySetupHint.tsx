// SPDX-License-Identifier: AGPL-3.0-or-later

// TelemetrySetupHint (NAN-3936) — the delivery-setup half of an observability
// empty state. Shown under "no samples" / "no spans" / "awaiting evaluation"
// messages so an empty view says what to check next instead of reading as
// "healthy" or "broken". Dense: 11px meta.

/** Setup help shown when a view has no rows for its signal. */
export function TelemetrySetupHint() {
  return (
    <div className="mt-2 text-[11px] text-fg-4">
      Check the selected range and filters. If your exporter is running, check its delivery errors and queued data.
      {' '}<a href="https://nano.rs/docs/integrations/otlp#observability-pages" target="_blank" rel="noopener noreferrer" className="text-brand hover:underline">Set up OpenTelemetry</a>
    </div>
  );
}
