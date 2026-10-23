// SPDX-License-Identifier: AGPL-3.0-or-later

// TelemetryUnavailable (NAN-2361) — the honest empty state for a shared-lake
// tenant whose deployment does not ingest spans/metrics. Rendered in place of
// the data tabs (Services / Traces / Metrics / Infrastructure / RUM) and the
// trace waterfall, and as a compact notice above the definition tabs
// (Synthetics / SLOs / monitors), which keep working as saved definitions.
//
// The verdict comes from GET /api/observability/telemetry via the
// useTelemetryAvailability hook (src/hooks); dedicated deployments never ask and never render
// this. Dense: 12.5px body, 11px meta, mono for the reason code.

import { Radio } from 'lucide-react';

import type { TelemetryAvailability } from '@/lib/api/observability';

const DEFAULT_DETAIL =
  'Traces and metrics are not ingested on this deployment. SLOs, synthetic checks and metric monitors are saved but not evaluated.';

export interface TelemetryUnavailableProps {
  telemetry?: TelemetryAvailability;
  /** What the surface would have shown, e.g. "Service RED metrics". */
  subject: string;
}

/** Full-body empty state for a data tab. */
export function TelemetryUnavailable({ telemetry, subject }: TelemetryUnavailableProps) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <Radio className="w-6 h-6 text-fg-4 mb-2" strokeWidth={1.5} />
      <div className="text-[12.5px] text-fg-2">{subject} are not available here.</div>
      <div className="text-[11px] text-fg-4 mt-1 max-w-[340px]">
        {telemetry?.detail ?? DEFAULT_DETAIL}
      </div>
      <TelemetrySetupHint />
      {telemetry?.reason && (
        <div className="font-mono text-[10.5px] text-fg-4 mt-2">{telemetry.reason}</div>
      )}
    </div>
  );
}

/** One-line notice above a definition tab that still works without data. */
export function TelemetryUnavailableNotice({
  telemetry,
  subject,
}: TelemetryUnavailableProps) {
  return (
    <div className="flex items-center gap-2 h-7 px-2.5 mb-2.5 border border-border rounded-md text-[11px] text-fg-3">
      <Radio className="w-[13px] h-[13px] text-fg-4 shrink-0" strokeWidth={1.5} />
      <span className="truncate">
        {subject}: {telemetry?.detail ?? DEFAULT_DETAIL}
      </span>
      {telemetry?.reason && (
        <span className="ml-auto font-mono text-[10.5px] text-fg-4 shrink-0">{telemetry.reason}</span>
      )}
    </div>
  );
}

/** Setup help is also shown when a live drain has no rows for a signal. */
export function TelemetrySetupHint() {
  return (
    <div className="mt-2 text-[11px] text-fg-4">
      Check the selected range and filters. If your exporter is running, check its delivery errors and queued data.
      {' '}<a href="https://nano.rs/docs/integrations/otlp#observability-pages" target="_blank" rel="noopener noreferrer" className="text-brand hover:underline">Set up OpenTelemetry</a>
    </div>
  );
}
