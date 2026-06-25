// SPDX-License-Identifier: AGPL-3.0-or-later

// AlertsTab (NAN-1536) — monitor summary + active incidents + monitors table.
// REUSES the existing alerting subsystem: api.getAlertCounts / api.listAlerts /
// api.getAlertVelocity (via the use-api hooks) are adapted into the design's
// monitor shape inside <AlertsMonitors>. No new alert backend.
//
// The Alerts surface keys off the detection-alert lifecycle, not the span time
// range, so the shared time-range props are intentionally unused here.

import AlertsMonitors from '@/components/observability/AlertsMonitors';
import type { ObservabilityTabProps } from '../types';

export function AlertsTab(_props: ObservabilityTabProps) {
  return <AlertsMonitors />;
}

export default AlertsTab;
