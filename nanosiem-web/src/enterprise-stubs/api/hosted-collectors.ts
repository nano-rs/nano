// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition copy of the pull collector types. The collector catalog and
// its routes are enterprise-only (NAN-3861): open builds list no collectors.
// The shapes match the enterprise module so shared code and tests typecheck in
// both editions.
export interface HostedCollectorField { name: string; label: string; required: boolean; help?: string; placeholder?: string }
export interface HostedCollector {
  slug: string; name: string; description?: string;
  /** Vendor API the collector reads (`Microsoft Graph`); never the internal HEC delivery. */
  origin?: string;
  credential_fields: HostedCollectorField[]; config_fields: HostedCollectorField[];
  streams: Array<{ id: string; label: string; source_type: string; default: boolean }>;
}
export interface HostedCollectorFeed {
  rotation_config?: Record<string, string>; rotation_credential_fields?: string[];
  id: string; source_slug: string; enabled: boolean; credential: string; rollout_state: string | null;
  last_success_at: string | null; last_status: string | null; last_error: string | null; next_run_at: string;
}
export interface HostedCollectorInstall {
  credentials: Record<string, string>; config: Record<string, string>; streams: string[];
}

export interface HostedCollectorRotation {
  component?: string; credentials: Record<string, string>; config: Record<string, string>;
}
