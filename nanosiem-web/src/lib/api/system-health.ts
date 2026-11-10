// SPDX-License-Identifier: AGPL-3.0-or-later

export type SystemHealthStatus = 'active' | 'resolved';
export type SystemHealthSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational';

export interface SystemHealthEvent {
  id: string;
  tenant_id: string;
  dedup_key: string;
  category: string;
  severity: SystemHealthSeverity;
  status: SystemHealthStatus;
  title: string;
  summary: string;
  resource_type: string;
  resource_id: string | null;
  resource_name: string | null;
  diagnostic_context: Record<string, unknown>;
  remediation: string | null;
  source: string;
  occurrence_count: number;
  first_seen_at: string;
  last_seen_at: string;
  last_notified_at: string | null;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  resolved_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface SystemHealthEventList {
  events: SystemHealthEvent[];
  total: number;
}

export interface SystemHealthSummary {
  active: number;
  unacknowledged: number;
  critical: number;
  high: number;
  delivery_pending: number;
  delivery_dead: number;
}

export interface SystemHealthDelivery {
  id: string;
  event_id: string;
  webhook_id: string;
  webhook_name: string;
  event_action: string;
  status: string;
  attempt_count: number;
  next_attempt_at: string;
  delivered_at: string | null;
  last_status_code: number | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

/** NAN-5204: `GET /api/system/backup-status` (`settings:system`). */
export interface BackupStatusResponse {
  /** False when automatic backups never reported (every other field null). */
  configured: boolean;
  enabled: boolean | null;
  enabled_since: string | null;
  last_attempt_at: string | null;
  last_outcome: 'success' | 'partial' | 'failure' | null;
  last_success_at: string | null;
  last_success_backup_id: string | null;
  last_success_size_bytes: number | null;
  last_failure_at: string | null;
  last_failure_error: string | null;
  consecutive_failures: number | null;
  destination_kind: 'path' | 's3' | null;
  destination: string | null;
  clickhouse_data: 'included' | 'excluded' | null;
  schedule: string | null;
  keep: number | null;
  next_run_at: string | null;
  updated_at: string | null;
  /** Enabled and no successful backup within `stale_after_hours`. */
  stale: boolean;
  stale_after_hours: number;
}

export class SystemHealthApi {
  constructor(private request: <T>(endpoint: string, options?: RequestInit) => Promise<T>) {}

  listEvents(params: {
    status?: SystemHealthStatus;
    category?: string;
    severity?: SystemHealthSeverity;
    limit?: number;
    offset?: number;
  } = {}): Promise<SystemHealthEventList> {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined) query.set(key, String(value));
    }
    const suffix = query.size ? `?${query}` : '';
    return this.request(`/api/system-health/events${suffix}`);
  }

  getSummary(): Promise<SystemHealthSummary> {
    return this.request('/api/system-health/summary');
  }

  acknowledge(id: string): Promise<SystemHealthEvent> {
    return this.request(`/api/system-health/events/${id}/acknowledge`, { method: 'POST' });
  }

  resolve(id: string): Promise<SystemHealthEvent> {
    return this.request(`/api/system-health/events/${id}/resolve`, { method: 'POST' });
  }

  listDeliveries(id: string, limit = 50): Promise<SystemHealthDelivery[]> {
    return this.request(`/api/system-health/events/${id}/deliveries?limit=${limit}`);
  }

  /** NAN-5204: automatic backup status reported by the nano-backup sidecar. */
  getBackupStatus(): Promise<BackupStatusResponse> {
    return this.request('/api/system/backup-status');
  }
}

