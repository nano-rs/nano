// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5204: "Last backup" card on the Settings landing (open core).
 *
 * Reads `GET /api/system/backup-status` (`settings:system`), fed by the
 * optional nano-backup sidecar. Shares the banner's query key so both read
 * one cached response.
 */

import type { ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';
import type { BackupStatusResponse } from '@/lib/api/system-health';
import { cn } from '@/lib/utils';
import { formatBytes, formatRelativeCompact, formatUTCCompact } from '@/lib/date-utils';
import { AUTOMATIC_BACKUPS_DOCS_URL, BACKUP_STATUS_QUERY_KEY } from '@/lib/backup-status';

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline gap-3 px-3 py-1.5 min-h-[26px]">
      <span className="w-[92px] shrink-0 text-[11px] text-muted-foreground">{label}</span>
      <span className="min-w-0 flex-1 text-[12px] text-foreground">{children}</span>
    </div>
  );
}

function When({ at }: { at: string | null }) {
  if (!at) return <span className="text-muted-foreground">never</span>;
  return (
    <span className="font-mono text-[11px] tabular-nums" title={at}>
      {formatUTCCompact(at)}
      <span className="text-muted-foreground"> · {formatRelativeCompact(at)}</span>
    </span>
  );
}

function StateBadge({ status }: { status: BackupStatusResponse }) {
  const [label, tone] = !status.enabled
    ? ['Disabled', 'text-muted-foreground border-border']
    : status.stale
      ? ['Stale', 'text-amber-600 border-amber-300 dark:text-amber-400 dark:border-amber-500/40']
      : status.last_outcome === 'failure'
        ? ['Last run failed', 'text-red-500 border-red-300 dark:border-red-500/40']
        : status.last_outcome === 'partial'
          ? ['Last run partial', 'text-amber-600 border-amber-300 dark:text-amber-400 dark:border-amber-500/40']
          : ['Enabled', 'text-emerald-600 border-emerald-300 dark:text-emerald-400 dark:border-emerald-500/40'];
  return (
    <span className={cn('rounded border px-1.5 py-px text-[10px] uppercase tracking-wider font-medium', tone)}>
      {label}
    </span>
  );
}

function BackupDetails({ status }: { status: BackupStatusResponse }) {
  return (
    <div className="divide-y divide-border/60">
      <Row label="Destination">
        <span className="font-mono text-[11px] break-all">
          {status.destination_kind ? `${status.destination_kind}: ` : ''}{status.destination ?? '—'}
        </span>
      </Row>
      <Row label="Schedule">
        <span className="font-mono text-[11px]">
          daily {status.schedule ?? '—'} · keep {status.keep ?? '—'}
        </span>
      </Row>
      <Row label="Scope">
        {status.clickhouse_data === 'included'
          ? 'PostgreSQL + ClickHouse data'
          : 'PostgreSQL only (ClickHouse data not included)'}
      </Row>
      <Row label="Last success">
        <When at={status.last_success_at} />
        {status.last_success_size_bytes !== null && (
          <span className="font-mono text-[11px] text-muted-foreground"> · {formatBytes(status.last_success_size_bytes)}</span>
        )}
        {status.last_success_backup_id && (
          <div className="font-mono text-[10.5px] text-muted-foreground truncate" title={status.last_success_backup_id}>
            {status.last_success_backup_id}
          </div>
        )}
      </Row>
      {status.last_failure_at && (
        <Row label={status.last_outcome === 'partial' ? 'Last warning' : 'Last failure'}>
          <When at={status.last_failure_at} />
          {(status.consecutive_failures ?? 0) > 0 && (
            <span className="font-mono text-[11px] text-red-500"> · {status.consecutive_failures} in a row</span>
          )}
          {status.last_failure_error && (
            <div className="font-mono text-[10.5px] text-muted-foreground break-words line-clamp-3" title={status.last_failure_error}>
              {status.last_failure_error}
            </div>
          )}
        </Row>
      )}
      {status.enabled && (
        <Row label="Next run">
          {status.next_run_at
            ? <span className="font-mono text-[11px] tabular-nums">{formatUTCCompact(status.next_run_at)}</span>
            : <span className="text-muted-foreground">—</span>}
        </Row>
      )}
    </div>
  );
}

export function LastBackupCard() {
  const { data: status, isLoading, isError } = useQuery({
    queryKey: BACKUP_STATUS_QUERY_KEY,
    queryFn: () => api.systemHealth.getBackupStatus(),
    staleTime: 5 * 60_000,
    retry: false,
  });

  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <span className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium">Last backup</span>
        {status?.configured && <StateBadge status={status} />}
        <div className="flex-1 h-px bg-border/60 mx-1" />
        <a
          href={AUTOMATIC_BACKUPS_DOCS_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="text-[10.5px] text-muted-foreground/70 hover:text-foreground hover:underline"
        >
          docs
        </a>
      </div>
      <div className="rounded-lg border border-border/60 bg-card overflow-hidden">
        {isLoading && <div className="px-3 py-4 text-center text-[11px] text-muted-foreground">Loading…</div>}
        {isError && <div className="px-3 py-4 text-center text-[11px] text-muted-foreground">Backup status unavailable.</div>}
        {status && !status.configured && (
          <div className="px-3 py-3 text-[12px] text-muted-foreground leading-snug">
            Automatic backups are off. Set them up with{' '}
            <code className="font-mono text-[11px] text-foreground">scripts/nano backup-schedule --configure</code>.
          </div>
        )}
        {status?.configured && <BackupDetails status={status} />}
      </div>
    </div>
  );
}
