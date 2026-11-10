// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5204: "No successful backup in 36 hours" for admins.
 *
 * Driven by `GET /api/system/backup-status`, which the optional nano-backup
 * sidecar feeds after every scheduled attempt. Open core: no edition gate.
 * Shown only to `settings:system` holders and only while the server says the
 * status is stale (the 36h rule lives server-side in one place). Dismissal
 * lasts for the browser session only: an unprotected deployment keeps
 * reminding.
 */

import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { DatabaseBackup, X } from 'lucide-react';
import { api } from '../lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { formatUTCCompact } from '@/lib/date-utils';
import {
  AUTOMATIC_BACKUPS_DOCS_URL,
  BACKUP_BANNER_DISMISSED_KEY,
  BACKUP_STATUS_QUERY_KEY,
} from '@/lib/backup-status';

function readDismissed(): boolean {
  try {
    return window.sessionStorage.getItem(BACKUP_BANNER_DISMISSED_KEY) === '1';
  } catch {
    return false;
  }
}

function writeDismissed() {
  try {
    window.sessionStorage.setItem(BACKUP_BANNER_DISMISSED_KEY, '1');
  } catch {
    // Storage blocked: the dismissal lasts until the next render cycle only.
  }
}

export function BackupStatusBanner() {
  const { hasPermission } = useAuth();
  const enabled = hasPermission('settings:system');
  const [dismissed, setDismissed] = useState<boolean>(() => readDismissed());

  const { data: status } = useQuery({
    queryKey: BACKUP_STATUS_QUERY_KEY,
    queryFn: () => api.systemHealth.getBackupStatus(),
    enabled,
    staleTime: 5 * 60_000,
    refetchInterval: 30 * 60_000,
    retry: false,
  });

  if (!enabled || dismissed || !status?.stale) return null;

  return (
    <div
      role="status"
      className="mx-6 mt-3 flex items-center justify-between gap-3 rounded-md border border-amber-200 bg-amber-50/80 px-3 py-2 text-[12px] dark:border-amber-500/30 dark:bg-amber-500/10"
    >
      <div className="flex min-w-0 items-center gap-2.5">
        <DatabaseBackup className="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" strokeWidth={1.5} />
        <span className="font-medium">No successful backup in {status.stale_after_hours} hours</span>
        <span className="truncate text-muted-foreground">
          Last success:{' '}
          <span className="font-mono text-[11px]" data-testid="backup-banner-last-success">
            {status.last_success_at ? formatUTCCompact(status.last_success_at) : 'never'}
          </span>
        </span>
      </div>
      <div className="flex shrink-0 items-center gap-3">
        <Link to="/settings" className="text-primary hover:underline">
          Backup status
        </Link>
        <a href={AUTOMATIC_BACKUPS_DOCS_URL} target="_blank" rel="noopener noreferrer" className="font-medium text-primary hover:underline">
          Automatic backups
        </a>
        <button
          onClick={() => { writeDismissed(); setDismissed(true); }}
          className="rounded p-1 text-muted-foreground hover:bg-muted"
          aria-label="Dismiss backup warning for this session"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}
