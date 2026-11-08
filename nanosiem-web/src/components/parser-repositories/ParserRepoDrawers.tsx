// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-526 — slide-over drawers for the redesigned Parser Repositories page.
//   • SyncHistoryDrawer — single "last sync" entry until a backend history
//     endpoint exists. Mirrors NAN-505's RuleRepositories drawer.
//
// Bulk import remains in `BatchImportParsersModal.tsx` (already wired to the
// per-parser ingestion-method picker that the legacy page used). The new
// toolbar opens that modal directly.

import {
  CircleAlert,
  CircleCheck,
  Clock,
  GitCommit,
  RefreshCw,
  X,
  XCircle,
} from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { cn } from '@/lib/utils';
import type { ParserRepoView } from './helpers';

// ------------------------------------------------------------------
// Side drawer shell
// ------------------------------------------------------------------

interface DrawerShellProps {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: React.ReactNode;
  width?: number;
  footer?: React.ReactNode;
  children: React.ReactNode;
}

function SideDrawer({
  open,
  onClose,
  title,
  subtitle,
  width = 460,
  footer,
  children,
}: DrawerShellProps) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div
        className="absolute right-0 top-0 bottom-0 border-l border-border bg-card flex flex-col shadow-2xl"
        style={{ width }}
      >
        <div className="flex items-start gap-2 px-4 pt-3 pb-3 border-b border-border shrink-0">
          <div className="flex-1 min-w-0">
            <div className="text-[13px] font-semibold text-foreground">{title}</div>
            {subtitle && (
              <div className="text-[11px] text-muted-foreground mt-0.5 truncate">{subtitle}</div>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="h-[24px] w-[24px] rounded-md flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-foreground/5"
            aria-label="Close drawer"
          >
            <X className="w-[13px] h-[13px]" strokeWidth={1.5} />
          </button>
        </div>
        <div className="flex-1 overflow-auto">{children}</div>
        {footer && (
          <div className="border-t border-border px-4 py-3 shrink-0 bg-card">{footer}</div>
        )}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------
// Sync history — single "last sync" entry until backend history lands
// ------------------------------------------------------------------

interface SyncHistoryProps {
  open: boolean;
  onClose: () => void;
  repo: ParserRepoView | null;
  syncing: boolean;
  onSyncNow: (id: string) => void;
}

export function SyncHistoryDrawer({
  open,
  onClose,
  repo,
  syncing,
  onSyncNow,
}: SyncHistoryProps) {
  if (!repo) return null;
  const lastError = repo.raw.last_sync_error;
  return (
    <SideDrawer
      open={open}
      onClose={onClose}
      title="Sync history"
      subtitle={<span className="font-mono">{repo.slug}</span>}
      width={460}
      footer={
        <div className="flex items-center gap-2">
          <div className="flex-1 text-[10.5px] text-muted-foreground font-mono">
            {repo.autoSync !== 'off' ? (
              <>
                next auto-sync in <span className="text-foreground/70">{repo.nextSync.in}</span> ·{' '}
                {repo.nextSync.cadence}
              </>
            ) : (
              'auto-sync disabled'
            )}
          </div>
          <button
            type="button"
            onClick={() => onSyncNow(repo.id)}
            disabled={syncing}
            className={cn(
              'h-[28px] px-3 rounded-md text-[11.5px] font-medium flex items-center gap-1.5 border',
              syncing
                ? 'border-border bg-foreground/5 text-muted-foreground cursor-not-allowed'
                : 'bg-primary border-primary text-primary-foreground hover:bg-primary/90',
            )}
          >
            <RefreshCw
              className={cn('w-[11px] h-[11px]', syncing && 'animate-spin')}
              strokeWidth={1.5}
            />
            {syncing ? 'Syncing' : 'Sync now'}
          </button>
        </div>
      }
    >
      <div className="p-4">
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2.5">
          Last sync
        </div>

        {repo.lastSync.ts ? (
          <ol className="relative border-l border-border ml-2 pl-4 space-y-3">
            <li className="relative">
              <span
                className={cn(
                  'absolute -left-[19px] top-1 w-[10px] h-[10px] rounded-full border-2',
                  repo.lastSync.result === 'failed'
                    ? 'border-destructive bg-destructive/20'
                    : repo.lastSync.result === 'pending'
                      ? 'border-warning bg-warning/20'
                      : 'border-success bg-success/20',
                )}
              />
              <div className="flex items-center gap-1.5 text-[11.5px] font-medium text-foreground">
                {repo.lastSync.result === 'failed' ? (
                  <XCircle className="w-[12px] h-[12px] text-destructive" strokeWidth={1.5} />
                ) : repo.lastSync.result === 'pending' ? (
                  <LoadingIcon className="w-[12px] h-[12px] text-warning" strokeWidth={1.5} />
                ) : (
                  <CircleCheck className="w-[12px] h-[12px] text-success" strokeWidth={1.5} />
                )}
                {repo.lastSync.result === 'failed'
                  ? 'Sync failed'
                  : repo.lastSync.result === 'pending'
                    ? 'Sync in progress'
                    : 'Sync complete'}
                <span className="ml-auto text-[10.5px] font-mono text-muted-foreground">
                  {repo.lastSync.relative}
                </span>
              </div>
              <div className="mt-1.5 flex items-center gap-2 text-[10.5px] font-mono text-muted-foreground">
                <span className="flex items-center gap-1">
                  <GitCommit className="w-[10px] h-[10px]" strokeWidth={1.5} />
                  {repo.lastCommit.sha}
                </span>
                <span>·</span>
                <span className="text-foreground/70">{repo.total} parsers</span>
              </div>
              {lastError && (
                <div className="mt-2 rounded-md border border-destructive/30 bg-destructive/5 px-2.5 py-2 text-[10.5px] text-destructive font-mono leading-relaxed">
                  {lastError}
                </div>
              )}
            </li>
          </ol>
        ) : (
          <div className="rounded-md border border-border bg-card px-3 py-2.5 flex items-center gap-2 text-[11px] text-muted-foreground">
            <CircleAlert className="w-[12px] h-[12px]" strokeWidth={1.5} />
            This repository hasn't been synced yet. Click <span className="font-mono">Sync now</span> to
            kick off the first pull.
          </div>
        )}

        <div className="mt-4 rounded-md border border-border bg-card px-3 py-2.5 text-[10.5px] text-muted-foreground leading-relaxed">
          <div className="flex items-center gap-1.5 text-foreground/80 font-medium mb-1">
            <Clock className="w-[12px] h-[12px]" strokeWidth={1.5} />
            History coming soon
          </div>
          Per-sync history (every pull, with diff counts and errors) will land alongside the backend
          sync-events table. For now this drawer surfaces the most recent sync only.
        </div>
      </div>
    </SideDrawer>
  );
}
