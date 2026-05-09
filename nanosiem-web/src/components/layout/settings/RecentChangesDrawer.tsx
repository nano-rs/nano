// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Right-edge drawer listing the last 50 audit-log entries. Click any row to
 * jump to the related section. Mirrors `design-ref/shadcn/settings-shell.jsx`
 * `AuditDrawer`.
 */

import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Clock, X, ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useAuditLog } from '@/hooks/use-api';
import type { AuditLogEntry } from '@/lib/api/types';

interface RecentChangesDrawerProps {
  open: boolean;
  onClose: () => void;
}

type Tone = 'good' | 'warn' | 'danger' | 'neutral';

function toneFor(entry: AuditLogEntry): Tone {
  if (entry.success === false) return 'danger';
  const action = (entry.action || '').toLowerCase();
  if (action.includes('delete') || action.includes('revoke') || action.includes('disable')) return 'warn';
  if (action.includes('create') || action.includes('add') || action.includes('grant')) return 'good';
  return 'neutral';
}

/**
 * Map an audit entry's resource_type → settings route. Conservative: when we
 * don't know, leave the row non-clickable rather than send the user somewhere
 * weird.
 */
function targetForEntry(entry: AuditLogEntry): string | null {
  const rt = (entry.resource_type || '').toLowerCase();
  switch (rt) {
    case 'user': return '/settings/access-control?tab=users';
    case 'group': return '/settings/access-control?tab=groups';
    case 'role': return '/settings/access-control?tab=roles';
    case 'apikey':
    case 'api_key': return '/settings/access-control?tab=api-keys';
    case 'session': return '/settings/access-control?tab=sessions';
    case 'webhook': return '/settings/webhooks';
    case 'oidc':
    case 'oidc_provider':
    case 'sso': return '/settings/oidc';
    case 'risk_settings':
    case 'risk': return '/settings/risk';
    case 'prevalence_settings':
    case 'prevalence': return '/settings/prevalence';
    case 'retention':
    case 'storage': return '/settings/storage';
    case 'search_settings':
    case 'search': return '/settings/search';
    case 'case_settings':
    case 'case': return '/settings/cases';
    case 'queue': return '/settings/cases/queues';
    case 'enrichment':
    case 'enrichment_agent': return '/enrichments';
    case 'audit_log': return '/settings/audit';
    default: return null;
  }
}

function relativeAge(ts: string): string {
  const then = new Date(ts).getTime();
  if (Number.isNaN(then)) return '';
  const diff = Date.now() - then;
  if (diff < 60_000) return `${Math.max(1, Math.round(diff / 1000))}s`;
  if (diff < 3_600_000) return `${Math.round(diff / 60_000)}m`;
  if (diff < 86_400_000) return `${Math.round(diff / 3_600_000)}h`;
  return `${Math.round(diff / 86_400_000)}d`;
}

export function RecentChangesDrawer({ open, onClose }: RecentChangesDrawerProps) {
  const navigate = useNavigate();
  const query = useMemo(() => ({ limit: 50 }), []);
  const { data, loading, error } = useAuditLog(query);
  const entries = data?.logs ?? [];

  if (!open) return null;

  return (
    <>
      {/* Scrim — sits over the body grid cell only, not the rail */}
      <div className="absolute inset-0 z-40 bg-black/30" onClick={onClose} />

      {/* Drawer */}
      <aside
        className="absolute top-[42px] right-0 bottom-[22px] w-[380px] z-50 border-l border-border flex flex-col"
        style={{ background: 'var(--panel)' }}
        aria-label="Recent configuration changes"
      >
        <div className="h-10 px-3 flex items-center gap-2 border-b border-border shrink-0">
          <Clock className="w-[13px] h-[13px] text-muted-foreground" />
          <span className="text-[12px] font-medium text-foreground">Recent configuration changes</span>
          <span className="ml-auto text-[10.5px] text-muted-foreground">last 50</span>
          <button
            onClick={onClose}
            className="ml-1 w-5 h-5 rounded flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-foreground/5"
          >
            <X className="w-[12px] h-[12px]" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto scrollbar-thin">
          {loading && entries.length === 0 && (
            <div className="px-3 py-6 text-center text-[11.5px] text-muted-foreground">Loading…</div>
          )}
          {error && (
            <div className="px-3 py-6 text-center text-[11.5px] text-red-500">
              Couldn't load audit log. {String(error)}
            </div>
          )}
          {!loading && !error && entries.length === 0 && (
            <div className="px-3 py-6 text-center text-[11.5px] text-muted-foreground">
              No recent changes.
            </div>
          )}
          {entries.map(ev => {
            const target = targetForEntry(ev);
            const tone = toneFor(ev);
            const detail = ev.message
              || (ev.resource_name ? `${ev.action || 'changed'} · ${ev.resource_name}` : ev.action || '');
            return (
              <button
                key={ev.id}
                disabled={!target}
                onClick={() => { if (target) { navigate(target); onClose(); } }}
                className={cn(
                  'w-full text-left px-3 py-2.5 border-b border-border transition-colors',
                  target ? 'hover:bg-foreground/[0.03] cursor-pointer' : 'cursor-default opacity-90',
                )}
              >
                <div className="flex items-center gap-2">
                  <span className={cn(
                    'w-1 h-1 rounded-full',
                    tone === 'good' && 'bg-emerald-500',
                    tone === 'warn' && 'bg-yellow-500',
                    tone === 'danger' && 'bg-red-500',
                    tone === 'neutral' && 'bg-muted-foreground',
                  )} />
                  <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums shrink-0">
                    {relativeAge(ev.timestamp)}
                  </span>
                  <span className="font-mono text-[10.5px] text-foreground/80 truncate">
                    {ev.user_name || (ev.user_id ? ev.user_id.slice(0, 8) : 'system')}
                  </span>
                  <span className="text-[10.5px] text-muted-foreground shrink-0">
                    {ev.action || ''}
                  </span>
                  {ev.resource_type && (
                    <span className="ml-auto text-[10.5px] text-foreground uppercase tracking-wider shrink-0">
                      {ev.resource_type.replace(/_/g, ' ')}
                    </span>
                  )}
                </div>
                <div className="text-[11px] text-muted-foreground mt-1 leading-snug truncate">{detail}</div>
              </button>
            );
          })}
        </div>

        <div className="shrink-0 h-8 px-3 border-t border-border flex items-center">
          <button
            onClick={() => { navigate('/settings/audit'); onClose(); }}
            className="text-[11px] text-muted-foreground hover:text-foreground flex items-center gap-1"
          >
            View full audit log <ChevronRight className="w-[10px] h-[10px]" />
          </button>
        </div>
      </aside>
    </>
  );
}
