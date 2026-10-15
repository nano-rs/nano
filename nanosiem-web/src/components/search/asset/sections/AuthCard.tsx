// SPDX-License-Identifier: AGPL-3.0-or-later

import { ShieldCheck } from 'lucide-react';
import type { AssetDossierAuth } from '@/lib/api/types';
import { cn } from '@/lib/utils';
import { SectionCard, EmptyCell, PendingCell, StatCell } from './_shared';
import { formatCompact, formatEventTimeFull, formatEventTimeShort } from '../helpers';

/** NAN-3408: one failure token for the header, the FAILURE tile (`warn`) and the rows. */
const FAIL_TEXT = 'text-[oklch(72%_0.14_80)]';
const FAIL_DOT = 'oklch(72% 0.14 80)';
const OK_DOT = 'oklch(72% 0.16 160)';

export type AuthStatKey = 'SUCCESS' | 'FAILURE' | 'INTERACT' | 'NETWORK';

interface AuthCardProps {
  /** NAN-3291: the dossier is still reading; an empty section is not yet known to be empty. */
  pending?: boolean;
  auth: AssetDossierAuth;
  onOpenAll?: () => void;
  onStatClick?: (key: AuthStatKey) => void;
}

export function AuthCard({ auth, onOpenAll, onStatClick, pending = false }: AuthCardProps) {
  const { success, failure, interactive, network, lateral, recent } = auth;
  const total = success + failure;

  if (total === 0 && recent.length === 0) {
    return (
      <SectionCard
        title="Authentication"
        action={<span>All auth events ↗</span>}
        onActionClick={onOpenAll}
        icon={<ShieldCheck className="w-[13px] h-[13px] text-muted-foreground/70" />}
      >
        {pending ? <PendingCell /> : <EmptyCell>No auth events for this entity in range</EmptyCell>}
      </SectionCard>
    );
  }

  return (
    <SectionCard
      title="Authentication"
      action={<span>All auth events ↗</span>}
      onActionClick={onOpenAll}
      icon={<ShieldCheck className="w-[13px] h-[13px] text-muted-foreground/70" />}
    >
      <div className="space-y-3">
        <div className="text-[11px] text-muted-foreground/70 font-mono">
          <span className="tabular-nums text-foreground">{formatCompact(success)}</span> success ·{' '}
          <span
            className={cn(
              'tabular-nums',
              failure > 0 ? FAIL_TEXT : 'text-foreground'
            )}
          >
            {formatCompact(failure)}
          </span>{' '}
          fail
        </div>

        <div className="grid grid-cols-4 gap-2">
          <StatCell
            value={success}
            label="SUCCESS"
            onClick={onStatClick ? () => onStatClick('SUCCESS') : undefined}
            disabled={success === 0}
          />
          <StatCell
            value={failure}
            label="FAILURE"
            tone={failure > 0 ? 'warn' : 'default'}
            onClick={onStatClick ? () => onStatClick('FAILURE') : undefined}
            disabled={failure === 0}
          />
          <StatCell
            value={interactive}
            label="INTERACT."
            onClick={onStatClick ? () => onStatClick('INTERACT') : undefined}
            disabled={interactive === 0}
          />
          <StatCell
            value={network + lateral}
            label="NETWORK"
            onClick={onStatClick ? () => onStatClick('NETWORK') : undefined}
            disabled={network + lateral === 0}
          />
        </div>

        {recent.length > 0 && (
          <div>
            <div className="text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70 mb-1.5">
              Recent logons · UTC
            </div>
            <ul>
              {recent.slice(0, 6).map((r, i) => (
                <li
                  key={`${r.ts}-${i}`}
                  data-testid="auth-recent-row"
                  className="flex items-center gap-2 h-6 min-w-0 whitespace-nowrap overflow-hidden text-[11.5px] font-mono"
                >
                  <span
                    className="tabular-nums text-muted-foreground/70 w-[14ch] shrink-0"
                    title={formatEventTimeFull(r.ts)}
                  >
                    {formatEventTimeShort(r.ts)}
                  </span>
                  <span
                    className="w-1.5 h-1.5 rounded-full shrink-0"
                    style={{ background: r.result === 'failure' ? FAIL_DOT : OK_DOT }}
                  />
                  <span className="text-muted-foreground/70 w-[80px] truncate shrink-0">
                    {r.auth_type}
                  </span>
                  {r.user && (
                    <span className="text-foreground truncate max-w-[140px]">{r.user}</span>
                  )}
                  {r.src && (
                    <span className="text-muted-foreground/70 truncate min-w-0">
                      via <span className="text-foreground">{r.src}</span>
                    </span>
                  )}
                  {r.result === 'failure' && r.reason && (
                    <span className={cn('ml-auto truncate max-w-[120px]', FAIL_TEXT)}>
                      {r.reason}
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </SectionCard>
  );
}

