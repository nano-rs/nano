// SPDX-License-Identifier: AGPL-3.0-or-later

import type { ElementType } from 'react';
import { User as UserIcon, Shield } from 'lucide-react';
import { cn } from '@/lib/utils';
import type {
  CloudDossierAssumeChain,
  CloudDossierAssumeHop,
  CloudDossierKeyAction,
} from '@/lib/api/types';
import { CloudCard, cloudSevTone } from '../cloud-overview/shared';

interface AssumeRoleChainProps {
  chain: CloudDossierAssumeChain;
  /** Pivot to the dossier for a role along the chain */
  onPivotPrincipal?: (id: string) => void;
  /** Append an action filter to the base search */
  onPivotAction?: (action: string) => void;
  /** Append a resource_name filter to the base search */
  onPivotTarget?: (target: string) => void;
}

export function AssumeRoleChain({
  chain,
  onPivotPrincipal,
  onPivotAction,
  onPivotTarget,
}: AssumeRoleChainProps) {
  const hasHops = chain.hops.length > 0;
  const hasActions = chain.key_actions.length > 0;

  return (
    <CloudCard
      title="AssumeRole chain"
      subtitle="privilege escalation path"
      accent="oklch(70% 0.15 50)"
    >
      <div className="p-4">
        <div className="flex items-stretch gap-0 flex-wrap">
          <AssumeNode
            label={chain.origin_label}
            account={chain.origin_account}
            kind="origin"
            note={chain.origin_note}
          />
          {chain.hops.map((h, i) => (
            <NodeAndArrow
              key={`${h.to_label}-${i}`}
              hop={h}
              onPivotPrincipal={onPivotPrincipal}
            />
          ))}
          {!hasHops && (
            <div className="flex-1 flex items-center justify-center py-6 text-[11px] text-muted-foreground/60 font-mono">
              No AssumeRole hops in this window
            </div>
          )}
        </div>

        {hasActions && (
          <div className="mt-4 pt-3 border-t border-border">
            <div className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground/80 mb-2">
              Key actions along the chain
            </div>
            <div className="space-y-1">
              {chain.key_actions.map((a, i) => (
                <KeyActionRow
                  key={`${a.at}-${i}`}
                  action={a}
                  onPivotPrincipal={onPivotPrincipal}
                  onPivotAction={onPivotAction}
                  onPivotTarget={onPivotTarget}
                />
              ))}
            </div>
          </div>
        )}
      </div>
    </CloudCard>
  );
}

function NodeAndArrow({
  hop,
  onPivotPrincipal,
}: {
  hop: CloudDossierAssumeHop;
  onPivotPrincipal?: (id: string) => void;
}) {
  return (
    <>
      <AssumeArrow at={hop.at} via={hop.via} sessionName={hop.session_name} calls={hop.calls} />
      <AssumeNode
        label={hop.to_label}
        account={hop.to_account}
        kind="role"
        sensitive={hop.sensitive}
        permissions={hop.permissions}
        note={hop.note}
        onClick={onPivotPrincipal ? () => onPivotPrincipal(hop.to_label) : undefined}
      />
    </>
  );
}

interface AssumeNodeProps {
  label: string;
  account?: string | null;
  kind: 'origin' | 'role';
  sensitive?: boolean;
  permissions?: string[];
  note?: string | null;
  /** Make the node interactive — clicking pivots into that role's dossier */
  onClick?: () => void;
}

function AssumeNode({ label, account, kind, sensitive, permissions, note, onClick }: AssumeNodeProps) {
  const tone =
    kind === 'origin'
      ? {
          bg: 'bg-[oklch(72%_0.16_60/0.1)]',
          border: 'border-[oklch(72%_0.16_60/0.4)]',
          text: 'text-[oklch(78%_0.14_60)]',
          icon: 'user' as const,
        }
      : sensitive
      ? {
          bg: 'bg-[oklch(62%_0.18_28/0.1)]',
          border: 'border-[oklch(62%_0.18_28/0.4)]',
          text: 'text-[oklch(72%_0.17_28)]',
          icon: 'role' as const,
        }
      : {
          bg: 'bg-foreground/5',
          border: 'border-border',
          text: 'text-foreground',
          icon: 'role' as const,
        };
  const Wrapper: ElementType = onClick ? 'button' : 'div';
  return (
    <Wrapper
      onClick={onClick}
      className={cn(
        'flex-1 min-w-[160px] rounded-lg border-2 px-3 py-2.5 text-left',
        tone.bg,
        tone.border,
        onClick && 'hover:brightness-125 transition-all cursor-pointer'
      )}
      title={onClick ? `Open dossier for ${label}` : undefined}
    >
      <div className="flex items-start gap-2">
        <div
          className={cn(
            'w-7 h-7 rounded-md flex items-center justify-center shrink-0 bg-background/50 border border-border',
            tone.text
          )}
        >
          {tone.icon === 'user' ? (
            <UserIcon className="w-4 h-4" strokeWidth={1.5} />
          ) : (
            <Shield className="w-4 h-4" strokeWidth={1.5} />
          )}
        </div>
        <div className="min-w-0 flex-1">
          <div className={cn('font-mono text-[12.5px] font-semibold truncate', tone.text)}>
            {label}
          </div>
          <div className="text-[10.5px] text-muted-foreground/80 font-mono truncate">
            {kind === 'origin' ? `user · ${account ?? '—'}` : `role · ${account ?? '—'}`}
          </div>
          {note && (
            <div className="text-[10.5px] text-muted-foreground/70 mt-1 leading-snug line-clamp-2">
              {note}
            </div>
          )}
          {permissions && permissions.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-1.5">
              {permissions.map((p) => (
                <span
                  key={p}
                  className="text-[9.5px] font-mono px-1 py-[1px] rounded bg-foreground/5 text-muted-foreground/80"
                >
                  {p}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>
    </Wrapper>
  );
}

function AssumeArrow({
  at,
  via,
  sessionName,
  calls,
}: {
  at: string;
  via: string;
  sessionName: string;
  calls: number;
}) {
  return (
    <div className="flex flex-col items-center justify-center px-2 py-2 shrink-0 w-[130px]">
      <div className="text-[9.5px] font-mono text-muted-foreground/70 tabular-nums mb-1">{at}</div>
      <div className="w-full flex items-center">
        <span className="h-px flex-1 bg-gradient-to-r from-border to-[oklch(68%_0.18_28)]" />
        <svg viewBox="0 0 16 16" className="w-3 h-3 text-[oklch(68%_0.18_28)] shrink-0" fill="currentColor">
          <path d="M2 7h10l-3-3h2l5 4-5 4h-2l3-3H2z" />
        </svg>
      </div>
      <div className="mt-1 text-center">
        <div className="text-[10px] font-mono text-primary">{via}</div>
        {sessionName && (
          <div className="text-[9.5px] font-mono text-muted-foreground/70 truncate max-w-full">
            "{sessionName}"
          </div>
        )}
        <div className="text-[9.5px] font-mono text-muted-foreground/80 tabular-nums">
          {calls.toLocaleString()} calls
        </div>
      </div>
    </div>
  );
}

function KeyActionRow({
  action,
  onPivotPrincipal,
  onPivotAction,
  onPivotTarget,
}: {
  action: CloudDossierKeyAction;
  onPivotPrincipal?: (id: string) => void;
  onPivotAction?: (action: string) => void;
  onPivotTarget?: (target: string) => void;
}) {
  const tone = cloudSevTone(action.severity);
  return (
    <div className="grid grid-cols-[52px_auto_1fr_auto] items-center gap-2 text-[12px] py-[3px] px-2 rounded-sm hover:bg-foreground/[0.03] font-mono">
      <span className="text-muted-foreground/80 tabular-nums text-[11.5px] shrink-0 whitespace-nowrap">
        {action.at}
      </span>
      {onPivotPrincipal && action.role ? (
        <button
          onClick={() => onPivotPrincipal(action.role)}
          className="text-muted-foreground/90 text-[11.5px] shrink-0 whitespace-nowrap hover:text-primary hover:underline text-left"
          title={`Open dossier for ${action.role}`}
        >
          {action.role}
        </button>
      ) : (
        <span className="text-muted-foreground/90 text-[11.5px] shrink-0 whitespace-nowrap">
          {action.role}
        </span>
      )}
      <span className="min-w-0 flex items-center gap-2 overflow-hidden">
        {onPivotAction ? (
          <button
            onClick={() => onPivotAction(action.action)}
            className="text-primary text-[11.5px] truncate min-w-0 hover:underline text-left"
            title={`Filter by action=${action.action}`}
          >
            {action.action}
          </button>
        ) : (
          <span className="text-primary text-[11.5px] truncate min-w-0">{action.action}</span>
        )}
        {action.target && (
          <>
            <span className="text-muted-foreground/70 shrink-0">→</span>
            {onPivotTarget ? (
              <button
                onClick={() => onPivotTarget(action.target)}
                className="text-foreground truncate text-[11.5px] min-w-0 hover:text-primary hover:underline text-left"
                title={`Filter by resource_name=${action.target}`}
              >
                {action.target}
              </button>
            ) : (
              <span className="text-foreground truncate text-[11.5px] min-w-0">
                {action.target}
              </span>
            )}
          </>
        )}
      </span>
      <span
        className={cn(
          'text-[10px] px-1.5 py-0.5 rounded-sm shrink-0 whitespace-nowrap',
          tone.bg,
          tone.text
        )}
      >
        {action.severity}
      </span>
    </div>
  );
}

