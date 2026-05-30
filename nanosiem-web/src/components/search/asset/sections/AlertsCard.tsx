// SPDX-License-Identifier: AGPL-3.0-or-later

import { AlertTriangle, ExternalLink } from 'lucide-react';
import type { EntityAlertSummary } from '@/lib/api/types';
import { cn } from '@/lib/utils';
import { sevTone, formatTimeRelative } from '../helpers';
import { SectionCard, EmptyCell } from './_shared';

interface AlertsCardProps {
  alerts: EntityAlertSummary[];
  total?: number;
  onAlertClick?: (alertRowId: string) => void;
  onOpenSequence?: () => void;
}

export function AlertsCard({ alerts, total, onAlertClick, onOpenSequence }: AlertsCardProps) {
  const bySev = {
    critical: alerts.filter((a) => a.severity.toLowerCase() === 'critical').length,
    high: alerts.filter((a) => a.severity.toLowerCase() === 'high').length,
    medium: alerts.filter((a) => a.severity.toLowerCase() === 'medium').length,
    low: alerts.filter((a) => a.severity.toLowerCase() === 'low').length,
  };
  const open = alerts.filter((a) => (a.status ?? '').toLowerCase() === 'open').length;
  const closed = alerts.length - open;

  const top = [...alerts]
    .sort((a, b) => {
      const order = ['critical', 'high', 'medium', 'low', 'informational'];
      const ai = order.indexOf(a.severity.toLowerCase());
      const bi = order.indexOf(b.severity.toLowerCase());
      return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
    })
    .slice(0, 5);

  return (
    <SectionCard
      title="Alerts"
      count={total ?? alerts.length}
      action={<span className="text-[11px]">Open sequence ↗</span>}
      onActionClick={onOpenSequence}
      icon={<AlertTriangle className="w-[13px] h-[13px] text-muted-foreground/70" />}
    >
      {alerts.length === 0 ? (
        <EmptyCell>No alerts for this entity in range</EmptyCell>
      ) : (
        <div className="space-y-2.5">
          <div className="flex items-center gap-2 text-[11px] font-mono flex-wrap">
            <Chip label={`${bySev.critical} critical`} tone="critical" show={bySev.critical > 0} />
            <Chip label={`${bySev.high} high`} tone="high" show={bySev.high > 0} />
            <Chip label={`${bySev.medium} medium`} tone="medium" show={bySev.medium > 0} />
            <Chip label={`${bySev.low} low`} tone="low" show={bySev.low > 0} />
            <span className="text-muted-foreground/70">
              {open} open · {closed} closed
            </span>
          </div>
          <ul className="space-y-2">
            {top.map((a) => {
              const inner = (
                <>
                  <span
                    className="w-1.5 h-1.5 rounded-full mt-[7px] shrink-0"
                    style={{ background: sevTone(a.severity).dot }}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-baseline gap-2">
                      <div className="text-[12.5px] text-foreground truncate font-medium">
                        {a.rule_name ?? '(rule deleted)'}
                      </div>
                      <SevPill sev={a.severity} />
                    </div>
                    <div className="text-[10.5px] font-mono text-muted-foreground/70 mt-0.5">
                      {a.alert_id.slice(0, 8)} · {formatTimeRelative(a.created_at)} ·{' '}
                      <span className="text-foreground/70">{a.status}</span>
                    </div>
                  </div>
                  <ExternalLink className="w-3 h-3 text-muted-foreground/50 opacity-0 group-hover:opacity-100 shrink-0 mt-1" />
                </>
              );
              return (
                <li key={a.id}>
                  {onAlertClick ? (
                    <button
                      type="button"
                      onClick={() => onAlertClick(a.alert_id)}
                      className="w-full flex items-start gap-2.5 text-left -mx-2 px-2 py-1 rounded hover:bg-foreground/5 focus:outline-none focus-visible:ring-1 focus-visible:ring-primary"
                    >
                      {inner}
                    </button>
                  ) : (
                    <div className="flex items-start gap-2.5">{inner}</div>
                  )}
                </li>
              );
            })}
            {alerts.length > top.length && (
              <li className="text-[11px] text-muted-foreground/70 pl-3.5 pt-1">
                Show {alerts.length - top.length} more →
              </li>
            )}
          </ul>
        </div>
      )}
    </SectionCard>
  );
}

function Chip({
  label,
  tone,
  show,
}: {
  label: string;
  tone: 'critical' | 'high' | 'medium' | 'low';
  show: boolean;
}) {
  if (!show) return null;
  const t = sevTone(tone);
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10.5px] font-semibold',
        t.bg,
        t.text
      )}
    >
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: t.dot }} />
      {label}
    </span>
  );
}

function SevPill({ sev }: { sev: string }) {
  const t = sevTone(sev);
  return (
    <span
      className={cn(
        'text-[9.5px] font-mono uppercase tracking-[0.08em] px-1.5 py-0.5 rounded shrink-0',
        t.bg,
        t.text
      )}
    >
      {sev}
    </span>
  );
}

