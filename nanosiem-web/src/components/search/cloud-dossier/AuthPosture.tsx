// SPDX-License-Identifier: AGPL-3.0-or-later

import { User as UserIcon, Shield } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { CloudDossierAuthPosture, CloudRiskBand } from '@/lib/api/types';
import { CloudCard, cloudSevTone } from '../cloud-overview/shared';

interface AuthPostureProps {
  posture: CloudDossierAuthPosture;
  /** Click a principal row to pivot into that principal's dossier */
  onPivotPrincipal?: (id: string) => void;
}

export function AuthPosture({ posture, onPivotPrincipal }: AuthPostureProps) {
  const total = Math.max(1, posture.total_principals);
  const pct = posture.with_mfa / total;
  return (
    <CloudCard
      title="MFA · auth posture"
      subtitle={`${posture.without_mfa}/${posture.total_principals} principals without MFA`}
      accent="oklch(68% 0.14 280)"
    >
      <div className="p-3 space-y-3">
        <div>
          <div className="flex items-center gap-2 text-[11px] font-mono text-muted-foreground/80 mb-1">
            <span className="text-foreground">{posture.with_mfa}</span> with MFA
            <span className="text-muted-foreground/70">·</span>
            <span className="text-[oklch(72%_0.17_28)]">{posture.without_mfa} without</span>
            <span className="flex-1" />
            <span className="tabular-nums">{(pct * 100).toFixed(0)}% coverage</span>
          </div>
          <div className="h-2 rounded-full bg-foreground/[0.06] overflow-hidden flex">
            <div
              className="h-full bg-[oklch(72%_0.16_160)]"
              style={{ width: `${pct * 100}%` }}
            />
            <div
              className="h-full bg-[oklch(68%_0.18_28)]"
              style={{ width: `${(1 - pct) * 100}%` }}
            />
          </div>
        </div>

        <div className="grid grid-cols-3 gap-2 text-[11.5px]">
          <PostureStat
            n={posture.privileged_without_mfa}
            label="privileged without MFA"
            band="critical"
          />
          <PostureStat
            n={posture.privileged_calls_without_mfa}
            label="privileged calls (no MFA)"
            band="high"
          />
          <PostureStat
            n={`${posture.oldest_key_days}d`}
            label="oldest key age"
            band={posture.oldest_key_days > 90 ? 'high' : 'medium'}
          />
        </div>

        {posture.principals.length > 0 && (
          <div className="border-t border-border pt-2">
            <div className="grid grid-cols-[1fr_72px_72px_80px_72px] gap-2 px-2 pb-1 text-[9.5px] font-mono uppercase tracking-[0.08em] text-muted-foreground/70">
              <span>Principal</span>
              <span className="text-right">MFA</span>
              <span className="text-right">Priv</span>
              <span className="text-right">Key age</span>
              <span className="text-right">Last</span>
            </div>
            <div className="space-y-[1px]">
              {posture.principals.map((p) => {
                const Icon = p.is_role ? Shield : UserIcon;
                const clickable = !!onPivotPrincipal && !p.anomaly;
                return (
                  <button
                    key={p.name}
                    onClick={clickable ? () => onPivotPrincipal!(p.name) : undefined}
                    disabled={!clickable}
                    className={cn(
                      'w-full grid grid-cols-[1fr_72px_72px_80px_72px] gap-2 px-2 py-1 rounded-sm hover:bg-foreground/[0.03] items-center font-mono text-[11.5px] text-left',
                      clickable && 'enabled:hover:text-primary cursor-pointer',
                      p.anomaly && 'bg-[oklch(68%_0.18_28/0.06)]'
                    )}
                    title={clickable ? `Open dossier for ${p.name}` : undefined}
                  >
                    <span className="flex items-center gap-1.5 min-w-0">
                      <Icon
                        className="w-[11px] h-[11px] text-muted-foreground/70 shrink-0"
                        strokeWidth={1.5}
                      />
                      <span
                        className={cn(
                          'truncate',
                          p.anomaly ? 'text-[oklch(72%_0.17_28)]' : 'text-foreground'
                        )}
                      >
                        {p.name}
                      </span>
                    </span>
                    <span className="text-right">
                      {p.mfa === null ? (
                        <span className="text-muted-foreground/70">—</span>
                      ) : p.mfa ? (
                        <span className="text-[oklch(72%_0.16_160)]">on</span>
                      ) : (
                        <span className="text-[oklch(72%_0.17_28)]">off</span>
                      )}
                    </span>
                    <span className="text-right">
                      {p.privileged ? (
                        <span className="text-[oklch(78%_0.14_60)]">yes</span>
                      ) : (
                        <span className="text-muted-foreground/70">no</span>
                      )}
                    </span>
                    <span className="text-right tabular-nums text-muted-foreground/80">
                      {p.key_age_days == null ? '—' : `${p.key_age_days}d`}
                    </span>
                    <span className="text-right tabular-nums text-muted-foreground/80 text-[10.5px]">
                      {p.last_call ?? '—'}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </CloudCard>
  );
}

function PostureStat({
  n,
  label,
  band,
}: {
  n: number | string;
  label: string;
  band: CloudRiskBand;
}) {
  const tone = cloudSevTone(band);
  return (
    <div className={cn('rounded-md border px-2.5 py-2', tone.border, tone.bg)}>
      <div className={cn('text-[22px] font-semibold tabular-nums leading-none', tone.text)}>
        {n}
      </div>
      <div className="text-[10px] font-mono uppercase tracking-[0.06em] text-muted-foreground/80 mt-1 leading-tight">
        {label}
      </div>
    </div>
  );
}
