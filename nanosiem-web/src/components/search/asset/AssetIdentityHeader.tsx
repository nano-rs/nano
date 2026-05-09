// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react';
import { Search, Filter, Bookmark, Share2, ChevronDown } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { AssetDossierIdentity } from '@/lib/api/types';
import type { EntityRiskSummary } from '@/lib/api/types';
import {
  FactCell,
  RiskGauge,
  riskBandForScore,
  riskTone,
  formatTimeRelative,
  formatDate,
} from './helpers';

interface AssetIdentityHeaderProps {
  kind: 'host' | 'user';
  /** Primary identifier value (e.g. "WIN-HR11", "john.doe") */
  entityValue: string;
  /** Primary identifier field (e.g. "src_ip") — used to construct the Investigate pivot */
  entityField: string;
  identity: AssetDossierIdentity;
  risk: EntityRiskSummary | null;
  /** Tags — empty until we have an asset inventory / tagging system */
  tags?: string[];
  /** Investigate pivot: called with a field→value filter to scope the search */
  onInvestigate?: (filters: Record<string, unknown>) => void;
}

export function AssetIdentityHeader({
  kind,
  entityValue,
  entityField,
  identity,
  risk,
  tags = [],
  onInvestigate,
}: AssetIdentityHeaderProps) {
  const [scoreOpen, setScoreOpen] = useState(false);
  // Risk service can emit scores > 100 (uncapped sum of contributing factors);
  // the display surface is 0-100 so we clamp here.
  const displayScore = Math.min(100, Math.max(0, Math.round(risk?.risk_score ?? 0)));
  const band = riskBandForScore(displayScore);
  const tone = riskTone(band);

  const displayName = kind === 'host' ? identity.hostname ?? entityValue : entityValue;
  const fqdn = kind === 'host' ? identity.hostname ?? entityValue : null;
  const subLine =
    kind === 'host'
      ? [fqdn, identity.ip, identity.vendor_product].filter(Boolean).join(' · ')
      : [identity.user, identity.domain].filter(Boolean).join(' · ');

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="p-5 flex items-start gap-5">
        <EntityIcon kind={kind} />

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-[22px] font-semibold text-foreground tracking-tight whitespace-nowrap">
              {displayName}
            </h1>
            <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-foreground/5 text-muted-foreground/70">
              {kind}
            </span>
          </div>

          {subLine && (
            <div className="text-[12.5px] text-muted-foreground/70 mt-0.5 font-mono truncate">
              {subLine}
            </div>
          )}

          {/* Key facts — 4 columns × 2 rows */}
          <div className="grid grid-cols-4 gap-x-4 gap-y-2 mt-3 text-[12px]">
            {kind === 'host' ? (
              <>
                <FactCell k="IP" v={<span className="font-mono">{identity.ip ?? '—'}</span>} />
                <FactCell
                  k="MAC"
                  v={<span className="font-mono text-[11px]">{identity.mac ?? '—'}</span>}
                />
                <FactCell k="Domain" v={identity.domain ?? '—'} />
                <FactCell k="Vendor" v={identity.vendor_product ?? '—'} />
                <FactCell k="First seen" v={formatDate(identity.first_seen_in_range) || '—'} />
                <FactCell
                  k="Last seen"
                  v={
                    <span className="flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-[oklch(72%_0.16_160)] animate-pulse" />
                      {formatTimeRelative(identity.last_seen_in_range) || '—'}
                    </span>
                  }
                />
                <FactCell
                  k="Log sources"
                  v={
                    <span className="inline-flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-[oklch(72%_0.16_160)]" />
                      <span className="tabular-nums">
                        {identity.log_sources.length}/{identity.log_sources.length}
                      </span>
                      <span className="text-muted-foreground/70 text-[11px]">healthy</span>
                    </span>
                  }
                  sub={identity.log_sources
                    .slice(0, 3)
                    .map((s) => s.name)
                    .join(' · ')}
                />
                <FactCell k="User (last)" v={identity.user ?? '—'} />
              </>
            ) : (
              <>
                <FactCell k="UPN" v={<span className="font-mono text-[11px]">{entityValue}</span>} />
                <FactCell k="Hostname (last)" v={identity.hostname ?? '—'} />
                <FactCell k="IP (last)" v={<span className="font-mono">{identity.ip ?? '—'}</span>} />
                <FactCell k="Domain" v={identity.domain ?? '—'} />
                <FactCell k="First seen" v={formatDate(identity.first_seen_in_range) || '—'} />
                <FactCell
                  k="Last seen"
                  v={
                    <span className="flex items-center gap-1.5">
                      <span className="w-1.5 h-1.5 rounded-full bg-[oklch(72%_0.16_160)] animate-pulse" />
                      {formatTimeRelative(identity.last_seen_in_range) || '—'}
                    </span>
                  }
                />
                <FactCell
                  k="Log sources"
                  v={
                    <span className="tabular-nums">
                      {identity.log_sources.length} active
                    </span>
                  }
                  sub={identity.log_sources
                    .slice(0, 3)
                    .map((s) => s.name)
                    .join(' · ')}
                />
                <FactCell k="MAC" v={<span className="font-mono text-[11px]">{identity.mac ?? '—'}</span>} />
              </>
            )}
          </div>

          {tags.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-3">
              {tags.map((t) => (
                <span
                  key={t}
                  className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-foreground/5 text-muted-foreground/70 hover:text-foreground cursor-default"
                >
                  {t}
                </span>
              ))}
            </div>
          )}
        </div>

        <div className="flex flex-col items-end gap-3 shrink-0 w-[260px]">
          {risk ? (
            <button
              onClick={() => setScoreOpen((o) => !o)}
              className={cn(
                'w-full rounded-lg border px-3 py-2.5 flex items-center gap-3 text-left transition-colors hover:bg-opacity-80',
                tone.border,
                tone.bg
              )}
            >
              <RiskGauge score={displayScore} band={band} />
              <div className="flex-1 min-w-0">
                <div
                  className={cn(
                    'text-[10px] font-mono uppercase tracking-[0.12em]',
                    tone.label
                  )}
                >
                  Risk · {band}
                </div>
                <div className="flex items-baseline gap-1.5 mt-0.5">
                  <span className={cn('text-[20px] font-semibold tabular-nums', tone.text)}>
                    {displayScore}
                  </span>
                  <span className="text-[10px] text-muted-foreground/70">/ 100</span>
                </div>
              </div>
              <ChevronDown
                className={cn(
                  'w-3 h-3 transition-transform text-muted-foreground/70',
                  scoreOpen && 'rotate-180'
                )}
              />
            </button>
          ) : (
            <div className="w-full rounded-lg border border-border bg-foreground/3 px-3 py-2.5 flex items-center gap-3">
              <RiskGauge score={0} band="none" />
              <div className="flex-1 min-w-0">
                <div className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70">
                  Risk
                </div>
                <div className="text-[14px] text-muted-foreground/70 mt-0.5">No findings</div>
              </div>
            </div>
          )}

          <div className="flex items-center gap-1 w-full">
            <HeaderAction
              icon={<Search className="w-[12px] h-[12px]" />}
              label="Investigate"
              primary
              title={`Pivot to raw events for ${entityField}=${entityValue}`}
              className="flex-1"
              onClick={
                onInvestigate
                  ? () => onInvestigate({ [entityField]: entityValue })
                  : undefined
              }
              disabled={!onInvestigate}
            />
            <HeaderAction
              icon={<Filter className="w-[12px] h-[12px]" />}
              label=""
              title="Scoped filters — not yet wired"
              disabled
            />
            <HeaderAction
              icon={<Bookmark className="w-[12px] h-[12px]" />}
              label=""
              title="Watchlist — not yet wired"
              disabled
            />
            <HeaderAction
              icon={<Share2 className="w-[12px] h-[12px]" />}
              label=""
              title="Copy link"
              onClick={() => {
                void navigator.clipboard?.writeText(window.location.href);
              }}
            />
          </div>
        </div>
      </div>

      {scoreOpen && risk && (
        <div className="border-t border-border bg-muted/30 px-5 py-3 space-y-1.5">
          <div className="text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70">
            Risk summary
          </div>
          <div className="text-[11.5px] text-foreground flex items-baseline gap-3 flex-wrap">
            <span>
              <span className="text-muted-foreground/70">findings:</span>{' '}
              <span className="tabular-nums">{risk.finding_count}</span>
            </span>
            {risk.last_rule_name && (
              <span>
                <span className="text-muted-foreground/70">last rule:</span>{' '}
                <span className="font-mono">{risk.last_rule_name}</span>
              </span>
            )}
            {risk.last_severity && (
              <span>
                <span className="text-muted-foreground/70">last sev:</span>{' '}
                <span className="font-mono">{risk.last_severity}</span>
              </span>
            )}
            {risk.last_finding_at && (
              <span>
                <span className="text-muted-foreground/70">last finding:</span>{' '}
                <span className="font-mono tabular-nums">
                  {formatTimeRelative(risk.last_finding_at)}
                </span>
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function EntityIcon({ kind }: { kind: 'host' | 'user' }) {
  return (
    <div className="w-[72px] h-[72px] rounded-xl border border-border bg-muted/40 flex items-center justify-center shrink-0">
      {kind === 'host' ? (
        <svg
          viewBox="0 0 24 24"
          className="w-9 h-9 text-primary"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.4"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <rect x="3" y="4" width="18" height="12" rx="1.5" />
          <path d="M8 20h8M12 16v4" />
          <path d="M7 8h3M7 11h2" strokeWidth="1" opacity="0.5" />
        </svg>
      ) : (
        <svg
          viewBox="0 0 24 24"
          className="w-9 h-9 text-primary"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.4"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <circle cx="12" cy="9" r="4" />
          <path d="M4 20c0-4 4-6 8-6s8 2 8 6" />
        </svg>
      )}
    </div>
  );
}

interface HeaderActionProps {
  icon: React.ReactNode;
  label: string;
  primary?: boolean;
  title?: string;
  className?: string;
  onClick?: () => void;
  disabled?: boolean;
}

function HeaderAction({ icon, label, primary, title, className, onClick, disabled }: HeaderActionProps) {
  return (
    <button
      title={title}
      onClick={onClick}
      disabled={disabled}
      className={cn(
        'inline-flex items-center justify-center gap-1.5 h-7 rounded-md text-[11px] font-mono font-semibold transition-colors',
        label ? 'px-2.5' : 'w-7',
        primary
          ? 'border border-primary/40 text-primary hover:bg-primary/10'
          : 'border border-border text-muted-foreground hover:text-foreground hover:bg-foreground/5',
        disabled && 'opacity-40 cursor-not-allowed hover:bg-transparent hover:text-muted-foreground',
        className
      )}
    >
      {icon}
      {label}
    </button>
  );
}
