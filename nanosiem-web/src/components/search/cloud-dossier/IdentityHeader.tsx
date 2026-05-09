// SPDX-License-Identifier: AGPL-3.0-or-later

import { Search as SearchIcon, User as UserIcon, Shield, AlertTriangle } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { CloudDossierIdentity, CloudDossierRisk } from '@/lib/api/types';
import {
  CloudFact,
  CloudRiskGauge,
  cloudSevTone,
} from '../cloud-overview/shared';

interface IdentityHeaderProps {
  identity: CloudDossierIdentity;
  risk: CloudDossierRisk;
  eventsTotal: number;
  onInvestigate?: () => void;
  /** Click the account id to scope the base search to that account */
  onPivotAccount?: (accountId: string) => void;
  /** Click a source IP to scope the base search to that IP */
  onPivotIp?: (ip: string) => void;
  /** Click an assumed role chip to pivot into that role's dossier */
  onPivotAssumedRole?: (role: string) => void;
}

export function IdentityHeader({
  identity,
  risk,
  eventsTotal,
  onInvestigate,
  onPivotAccount,
  onPivotIp,
  onPivotAssumedRole,
}: IdentityHeaderProps) {
  const tone = cloudSevTone(risk.band);
  const isRole = identity.principal_type === 'role';
  const assumedRolesLabel = identity.assumed_roles.length
    ? identity.assumed_roles.slice(0, 3).join(' · ')
    : '—';

  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="p-4">
        <div className="flex items-start gap-4">
          <div className="w-14 h-14 rounded-lg bg-gradient-to-br from-[oklch(72%_0.16_60/0.2)] to-[oklch(72%_0.16_60/0.05)] border border-[oklch(72%_0.16_60/0.35)] flex items-center justify-center shrink-0">
            {isRole ? (
              <Shield className="w-6 h-6 text-[oklch(78%_0.14_70)]" strokeWidth={1.5} />
            ) : (
              <UserIcon className="w-6 h-6 text-[oklch(78%_0.14_70)]" strokeWidth={1.5} />
            )}
          </div>

          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-[22px] font-semibold text-foreground tracking-tight">
                {identity.id}
              </h1>
              <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-foreground/5 text-muted-foreground/80">
                {identity.principal_type}
              </span>
              {identity.mfa === false && (
                <span className="inline-flex items-center gap-1 text-[10.5px] px-1.5 py-0.5 rounded bg-[oklch(62%_0.18_28/0.15)] text-[oklch(72%_0.17_28)] font-mono">
                  <AlertTriangle className="w-[10px] h-[10px]" strokeWidth={2} />
                  no mfa
                </span>
              )}
              {typeof identity.key_age_days === 'number' && identity.key_age_days > 90 && (
                <span className="inline-flex items-center gap-1 text-[10.5px] px-1.5 py-0.5 rounded bg-[oklch(70%_0.16_55/0.15)] text-[oklch(78%_0.14_60)] font-mono">
                  key · {identity.key_age_days}d old
                </span>
              )}
            </div>
            {identity.arn && (
              <div className="text-[12.5px] text-muted-foreground/80 mt-1 font-mono truncate">
                {identity.arn}
              </div>
            )}

            <div className="grid grid-cols-4 gap-x-4 gap-y-2 mt-3 text-[12px]">
              <CloudFact
                k="Account"
                v={
                  identity.account && onPivotAccount ? (
                    <button
                      onClick={() => onPivotAccount(identity.account!)}
                      className="font-mono hover:text-primary hover:underline text-left truncate"
                      title="Filter search by this account"
                    >
                      {identity.account}
                    </button>
                  ) : (
                    <span className="font-mono">{identity.account ?? '—'}</span>
                  )
                }
                sub={identity.account_name ?? undefined}
              />
              <CloudFact
                k="First seen"
                v={<span className="font-mono">{formatDate(identity.first_seen)}</span>}
                sub={identity.created_by ? `created by ${identity.created_by}` : undefined}
              />
              <CloudFact
                k="Last activity"
                v={
                  <span className="flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-[oklch(72%_0.16_160)] animate-pulse" />
                    {formatTs(identity.last_seen)}
                  </span>
                }
                sub={`${eventsTotal.toLocaleString()} events`}
              />
              <CloudFact
                k="Source IPs"
                v={
                  identity.ips.length > 0 && onPivotIp ? (
                    <div className="flex flex-wrap items-center gap-1">
                      {identity.ips.slice(0, 3).map((ip) => (
                        <button
                          key={ip.ip}
                          onClick={() => onPivotIp(ip.ip)}
                          className="font-mono text-[11.5px] hover:text-primary hover:underline tabular-nums"
                          title={`Filter by src_ip=${ip.ip}`}
                        >
                          {ip.ip}
                        </button>
                      ))}
                      {identity.ips.length > 3 && (
                        <span className="text-muted-foreground/70 text-[10.5px]">
                          +{identity.ips.length - 3}
                        </span>
                      )}
                    </div>
                  ) : (
                    <span className="tabular-nums">
                      {identity.ips.length} {identity.ips.length === 0 && '—'}
                    </span>
                  )
                }
                sub={identity.ips[0]?.geo ?? undefined}
              />
              <CloudFact
                k="Assumed roles"
                v={
                  identity.assumed_roles.length > 0 && onPivotAssumedRole ? (
                    <div className="flex flex-wrap items-center gap-1">
                      {identity.assumed_roles.slice(0, 3).map((role) => (
                        <button
                          key={role}
                          onClick={() => onPivotAssumedRole(role)}
                          className="font-mono text-[11.5px] hover:text-primary hover:underline"
                          title={`Open dossier for ${role}`}
                        >
                          {role}
                        </button>
                      ))}
                    </div>
                  ) : (
                    <span className="font-mono">{assumedRolesLabel}</span>
                  )
                }
                sub={identity.assumed_roles.length > 0 ? 'sts:AssumeRole' : undefined}
              />
              <CloudFact
                k="User-agents"
                v={<span className="tabular-nums">{identity.user_agents.length}</span>}
                sub={identity.user_agents
                  .slice(0, 3)
                  .map((u) => u.kind)
                  .join(' · ')}
              />
              <CloudFact
                k="Groups"
                v={identity.groups.length ? identity.groups.join(', ') : '—'}
              />
              <CloudFact
                k="Console"
                v={
                  <span className={identity.console ? 'text-foreground' : 'text-muted-foreground/70'}>
                    {identity.console ? 'yes' : 'api-only'}
                  </span>
                }
              />
            </div>

            {identity.tags.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-3">
                {identity.tags.map((t) => (
                  <span
                    key={t}
                    className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-foreground/5 text-muted-foreground/80"
                  >
                    {t}
                  </span>
                ))}
              </div>
            )}
          </div>

          <div className="flex flex-col items-end gap-3 shrink-0 w-[260px]">
            <div
              className={cn(
                'w-full rounded-lg border px-3 py-2.5 flex items-center gap-3',
                tone.border,
                tone.bg
              )}
            >
              <CloudRiskGauge score={risk.score} band={risk.band} />
              <div className="flex-1 min-w-0">
                <div className={cn('text-[10px] font-mono uppercase tracking-[0.12em]', tone.text)}>
                  Risk · {risk.band}
                </div>
                <div className="flex items-baseline gap-1.5 mt-0.5">
                  <span className={cn('text-[20px] font-semibold tabular-nums', tone.text)}>
                    {risk.score}
                  </span>
                  <span className="text-[10px] text-muted-foreground/70">/ 100</span>
                </div>
              </div>
            </div>
            {onInvestigate && (
              <button
                onClick={onInvestigate}
                className="w-full inline-flex items-center justify-center gap-1.5 h-7 rounded-md border border-primary/40 text-primary text-[11px] font-mono font-semibold hover:bg-primary/10 px-2.5"
              >
                <SearchIcon className="w-[12px] h-[12px]" />
                Investigate
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function formatDate(s: string | null): string {
  if (!s) return '—';
  if (s.length >= 10) return s.slice(0, 10);
  return s;
}

function formatTs(s: string | null): string {
  if (!s) return '—';
  if (s.length >= 16) return s.slice(11, 16) + ' UTC';
  return s;
}
