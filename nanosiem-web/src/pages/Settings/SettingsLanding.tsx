// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Settings landing page (`/settings`).
 *
 * Search-first overview that surfaces:
 *   1. Big global search across sections + descriptions (⌘K).
 *   2. Needs-attention strip (live signals: failing webhooks, expiring keys,
 *      dormant users, etc.).
 *   3. Grouped browse grid (Workspace / Detection & Search / Administration /
 *      Developer).
 *   4. Recent-changes preview (last 6 audit entries) — full drawer is on the
 *      Settings topbar.
 *
 * Mirrors `design-ref/shadcn/settings-landing.jsx`.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search as SearchIcon, ChevronRight, AlertCircle } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useAuth } from '@/contexts/AuthContext';
import { useCapabilities } from '@/hooks/use-capabilities';
import { useSystemConfig } from '@/hooks/use-api';
import { useAuditLog } from '@/hooks/use-api';
import {
  SETTINGS_GROUPS,
  SETTINGS_SECTIONS,
  GROUP_LABEL,
  type SettingsSection,
  type SectionStatus,
} from '@/components/layout/settings/sections';

const STATUS_DOT: Record<NonNullable<SectionStatus>, string> = {
  ok: '',
  attention: 'bg-primary',
  warn: 'bg-yellow-500',
  danger: 'bg-red-500',
};

interface SearchResult {
  id: string;
  label: string;
  desc: string;
  group: string;
  href: string;
}

function LandingSearch({ visibleSections }: { visibleSections: SettingsSection[] }) {
  const navigate = useNavigate();
  const [q, setQ] = useState('');
  const [activeIdx, setActiveIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const results = useMemo<SearchResult[]>(() => {
    const query = q.trim().toLowerCase();
    if (!query) return [];
    const out: SearchResult[] = [];
    for (const s of visibleSections) {
      const selfMatch = s.label.toLowerCase().includes(query) || s.desc.toLowerCase().includes(query);
      if (selfMatch) {
        out.push({ id: s.id, label: s.label, desc: s.desc, group: s.group, href: s.href });
      }
      for (const c of s.children || []) {
        if (c.label.toLowerCase().includes(query)) {
          out.push({
            id: c.id,
            label: `${s.label} / ${c.label}`,
            desc: s.desc,
            group: s.group,
            href: c.href,
          });
        }
      }
    }
    return out.slice(0, 8);
  }, [q, visibleSections]);

  useEffect(() => { setActiveIdx(0); }, [q]);

  const handleKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (!results.length) return;
    if (e.key === 'ArrowDown') { e.preventDefault(); setActiveIdx(i => (i + 1) % results.length); }
    if (e.key === 'ArrowUp') { e.preventDefault(); setActiveIdx(i => (i - 1 + results.length) % results.length); }
    if (e.key === 'Enter') { e.preventDefault(); navigate(results[activeIdx].href); }
  };

  return (
    <div className="relative max-w-[680px] mx-auto w-full">
      <div className={cn(
        'rounded-xl border border-border bg-card overflow-hidden',
        results.length > 0 && 'rounded-b-none',
      )}>
        <div className="flex items-center gap-2.5 px-3.5 py-3">
          <SearchIcon className="w-[16px] h-[16px] text-muted-foreground" />
          <input
            ref={inputRef}
            value={q}
            onChange={e => setQ(e.target.value)}
            onKeyDown={handleKey}
            placeholder="Search all settings — e.g. session timeout, SSO, storage retention…"
            className="flex-1 bg-transparent outline-none text-[14px] text-foreground placeholder:text-muted-foreground"
          />
          <span className="font-mono text-[10.5px] text-muted-foreground/70 tracking-wide">⌘K</span>
        </div>
      </div>
      {results.length > 0 && (
        <div className="absolute left-0 right-0 top-full border border-t-0 border-border bg-card rounded-b-xl overflow-hidden shadow-[0_8px_30px_rgba(0,0,0,0.3)] z-30">
          {results.map((r, i) => {
            const active = i === activeIdx;
            return (
              <button
                key={r.id}
                onClick={() => navigate(r.href)}
                onMouseEnter={() => setActiveIdx(i)}
                className={cn(
                  'w-full flex items-center gap-2.5 px-3.5 py-2 text-left transition-colors',
                  active ? 'bg-foreground/[0.04]' : 'hover:bg-foreground/[0.04]',
                )}
              >
                <span className="text-[12.5px] text-foreground">{r.label}</span>
                <span className="text-[10.5px] text-muted-foreground/70 ml-auto uppercase tracking-wider">
                  {GROUP_LABEL[r.group as keyof typeof GROUP_LABEL]}
                </span>
                {active && <ChevronRight className="w-[11px] h-[11px] text-muted-foreground" />}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

interface AttentionItem {
  id: string;
  title: string;
  sub: string;
  href: string;
  severity: 'attention' | 'warn' | 'danger';
}

function useAttentionItems(visibleSections: SettingsSection[]): AttentionItem[] {
  // Until each section ships its own counter API, derive a synthetic but
  // correctly-permissioned punch list from sections that have non-ok status
  // metadata or a known sub-message. Real signals (e.g. failing webhooks) will
  // replace these as section ports land.
  return useMemo(() => {
    const items: AttentionItem[] = [];
    for (const s of visibleSections) {
      if (s.status && s.status !== 'ok' && s.attentionMsg) {
        items.push({
          id: s.id,
          title: `${s.label} needs attention`,
          sub: s.attentionMsg,
          href: s.href,
          severity: s.status === 'danger' ? 'danger' : s.status === 'warn' ? 'warn' : 'attention',
        });
      }
    }
    return items;
  }, [visibleSections]);
}

function AttentionStrip({ items }: { items: AttentionItem[] }) {
  const navigate = useNavigate();
  if (items.length === 0) return null;
  const sevToneCls = (s: AttentionItem['severity']) => {
    if (s === 'danger') return { color: 'text-red-500', dot: 'bg-red-500', label: 'Failing' };
    if (s === 'warn') return { color: 'text-yellow-500', dot: 'bg-yellow-500', label: 'Warning' };
    return { color: 'text-primary', dot: 'bg-primary', label: 'Attention' };
  };
  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <span className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium">Needs attention</span>
        <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums">{items.length}</span>
        <div className="flex-1 h-px bg-border/60 mx-1" />
        <span className="text-[10.5px] text-muted-foreground/70">surfaces from settings, audit, and health</span>
      </div>
      <div className="grid grid-cols-3 gap-2">
        {items.map(a => {
          const sev = sevToneCls(a.severity);
          return (
            <button
              key={a.id}
              onClick={() => navigate(a.href)}
              className="group text-left rounded-lg border border-border/60 bg-card px-3 py-2.5 hover:border-foreground/20 transition-colors"
            >
              <div className="flex items-center gap-1.5">
                <span className={cn('w-1.5 h-1.5 rounded-full', sev.dot)} />
                <span className={cn('text-[10px] uppercase tracking-[0.08em] font-medium', sev.color)}>{sev.label}</span>
                <ChevronRight className="w-[11px] h-[11px] text-muted-foreground/70 ml-auto group-hover:text-muted-foreground" />
              </div>
              <div className="text-[12.5px] text-foreground mt-1.5 leading-snug">{a.title}</div>
              <div className="text-[10.5px] text-muted-foreground mt-0.5 leading-snug">{a.sub}</div>
            </button>
          );
        })}
      </div>
    </div>
  );
}

function SettingsGrid({ visibleSections }: { visibleSections: SettingsSection[] }) {
  const navigate = useNavigate();
  return (
    <div className="flex flex-col gap-5">
      {SETTINGS_GROUPS.map(g => {
        const items = visibleSections.filter(s => s.group === g.id);
        if (items.length === 0) return null;
        return (
          <div key={g.id}>
            <div className="flex items-baseline gap-2 mb-2">
              <span className="text-[11px] uppercase tracking-[0.12em] text-foreground/80 font-medium">{g.label}</span>
              <span className="text-[11px] text-muted-foreground">— {g.desc}</span>
            </div>
            <div className="grid grid-cols-3 gap-2">
              {items.map(s => {
                const Icon = s.icon;
                const dotCls = s.status && s.status !== 'ok' ? STATUS_DOT[s.status] : '';
                return (
                  <button
                    key={s.id}
                    onClick={() => navigate(s.href)}
                    className="group text-left rounded-lg border border-border/60 bg-card hover:border-foreground/20 transition-colors px-3 py-2.5"
                  >
                    <div className="flex items-center gap-2">
                      <Icon className="w-[14px] h-[14px] text-muted-foreground group-hover:text-foreground/80" />
                      <span className="text-[12.5px] text-foreground font-medium">{s.label}</span>
                      {dotCls && <span className={cn('w-1.5 h-1.5 rounded-full ml-auto', dotCls)} />}
                      {s.comingSoon && (
                        <span className="ml-auto text-[9px] uppercase tracking-wider text-muted-foreground/70 font-mono">soon</span>
                      )}
                    </div>
                    <div className="text-[10.5px] text-muted-foreground mt-1 leading-snug">{s.desc}</div>
                    {s.attentionMsg && (
                      <div className="text-[10.5px] text-yellow-500 mt-1">{s.attentionMsg}</div>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
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

function RecentChangesPreview() {
  const navigate = useNavigate();
  const query = useMemo(() => ({ limit: 6 }), []);
  const { data, loading } = useAuditLog(query);
  const entries = data?.logs ?? [];

  return (
    <div>
      <div className="flex items-center gap-2 mb-2">
        <span className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium">Recent changes</span>
        <div className="flex-1 h-px bg-border/60 mx-1" />
        <span className="text-[10.5px] text-muted-foreground/70">last 6</span>
      </div>
      <div className="rounded-lg border border-border/60 bg-card divide-y divide-border/60 overflow-hidden">
        {loading && entries.length === 0 && (
          <div className="px-3 py-6 text-center text-[11px] text-muted-foreground">Loading…</div>
        )}
        {!loading && entries.length === 0 && (
          <div className="px-3 py-6 text-center text-[11px] text-muted-foreground">No recent changes.</div>
        )}
        {entries.map(ev => {
          const tone: 'good' | 'warn' | 'danger' | 'neutral' = !ev.success
            ? 'danger'
            : (ev.action || '').toLowerCase().includes('delete') || (ev.action || '').toLowerCase().includes('revoke')
            ? 'warn'
            : (ev.action || '').toLowerCase().includes('create') || (ev.action || '').toLowerCase().includes('add')
            ? 'good'
            : 'neutral';
          return (
            <button
              key={ev.id}
              onClick={() => navigate('/settings/audit')}
              className="w-full text-left flex items-center gap-2 px-3 py-2 hover:bg-foreground/[0.03] transition-colors"
            >
              <span className={cn(
                'w-1 h-1 rounded-full shrink-0',
                tone === 'good' && 'bg-emerald-500',
                tone === 'warn' && 'bg-yellow-500',
                tone === 'danger' && 'bg-red-500',
                tone === 'neutral' && 'bg-muted-foreground',
              )} />
              <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums w-[34px] shrink-0">{relativeAge(ev.timestamp)}</span>
              <span className="font-mono text-[10.5px] text-foreground/80 shrink-0 truncate max-w-[80px]">
                {ev.user_name || 'system'}
              </span>
              <span className="text-[10.5px] text-muted-foreground min-w-0 truncate">{ev.action}</span>
              <span className="text-[10.5px] text-foreground/90 flex-1 min-w-0 truncate">{ev.message || ev.resource_name}</span>
              {ev.resource_type && (
                <span className="text-[10px] text-muted-foreground/70 ml-auto shrink-0 uppercase tracking-wider">
                  {ev.resource_type.replace(/_/g, ' ')}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}

export function SettingsLanding() {
  useDocumentTitle('Settings');
  const { hasPermission, hasAnyPermission, isDemoUser } = useAuth();
  const { capabilities } = useCapabilities();
  const { data: systemConfig } = useSystemConfig();
  const isAirGap = systemConfig?.air_gap === true;

  const visibleSections = useMemo(() => {
    return SETTINGS_SECTIONS
      .map(s => {
        if (s.capability && !capabilities[s.capability]) return null;
        if (s.demoHidden && isDemoUser) return null;
        if (s.airgapOnly && !isAirGap) return null;
        const ok = !s.permissions
          || (Array.isArray(s.permissions) ? hasAnyPermission(s.permissions) : hasPermission(s.permissions));
        if (!ok) return null;
        return s;
      })
      .filter((s): s is SettingsSection => s !== null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasPermission, hasAnyPermission, isDemoUser, capabilities, isAirGap]);

  const attention = useAttentionItems(visibleSections);

  return (
    <div className="h-full">
      <div className="max-w-[1040px] mx-auto px-8 py-10 flex flex-col gap-8">
        <div className="flex flex-col items-center gap-2 text-center pt-4">
          <div className="text-[22px] font-semibold tracking-tight text-foreground leading-none">Settings</div>
          <div className="text-[12.5px] text-muted-foreground">
            {visibleSections.length} sections. Search anything, or jump to what needs attention.
          </div>
        </div>

        <LandingSearch visibleSections={visibleSections} />

        {attention.length > 0 ? (
          <AttentionStrip items={attention} />
        ) : (
          <div className="rounded-lg border border-border/60 bg-card px-4 py-3 flex items-center gap-2.5 text-[12px] text-muted-foreground">
            <AlertCircle className="w-[14px] h-[14px] text-emerald-500" />
            <span>Nothing needs attention right now.</span>
          </div>
        )}

        <div className="grid grid-cols-[1fr_360px] gap-6">
          <SettingsGrid visibleSections={visibleSections} />
          <RecentChangesPreview />
        </div>

        <div className="h-4" />
      </div>
    </div>
  );
}

export default SettingsLanding;
