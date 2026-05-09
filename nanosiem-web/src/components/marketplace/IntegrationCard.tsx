// SPDX-License-Identifier: AGPL-3.0-or-later

import { AlertTriangle, Download, RefreshCw, Settings } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { MarketplaceCatalogEntry } from '@/lib/api/marketplace';
import { MonoSwatch, getCategoryTone } from './MonoSwatch';

export type IntegrationState =
  | 'not'         // not installed
  | 'update'      // installed, manifest_version > installed_version
  | 'notconfig'   // installed, requires creds, missing
  | 'installed'   // installed but disabled
  | 'configured'; // installed, enabled, has creds (running)

export function getIntegrationState(entry: MarketplaceCatalogEntry): IntegrationState {
  if (!entry.installed) return 'not';
  if (entry.manifest_version > (entry.installed_version ?? 0)) return 'update';
  if (entry.requires_credential === 'required' && !entry.has_credentials) return 'notconfig';
  if (!entry.enabled) return 'installed';
  return 'configured';
}

const CATEGORY_LABEL: Record<string, string> = {
  data: 'Data',
  agent: 'Agent',
  identity: 'Identity',
  security: 'Security',
};

interface StateBadgeProps {
  state: IntegrationState;
}

export function StateBadge({ state }: StateBadgeProps) {
  const map = {
    installed:  { label: 'INSTALLED',     bg: 'bg-muted/40',     bd: 'border-border',           fg: 'text-muted-foreground' },
    configured: { label: 'ACTIVE',        bg: 'bg-emerald-500/10', bd: 'border-emerald-500/30', fg: 'text-emerald-500' },
    notconfig:  { label: 'NOT CONFIGURED',bg: 'bg-amber-500/10',   bd: 'border-amber-500/30',   fg: 'text-amber-500' },
    update:     { label: 'UPDATE',        bg: 'bg-primary/12',     bd: 'border-primary/40',     fg: 'text-primary' },
    not:        { label: 'NOT INSTALLED', bg: 'bg-muted/40',       bd: 'border-border',         fg: 'text-muted-foreground' },
  } as const;
  const m = map[state];
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 px-1.5 py-0.5 rounded font-mono text-[9.5px] uppercase tracking-[0.1em] border whitespace-nowrap',
        m.bg, m.bd, m.fg,
      )}
    >
      {state === 'configured' && (
        <span
          className="w-1 h-1 rounded-full bg-emerald-500"
          style={{ boxShadow: '0 0 4px currentColor' }}
        />
      )}
      {m.label}
    </span>
  );
}

interface IntegrationCardProps {
  entry: MarketplaceCatalogEntry;
  onOpen: (slug: string) => void;
  onInstall: (slug: string) => void;
}

export function IntegrationCard({ entry, onOpen, onInstall }: IntegrationCardProps) {
  const state = getIntegrationState(entry);
  const tone = getCategoryTone(entry.category);
  const monogram = (entry.name?.trim()?.[0] || '?').toUpperCase();
  const artifacts = entry.tags?.slice(0, 4) ?? [];

  return (
    <button
      type="button"
      onClick={() => onOpen(entry.slug)}
      className="bg-card border border-border/60 rounded-lg p-3.5 text-left hover:border-border hover:bg-muted/20 transition-colors group relative shadow-none"
      data-mp-card
      data-mp-slug={entry.slug}
    >
      <div className="flex items-start gap-3">
        <MonoSwatch ch={monogram} tone={tone} size={38} />
        <div className="flex-1 min-w-0">
          <div className="text-[13.5px] font-semibold text-foreground leading-tight truncate">{entry.name}</div>
          <div className="flex items-center gap-1.5 mt-1 text-[10.5px] font-mono text-muted-foreground uppercase tracking-[0.08em]">
            <span style={{ color: tone }}>{CATEGORY_LABEL[entry.category] || entry.category}</span>
          </div>
        </div>
        <StateBadge state={state} />
      </div>

      <p className="text-[11.5px] text-muted-foreground mt-3 line-clamp-2 leading-[1.5]" style={{ textWrap: 'pretty' }}>
        {entry.description || 'No description'}
      </p>

      {artifacts.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1">
          {artifacts.map(a => (
            <span key={a} className="text-[10px] font-mono text-muted-foreground px-1.5 py-0.5 rounded bg-muted/40 border border-border/60">
              {a}
            </span>
          ))}
        </div>
      )}

      <div className="mt-3.5 pt-3 border-t border-border/60 flex items-center justify-between min-h-[24px]">
        <FooterStatus state={state} entry={entry} />
        <FooterAction
          state={state}
          slug={entry.slug}
          onInstall={onInstall}
        />
      </div>
    </button>
  );
}

function FooterStatus({ state, entry }: { state: IntegrationState; entry: MarketplaceCatalogEntry }) {
  if (state === 'not') return <span className="text-[11px] text-muted-foreground font-mono">Not installed</span>;
  if (state === 'configured') {
    return (
      <span className="text-[11px] text-emerald-500 font-mono inline-flex items-center gap-1">
        <span
          className="w-1 h-1 rounded-full bg-emerald-500"
          style={{ boxShadow: '0 0 4px currentColor' }}
        />
        running
      </span>
    );
  }
  if (state === 'notconfig') {
    return (
      <span className="text-[11px] text-amber-500 font-mono inline-flex items-center gap-1">
        <AlertTriangle className="w-[10px] h-[10px]" /> needs config
      </span>
    );
  }
  if (state === 'update') {
    const fromV = entry.installed_version ?? 0;
    const toV = entry.manifest_version;
    return <span className="text-[11px] text-primary font-mono">{`v${fromV} → v${toV}`}</span>;
  }
  return <span className="text-[11px] text-muted-foreground font-mono">Disabled</span>;
}

function FooterAction({
  state,
  slug,
  onInstall,
}: {
  state: IntegrationState;
  slug: string;
  onInstall: (slug: string) => void;
}) {
  const stop = (e: React.MouseEvent) => e.stopPropagation();
  if (state === 'not') {
    return (
      <span
        role="button"
        tabIndex={0}
        onClick={(e) => { stop(e); onInstall(slug); }}
        className="h-6 px-2 rounded inline-flex items-center gap-1 text-[11px] text-muted-foreground hover:text-primary hover:bg-primary/10 font-mono cursor-pointer"
      >
        <Download className="w-[10px] h-[10px]" /> install
      </span>
    );
  }
  if (state === 'notconfig') {
    return (
      <span className="h-6 px-2 rounded inline-flex items-center gap-1 text-[11px] text-amber-500 font-mono">
        <Settings className="w-[10px] h-[10px]" /> configure
      </span>
    );
  }
  if (state === 'update') {
    return (
      <span className="h-6 px-2 rounded inline-flex items-center gap-1 text-[11px] text-primary font-mono">
        <RefreshCw className="w-[10px] h-[10px]" /> update
      </span>
    );
  }
  return (
    <span className="h-6 px-2 rounded inline-flex items-center text-[11px] text-muted-foreground group-hover:text-foreground font-mono">
      <Settings className="w-[10px] h-[10px]" />
    </span>
  );
}
