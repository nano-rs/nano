// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Reusable scope (permission) picker for API key create + edit dialogs.
 *
 * Presets are derived from the live permission catalogue at runtime so they
 * stay in sync with the backend. Semi-controlled: it owns the preset/custom
 * UI state (seeded from `initialScopes`) and reports the resolved scope list
 * up via `onChange` whenever the selection changes.
 *
 * The preset definitions themselves live in `./scope-presets` so they can be
 * tested against the real permission catalogue without a DOM (NAN-2226).
 */

import { useEffect, useMemo, useState } from 'react';
import { Search as SearchIcon, Check } from 'lucide-react';
import { cn } from '@/lib/utils';
import { type PermissionInfo } from '@/lib/api';
import { SCOPE_PRESETS, initialPresetId, presetScopeIds } from './scope-presets';
import { GRANT_ALL, UNGRANTABLE_HINT, canToggleGrant, grantableOnly, type CanGrant } from '@/lib/grantable-permissions';

interface ScopeSelectorProps {
  permissions: PermissionInfo[];
  /** Scopes to seed the picker with (e.g. an existing key's permissions). */
  initialScopes: string[];
  /** Preset to start on when `initialScopes` is empty (create starts read-only). */
  defaultPresetId?: string;
  onChange: (scopes: string[]) => void;
  /** NAN-5329: permissions the creator may grant; others are not tickable and presets skip them. */
  canGrant?: CanGrant;
}

interface ScopeGroup {
  key: string;
  label: string;
  /** Plain-English explainer shown under the header (the unknown group). */
  note?: string;
  items: PermissionInfo[];
}

/** Shown for scopes on a key that the permission list no longer has (NAN-5901). */
const UNKNOWN_SCOPE_NOTE =
  "This key has scopes that no longer exist in nano. They do nothing, and you can't save the key until you clear them.";

/** The resource part of a scope id: `rule_repositories:edit` -> `rule_repositories`. */
function scopePrefix(id: string): string {
  const i = id.indexOf(':');
  return i === -1 ? id : id.slice(0, i);
}

export function ScopeSelector({ permissions, initialScopes, defaultPresetId = 'custom', onChange, canGrant = GRANT_ALL }: ScopeSelectorProps) {
  const [presetId, setPresetId] = useState<string>(() =>
    initialPresetId(permissions, initialScopes, defaultPresetId, canGrant),
  );
  const [customScopes, setCustomScopes] = useState<Set<string>>(() => new Set(initialScopes));
  const [scopeQuery, setScopeQuery] = useState('');

  const presetScopes = useMemo(() => {
    const out: Record<string, string[]> = {};
    for (const p of SCOPE_PRESETS) {
      out[p.id] = grantableOnly(presetScopeIds(permissions, p.id), canGrant);
    }
    return out;
  }, [permissions, canGrant]);

  const activeScopes = presetId === 'custom' ? [...customScopes] : presetScopes[presetId] || [];

  // Report the resolved selection upward whenever it changes (mount, preset
  // switch, custom toggle, or async permission-catalogue load).
  useEffect(() => {
    onChange(activeScopes);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [presetId, customScopes, permissions]);

  // NAN-5901: a key can hold scopes the live catalogue no longer has
  // (migrations retired e.g. `feeds:*`, `alerts:triage` but left them on
  // existing keys). They must show so they can be cleared: the server refuses
  // to save a key that still lists them. Only computed once the catalogue has
  // loaded, so a key opened mid-load is not shown as all-unknown.
  const knownIds = useMemo(() => new Set(permissions.map(p => p.id)), [permissions]);
  const unknownScopes = useMemo(() => {
    if (permissions.length === 0) return [];
    return [...new Set(initialScopes)].filter(id => !knownIds.has(id)).sort((x, y) => x.localeCompare(y));
  }, [initialScopes, knownIds, permissions.length]);

  // Unknown scopes can be cleared but never ticked again, even for a `*` admin.
  const grantFor: CanGrant = id => knownIds.has(id) && canGrant(id);

  const q = scopeQuery.trim().toLowerCase();
  const filterActive = q.length > 0;

  // Group by resource prefix (the part before ':') with a map, so each prefix
  // is exactly one group whatever the sort order. Every match renders; the
  // catalogue is a few hundred rows at most, so no windowing.
  const groups = useMemo(() => {
    const byPrefix = new Map<string, PermissionInfo[]>();
    for (const p of permissions) {
      if (q && !p.id.toLowerCase().includes(q) && !p.description.toLowerCase().includes(q)) continue;
      const prefix = scopePrefix(p.id);
      const items = byPrefix.get(prefix);
      if (items) items.push(p);
      else byPrefix.set(prefix, [p]);
    }
    const out: ScopeGroup[] = [...byPrefix.entries()]
      .sort(([x], [y]) => x.localeCompare(y))
      .map(([prefix, items]) => ({
        key: `p:${prefix}`,
        label: prefix,
        items: [...items].sort((x, y) => x.id.localeCompare(y.id)),
      }));
    const unknownShown = unknownScopes.filter(id => !q || id.toLowerCase().includes(q));
    if (unknownShown.length > 0) {
      out.push({
        key: 'unknown',
        label: 'Unknown or retired',
        note: UNKNOWN_SCOPE_NOTE,
        items: unknownShown.map(id => ({ id, name: id, category: '', description: 'No longer exists' })),
      });
    }
    return out;
  }, [permissions, unknownScopes, q]);

  const toggleScope = (id: string) => {
    if (!canToggleGrant(id, customScopes.has(id), grantFor)) return;
    const next = new Set(customScopes);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setCustomScopes(next);
    if (presetId !== 'custom') setPresetId('custom');
  };

  // Bulk actions work on what is shown: the whole list, or just the filter
  // matches. Select only adds what the creator can grant (NAN-5329) and never
  // an unknown scope; clearing is always allowed.
  const shownIds = groups.flatMap(g => g.items.map(p => p.id));
  const totalCount = permissions.length + unknownScopes.length;
  const addable = grantableOnly(shownIds, grantFor).filter(id => !customScopes.has(id));
  const clearable = shownIds.filter(id => customScopes.has(id));

  const selectAllShown = () => {
    if (addable.length === 0) return;
    const next = new Set(customScopes);
    for (const id of addable) next.add(id);
    setCustomScopes(next);
  };

  const clearShown = () => {
    if (clearable.length === 0) return;
    const next = new Set(customScopes);
    for (const id of clearable) next.delete(id);
    setCustomScopes(next);
  };

  return (
    <>
      {/* Three presets since NAN-2226 retired the unbuildable "Event ingest"
          one — three columns so the row stays full rather than leaving a hole. */}
      <div className="grid grid-cols-3 gap-2 mb-2">
        {SCOPE_PRESETS.map(p => (
          <button
            key={p.id}
            type="button"
            onClick={() => setPresetId(p.id)}
            className={cn(
              'text-left px-2.5 py-2 rounded-md border transition-colors',
              presetId === p.id
                ? 'border-primary/50 bg-primary/5'
                : 'border-border bg-card hover:border-foreground/20',
            )}
          >
            <div className={cn('text-[11.5px] font-medium', presetId === p.id ? 'text-primary' : 'text-foreground')}>
              {p.label}
            </div>
            <div className="text-[10.5px] text-muted-foreground leading-tight mt-0.5">
              {p.id === 'custom' ? p.desc : `${(presetScopes[p.id] || []).length} scopes · ${p.desc}`}
            </div>
          </button>
        ))}
      </div>

      {presetId === 'custom' && (
        <div className="rounded-md border border-border overflow-hidden">
          <div className="h-7 px-2.5 flex items-center gap-2 border-b border-border bg-card/50">
            <SearchIcon className="w-[11px] h-[11px] text-muted-foreground" />
            <input
              value={scopeQuery}
              onChange={e => setScopeQuery(e.target.value)}
              aria-label="Filter scopes"
              placeholder="Filter scopes…"
              className="flex-1 bg-transparent outline-none text-[11px] text-foreground placeholder:text-muted-foreground/70"
            />
          </div>
          <div className="h-6 px-2.5 flex items-center gap-2 border-b border-border text-[10.5px]">
            <span className="font-mono text-muted-foreground tabular-nums" data-testid="scope-count">
              {shownIds.length} of {totalCount} shown · {customScopes.size} selected
            </span>
            <span className="flex-1" />
            <button
              type="button"
              onClick={selectAllShown}
              disabled={addable.length === 0}
              className="text-primary hover:underline disabled:text-muted-foreground/50 disabled:no-underline disabled:cursor-not-allowed"
            >
              {filterActive ? 'Select matches I can grant' : 'Select all I can grant'}
            </button>
            <span className="text-border" aria-hidden="true">|</span>
            <button
              type="button"
              onClick={clearShown}
              disabled={clearable.length === 0}
              className="text-muted-foreground hover:text-foreground hover:underline disabled:text-muted-foreground/50 disabled:no-underline disabled:cursor-not-allowed"
            >
              {filterActive ? 'Clear matches' : 'Clear'}
            </button>
          </div>
          <div className="max-h-[320px] overflow-y-auto scroll-pt-5 scrollbar-thin">
            {groups.map(g => (
              <div key={g.key} role="group" aria-label={g.label}>
                <div className="sticky top-0 z-[1] h-5 px-2.5 flex items-center gap-2 border-b border-border/50 bg-card">
                  <span className={cn('text-[10px]', g.note ? 'text-yellow-500' : 'font-mono text-muted-foreground')}>{g.label}</span>
                  <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums">
                    {g.items.filter(p => customScopes.has(p.id)).length}/{g.items.length}
                  </span>
                </div>
                {g.note && (
                  <div className="px-2.5 py-1 border-b border-border/50 text-[10.5px] text-muted-foreground leading-snug">{g.note}</div>
                )}
                {g.items.map(p => {
                  const on = customScopes.has(p.id);
                  const blocked = !canToggleGrant(p.id, on, grantFor);
                  return (
                    <button
                      key={p.id}
                      type="button"
                      role="checkbox"
                      aria-checked={on}
                      aria-disabled={blocked || undefined}
                      disabled={blocked}
                      title={blocked ? (knownIds.has(p.id) ? UNGRANTABLE_HINT : UNKNOWN_SCOPE_NOTE) : undefined}
                      aria-label={`${p.id}: ${p.description}`}
                      onClick={() => toggleScope(p.id)}
                      className={cn(
                        'w-full flex items-center gap-2 px-2.5 h-7 border-b border-border/50 last:border-b-0 transition-colors text-left',
                        on ? 'bg-primary/8' : blocked ? 'opacity-45 cursor-not-allowed' : 'hover:bg-foreground/[0.025]',
                      )}
                    >
                      <div className={cn(
                        'w-3.5 h-3.5 rounded-sm border flex items-center justify-center shrink-0',
                        on ? 'border-primary bg-primary text-primary-foreground' : 'border-border bg-card',
                      )}>
                        {on && <Check className="w-[9px] h-[9px]" />}
                      </div>
                      <div className="min-w-0 flex-1 flex items-baseline gap-2">
                        <span className="font-mono text-[11px] text-foreground shrink-0 max-w-[60%] truncate">{p.id}</span>
                        <span className="text-[10.5px] text-muted-foreground truncate">{p.description}</span>
                      </div>
                    </button>
                  );
                })}
              </div>
            ))}
            {shownIds.length === 0 && (
              <div className="px-3 py-4 text-center text-[11px] text-muted-foreground">No scopes match.</div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
