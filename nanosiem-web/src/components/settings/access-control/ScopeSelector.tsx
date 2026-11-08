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
import { SCOPE_PRESETS, derivePreset, presetScopeIds } from './scope-presets';

interface ScopeSelectorProps {
  permissions: PermissionInfo[];
  /** Scopes to seed the picker with (e.g. an existing key's permissions). */
  initialScopes: string[];
  /** Preset to start on when `initialScopes` is empty (create starts read-only). */
  defaultPresetId?: string;
  onChange: (scopes: string[]) => void;
}

export function ScopeSelector({ permissions, initialScopes, defaultPresetId = 'custom', onChange }: ScopeSelectorProps) {
  const [presetId, setPresetId] = useState<string>(() =>
    initialScopes.length > 0 ? derivePreset(permissions, initialScopes) : defaultPresetId,
  );
  const [customScopes, setCustomScopes] = useState<Set<string>>(() => new Set(initialScopes));
  const [scopeQuery, setScopeQuery] = useState('');

  const presetScopes = useMemo(() => {
    const out: Record<string, string[]> = {};
    for (const p of SCOPE_PRESETS) {
      out[p.id] = presetScopeIds(permissions, p.id);
    }
    return out;
  }, [permissions]);

  const activeScopes = presetId === 'custom' ? [...customScopes] : presetScopes[presetId] || [];

  // Report the resolved selection upward whenever it changes (mount, preset
  // switch, custom toggle, or async permission-catalogue load).
  useEffect(() => {
    onChange(activeScopes);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [presetId, customScopes, permissions]);

  const filteredScopes = useMemo(() => {
    const q = scopeQuery.trim().toLowerCase();
    if (!q) return permissions;
    return permissions.filter(p =>
      p.id.toLowerCase().includes(q)
      || p.description.toLowerCase().includes(q),
    );
  }, [scopeQuery, permissions]);

  const toggleScope = (id: string) => {
    const next = new Set(customScopes);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setCustomScopes(next);
    if (presetId !== 'custom') setPresetId('custom');
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
              placeholder="Filter scopes…"
              className="flex-1 bg-transparent outline-none text-[11px] text-foreground placeholder:text-muted-foreground/70"
            />
            <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums">{customScopes.size}</span>
          </div>
          <div className="max-h-[200px] overflow-y-auto scrollbar-thin">
            {filteredScopes.slice(0, 100).map(p => {
              const on = customScopes.has(p.id);
              return (
                <button
                  key={p.id}
                  type="button"
                  role="checkbox"
                  aria-checked={on}
                  aria-label={`${p.id} — ${p.description}`}
                  onClick={() => toggleScope(p.id)}
                  className={cn(
                    'w-full flex items-center gap-2 px-2.5 h-8 border-b border-border/50 last:border-b-0 transition-colors text-left',
                    on ? 'bg-primary/8' : 'hover:bg-foreground/[0.025]',
                  )}
                >
                  <div className={cn(
                    'w-3.5 h-3.5 rounded-sm border flex items-center justify-center shrink-0',
                    on ? 'border-primary bg-primary text-primary-foreground' : 'border-border bg-card',
                  )}>
                    {on && <Check className="w-[9px] h-[9px]" />}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="font-mono text-[11px] text-foreground truncate">{p.id}</div>
                    <div className="text-[10.5px] text-muted-foreground truncate leading-tight">{p.description}</div>
                  </div>
                </button>
              );
            })}
            {filteredScopes.length === 0 && (
              <div className="px-3 py-4 text-center text-[11px] text-muted-foreground">No scopes match.</div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
