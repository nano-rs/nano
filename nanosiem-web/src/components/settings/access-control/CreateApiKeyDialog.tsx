// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Create API Key dialog. Streamlined port of `design-ref/shadcn/settings-keys.jsx`
 * `CreateKeyDialog` to the real backend (`api.createApiKey` returns secret once).
 *
 * Reveal-once secret is surfaced by the parent (`ApiKeysView` renders the
 * `RevealOnceCard` over the list once the dialog dismisses) to keep this
 * dialog single-purpose.
 *
 * Scope picker offers presets + custom mode. Presets are derived from the
 * permission catalogue at runtime so they stay in sync with the backend.
 */

import { useEffect, useMemo, useState } from 'react';
import { KeyRound, Search as SearchIcon, Check, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import {
  api,
  type ApiKeyCreatedResponse,
  type PermissionInfo,
} from '@/lib/api';
import { Button } from '@/components/ui/button';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
  SheetFooter,
} from '@/components/ui/sheet';

interface CreateApiKeyDialogProps {
  open: boolean;
  permissions: PermissionInfo[];
  onClose: () => void;
  onCreated: (res: ApiKeyCreatedResponse) => void | Promise<void>;
}

const EXPIRES_OPTIONS = [
  { id: '30', label: '30 days', days: 30 },
  { id: '90', label: '90 days', days: 90 },
  { id: '365', label: '1 year', days: 365 },
  { id: 'never', label: 'Never', days: null },
] as const;

interface ScopePreset {
  id: string;
  label: string;
  desc: string;
  match: (p: PermissionInfo) => boolean;
}

const PRESETS: ScopePreset[] = [
  {
    id: 'readonly',
    label: 'Read-only',
    desc: 'view-only access across resources',
    match: p => p.id.endsWith(':view') || p.id.endsWith(':read'),
  },
  {
    id: 'detection-ci',
    label: 'Detection CI/CD',
    desc: 'rules + repos for git-driven authoring',
    match: p => p.id.startsWith('detections:') || p.id.startsWith('rules:') || p.id.startsWith('parsers:'),
  },
  {
    id: 'ingest',
    label: 'Event ingest',
    desc: 'event ingestion + read access for verification',
    match: p =>
      p.id === 'events:ingest'
      || p.id === 'search:read'
      || p.id === 'search:view'
      || p.id.startsWith('log_sources:'),
  },
  {
    id: 'custom',
    label: 'Custom',
    desc: 'pick scopes individually',
    match: () => false,
  },
];

export function CreateApiKeyDialog({ open, permissions, onClose, onCreated }: CreateApiKeyDialogProps) {
  const { toast } = useToast();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [presetId, setPresetId] = useState<string>('readonly');
  const [customScopes, setCustomScopes] = useState<Set<string>>(new Set());
  const [scopeQuery, setScopeQuery] = useState('');
  const [expiresId, setExpiresId] = useState<string>('90');
  const [rateLimit, setRateLimit] = useState<string>('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    setName('');
    setDescription('');
    setPresetId('readonly');
    setCustomScopes(new Set());
    setScopeQuery('');
    setExpiresId('90');
    setRateLimit('');
  }, [open]);

  const presetScopes = useMemo(() => {
    const out: Record<string, string[]> = {};
    for (const p of PRESETS) {
      out[p.id] = p.id === 'custom' ? [] : permissions.filter(perm => p.match(perm)).map(perm => perm.id);
    }
    return out;
  }, [permissions]);

  const activeScopes = presetId === 'custom' ? [...customScopes] : presetScopes[presetId] || [];

  const filteredScopes = useMemo(() => {
    const q = scopeQuery.trim().toLowerCase();
    if (!q) return permissions;
    return permissions.filter(p =>
      p.id.toLowerCase().includes(q)
      || p.description.toLowerCase().includes(q),
    );
  }, [scopeQuery, permissions]);

  const toggleScope = (id: string) => {
    setCustomScopes(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const nameValid = name.trim().length >= 2;
  const scopeValid = activeScopes.length > 0;
  const canSubmit = nameValid && scopeValid && !saving;

  const handleSubmit = async () => {
    if (!canSubmit) return;
    setSaving(true);
    try {
      const expiresOpt = EXPIRES_OPTIONS.find(o => o.id === expiresId);
      const expires_at = expiresOpt && expiresOpt.days != null
        ? new Date(Date.now() + expiresOpt.days * 86_400_000).toISOString()
        : undefined;
      const rl = rateLimit.trim() ? Number.parseInt(rateLimit, 10) : undefined;
      const res = await api.createApiKey({
        name: name.trim(),
        description: description.trim() || undefined,
        permissions: activeScopes,
        expires_at,
        rate_limit: rl && !Number.isNaN(rl) && rl > 0 ? rl : undefined,
      });
      toast({ title: 'Key created', description: `${name.trim()} · ${activeScopes.length} scope(s)` });
      await onCreated(res);
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to create key',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Sheet open={open} onOpenChange={(v) => !v && !saving && onClose()}>
      <SheetContent side="right" className="w-[600px] sm:max-w-[600px] p-0 gap-0 flex flex-col">
        <SheetHeader className="px-5 py-3.5 border-b border-border flex flex-row items-center gap-3 space-y-0 pr-12">
          <div className="w-8 h-8 rounded-md bg-primary/12 text-primary flex items-center justify-center shrink-0">
            <KeyRound className="w-[14px] h-[14px]" />
          </div>
          <div className="flex-1 min-w-0">
            <SheetTitle className="text-[14px] font-semibold leading-none">New API key</SheetTitle>
            <SheetDescription className="text-[11px] text-muted-foreground mt-1">
              You'll see the secret once on the next screen — copy it before dismissing.
            </SheetDescription>
          </div>
        </SheetHeader>

        <div className="overflow-y-auto scrollbar-thin px-5 py-4 flex flex-col gap-4 flex-1 min-h-0">
          <div>
            <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">Name</label>
            <input
              autoFocus
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="e.g. ci-deploy-robot"
              className="w-full h-8 px-2.5 rounded-md border border-border bg-card text-[12px] text-foreground placeholder:text-muted-foreground/70 outline-none focus:border-primary/60"
            />
          </div>

          <div>
            <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">
              Description <span className="text-muted-foreground/70 font-normal ml-1">(optional)</span>
            </label>
            <input
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder="What is this key for?"
              className="w-full h-8 px-2.5 rounded-md border border-border bg-card text-[12px] text-foreground placeholder:text-muted-foreground/70 outline-none focus:border-primary/60"
            />
          </div>

          <div>
            <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">Scopes</label>
            <div className="grid grid-cols-2 gap-2 mb-2">
              {PRESETS.map(p => (
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
            {!scopeValid && (
              <div className="text-[10.5px] text-yellow-500 mt-1.5">
                Pick at least one scope. A key with no scopes can't call any API.
              </div>
            )}
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">Expires</label>
              <div className="grid grid-cols-2 gap-1.5">
                {EXPIRES_OPTIONS.map(o => (
                  <button
                    key={o.id}
                    type="button"
                    onClick={() => setExpiresId(o.id)}
                    className={cn(
                      'h-7 px-2 rounded-md border text-[11px] transition-colors',
                      expiresId === o.id
                        ? 'border-primary/50 bg-primary/5 text-primary'
                        : 'border-border bg-card text-muted-foreground hover:text-foreground hover:border-foreground/20',
                    )}
                  >
                    {o.label}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">
                Rate limit <span className="text-muted-foreground/70 font-normal ml-1">(req/min, optional)</span>
              </label>
              <input
                type="number"
                value={rateLimit}
                onChange={e => setRateLimit(e.target.value)}
                placeholder="600"
                min={1}
                className="w-full h-8 px-2.5 rounded-md border border-border bg-card text-[12px] text-foreground placeholder:text-muted-foreground/70 outline-none focus:border-primary/60 font-mono"
              />
            </div>
          </div>
        </div>

        <SheetFooter className="border-t border-border px-5 py-3 flex flex-row items-center gap-2 sm:justify-end space-x-0">
          <div className="text-[10.5px] text-muted-foreground mr-auto">
            Treat the secret like a password — it grants whatever this key's scopes allow.
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} className="h-7 text-[11.5px]" disabled={saving}>
            Cancel
          </Button>
          <Button size="sm" onClick={handleSubmit} disabled={!canSubmit} className="h-7 text-[11.5px]">
            {saving && <Loader2 className="w-3 h-3 mr-1 animate-spin" />}
            Create key
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
