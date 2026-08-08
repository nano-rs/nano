// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Create API Key dialog. Streamlined port of `design-ref/shadcn/settings-keys.jsx`
 * `CreateKeyDialog` to the real backend (`api.createApiKey` returns secret once).
 *
 * Reveal-once secret is surfaced by the parent (`ApiKeysView` renders the
 * `RevealOnceCard` over the list once the dialog dismisses) to keep this
 * dialog single-purpose.
 *
 * Scope selection is delegated to the shared `ScopeSelector` so create + edit
 * stay in lockstep.
 */

import { useEffect, useState } from 'react';
import { KeyRound, Loader2 } from 'lucide-react';
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
import { ScopeSelector } from './ScopeSelector';

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

export function CreateApiKeyDialog({ open, permissions, onClose, onCreated }: CreateApiKeyDialogProps) {
  const { toast } = useToast();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [scopes, setScopes] = useState<string[]>([]);
  const [expiresId, setExpiresId] = useState<string>('90');
  const [rateLimit, setRateLimit] = useState<string>('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    setName('');
    setDescription('');
    setExpiresId('90');
    setRateLimit('');
  }, [open]);

  const nameValid = name.trim().length >= 2;
  const scopeValid = scopes.length > 0;
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
        permissions: scopes,
        expires_at,
        rate_limit: rl && !Number.isNaN(rl) && rl > 0 ? rl : undefined,
      });
      toast({ title: 'Key created', description: `${name.trim()} · ${scopes.length} scope(s)` });
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
            <ScopeSelector
              key={open ? 'open' : 'closed'}
              permissions={permissions}
              initialScopes={[]}
              defaultPresetId="readonly"
              onChange={setScopes}
            />
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
            {saving && <Loader2 className="w-3 h-3 animate-spin" />}
            Create key
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
