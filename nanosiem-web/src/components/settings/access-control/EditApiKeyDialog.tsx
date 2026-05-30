// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Edit API Key dialog — change an existing key's name, description, and scopes
 * in place (previously the only options were create / delete).
 *
 * `PUT /api/api-keys/{id}` is a tri-state partial update (NAN-1088): omitted
 * fields are left unchanged, so we simply don't send `expires_at`/`rate_limit`.
 * Expiry/rate-limit changes are intentionally out of scope here — rotate or
 * recreate for those. A clear of the description sends an explicit `null`.
 *
 * Scope selection is delegated to the shared `ScopeSelector`.
 */

import { useEffect, useState } from 'react';
import { KeyRound, Loader2 } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import {
  api,
  type ApiKeySummary,
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

interface EditApiKeyDialogProps {
  open: boolean;
  apiKey: ApiKeySummary;
  permissions: PermissionInfo[];
  onClose: () => void;
  onSaved: () => void | Promise<void>;
}

export function EditApiKeyDialog({ open, apiKey, permissions, onClose, onSaved }: EditApiKeyDialogProps) {
  const { toast } = useToast();
  const [name, setName] = useState(apiKey.name);
  const [description, setDescription] = useState(apiKey.description ?? '');
  const [scopes, setScopes] = useState<string[]>(apiKey.permissions);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    setName(apiKey.name);
    setDescription(apiKey.description ?? '');
  }, [open, apiKey]);

  const nameValid = name.trim().length >= 2;
  const scopeValid = scopes.length > 0;
  const canSubmit = nameValid && scopeValid && !saving;

  const handleSubmit = async () => {
    if (!canSubmit) return;
    setSaving(true);
    try {
      await api.updateApiKey(apiKey.id, {
        name: name.trim(),
        // Explicit null clears the description; omitting expiry/rate-limit
        // leaves them unchanged (partial update — NAN-1088).
        description: description.trim() || null,
        permissions: scopes,
      });
      toast({ title: 'Key updated', description: `${name.trim()} · ${scopes.length} scope(s)` });
      await onSaved();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to update key',
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
            <SheetTitle className="text-[14px] font-semibold leading-none">Edit API key</SheetTitle>
            <SheetDescription className="text-[11px] text-muted-foreground mt-1 font-mono truncate">
              {apiKey.key_prefix}…
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
              key={open ? apiKey.id : 'closed'}
              permissions={permissions}
              initialScopes={apiKey.permissions}
              onChange={setScopes}
            />
            {!scopeValid && (
              <div className="text-[10.5px] text-yellow-500 mt-1.5">
                Pick at least one scope. A key with no scopes can't call any API.
              </div>
            )}
          </div>

          <div className="text-[10.5px] text-muted-foreground/70">
            Scope changes take effect immediately. Expiry and rate limit are unchanged here — rotate or recreate the
            key to adjust those.
          </div>
        </div>

        <SheetFooter className="border-t border-border px-5 py-3 flex flex-row items-center gap-2 sm:justify-end space-x-0">
          <Button variant="ghost" size="sm" onClick={onClose} className="h-7 text-[11.5px]" disabled={saving}>
            Cancel
          </Button>
          <Button size="sm" onClick={handleSubmit} disabled={!canSubmit} className="h-7 text-[11.5px]">
            {saving && <Loader2 className="w-3 h-3 mr-1 animate-spin" />}
            Save changes
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
