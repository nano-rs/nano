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
import { KeyRound, ShieldAlert } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import {
  api,
  type ApiKeyCreatedResponse,
  type PermissionInfo,
} from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
  SheetFooter,
} from '@/components/ui/sheet';
import { ScopeSelector } from './ScopeSelector';
import { useAuth } from '@/contexts/AuthContext';
import { Term } from '@/components/ui/term';
import { ADMIN_PRESET_ID, adminPresetMissing } from './admin-preset';

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

/** NAN-5900: an admin key must expire, so "Never" is not offered for it. */
const ADMIN_EXPIRES_OPTIONS = EXPIRES_OPTIONS.filter(o => o.days != null);

type AccessMode = 'scopes' | typeof ADMIN_PRESET_ID;

export function CreateApiKeyDialog({ open, permissions, onClose, onCreated }: CreateApiKeyDialogProps) {
  const { toast } = useToast();
  // NAN-5329: only permissions the creator holds are grantable.
  const { hasPermission } = useAuth();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [scopes, setScopes] = useState<string[]>([]);
  const [expiresId, setExpiresId] = useState<string>('90');
  const [rateLimit, setRateLimit] = useState<string>('');
  const [saving, setSaving] = useState(false);
  // NAN-5900: "scopes" = pick scopes (presets + custom); "admin" = every permission.
  const [mode, setMode] = useState<AccessMode>('scopes');
  const [adminConfirmed, setAdminConfirmed] = useState(false);

  useEffect(() => {
    if (!open) return;
    setName('');
    setDescription('');
    setExpiresId('90');
    setRateLimit('');
    setMode('scopes');
    setAdminConfirmed(false);
  }, [open]);

  const isAdmin = mode === ADMIN_PRESET_ID;
  // The server refuses the preset unless the creator holds every permission.
  const adminMissing = adminPresetMissing(permissions, hasPermission);
  const adminAllowed = permissions.length > 0 && adminMissing.length === 0;
  const expiresOptions = isAdmin ? ADMIN_EXPIRES_OPTIONS : EXPIRES_OPTIONS;

  const chooseMode = (next: AccessMode) => {
    if (next === ADMIN_PRESET_ID && !adminAllowed) return;
    setMode(next);
    setAdminConfirmed(false);
    if (next === ADMIN_PRESET_ID && expiresId === 'never') setExpiresId('90');
  };

  const nameValid = name.trim().length >= 2;
  const scopeValid = isAdmin ? adminAllowed && adminConfirmed : scopes.length > 0;
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
        // NAN-5900: the server resolves the admin preset; send no list with it.
        permissions: isAdmin ? [] : scopes,
        ...(isAdmin ? { preset: ADMIN_PRESET_ID } : {}),
        expires_at,
        rate_limit: rl && !Number.isNaN(rl) && rl > 0 ? rl : undefined,
      });
      toast({
        title: 'Key created',
        description: isAdmin
          ? `${name.trim()} · admin (all ${permissions.length} permissions)`
          : `${name.trim()} · ${scopes.length} scope(s)`,
      });
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
              The secret is shown once on the next screen.
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
            <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">Access</label>
            <div className="grid grid-cols-2 gap-2 mb-2" role="radiogroup" aria-label="Access">
              <button
                type="button"
                role="radio"
                aria-checked={!isAdmin}
                onClick={() => chooseMode('scopes')}
                className={cn(
                  'text-left px-2.5 py-2 rounded-md border transition-colors',
                  !isAdmin ? 'border-primary/50 bg-primary/5' : 'border-border bg-card hover:border-foreground/20',
                )}
              >
                <div className={cn('text-[11.5px] font-medium', !isAdmin ? 'text-primary' : 'text-foreground')}>Pick scopes</div>
                <div className="text-[10.5px] text-muted-foreground leading-tight mt-0.5">only what this key needs</div>
              </button>
              <button
                type="button"
                role="radio"
                aria-checked={isAdmin}
                aria-disabled={!adminAllowed || undefined}
                disabled={!adminAllowed}
                data-testid="admin-preset"
                title={adminAllowed ? undefined : "You can make an admin key only if you hold every permission yourself."}
                onClick={() => chooseMode(ADMIN_PRESET_ID)}
                className={cn(
                  'text-left px-2.5 py-2 rounded-md border transition-colors',
                  isAdmin ? 'border-yellow-500/60 bg-yellow-500/5' : 'border-border bg-card hover:border-foreground/20',
                  !adminAllowed && 'opacity-45 cursor-not-allowed hover:border-border',
                )}
              >
                <div className={cn('text-[11.5px] font-medium', isAdmin ? 'text-yellow-500' : 'text-foreground')}>Admin (all permissions)</div>
                <div className="text-[10.5px] text-muted-foreground leading-tight mt-0.5">
                  <span className="font-mono tabular-nums">{permissions.length}</span> scopes · full control
                </div>
              </button>
            </div>

            {!adminAllowed && permissions.length > 0 && (
              <div className="text-[10.5px] text-muted-foreground mb-2" data-testid="admin-preset-unavailable">
                Admin keys need you to hold every permission. You're missing{' '}
                <span className="font-mono tabular-nums">{adminMissing.length}</span>, so you can't make one.
              </div>
            )}

            {isAdmin ? (
              <div className="rounded-md border border-yellow-500/40 bg-yellow-500/5 px-3 py-2.5 text-[11px] leading-snug" data-testid="admin-preset-summary">
                <div className="flex items-center gap-1.5 font-medium text-yellow-500 mb-1">
                  <ShieldAlert className="w-[13px] h-[13px]" strokeWidth={1.5} />
                  This key can do anything an admin can.
                </div>
                <p className="text-foreground/80">
                  An admin key gets every permission in nano today (<span className="font-mono tabular-nums">{permissions.length}</span>).
                  It can search all data, change rules, alerts and cases, and manage users, roles and settings.
                  Anyone with the secret has that power, so give it an expiry and keep it somewhere safe.
                </p>
                <p className="text-muted-foreground mt-1.5">
                  It can't create, rotate or change other API keys. That still needs a person signed in.
                </p>
                <p className="text-muted-foreground mt-1.5">
                  New permissions added in later nano releases are not added to this key on their own. Edit the key to add them.
                </p>
                <label className="flex items-start gap-2 mt-2 cursor-pointer">
                  <Checkbox
                    checked={adminConfirmed}
                    onCheckedChange={checked => setAdminConfirmed(checked === true)}
                    className="mt-[2px] h-3.5 w-3.5 cursor-pointer"
                    data-testid="admin-preset-confirm"
                  />
                  <span className="text-foreground">I understand this key can do anything an admin can.</span>
                </label>
              </div>
            ) : (
              <>
                <label className="block text-[11px] font-medium text-foreground/80 mb-1.5"><Term id="api-key-scope" nested>Scopes</Term></label>
                <ScopeSelector
                  key={open ? 'open' : 'closed'}
                  permissions={permissions}
                  canGrant={hasPermission}
                  initialScopes={[]}
                  defaultPresetId="readonly"
                  onChange={setScopes}
                />
                {!scopeValid && (
                  <div className="text-[10.5px] text-yellow-500 mt-1.5">
                    Pick at least one scope. A key with no scopes can't call any API.
                  </div>
                )}
              </>
            )}
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">Expires</label>
              <div className="grid grid-cols-2 gap-1.5">
                {expiresOptions.map(o => (
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
                <Term id="rate-limit" nested>Rate limit</Term> <span className="text-muted-foreground/70 font-normal ml-1">(req/min, optional)</span>
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
            Treat the secret like a password: it grants whatever this key's scopes allow.
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} className="h-7 text-[11.5px]" disabled={saving}>
            Cancel
          </Button>
          <Button size="sm" onClick={handleSubmit} disabled={!canSubmit} className="h-7 text-[11.5px]">
            {saving && <LoadingIcon className="w-3 h-3" />}
            Create key
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
