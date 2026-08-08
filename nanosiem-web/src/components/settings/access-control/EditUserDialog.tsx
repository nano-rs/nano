// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Edit User flyout. Replaces the legacy `pages/Settings/UserForm.tsx` route
 * (NAN-670) — Users now matches Groups / Roles / API Keys: edit happens in a
 * right-side `Sheet`, never a full-page navigation. Create flow remains
 * `InviteUserDialog`.
 *
 * SSO users: email + password are managed by the provider and rendered
 * disabled; group memberships still apply locally.
 */

import { useEffect, useMemo, useState } from 'react';
import { User as UserIcon, Loader2, Shield, RefreshCw, Copy, Check, AlertCircle } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { api, type UserDetail, type GroupDetail, type UpdateUserRequest } from '@/lib/api';
import { generateSecurePassword } from '@/lib/password';
import { Button } from '@/components/ui/button';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
  SheetFooter,
} from '@/components/ui/sheet';

interface EditUserDialogProps {
  open: boolean;
  user: UserDetail | null;
  groups: GroupDetail[];
  onClose: () => void;
  onUpdated: () => void | Promise<void>;
}

export function EditUserDialog({ open, user, groups, onClose, onUpdated }: EditUserDialogProps) {
  const { toast } = useToast();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [groupIds, setGroupIds] = useState<Set<string>>(new Set());
  const [saving, setSaving] = useState(false);
  const [pwCopied, setPwCopied] = useState(false);

  const ssoLocked = !!user?.oidc_provider;

  useEffect(() => {
    if (!open || !user) return;
    setName(user.name);
    setEmail(user.email);
    setPassword('');
    setGroupIds(new Set(user.groups.map(g => g.id)));
    setPwCopied(false);
  }, [open, user?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const sortedGroups = useMemo(() => {
    return [...groups].sort((a, b) => a.name.localeCompare(b.name));
  }, [groups]);

  const toggleGroup = (id: string) => {
    setGroupIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleGenerate = () => {
    setPassword(generateSecurePassword());
    setPwCopied(false);
  };

  const handleCopy = () => {
    if (!password) return;
    navigator.clipboard?.writeText(password);
    setPwCopied(true);
    setTimeout(() => setPwCopied(false), 1800);
  };

  const nameValid = name.trim().length >= 1;
  const emailValid = ssoLocked || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  const canSubmit = !!user && nameValid && emailValid && !saving;

  const handleSave = async () => {
    if (!canSubmit || !user) return;
    setSaving(true);
    try {
      const request: UpdateUserRequest = {
        name: name.trim() !== user.name ? name.trim() : undefined,
        email: !ssoLocked && email.trim() !== user.email ? email.trim() : undefined,
        password: !ssoLocked && password ? password : undefined,
        group_ids: [...groupIds],
      };
      await api.updateUser(user.id, request);
      toast({ title: 'User updated', description: `${name.trim()} has been updated.` });
      await onUpdated();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to update user',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Sheet open={open} onOpenChange={(v) => !v && !saving && onClose()}>
      <SheetContent side="right" className="w-[560px] sm:max-w-[560px] p-0 gap-0 flex flex-col">
        <SheetHeader className="px-5 py-3.5 border-b border-border flex flex-row items-center gap-3 space-y-0 pr-12">
          <div className="w-8 h-8 rounded-md bg-primary/12 text-primary flex items-center justify-center shrink-0">
            <UserIcon className="w-[14px] h-[14px]" />
          </div>
          <div className="flex-1 min-w-0">
            <SheetTitle className="text-[14px] font-semibold leading-none">
              {user ? `Edit ${user.name}` : 'Edit user'}
            </SheetTitle>
            <SheetDescription className="text-[11px] text-muted-foreground mt-1">
              {ssoLocked
                ? 'Profile fields are managed by SSO. Group memberships still apply locally.'
                : 'Update profile, password, and group memberships.'}
            </SheetDescription>
          </div>
        </SheetHeader>

        <div className="overflow-y-auto scrollbar-thin px-5 py-4 flex flex-col gap-4 flex-1 min-h-0">
          {ssoLocked && user?.oidc_provider && (
            <div className="rounded-md border border-violet-500/30 bg-violet-500/5 p-3 flex items-start gap-2.5">
              <Shield className="w-[13px] h-[13px] text-violet-400 shrink-0 mt-0.5" />
              <div className="text-[11.5px] text-foreground/80 leading-relaxed">
                Authenticated via <span className="font-mono">{user.oidc_provider}</span>. Email and password are read-only here.
              </div>
            </div>
          )}

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">Name</label>
              <input
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="Jane Doe"
                className="w-full h-8 px-2.5 rounded-md border border-border bg-card text-[12px] text-foreground placeholder:text-muted-foreground/70 outline-none focus:border-primary/60"
              />
            </div>
            <div>
              <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">Email</label>
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                disabled={ssoLocked}
                placeholder="jane@example.com"
                className="w-full h-8 px-2.5 rounded-md border border-border bg-card text-[12px] text-foreground placeholder:text-muted-foreground/70 outline-none focus:border-primary/60 disabled:opacity-60 disabled:cursor-not-allowed font-mono"
              />
            </div>
          </div>

          {!ssoLocked && (
            <div>
              <div className="flex items-center gap-2 mb-1.5">
                <label className="text-[11px] font-medium text-foreground/80">Password</label>
                {!password && (
                  <button
                    type="button"
                    onClick={handleGenerate}
                    className="ml-auto inline-flex items-center gap-1 text-[10.5px] text-primary hover:text-primary/90"
                  >
                    <RefreshCw className="w-[10px] h-[10px]" />
                    Reset password
                  </button>
                )}
              </div>

              {password ? (
                <div className="rounded-md border border-yellow-500/40 bg-yellow-500/5 p-3">
                  <div className="flex items-start gap-2">
                    <AlertCircle className="w-[12px] h-[12px] text-yellow-500 shrink-0 mt-0.5" />
                    <div className="flex-1 min-w-0">
                      <div className="text-[11.5px] text-foreground/80">
                        Copy this password now — it won't be shown again. Share it via your usual secure channel; the user will replace it on first sign-in.
                      </div>
                      <div className="mt-2 rounded-md border border-border bg-card p-2 flex items-center gap-2 font-mono text-[11.5px] text-foreground break-all">
                        <span className="flex-1">{password}</span>
                        <button
                          type="button"
                          onClick={handleCopy}
                          className="shrink-0 inline-flex items-center gap-1 text-[10.5px] text-primary hover:text-primary/90"
                        >
                          {pwCopied ? <Check className="w-[11px] h-[11px]" /> : <Copy className="w-[11px] h-[11px]" />}
                          {pwCopied ? 'Copied' : 'Copy'}
                        </button>
                      </div>
                      <div className="mt-2 flex items-center gap-3">
                        <button
                          type="button"
                          onClick={handleGenerate}
                          className="inline-flex items-center gap-1 text-[10.5px] text-muted-foreground hover:text-foreground"
                        >
                          <RefreshCw className="w-[10px] h-[10px]" />
                          Regenerate
                        </button>
                        <button
                          type="button"
                          onClick={() => { setPassword(''); setPwCopied(false); }}
                          className="text-[10.5px] text-muted-foreground hover:text-foreground"
                        >
                          Cancel reset
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <p className="text-[10.5px] text-muted-foreground/70">
                  Existing password unchanged. Reset to issue a new one.
                </p>
              )}
            </div>
          )}

          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <label className="text-[11px] font-medium text-foreground/80">Group memberships</label>
              <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums">
                {groupIds.size}/{sortedGroups.length}
              </span>
            </div>
            <div className="rounded-md border border-border overflow-hidden">
              <div className="max-h-[280px] overflow-y-auto scrollbar-thin">
                {sortedGroups.length === 0 ? (
                  <div className="px-3 py-4 text-center text-[11px] text-muted-foreground">
                    No groups yet — create one in the Groups tab.
                  </div>
                ) : (
                  sortedGroups.map(g => {
                    const on = groupIds.has(g.id);
                    return (
                      <button
                        key={g.id}
                        type="button"
                        role="checkbox"
                        aria-checked={on}
                        aria-label={g.name}
                        onClick={() => toggleGroup(g.id)}
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
                        <span className="text-[11.5px] text-foreground truncate">{g.name}</span>
                        {g.is_system && (
                          <span className="font-mono text-[9.5px] uppercase tracking-wider text-primary">system</span>
                        )}
                        {g.description && (
                          <span className="text-[10.5px] text-muted-foreground truncate ml-auto max-w-[220px]">
                            {g.description}
                          </span>
                        )}
                      </button>
                    );
                  })
                )}
              </div>
            </div>
          </div>
        </div>

        <SheetFooter className="border-t border-border px-5 py-3 flex flex-row items-center gap-2 sm:justify-end space-x-0">
          <div className="text-[10.5px] text-muted-foreground mr-auto">
            {ssoLocked ? 'SSO-managed user — only memberships are editable.' : 'Changes apply immediately on save.'}
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} className="h-7 text-[11.5px]" disabled={saving}>
            Cancel
          </Button>
          <Button size="sm" onClick={handleSave} disabled={!canSubmit} className="h-7 text-[11.5px]">
            {saving && <Loader2 className="w-3 h-3 animate-spin" />}
            Save changes
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
