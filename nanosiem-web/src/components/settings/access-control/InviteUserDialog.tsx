// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Invite User dialog. Mirrors `design-ref/shadcn/settings-invite.jsx` but
 * adapted to backend reality: there's no email-link invite flow yet, so we
 * create the user with an auto-generated temporary password and surface it
 * once for the admin to share out-of-band.
 *
 * When `/api/users/invite` ships, swap the password generation for a real
 * invite call and drop the reveal-once card.
 */

import { useEffect, useMemo, useState } from 'react';
import { User as UserIcon, Check, Loader2, Copy, AlertCircle, Users as UsersIcon } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { api, type GroupDetail } from '@/lib/api';
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

interface InviteUserDialogProps {
  open: boolean;
  groups: GroupDetail[];
  onClose: () => void;
  onCreated: () => void | Promise<void>;
}

interface SuccessState {
  email: string;
  password: string;
}

function nameFromEmail(email: string): string {
  const local = email.split('@')[0] || 'New User';
  return local
    .replace(/[._-]+/g, ' ')
    .split(' ')
    .filter(Boolean)
    .map(w => w[0].toUpperCase() + w.slice(1))
    .join(' ');
}

export function InviteUserDialog({ open, groups, onClose, onCreated }: InviteUserDialogProps) {
  const { toast } = useToast();
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [groupIds, setGroupIds] = useState<Set<string>>(new Set());
  const [message, setMessage] = useState('');
  const [success, setSuccess] = useState<SuccessState | null>(null);
  const [saving, setSaving] = useState(false);
  const [pwCopied, setPwCopied] = useState(false);

  // Default groups: "Everyone" if it exists, else nothing.
  useEffect(() => {
    if (!open) return;
    setEmail('');
    setName('');
    setMessage('');
    setSuccess(null);
    const everyone = groups.find(g => g.name.toLowerCase() === 'everyone');
    setGroupIds(everyone ? new Set([everyone.id]) : new Set());
  }, [open, groups]);

  // Auto-derive name from email until the user types one explicitly.
  const [userTypedName, setUserTypedName] = useState(false);
  useEffect(() => {
    if (!userTypedName && email) {
      setName(nameFromEmail(email));
    }
  }, [email, userTypedName]);

  const toggleGroup = (id: string) => {
    setGroupIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const emailValid = useMemo(() => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email), [email]);
  const nameValid = name.trim().length >= 1;
  const canSend = emailValid && nameValid && !saving;

  const handleSend = async () => {
    if (!canSend) return;
    setSaving(true);
    try {
      const password = generateSecurePassword();
      await api.createUser({
        email: email.trim(),
        name: name.trim(),
        password,
        group_ids: [...groupIds],
      });
      setSuccess({ email: email.trim(), password });
      toast({ title: 'User created', description: `${email.trim()} can now sign in.` });
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to create user',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleClose = async () => {
    if (success) {
      // Refresh parent so the new user appears in the list.
      await onCreated();
    }
    onClose();
  };

  return (
    <Sheet open={open} onOpenChange={(v) => !v && !saving && handleClose()}>
      <SheetContent side="right" className="w-[540px] sm:max-w-[540px] p-0 gap-0 flex flex-col">
        <SheetHeader className="px-5 py-3.5 border-b border-border flex flex-row items-center gap-3 space-y-0 pr-12">
          <div className="w-8 h-8 rounded-md bg-primary/12 text-primary flex items-center justify-center shrink-0">
            <UserIcon className="w-[14px] h-[14px]" />
          </div>
          <div className="flex-1 min-w-0">
            <SheetTitle className="text-[14px] font-semibold leading-none">
              {success ? 'User created' : 'Invite user'}
            </SheetTitle>
            <SheetDescription className="text-[11px] text-muted-foreground mt-1">
              {success
                ? `${success.email} is ready. Share the temporary password — they'll set their own on first sign-in.`
                : 'Add a new user. They can sign in with the temporary password, then change it.'}
            </SheetDescription>
          </div>
        </SheetHeader>

        {!success ? (
          <>
            <div className="overflow-y-auto scrollbar-thin px-5 py-4 flex flex-col gap-4 flex-1 min-h-0">
              <div>
                <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">Email</label>
                <input
                  autoFocus
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  placeholder="person@acme.io"
                  className="w-full h-8 px-2.5 rounded-md border border-border bg-card text-[12px] text-foreground placeholder:text-muted-foreground/70 outline-none focus:border-primary/60"
                />
                {email && !emailValid && (
                  <div className="text-[10.5px] text-yellow-500 mt-1">Enter a valid email address.</div>
                )}
              </div>

              <div>
                <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">Name</label>
                <input
                  value={name}
                  onChange={e => { setName(e.target.value); setUserTypedName(true); }}
                  placeholder="Auto-filled from email"
                  className="w-full h-8 px-2.5 rounded-md border border-border bg-card text-[12px] text-foreground placeholder:text-muted-foreground/70 outline-none focus:border-primary/60"
                />
              </div>

              <div>
                <div className="flex items-center gap-2 mb-1.5">
                  <label className="text-[11px] font-medium text-foreground/80">Groups</label>
                  <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums">{groupIds.size}</span>
                </div>
                {groups.length === 0 ? (
                  <div className="rounded-md border border-dashed border-border px-3 py-3 text-[11px] text-muted-foreground">
                    No groups yet — create one in the Groups tab.
                  </div>
                ) : (
                  <div className="flex flex-wrap gap-1.5">
                    {groups.map(g => {
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
                            'inline-flex items-center gap-1.5 h-7 px-2.5 rounded-md border text-[11.5px] transition-colors',
                            on
                              ? 'border-primary/40 bg-primary/10 text-primary'
                              : 'border-border bg-card text-muted-foreground hover:text-foreground hover:border-foreground/20',
                          )}
                        >
                          {on && <Check className="w-[11px] h-[11px]" />}
                          {!on && <UsersIcon className="w-[11px] h-[11px]" />}
                          {g.name}
                          <span className="font-mono text-[9.5px] text-muted-foreground/70 tabular-nums">{g.member_count}</span>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>

              <div>
                <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">
                  Personal message
                  <span className="text-muted-foreground/70 font-normal ml-1">(optional, you'll share this manually)</span>
                </label>
                <textarea
                  value={message}
                  onChange={e => setMessage(e.target.value)}
                  rows={3}
                  placeholder="Added you to the SOC team — see you in #triage."
                  className="w-full px-2.5 py-2 rounded-md border border-border bg-card text-[12px] text-foreground placeholder:text-muted-foreground/70 outline-none focus:border-primary/60 resize-none"
                />
                <div className="text-[10.5px] text-muted-foreground/70 mt-1">
                  Email-based invite links aren't shipped yet — for now you'll share the temp password yourself.
                </div>
              </div>
            </div>

            <SheetFooter className="border-t border-border px-5 py-3 flex flex-row items-center gap-2 sm:justify-end space-x-0">
              <div className="text-[10.5px] text-muted-foreground mr-auto">User will be created in Active state.</div>
              <Button variant="ghost" size="sm" onClick={onClose} className="h-7 text-[11.5px]" disabled={saving}>
                Cancel
              </Button>
              <Button size="sm" onClick={handleSend} disabled={!canSend} className="h-7 text-[11.5px]">
                {saving && <Loader2 className="w-3 h-3 mr-1 animate-spin" />}
                Create user
              </Button>
            </SheetFooter>
          </>
        ) : (
          <>
            <div className="px-5 py-6 flex flex-col gap-4 flex-1 min-h-0 overflow-y-auto scrollbar-thin">
              <div className="flex items-start gap-3">
                <div className="w-9 h-9 rounded-full bg-emerald-500/15 text-emerald-500 flex items-center justify-center shrink-0">
                  <Check className="w-[18px] h-[18px]" />
                </div>
                <div className="flex-1">
                  <div className="text-[13px] text-foreground font-medium">User created</div>
                  <div className="text-[11.5px] text-muted-foreground mt-1">
                    Sign-in details for <span className="font-mono text-foreground/80">{success.email}</span>:
                  </div>
                </div>
              </div>

              <div className="rounded-md border border-yellow-500/40 bg-yellow-500/5 p-3">
                <div className="flex items-start gap-2">
                  <AlertCircle className="w-[12px] h-[12px] text-yellow-500 shrink-0 mt-0.5" />
                  <div className="flex-1">
                    <div className="text-[11.5px] text-foreground/80">
                      Copy this temporary password now — it won't be shown again. Share it via your usual secure channel; the user will replace it on first sign-in.
                    </div>
                    <div className="mt-2 rounded-md border border-border bg-card p-2 flex items-center gap-2 font-mono text-[11.5px] text-foreground break-all">
                      <span className="flex-1">{success.password}</span>
                      <button
                        onClick={() => {
                          navigator.clipboard?.writeText(success.password);
                          setPwCopied(true);
                          setTimeout(() => setPwCopied(false), 1800);
                        }}
                        className="shrink-0 inline-flex items-center gap-1 text-[10.5px] text-primary hover:text-primary/90"
                      >
                        {pwCopied ? <Check className="w-[11px] h-[11px]" /> : <Copy className="w-[11px] h-[11px]" />}
                        {pwCopied ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <SheetFooter className="border-t border-border px-5 py-3 flex flex-row items-center gap-2 sm:justify-end space-x-0">
              <Button variant="ghost" size="sm" onClick={handleClose} className="h-7 text-[11.5px]">
                Close
              </Button>
              <Button
                size="sm"
                onClick={() => { setSuccess(null); }}
                className="h-7 text-[11.5px]"
              >
                Invite another
              </Button>
            </SheetFooter>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}
