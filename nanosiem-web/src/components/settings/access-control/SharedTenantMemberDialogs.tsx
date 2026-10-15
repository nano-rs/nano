// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Hosted-shared tenant member dialogs (NAN-2361).
 *
 * The shared IAM contract differs from a dedicated deployment in two ways the
 * dedicated dialogs cannot express:
 *   • a member is INVITED — no password; a fresh identity gets a one-time
 *     activation link (`/t/<slug>/auth/shared/activate#<token>`), an existing identity
 *     gets an acceptance link (`/auth/shared/memberships/accept#<token>`)
 *     plus ready-to-send e-mail copy; the admin hands either over;
 *   • roles (system + the tenant's own) and tenant groups are assigned to the
 *     membership; identity attributes belong to the member.
 * Same sheet density and structure as `InviteUserDialog` / `EditUserDialog`.
 */

import { useEffect, useMemo, useState } from 'react';
import { User as UserIcon, Check, Copy, AlertCircle, KeyRound } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { api, type RoleDetail, type GroupDetail, type SharedTenantMember, type SharedTenantInvitation, type SharedTenantMembershipInvitation } from '@/lib/api';
import { Button } from '@/components/ui/button';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
  SheetFooter,
} from '@/components/ui/sheet';

/** Platform ReadOnly role (`Uuid::from_u128(3)` as a typeid); the fetched
 * catalogue overrides it by name once loaded. */
const READ_ONLY_ROLE_ID = 'role_00000000000000000000000003';

function nameFromEmail(email: string): string {
  const local = email.split('@')[0] || 'New User';
  return local
    .replace(/[._-]+/g, ' ')
    .split(' ')
    .filter(Boolean)
    .map(w => w[0].toUpperCase() + w.slice(1))
    .join(' ');
}

/** System roles plus the tenant's custom roles (NAN-2361 wave 5). */
function useSystemRoles(open: boolean): RoleDetail[] {
  const [roles, setRoles] = useState<RoleDetail[]>([]);
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    api.listRoles()
      .then(res => { if (!cancelled) setRoles(res.roles); })
      .catch(() => { if (!cancelled) setRoles([]); });
    return () => { cancelled = true; };
  }, [open]);
  return roles;
}

function useTenantGroups(open: boolean): GroupDetail[] {
  const [groups, setGroups] = useState<GroupDetail[]>([]);
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    api.listGroups()
      .then(res => { if (!cancelled) setGroups(res.groups); })
      .catch(() => { if (!cancelled) setGroups([]); });
    return () => { cancelled = true; };
  }, [open]);
  return groups;
}

function RolePicker({ roles, selected, onToggle, single }: {
  roles: RoleDetail[];
  selected: Set<string>;
  onToggle: (id: string) => void;
  single?: boolean;
}) {
  if (roles.length === 0) {
    return (
      <div className="rounded-md border border-dashed border-border px-3 py-3 text-[11px] text-muted-foreground">
        Loading roles…
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-1.5">
      {roles.map(r => {
        const on = selected.has(r.id);
        return (
          <button
            key={r.id}
            type="button"
            role={single ? 'radio' : 'checkbox'}
            aria-checked={on}
            onClick={() => onToggle(r.id)}
            className={cn(
              'flex items-start gap-2 rounded-md border px-2.5 py-2 text-left transition-colors',
              on
                ? 'border-primary/40 bg-primary/10'
                : 'border-border bg-card hover:border-foreground/20',
            )}
          >
            <span className={cn('mt-0.5 w-[12px] h-[12px] shrink-0 rounded-sm border flex items-center justify-center', on ? 'border-primary bg-primary text-primary-foreground' : 'border-border')}>
              {on && <Check className="w-[9px] h-[9px]" />}
            </span>
            <span className="min-w-0">
              <span className={cn('block text-[12px]', on ? 'text-primary' : 'text-foreground')}>{r.name}</span>
              {r.description && <span className="block text-[10.5px] text-muted-foreground mt-0.5">{r.description}</span>}
              <span className="block font-mono text-[10px] text-muted-foreground/70 tabular-nums mt-0.5">{r.permissions.length} permissions</span>
            </span>
          </button>
        );
      })}
    </div>
  );
}

const inputCls = 'w-full h-8 px-2.5 rounded-md border border-border bg-card text-[12px] text-foreground placeholder:text-muted-foreground/70 outline-none focus:border-primary/60';

// ---------------------------------------------------------------------------
// Invite
// ---------------------------------------------------------------------------

interface SharedInviteMemberDialogProps {
  open: boolean;
  onClose: () => void;
  onCreated: () => void | Promise<void>;
}

interface InviteSuccess {
  email: string;
  invitation: SharedTenantInvitation;
  link: string;
  kind: 'activation' | 'acceptance';
  membershipInvitation?: SharedTenantMembershipInvitation;
}

export function SharedInviteMemberDialog({ open, onClose, onCreated }: SharedInviteMemberDialogProps) {
  const { toast } = useToast();
  const roles = useSystemRoles(open);
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [userTypedName, setUserTypedName] = useState(false);
  const [roleId, setRoleId] = useState<string>(READ_ONLY_ROLE_ID);
  const [saving, setSaving] = useState(false);
  const [success, setSuccess] = useState<InviteSuccess | null>(null);
  const [copied, setCopied] = useState(false);
  const [copiedEmail, setCopiedEmail] = useState(false);

  useEffect(() => {
    if (!open) return;
    setEmail('');
    setName('');
    setUserTypedName(false);
    setRoleId(READ_ONLY_ROLE_ID);
    setSuccess(null);
    setCopied(false);
    setCopiedEmail(false);
  }, [open]);

  useEffect(() => {
    if (!userTypedName && email) setName(nameFromEmail(email));
  }, [email, userTypedName]);

  // Default to the catalogue's ReadOnly role once it is known.
  useEffect(() => {
    const readOnly = roles.find(r => r.name.toLowerCase() === 'readonly');
    if (readOnly && !roles.some(r => r.id === roleId)) setRoleId(readOnly.id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [roles]);

  const emailValid = useMemo(() => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email), [email]);
  const canSend = emailValid && name.trim().length >= 1 && !saving;

  const handleSend = async () => {
    if (!canSend) return;
    setSaving(true);
    try {
      const res = await api.inviteSharedTenantMember({ email: email.trim(), name: name.trim(), role_id: roleId });
      const link = `${window.location.origin}${res.invitation.activation_path}`;
      const kind = res.invitation_kind ?? 'activation';
      setSuccess({ email: res.email, invitation: res.invitation, link, kind, membershipInvitation: res.membership_invitation });
      toast({
        title: 'Invitation issued',
        description: kind === 'acceptance'
          ? `${res.email} already has a nano account; they accept the invitation from a signed-in session.`
          : `${res.email} can activate their membership with the link.`,
      });
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to invite member',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleClose = async () => {
    if (success) await onCreated();
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
              {success ? 'Invitation issued' : 'Invite member'}
            </SheetTitle>
            <SheetDescription className="text-[11px] text-muted-foreground mt-1">
              {success
                ? (success.kind === 'acceptance'
                  ? `${success.email} signs in with their existing account and accepts the invitation.`
                  : `${success.email} sets their own password and enrolls MFA when they open the link.`)
                : 'Add a member to this tenant. New accounts set their own password on activation; existing accounts accept from a signed-in session.'}
            </SheetDescription>
          </div>
        </SheetHeader>

        {!success ? (
          <>
            <div className="overflow-y-auto scrollbar-thin px-5 py-4 flex flex-col gap-4 flex-1 min-h-0">
              <div>
                <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">Email</label>
                <input autoFocus type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="person@acme.io" className={inputCls} />
                {email && !emailValid && <div className="text-[10.5px] text-yellow-500 mt-1">Enter a valid email address.</div>}
              </div>
              <div>
                <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">Name</label>
                <input value={name} onChange={e => { setName(e.target.value); setUserTypedName(true); }} placeholder="Auto-filled from email" className={inputCls} />
              </div>
              <div>
                <div className="flex items-center gap-2 mb-1.5">
                  <KeyRound className="w-[11px] h-[11px] text-muted-foreground" />
                  <label className="text-[11px] font-medium text-foreground/80">Role</label>
                </div>
                <RolePicker roles={roles} selected={new Set([roleId])} onToggle={setRoleId} single />
                <div className="text-[10.5px] text-muted-foreground/70 mt-1.5">
                  System roles and this organization's custom roles; change them later from the member drawer.
                </div>
              </div>
            </div>
            <SheetFooter className="border-t border-border px-5 py-3 flex flex-row items-center gap-2 sm:justify-end space-x-0">
              <div className="text-[10.5px] text-muted-foreground mr-auto">Activation links are valid for 24 hours; acceptance links for 72 hours.</div>
              <Button variant="ghost" size="sm" onClick={onClose} className="h-7 text-[11.5px]" disabled={saving}>Cancel</Button>
              <Button size="sm" onClick={handleSend} disabled={!canSend} className="h-7 text-[11.5px]">
                {saving && <LoadingIcon className="w-3 h-3" />}
                Invite
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
                  <div className="text-[13px] text-foreground font-medium">Invitation issued</div>
                  <div className="text-[11.5px] text-muted-foreground mt-1">
                    {success.kind === 'acceptance' ? 'Acceptance link for ' : 'Activation link for '}<span className="font-mono text-foreground/80">{success.email}</span>
                    {' · '}expires <span className="font-mono">{new Date(success.invitation.expires_at).toISOString().replace('T', ' ').slice(0, 16)}Z</span>
                  </div>
                </div>
              </div>
              <div className="rounded-md border border-yellow-500/40 bg-yellow-500/5 p-3">
                <div className="flex items-start gap-2">
                  <AlertCircle className="w-[12px] h-[12px] text-yellow-500 shrink-0 mt-0.5" />
                  <div className="flex-1">
                    <div className="text-[11.5px] text-foreground/80">
                      {success.kind === 'acceptance'
                        ? 'Copy this link now — it is shown once. The invitee signs in to nano with their existing account, then opens it to accept.'
                        : 'Copy this link now — it is shown once and is the only way to activate the membership. Share it through your usual secure channel.'}
                    </div>
                    <div className="mt-2 rounded-md border border-border bg-card p-2 flex items-center gap-2 font-mono text-[11px] text-foreground break-all">
                      <span className="flex-1">{success.link}</span>
                      <button
                        onClick={() => {
                          navigator.clipboard?.writeText(success.link);
                          setCopied(true);
                          setTimeout(() => setCopied(false), 1800);
                        }}
                        className="shrink-0 inline-flex items-center gap-1 text-[10.5px] text-primary hover:text-primary/90"
                      >
                        {copied ? <Check className="w-[11px] h-[11px]" /> : <Copy className="w-[11px] h-[11px]" />}
                        {copied ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
              {success.membershipInvitation && (
                <div className="rounded-md border border-border bg-card p-3">
                  <div className="flex items-center justify-between mb-1.5">
                    <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium">Email copy</div>
                    <button
                      onClick={() => {
                        const m = success.membershipInvitation!;
                        navigator.clipboard?.writeText(`Subject: ${m.email_subject}\n\n${m.email_body}`);
                        setCopiedEmail(true);
                        setTimeout(() => setCopiedEmail(false), 1800);
                      }}
                      className="inline-flex items-center gap-1 text-[10.5px] text-primary hover:text-primary/90"
                    >
                      {copiedEmail ? <Check className="w-[11px] h-[11px]" /> : <Copy className="w-[11px] h-[11px]" />}
                      {copiedEmail ? 'Copied' : 'Copy email'}
                    </button>
                  </div>
                  <div className="text-[11.5px] text-foreground/90 font-medium">{success.membershipInvitation.email_subject}</div>
                  <pre className="mt-1.5 whitespace-pre-wrap font-mono text-[10.5px] text-muted-foreground leading-relaxed">{success.membershipInvitation.email_body}</pre>
                </div>
              )}
            </div>
            <SheetFooter className="border-t border-border px-5 py-3 flex flex-row items-center gap-2 sm:justify-end space-x-0">
              <Button variant="ghost" size="sm" onClick={handleClose} className="h-7 text-[11.5px]">Close</Button>
              <Button size="sm" onClick={() => { setSuccess(null); setEmail(''); setName(''); setUserTypedName(false); }} className="h-7 text-[11.5px]">
                Invite another
              </Button>
            </SheetFooter>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

// ---------------------------------------------------------------------------
// Edit roles
// ---------------------------------------------------------------------------

interface SharedEditMemberDialogProps {
  open: boolean;
  member: SharedTenantMember | null;
  onClose: () => void;
  onUpdated: () => void | Promise<void>;
}

export function SharedEditMemberDialog({ open, member, onClose, onUpdated }: SharedEditMemberDialogProps) {
  const { toast } = useToast();
  const roles = useSystemRoles(open);
  const groups = useTenantGroups(open);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [selectedGroups, setSelectedGroups] = useState<Set<string>>(new Set());
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open || !member) return;
    setSelected(new Set(member.roles.map(r => r.id)));
    setSelectedGroups(new Set((member.groups ?? []).map(g => g.id)));
  }, [open, member]);

  const toggle = (id: string) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };
  const toggleGroup = (id: string) => {
    setSelectedGroups(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const rolesUnchanged = useMemo(() => {
    if (!member) return true;
    const current = new Set(member.roles.map(r => r.id));
    return current.size === selected.size && [...selected].every(id => current.has(id));
  }, [member, selected]);
  const groupsUnchanged = useMemo(() => {
    if (!member) return true;
    const current = new Set((member.groups ?? []).map(g => g.id));
    return current.size === selectedGroups.size && [...selectedGroups].every(id => current.has(id));
  }, [member, selectedGroups]);
  const canSave = !!member && selected.size > 0 && !(rolesUnchanged && groupsUnchanged) && !saving;

  const handleSave = async () => {
    if (!member || !canSave) return;
    setSaving(true);
    try {
      await api.updateSharedTenantMember(member.id, {
        ...(rolesUnchanged ? {} : { role_ids: [...selected] }),
        ...(groupsUnchanged ? {} : { group_ids: [...selectedGroups] }),
      });
      toast({ title: 'Member updated', description: `${member.name}'s roles and groups were replaced; their sessions were signed out.` });
      await onUpdated();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to update member',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Sheet open={open} onOpenChange={(v) => !v && !saving && onClose()}>
      <SheetContent side="right" className="w-[480px] sm:max-w-[480px] p-0 gap-0 flex flex-col">
        <SheetHeader className="px-5 py-3.5 border-b border-border flex flex-row items-center gap-3 space-y-0 pr-12">
          <div className="w-8 h-8 rounded-md bg-primary/12 text-primary flex items-center justify-center shrink-0">
            <KeyRound className="w-[14px] h-[14px]" />
          </div>
          <div className="flex-1 min-w-0">
            <SheetTitle className="text-[14px] font-semibold leading-none">Edit roles and groups</SheetTitle>
            <SheetDescription className="text-[11px] text-muted-foreground mt-1">
              {member ? <span className="font-mono">{member.email}</span> : null}
            </SheetDescription>
          </div>
        </SheetHeader>
        <div className="overflow-y-auto scrollbar-thin px-5 py-4 flex flex-col gap-4 flex-1 min-h-0">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <label className="text-[11px] font-medium text-foreground/80">Roles</label>
              <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums">{selected.size}</span>
            </div>
            <RolePicker roles={roles} selected={selected} onToggle={toggle} />
            <div className="text-[10.5px] text-muted-foreground/70 mt-1.5">
              Direct roles. Roles a group grants stay while the member is in the group. The tenant always keeps at least one active Admin.
            </div>
          </div>
          {groups.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-1.5">
                <label className="text-[11px] font-medium text-foreground/80">Groups</label>
                <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums">{selectedGroups.size}</span>
              </div>
              <div className="flex flex-col gap-1.5">
                {groups.map(g => {
                  const on = selectedGroups.has(g.id);
                  return (
                    <button
                      key={g.id}
                      type="button"
                      role="checkbox"
                      aria-checked={on}
                      onClick={() => toggleGroup(g.id)}
                      className={cn(
                        'flex items-start gap-2 rounded-md border px-2.5 py-2 text-left transition-colors',
                        on ? 'border-primary/40 bg-primary/10' : 'border-border bg-card hover:border-foreground/20',
                      )}
                    >
                      <span className={cn('mt-0.5 w-[12px] h-[12px] shrink-0 rounded-sm border flex items-center justify-center', on ? 'border-primary bg-primary text-primary-foreground' : 'border-border')}>
                        {on && <Check className="w-[9px] h-[9px]" />}
                      </span>
                      <span className="min-w-0">
                        <span className={cn('block text-[12px]', on ? 'text-primary' : 'text-foreground')}>{g.name}</span>
                        <span className="block font-mono text-[10px] text-muted-foreground/70 tabular-nums mt-0.5">
                          {g.roles.map(r => r.name).join(', ') || 'no roles'} · {g.member_count} members
                        </span>
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>
          )}
          <div className="text-[10.5px] text-muted-foreground/70">
            Name, email and password belong to the member.
          </div>
        </div>
        <SheetFooter className="border-t border-border px-5 py-3 flex flex-row items-center gap-2 sm:justify-end space-x-0">
          <Button variant="ghost" size="sm" onClick={onClose} className="h-7 text-[11.5px]" disabled={saving}>Cancel</Button>
          <Button size="sm" onClick={handleSave} disabled={!canSave} className="h-7 text-[11.5px]">
            {saving && <LoadingIcon className="w-3 h-3" />}
            Save
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
