// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Create / Edit Group dialog. Mirrors `design-ref/shadcn/settings-create-group.jsx`.
 *
 * Flow:
 *   • name (required, ≥ 2 chars)
 *   • description (optional, single line)
 *   • default role grid — system roles excluded
 *   • initial members picker (search + multi-select)
 *
 * After create, walks the selected user list and updates each user's group
 * memberships to include the new group — the create endpoint accepts roles
 * but not members.
 */

import { useEffect, useMemo, useState } from 'react';
import { Layers, Search as SearchIcon, X, Check, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import {
  api,
  type RoleSummary,
  type UserDetail,
  type GroupDetail,
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

interface CreateGroupDialogProps {
  open: boolean;
  /** When set, the dialog renders in edit mode for the given group. */
  editing?: GroupDetail | null;
  onClose: () => void;
  onCreated: () => void | Promise<void>;
  roles: RoleSummary[];
  users: UserDetail[];
}

export function CreateGroupDialog({
  open,
  editing,
  onClose,
  onCreated,
  roles,
  users,
}: CreateGroupDialogProps) {
  const { toast } = useToast();
  const isEditing = !!editing;
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [roleId, setRoleId] = useState<string>('');
  const [memberIds, setMemberIds] = useState<Set<string>>(new Set());
  const [memberQuery, setMemberQuery] = useState('');
  const [saving, setSaving] = useState(false);

  // Re-seed form whenever the dialog (re-)opens. In edit mode we hydrate from
  // the editing target; in create mode we reset.
  useEffect(() => {
    if (!open) return;
    if (editing) {
      setName(editing.name);
      setDescription(editing.description || '');
      setRoleId(editing.roles[0]?.id || '');
      const initial = new Set<string>();
      for (const u of users) {
        if (u.groups.some(g => g.id === editing.id)) initial.add(u.id);
      }
      setMemberIds(initial);
    } else {
      setName('');
      setDescription('');
      setRoleId(roles.find(r => !r.is_system)?.id || '');
      setMemberIds(new Set());
    }
    setMemberQuery('');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, editing?.id]);

  const assignableRoles = useMemo(() => roles.filter(r => !r.is_system), [roles]);
  const filteredUsers = useMemo(() => {
    const q = memberQuery.trim().toLowerCase();
    if (!q) return users;
    return users.filter(u =>
      u.name.toLowerCase().includes(q) || u.email.toLowerCase().includes(q),
    );
  }, [memberQuery, users]);

  const toggleMember = (id: string) => {
    setMemberIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const nameValid = name.trim().length >= 2;
  const canSubmit = nameValid && !saving;

  const handleSubmit = async () => {
    if (!canSubmit) return;
    setSaving(true);
    try {
      const role_ids = roleId ? [roleId] : [];
      let groupId: string;
      if (isEditing && editing) {
        await api.updateGroup(editing.id, {
          name: name.trim(),
          description: description.trim() || undefined,
          role_ids,
        });
        groupId = editing.id;
      } else {
        const created = await api.createGroup({
          name: name.trim(),
          description: description.trim() || undefined,
          role_ids,
        });
        groupId = created.id;
      }

      // Reconcile members. Compare desired vs current and patch each user.
      const desired = memberIds;
      const usersById = new Map(users.map(u => [u.id, u]));
      const updates: Promise<unknown>[] = [];
      for (const uid of desired) {
        const u = usersById.get(uid);
        if (!u) continue;
        const has = u.groups.some(g => g.id === groupId);
        if (!has) {
          const next = [...u.groups.map(g => g.id), groupId];
          updates.push(api.updateUser(u.id, { group_ids: next }).catch(() => undefined));
        }
      }
      if (isEditing) {
        for (const u of users) {
          const has = u.groups.some(g => g.id === groupId);
          if (has && !desired.has(u.id)) {
            const next = u.groups.map(g => g.id).filter(id => id !== groupId);
            updates.push(api.updateUser(u.id, { group_ids: next }).catch(() => undefined));
          }
        }
      }
      if (updates.length) await Promise.all(updates);

      toast({
        title: isEditing ? 'Group updated' : 'Group created',
        description: `${name.trim()} is ready${desired.size ? ` with ${desired.size} member(s)` : ''}.`,
      });
      await onCreated();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to save group',
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
            <Layers className="w-[14px] h-[14px]" />
          </div>
          <div className="flex-1 min-w-0">
            <SheetTitle className="text-[14px] font-semibold leading-none">
              {isEditing ? 'Edit group' : 'New group'}
            </SheetTitle>
            <SheetDescription className="text-[11px] text-muted-foreground mt-1">
              Groups cluster users that share a default role and scopes.
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
              placeholder="e.g. Threat Intel"
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
              placeholder="One-line summary — who's in this group"
              className="w-full h-8 px-2.5 rounded-md border border-border bg-card text-[12px] text-foreground placeholder:text-muted-foreground/70 outline-none focus:border-primary/60"
            />
          </div>

          {assignableRoles.length > 0 && (
            <div>
              <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">Default role</label>
              <div className="grid grid-cols-3 gap-2">
                {assignableRoles.map(r => (
                  <button
                    key={r.id}
                    type="button"
                    onClick={() => setRoleId(r.id)}
                    className={cn(
                      'px-2.5 py-2 rounded-md border text-left transition-colors',
                      roleId === r.id
                        ? 'border-primary/50 bg-primary/5'
                        : 'border-border bg-card hover:border-foreground/20',
                    )}
                  >
                    <div className={cn('text-[11.5px] font-medium truncate', roleId === r.id ? 'text-primary' : 'text-foreground')}>
                      {r.name}
                    </div>
                    <div className="font-mono text-[10px] text-muted-foreground mt-0.5 tabular-nums">
                      {r.is_system ? 'system' : 'role'}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <label className="text-[11px] font-medium text-foreground/80">
                {isEditing ? 'Members' : 'Initial members'}{' '}
                <span className="text-muted-foreground/70 font-normal">({memberIds.size})</span>
              </label>
              <div className="flex-1" />
              <div className="h-6 flex-none rounded border border-border bg-card flex items-center gap-1.5 px-1.5 w-[180px]">
                <SearchIcon className="w-[11px] h-[11px] text-muted-foreground" />
                <input
                  value={memberQuery}
                  onChange={e => setMemberQuery(e.target.value)}
                  placeholder="Filter users…"
                  className="flex-1 bg-transparent outline-none text-[11px] text-foreground placeholder:text-muted-foreground/70 min-w-0"
                />
              </div>
            </div>
            <div className="rounded-md border border-border overflow-hidden">
              <div className="max-h-[180px] overflow-y-auto scrollbar-thin">
                {filteredUsers.slice(0, 50).map(u => {
                  const on = memberIds.has(u.id);
                  return (
                    <button
                      key={u.id}
                      type="button"
                      role="checkbox"
                      aria-checked={on}
                      aria-label={`${u.name} (${u.email})`}
                      onClick={() => toggleMember(u.id)}
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
                      <span className="text-[11.5px] text-foreground truncate">{u.name}</span>
                      <span className="font-mono text-[10.5px] text-muted-foreground truncate">{u.email}</span>
                    </button>
                  );
                })}
                {filteredUsers.length === 0 && (
                  <div className="px-3 py-4 text-center text-[11px] text-muted-foreground">No users match.</div>
                )}
              </div>
            </div>
            {memberIds.size > 0 && (
              <div className="flex flex-wrap gap-1 mt-2">
                {[...memberIds].slice(0, 6).map(id => {
                  const u = users.find(x => x.id === id);
                  if (!u) return null;
                  return (
                    <span key={id} className="inline-flex items-center gap-1 h-5 px-1.5 rounded-sm bg-primary/10 text-primary text-[10.5px]">
                      {u.name}
                      <button
                        type="button"
                        onClick={() => toggleMember(id)}
                        className="text-primary/70 hover:text-primary"
                      >
                        <X className="w-[9px] h-[9px]" />
                      </button>
                    </span>
                  );
                })}
                {memberIds.size > 6 && (
                  <span className="inline-flex items-center h-5 px-1.5 text-[10.5px] text-muted-foreground font-mono">
                    +{memberIds.size - 6} more
                  </span>
                )}
              </div>
            )}
          </div>
        </div>

        <SheetFooter className="border-t border-border px-5 py-3 flex flex-row items-center gap-2 sm:justify-end space-x-0">
          <div className="text-[10.5px] text-muted-foreground mr-auto">
            {isEditing ? 'Member changes apply immediately.' : 'You can add more members later.'}
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} className="h-7 text-[11.5px]" disabled={saving}>
            Cancel
          </Button>
          <Button size="sm" onClick={handleSubmit} disabled={!canSubmit} className="h-7 text-[11.5px]">
            {saving && <Loader2 className="w-3 h-3 animate-spin" />}
            {isEditing ? 'Save changes' : 'Create group'}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
