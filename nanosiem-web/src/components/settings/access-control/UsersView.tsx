// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Users — Access Control deep-dive.
 *
 * Mirrors `design-ref/shadcn/settings-users.jsx` `UsersView`:
 *   • Filter bar: search input · status pill filters · Export CSV · Invite user
 *   • Sticky column header
 *   • Dense rows (28-30px), avatar · name · email · status pill · groups · last login
 *   • Footer count line (mono, redesign-density)
 *   • Right-side drawer with user detail + actions (Edit / Disable / Enable / Delete)
 */

import { useEffect, useMemo, useState } from 'react';
import {
  Search as SearchIcon,
  Plus,
  Download,
  ChevronRight,
  X,
  Loader2,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { useTierContext } from '@/hooks/use-tier';
import { api, type UserDetail, type GroupDetail } from '@/lib/api';
import { Button } from '@/components/ui/button';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { formatUTC } from '@/lib/date-utils';
import { TierUsageBar } from '@/components/TierUsageBar';
import { InviteUserDialog } from './InviteUserDialog';
import { EditUserDialog } from './EditUserDialog';
import { MfaEnforcementPanel } from './MfaEnforcementPanel';

// ---------- presentation helpers ----------

type UserStatus = 'active' | 'locked' | 'disabled';

const STATUS_PILL: Record<UserStatus, { label: string; cls: string }> = {
  active: { label: 'Active', cls: 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30' },
  locked: { label: 'Locked', cls: 'bg-yellow-500/12 text-yellow-500 border-yellow-500/30' },
  disabled: { label: 'Disabled', cls: 'bg-red-500/12 text-red-500 border-red-500/30' },
};

function StatusPill({ status }: { status: string }) {
  const def = STATUS_PILL[status as UserStatus] || { label: status, cls: 'bg-foreground/10 text-foreground/80 border-border' };
  return (
    <span className={cn('inline-flex items-center h-5 px-1.5 rounded-sm border text-[10.5px] font-medium', def.cls)}>
      {def.label}
    </span>
  );
}

function initialsFor(name: string): string {
  if (!name) return 'U';
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return name.substring(0, 2).toUpperCase();
}

function Avatar({ name, isSso }: { name: string; isSso?: boolean }) {
  return (
    <div
      className={cn(
        'w-6 h-6 rounded-full flex items-center justify-center font-mono font-semibold text-[10px] shrink-0',
        isSso ? 'bg-violet-500/15 text-violet-400' : 'bg-primary/15 text-primary',
      )}
      title={isSso ? 'Provisioned via SSO' : undefined}
    >
      {initialsFor(name)}
    </div>
  );
}

// ---------- row ----------

interface UserRowProps {
  user: UserDetail;
  selected: boolean;
  onSelect: (id: string) => void;
}

function UserRow({ user, selected, onSelect }: UserRowProps) {
  return (
    <button
      onClick={() => onSelect(user.id)}
      className={cn(
        'group grid grid-cols-[28px_minmax(180px,2fr)_minmax(180px,2fr)_92px_minmax(160px,2fr)_minmax(120px,1fr)_18px] gap-3 items-center px-3 h-10 border-b border-border/60 text-left transition-colors w-full',
        selected ? 'bg-foreground/[0.04]' : 'hover:bg-foreground/[0.025]',
      )}
    >
      <Avatar name={user.name} isSso={!!user.oidc_provider} />
      <div className="min-w-0">
        <div className="text-[12.5px] text-foreground truncate leading-tight">{user.name}</div>
        {user.oidc_provider && (
          <div className="text-[10px] text-muted-foreground/70 truncate leading-tight mt-0.5">via {user.oidc_provider}</div>
        )}
      </div>
      <div className="min-w-0 font-mono text-[11.5px] text-foreground/80 truncate">{user.email}</div>
      <div><StatusPill status={user.status} /></div>
      <div className="min-w-0 flex items-center gap-1 flex-wrap">
        {user.groups.slice(0, 2).map(g => (
          <span key={g.id} className="inline-flex items-center h-5 px-1.5 rounded-sm border border-border text-[10.5px] text-foreground/80 bg-card">
            {g.name}
          </span>
        ))}
        {user.groups.length > 2 && (
          <span className="text-[10.5px] text-muted-foreground">+{user.groups.length - 2}</span>
        )}
      </div>
      <div className="min-w-0 font-mono text-[11px] text-muted-foreground tabular-nums truncate">
        {user.last_login_at ? formatUTC(user.last_login_at) : '—'}
      </div>
      <ChevRight className="text-muted-foreground/70 group-hover:text-muted-foreground" />
    </button>
  );
}

function ChevRight({ className }: { className?: string }) {
  return <ChevronRight className={cn('w-[11px] h-[11px]', className)} />;
}

// ---------- detail drawer ----------

interface UserDrawerProps {
  user: UserDetail | null;
  onClose: () => void;
  onEdit: (user: UserDetail) => void;
  onDisable: (user: UserDetail) => void;
  onEnable: (user: UserDetail) => void;
  onUnlock: (user: UserDetail) => void;
  onDelete: (user: UserDetail) => void;
}

function UserDrawer({ user, onClose, onEdit, onDisable, onEnable, onUnlock, onDelete }: UserDrawerProps) {
  if (!user) return null;
  const isSelf = false; // TODO: useAuth().user?.id === user.id when ID shape stabilizes
  return (
    <aside
      className="w-[340px] border-l border-border flex flex-col shrink-0"
      style={{ background: 'var(--panel)' }}
      aria-label="User details"
    >
      <div className="h-10 px-3 flex items-center gap-2 border-b border-border shrink-0">
        <Avatar name={user.name} isSso={!!user.oidc_provider} />
        <div className="min-w-0 flex-1">
          <div className="text-[12px] font-medium text-foreground truncate leading-tight">{user.name}</div>
          <div className="text-[10.5px] text-muted-foreground font-mono truncate">{user.email}</div>
        </div>
        <button
          onClick={onClose}
          className="w-5 h-5 rounded flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-foreground/5"
        >
          <X className="w-[12px] h-[12px]" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto scrollbar-thin px-3 py-3 flex flex-col gap-4">
        <div>
          <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1.5">Status</div>
          <div className="flex items-center gap-2">
            <StatusPill status={user.status} />
            {user.oidc_provider && (
              <span className="text-[10.5px] text-muted-foreground">SSO · {user.oidc_provider}</span>
            )}
          </div>
        </div>

        <div>
          <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1.5">Groups</div>
          {user.groups.length === 0 ? (
            <div className="text-[11.5px] text-muted-foreground italic">No groups</div>
          ) : (
            <div className="flex items-center gap-1 flex-wrap">
              {user.groups.map(g => (
                <span key={g.id} className="inline-flex items-center h-5 px-1.5 rounded-sm border border-border text-[10.5px] text-foreground/80 bg-card">
                  {g.name}
                </span>
              ))}
            </div>
          )}
        </div>

        <div>
          <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1.5">Last login</div>
          <div className="text-[12px] text-foreground font-mono">
            {user.last_login_at ? formatUTC(user.last_login_at) : '—'}
          </div>
        </div>

        <div>
          <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1.5">Created</div>
          <div className="text-[12px] text-foreground/80 font-mono">{formatUTC(user.created_at)}</div>
        </div>
      </div>

      <div className="shrink-0 border-t border-border px-3 py-2 flex items-center gap-2 flex-wrap">
        <Button size="sm" variant="outline" className="h-7 text-[11.5px] px-2.5" onClick={() => onEdit(user)}>
          Edit
        </Button>
        {user.status === 'locked' && (
          <Button size="sm" variant="outline" className="h-7 text-[11.5px] px-2.5" onClick={() => onUnlock(user)}>
            Unlock
          </Button>
        )}
        <div className="flex-1" />
        {user.status === 'active' && !isSelf && (
          <Button
            size="sm"
            variant="ghost"
            className="h-7 text-[11.5px] px-2.5 text-yellow-500 hover:text-yellow-500/90"
            onClick={() => onDisable(user)}
          >
            Disable
          </Button>
        )}
        {user.status === 'disabled' && (
          <Button
            size="sm"
            variant="ghost"
            className="h-7 text-[11.5px] px-2.5 text-emerald-500 hover:text-emerald-500/90"
            onClick={() => onEnable(user)}
          >
            Enable
          </Button>
        )}
        {!isSelf && (
          <Button
            size="sm"
            variant="ghost"
            className="h-7 text-[11.5px] px-2.5 text-red-500 hover:text-red-500/90"
            onClick={() => onDelete(user)}
          >
            Delete
          </Button>
        )}
      </div>
    </aside>
  );
}

// ---------- view ----------

const STATUS_FILTERS: Array<{ id: 'all' | UserStatus; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'active', label: 'Active' },
  { id: 'locked', label: 'Locked' },
  { id: 'disabled', label: 'Disabled' },
];

interface PendingAction {
  user: UserDetail;
  kind: 'delete' | 'disable' | 'enable' | 'unlock';
}

export function UsersView() {
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const { status: tierStatus, isEnforced } = useTierContext();

  const canCreate = hasPermission('users:create');
  const canEdit = hasPermission('users:edit');
  const canDelete = hasPermission('users:delete');

  const [users, setUsers] = useState<UserDetail[]>([]);
  const [groups, setGroups] = useState<GroupDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | UserStatus>('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [pending, setPending] = useState<PendingAction | null>(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [editing, setEditing] = useState<UserDetail | null>(null);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [res, groupsRes] = await Promise.all([
        api.listUsers(),
        api.listGroups().catch(() => ({ groups: [] as GroupDetail[], total: 0 })),
      ]);
      setUsers(res.users);
      setGroups(groupsRes.groups);
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to load users',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const counts = useMemo(() => {
    const c: Record<string, number> = { all: users.length };
    for (const u of users) c[u.status] = (c[u.status] || 0) + 1;
    return c;
  }, [users]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return users.filter(u => {
      if (statusFilter !== 'all' && u.status !== statusFilter) return false;
      if (!q) return true;
      return (
        u.name.toLowerCase().includes(q) ||
        u.email.toLowerCase().includes(q) ||
        u.groups.some(g => g.name.toLowerCase().includes(q))
      );
    });
  }, [query, statusFilter, users]);

  const selected = users.find(u => u.id === selectedId) || null;

  const handleEdit = (user: UserDetail) => {
    setEditing(user);
  };

  const performPending = async () => {
    if (!pending) return;
    const { user, kind } = pending;
    setActionLoading(true);
    try {
      if (kind === 'delete') {
        await api.deleteUser(user.id);
        toast({ title: 'User deleted', description: `${user.name} has been deleted.` });
      } else if (kind === 'disable') {
        await api.disableUser(user.id);
        toast({ title: 'User disabled', description: `${user.name} can no longer sign in.` });
      } else if (kind === 'enable') {
        await api.enableUser(user.id);
        toast({ title: 'User enabled', description: `${user.name} can sign in again.` });
      } else if (kind === 'unlock') {
        await api.unlockUser(user.id);
        toast({ title: 'User unlocked', description: `${user.name} can sign in again.` });
      }
      setPending(null);
      if (kind === 'delete' && selectedId === user.id) setSelectedId(null);
      await fetchData();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : `Failed to ${kind} user`,
        variant: 'destructive',
      });
    } finally {
      setActionLoading(false);
    }
  };

  const exportCsv = () => {
    const header = ['name', 'email', 'status', 'groups', 'last_login_at', 'created_at'];
    const rows = filtered.map(u => [
      u.name,
      u.email,
      u.status,
      u.groups.map(g => g.name).join('|'),
      u.last_login_at || '',
      u.created_at,
    ]);
    const csv = [header, ...rows]
      .map(r => r.map(c => /[",\n]/.test(String(c)) ? `"${String(c).replace(/"/g, '""')}"` : String(c)).join(','))
      .join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `users-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <>
      <div className="flex-1 flex min-h-0">
        <div className="flex-1 flex flex-col min-w-0">
          {/* Org-wide MFA enforcement (admin-only; renders nothing for
              users without `settings:system`). Sits above the filter bar
              so the policy state is the first thing an admin sees when
              landing on the user list. */}
          <MfaEnforcementPanel />
          {/* Filter bar */}
          <div className="shrink-0 px-5 pt-4 pb-2.5 flex items-center gap-2 flex-wrap">
            <div className="h-8 rounded-md border border-border bg-card flex items-center gap-2 px-2.5 w-[300px]">
              <SearchIcon className="w-[12px] h-[12px] text-muted-foreground" />
              <input
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="Search users, email, group…"
                className="flex-1 bg-transparent outline-none text-[12px] text-foreground placeholder:text-muted-foreground/70"
              />
            </div>
            <div className="flex items-center gap-1 flex-wrap">
              {STATUS_FILTERS.map(f => {
                const active = statusFilter === f.id;
                const n = counts[f.id] ?? 0;
                return (
                  <button
                    key={f.id}
                    onClick={() => setStatusFilter(f.id)}
                    className={cn(
                      'h-7 px-2.5 rounded-md border text-[11.5px] flex items-center gap-1.5 transition-colors',
                      active
                        ? 'border-foreground/20 bg-foreground/[0.04] text-foreground'
                        : 'border-border bg-card text-muted-foreground hover:text-foreground hover:border-foreground/20',
                    )}
                  >
                    <span>{f.label}</span>
                    <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums">{n}</span>
                  </button>
                );
              })}
            </div>
            <div className="flex-1" />
            {isEnforced && tierStatus && (
              <TierUsageBar
                label="members"
                current={tierStatus.usage.team_members}
                limit={tierStatus.limits.max_team_members}
              />
            )}
            <Button size="sm" variant="outline" className="h-7 text-[11.5px] px-2.5" onClick={exportCsv}>
              <Download className="w-[12px] h-[12px] mr-1" />
              Export CSV
            </Button>
            {canCreate && (
              <Button
                size="sm"
                className="h-7 text-[11.5px] px-2.5"
                onClick={() => setInviteOpen(true)}
              >
                <Plus className="w-[12px] h-[12px] mr-1" />
                Invite user
              </Button>
            )}
          </div>

          {/* Column header */}
          <div className="shrink-0 grid grid-cols-[28px_minmax(180px,2fr)_minmax(180px,2fr)_92px_minmax(160px,2fr)_minmax(120px,1fr)_18px] gap-3 px-3 py-1.5 border-y border-border bg-card/50 text-[10px] uppercase tracking-[0.08em] text-muted-foreground font-medium">
            <span />
            <span>Name</span>
            <span>Email</span>
            <span>Status</span>
            <span>Groups</span>
            <span>Last login</span>
            <span />
          </div>

          {/* Body */}
          <div className="flex-1 overflow-y-auto scrollbar-thin">
            {loading && (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
              </div>
            )}
            {!loading && filtered.map(u => (
              <UserRow
                key={u.id}
                user={u}
                selected={selectedId === u.id}
                onSelect={setSelectedId}
              />
            ))}
            {!loading && filtered.length === 0 && (
              <div className="px-6 py-12 text-center text-[12px] text-muted-foreground">
                {users.length === 0 ? 'No users yet.' : 'No users match those filters.'}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="shrink-0 h-8 px-5 border-t border-border flex items-center font-mono text-[10.5px] text-muted-foreground tracking-wide">
            <span>{filtered.length} of {users.length} users</span>
            <span className="ml-auto">
              {counts.active || 0} active · {counts.locked || 0} locked · {counts.disabled || 0} disabled
            </span>
          </div>
        </div>

        {selected && (
          <UserDrawer
            user={selected}
            onClose={() => setSelectedId(null)}
            onEdit={canEdit ? handleEdit : () => {}}
            onDisable={(u) => setPending({ user: u, kind: 'disable' })}
            onEnable={(u) => setPending({ user: u, kind: 'enable' })}
            onUnlock={(u) => setPending({ user: u, kind: 'unlock' })}
            onDelete={canDelete ? (u) => setPending({ user: u, kind: 'delete' }) : () => {}}
          />
        )}
      </div>

      <InviteUserDialog
        open={inviteOpen}
        groups={groups}
        onClose={() => setInviteOpen(false)}
        onCreated={async () => {
          setInviteOpen(false);
          await fetchData();
        }}
      />

      <EditUserDialog
        open={!!editing}
        user={editing}
        groups={groups}
        onClose={() => setEditing(null)}
        onUpdated={async () => {
          setEditing(null);
          await fetchData();
        }}
      />

      <AlertDialog open={!!pending} onOpenChange={(open) => !open && setPending(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {pending?.kind === 'delete' && 'Delete user'}
              {pending?.kind === 'disable' && 'Disable user'}
              {pending?.kind === 'enable' && 'Enable user'}
              {pending?.kind === 'unlock' && 'Unlock user'}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {pending?.kind === 'delete' && (
                <>Permanently delete <span className="text-foreground font-medium">{pending?.user.name}</span>? This cannot be undone.</>
              )}
              {pending?.kind === 'disable' && (
                <>Disable <span className="text-foreground font-medium">{pending?.user.name}</span>? They won't be able to sign in until re-enabled.</>
              )}
              {pending?.kind === 'enable' && (
                <>Re-enable <span className="text-foreground font-medium">{pending?.user.name}</span>? They'll regain access to the platform.</>
              )}
              {pending?.kind === 'unlock' && (
                <>Unlock <span className="text-foreground font-medium">{pending?.user.name}</span>? They'll be able to sign in again.</>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={performPending}
              disabled={actionLoading}
              className={pending?.kind === 'delete' ? 'bg-destructive hover:bg-destructive/90 text-destructive-foreground' : ''}
            >
              {actionLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
              {pending?.kind === 'delete' && 'Delete'}
              {pending?.kind === 'disable' && 'Disable'}
              {pending?.kind === 'enable' && 'Enable'}
              {pending?.kind === 'unlock' && 'Unlock'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
