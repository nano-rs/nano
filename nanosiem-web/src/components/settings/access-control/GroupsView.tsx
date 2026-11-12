// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Groups — Access Control deep-dive (master/detail).
 *
 * Mirrors `design-ref/shadcn/settings-groups.jsx` `GroupsView`:
 *   • 320px master list on the left (search + create + per-group rows)
 *   • Detail pane on the right: header (icon · name · managed pill · rename
 *     / add-members), 4-up meta grid (default role / member count / created /
 *     updated), scope chips, members table with remove.
 *
 * NAN-5274: on enterprise builds a group that a SCIM-provisioned IdP group
 * feeds (through an SSO group mapping) shows a "SCIM" pill and a banner naming
 * the provider. Open builds get the stub hook, which reports no sources, so
 * every group stays "Local" and nothing SCIM-related renders.
 */

import { useEffect, useMemo, useState } from 'react';
import {
  Search as SearchIcon,
  Plus,
  PencilLine,
  Layers,
  Shield,
  X,
  AlertCircle,
} from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { api, type GroupDetail, type RoleSummary, type UserDetail } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { formatUTC } from '@/lib/date-utils';
import { CreateGroupDialog } from './CreateGroupDialog';
import { useCapabilitiesOptional } from '@/hooks/use-capabilities';
import { useScimGroupSources, type ScimGroupSource } from '@/enterprise/hooks/use-scim-group-sources';

function SourcePill({ group, scim, size }: { group: GroupDetail; scim: ScimGroupSource[]; size: 'sm' | 'md' }) {
  const label = group.is_system ? 'System' : scim.length > 0 ? 'SCIM' : 'Local';
  const title = scim.length > 0
    ? `Members also provisioned by ${scim.map(s => `${s.provider_name} (${s.idp_group})`).join(', ')}`
    : undefined;
  return (
    <span
      title={title}
      className={cn(
        'inline-flex items-center rounded-sm font-mono',
        size === 'sm'
          ? 'h-4 px-1.5 text-[9.5px] bg-foreground/[0.06] text-muted-foreground'
          : 'h-5 px-1.5 text-[10px] border border-border bg-card text-muted-foreground',
        label === 'SCIM' && 'text-primary',
      )}
    >
      {label}
    </span>
  );
}

function initialsFor(name: string): string {
  if (!name) return '?';
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return name.substring(0, 2).toUpperCase();
}

function MemberAvatar({ name }: { name: string }) {
  return (
    <div className="w-5 h-5 rounded-full bg-primary/15 text-primary flex items-center justify-center font-mono font-semibold text-[9px] shrink-0">
      {initialsFor(name)}
    </div>
  );
}

interface GroupListItemProps {
  group: GroupDetail;
  scim: ScimGroupSource[];
  selected: boolean;
  onSelect: (id: string) => void;
}

function GroupListItem({ group, scim, selected, onSelect }: GroupListItemProps) {
  const primaryRole = group.roles[0]?.name || '—';
  return (
    <button
      onClick={() => onSelect(group.id)}
      className={cn(
        'w-full text-left px-3 py-2.5 border-b border-border/60 flex items-start gap-2.5 transition-colors',
        selected ? 'bg-foreground/[0.04]' : 'hover:bg-foreground/[0.025]',
      )}
    >
      <div className="w-6 h-6 rounded-md bg-card border border-border flex items-center justify-center shrink-0">
        <Layers className="w-[12px] h-[12px] text-muted-foreground" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <div className="text-[12.5px] text-foreground font-medium truncate leading-tight">{group.name}</div>
          <div className="font-mono text-[10.5px] text-muted-foreground tabular-nums">{group.member_count}</div>
        </div>
        {group.description && (
          <div className="text-[11px] text-muted-foreground truncate mt-0.5">{group.description}</div>
        )}
        <div className="flex items-center gap-1.5 mt-1">
          <SourcePill group={group} scim={scim} size="sm" />
          <span className="text-[10.5px] text-muted-foreground truncate">→ {primaryRole}</span>
        </div>
      </div>
    </button>
  );
}

interface GroupDetailViewProps {
  group: GroupDetail;
  scim: ScimGroupSource[];
  members: UserDetail[];
  membersLoading: boolean;
  /** Why the member list cannot be shown (e.g. the viewer lacks users:view). */
  membersUnavailable?: string | null;
  onEdit: () => void;
  onDelete: () => void;
}

function Labeled({ label, mono, children }: { label: string; mono?: boolean; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1.5">{label}</div>
      <div className={cn('text-[12px] text-foreground', mono && 'font-mono')}>{children}</div>
    </div>
  );
}

function GroupDetailView({ group, scim, members, membersLoading, membersUnavailable, onEdit, onDelete }: GroupDetailViewProps) {
  const { hasPermission } = useAuth();
  const canEdit = hasPermission('groups:edit');
  const canDelete = hasPermission('groups:delete');
  const primaryRole = group.roles[0];

  return (
    <div className="flex-1 overflow-y-auto scrollbar-thin">
      {/* Header */}
      <div className="px-6 pt-5 pb-4 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-card border border-border flex items-center justify-center">
            <Layers className="w-[15px] h-[15px] text-muted-foreground" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <div className="text-[17px] font-semibold text-foreground tracking-tight leading-none">{group.name}</div>
              <SourcePill group={group} scim={scim} size="md" />
            </div>
            {group.description && (
              <div className="text-[12px] text-muted-foreground mt-1 max-w-[520px]">{group.description}</div>
            )}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {canEdit && !group.is_system && (
              <Button size="sm" variant="outline" className="h-7 text-[11.5px] px-2.5" onClick={onEdit}>
                <PencilLine className="w-[11px] h-[11px]" />
                Edit
              </Button>
            )}
          </div>
        </div>
      </div>

      {/* Body */}
      <div className="px-6 py-5 flex flex-col gap-6">
        {scim.length > 0 && (
          <div className="rounded-md border border-border bg-card/50 px-3 py-2 text-[11.5px] text-foreground/80">
            Members are also provisioned over SCIM from{' '}
            {scim.map((s, i) => (
              <span key={`${s.provider_id}:${s.idp_group}`}>
                {i > 0 && ', '}
                <span className="text-foreground">{s.provider_name}</span>{' '}
                <span className="font-mono text-[10.5px] text-muted-foreground">{s.idp_group}</span>
              </span>
            ))}
            . The identity provider adds and removes those members; members added here stay.
          </div>
        )}
        {/* Meta grid */}
        <div className="grid grid-cols-4 gap-6">
          <Labeled label="Default role">
            {primaryRole ? (
              <div className="flex items-center gap-1.5">
                <Shield className="w-[12px] h-[12px] text-muted-foreground" />
                <span>{primaryRole.name}</span>
              </div>
            ) : (
              <span className="text-muted-foreground italic">—</span>
            )}
          </Labeled>
          <Labeled label="Members">
            <span className="font-mono tabular-nums">{group.member_count}</span>
          </Labeled>
          <Labeled label="Created" mono>
            {formatUTC(group.created_at)}
          </Labeled>
          <Labeled label="Updated" mono>
            {formatUTC(group.updated_at)}
          </Labeled>
        </div>

        {/* Members table */}
        <div>
          <div className="flex items-center gap-2 mb-2">
            <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium">Members</div>
            <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums">{group.member_count}</span>
            <div className="flex-1" />
          </div>
          <div className="rounded-md border border-border overflow-hidden">
            <div className="grid grid-cols-[24px_minmax(160px,1.5fr)_minmax(160px,1.5fr)_minmax(120px,1fr)_100px_24px] gap-3 px-3 py-1.5 bg-card/50 border-b border-border text-[10px] uppercase tracking-[0.08em] text-muted-foreground font-medium">
              <span />
              <span>Name</span>
              <span>Email</span>
              <span>Status</span>
              <span>Last login</span>
              <span />
            </div>
            {membersLoading ? (
              <div className="px-4 py-6 text-center">
                <LoadingIcon className="w-4 h-4 text-muted-foreground inline" />
              </div>
            ) : membersUnavailable ? (
              <div className="px-4 py-6 text-center text-[11.5px] text-muted-foreground">{membersUnavailable}</div>
            ) : members.length === 0 ? (
              <div className="px-4 py-6 text-center text-[11.5px] text-muted-foreground">No members yet.</div>
            ) : (
              members.map(u => (
                <div
                  key={u.id}
                  className="grid grid-cols-[24px_minmax(160px,1.5fr)_minmax(160px,1.5fr)_minmax(120px,1fr)_100px_24px] gap-3 items-center px-3 h-9 border-b border-border/60 last:border-b-0 hover:bg-foreground/[0.025] transition-colors"
                >
                  <MemberAvatar name={u.name} />
                  <div className="text-[12px] text-foreground truncate">{u.name}</div>
                  <div className="font-mono text-[11px] text-foreground/80 truncate">{u.email}</div>
                  <div className="text-[11.5px] text-muted-foreground truncate capitalize">{u.status}</div>
                  <div className="font-mono text-[10.5px] text-muted-foreground truncate">
                    {u.last_login_at ? formatUTC(u.last_login_at) : '—'}
                  </div>
                  <span />
                </div>
              ))
            )}
          </div>
        </div>

        {/* Danger zone */}
        {canDelete && !group.is_system && (
          <div className="rounded-md border border-red-500/25 bg-red-500/5 p-3 flex items-center gap-3">
            <AlertCircle className="w-[13px] h-[13px] text-red-500 shrink-0" />
            <div className="flex-1 text-[11.5px] text-foreground/80">
              Deleting a group removes the default role assignment from all of its members.
            </div>
            <button onClick={onDelete} className="text-[11px] text-red-500 hover:underline shrink-0">
              Delete group
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export const MEMBERS_NEED_USERS_VIEW = 'Viewing members needs the users:view permission.';

function isForbidden(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { status?: number }).status === 403;
}

export function GroupsView() {
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const canCreate = hasPermission('groups:create');
  // SSO (and with it SCIM) exists only on licensed enterprise builds.
  const ssoAvailable = useCapabilitiesOptional()?.capabilities.sso ?? false;
  const scimSources = useScimGroupSources(ssoAvailable);

  const [groups, setGroups] = useState<GroupDetail[]>([]);
  const [users, setUsers] = useState<UserDetail[]>([]);
  const [roles, setRoles] = useState<RoleSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const canViewUsers = hasPermission('users:view');
  const [usersLoading, setUsersLoading] = useState(canViewUsers);
  // NAN-5307: never show "No members yet" when the member list simply could
  // not be read — say why instead.
  const [usersUnavailable, setUsersUnavailable] = useState<string | null>(
    canViewUsers ? null : MEMBERS_NEED_USERS_VIEW,
  );
  const [query, setQuery] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState<GroupDetail | null>(null);
  const [pendingDelete, setPendingDelete] = useState<GroupDetail | null>(null);
  const [actionLoading, setActionLoading] = useState(false);

  const fetchAll = async () => {
    setLoading(true);
    try {
      const [groupsRes, rolesRes] = await Promise.all([
        api.listGroups(),
        api.listRoles(),
      ]);
      setGroups(groupsRes.groups);
      setRoles(rolesRes.roles);
      if (!selectedId && groupsRes.groups.length > 0) {
        setSelectedId(groupsRes.groups[0].id);
      }
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to load groups',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Users are needed both for the member table on the right AND for the
  // CreateGroupDialog. Fetch once for both.
  useEffect(() => {
    // Without users:view the request is refused (and audited as a denial),
    // so don't send it.
    if (!canViewUsers) {
      setUsersUnavailable(MEMBERS_NEED_USERS_VIEW);
      setUsersLoading(false);
      return;
    }
    let cancelled = false;
    setUsersLoading(true);
    api.listUsers().then(res => {
      if (cancelled) return;
      setUsers(res.users);
      setUsersUnavailable(null);
    }).catch(err => {
      if (cancelled) return;
      setUsersUnavailable(
        isForbidden(err)
          ? MEMBERS_NEED_USERS_VIEW
          : `Could not load members: ${err instanceof Error ? err.message : 'unknown error'}`,
      );
    }).finally(() => {
      if (!cancelled) setUsersLoading(false);
    });
    return () => { cancelled = true; };
  }, [canViewUsers]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return groups;
    return groups.filter(g =>
      g.name.toLowerCase().includes(q)
      || (g.description?.toLowerCase().includes(q) ?? false)
      || g.roles.some(r => r.name.toLowerCase().includes(q)),
    );
  }, [query, groups]);

  const selected = groups.find(g => g.id === selectedId) || filtered[0] || null;
  const selectedMembers = useMemo(() => {
    if (!selected) return [];
    return users.filter(u => u.groups.some(g => g.id === selected.id));
  }, [selected, users]);

  const handleDelete = async () => {
    if (!pendingDelete) return;
    setActionLoading(true);
    try {
      await api.deleteGroup(pendingDelete.id);
      toast({ title: 'Group deleted', description: `${pendingDelete.name} has been deleted.` });
      const remaining = groups.filter(g => g.id !== pendingDelete.id);
      setSelectedId(remaining[0]?.id || null);
      setPendingDelete(null);
      await fetchAll();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to delete group',
        variant: 'destructive',
      });
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <>
      <div className="flex-1 flex min-h-0">
        {/* Master — group list */}
        <div
          className="w-[320px] shrink-0 flex flex-col border-r border-border"
          style={{ background: 'var(--panel)' }}
        >
          <div className="shrink-0 px-3 py-3 flex items-center gap-2 border-b border-border">
            <div className="h-7 flex-1 rounded-md border border-border bg-card flex items-center gap-2 px-2">
              <SearchIcon className="w-[12px] h-[12px] text-muted-foreground" />
              <input
                value={query}
                onChange={e => setQuery(e.target.value)}
                placeholder="Filter groups…"
                className="flex-1 bg-transparent outline-none text-[11.5px] text-foreground placeholder:text-muted-foreground/70"
              />
            </div>
            {canCreate && (
              <button
                onClick={() => setShowCreate(true)}
                className="h-7 w-7 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 flex items-center justify-center"
                title="New group"
              >
                <Plus className="w-[12px] h-[12px]" />
              </button>
            )}
          </div>
          <div className="flex-1 overflow-y-auto scrollbar-thin">
            {loading ? (
              <div className="flex items-center justify-center py-12">
                <LoadingIcon className="w-4 h-4 text-muted-foreground" />
              </div>
            ) : filtered.length === 0 ? (
              <div className="px-4 py-8 text-center text-[11.5px] text-muted-foreground">
                {groups.length === 0 ? 'No groups yet.' : 'No groups match.'}
              </div>
            ) : (
              filtered.map(g => (
                <GroupListItem
                  key={g.id}
                  group={g}
                  scim={scimSources.get(g.id) ?? []}
                  selected={selected?.id === g.id}
                  onSelect={setSelectedId}
                />
              ))
            )}
          </div>
          <div className="shrink-0 h-8 px-3 border-t border-border flex items-center font-mono text-[10.5px] text-muted-foreground">
            {groups.length} groups · {groups.filter(g => g.is_system).length} system
          </div>
        </div>

        {/* Detail */}
        {selected ? (
          <GroupDetailView
            group={selected}
            scim={scimSources.get(selected.id) ?? []}
            members={selectedMembers}
            membersLoading={usersLoading}
            membersUnavailable={usersUnavailable}
            onEdit={() => setEditing(selected)}
            onDelete={() => setPendingDelete(selected)}
          />
        ) : (
          <div className="flex-1 flex items-center justify-center text-[12px] text-muted-foreground">
            {loading ? null : 'Select a group.'}
          </div>
        )}
      </div>

      <CreateGroupDialog
        open={showCreate}
        onClose={() => setShowCreate(false)}
        roles={roles}
        users={users}
        onCreated={async () => {
          setShowCreate(false);
          await fetchAll();
        }}
      />

      <CreateGroupDialog
        open={!!editing}
        editing={editing}
        onClose={() => setEditing(null)}
        roles={roles}
        users={users}
        onCreated={async () => {
          setEditing(null);
          await fetchAll();
        }}
      />

      <ConfirmDialog
        open={!!pendingDelete}
        onOpenChange={(open) => !open && setPendingDelete(null)}
        variant="danger"
        title="Delete group"
        description={
          <>
            Permanently delete <span className="text-foreground font-medium">{pendingDelete?.name}</span>?
            {' '}All members lose this group's role assignment. This cannot be undone.
          </>
        }
        confirmLabel="Delete"
        loadingLabel="Deleting…"
        loading={actionLoading}
        onConfirm={handleDelete}
      />

      {/* Suppress unused-import lint — X is used in the future drag-to-remove
          interaction once the backend exposes member-mutation endpoints. */}
      <X className="hidden" />
    </>
  );
}
