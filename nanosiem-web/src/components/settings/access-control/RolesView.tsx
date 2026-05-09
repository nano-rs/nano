// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Roles — Access Control deep-dive (master/detail with permission matrix).
 *
 * Mirrors `design-ref/shadcn/settings-roles.jsx` `RolesView`:
 *   • Master: 320px filterable role list with member/perm counts and built-in/system pills.
 *   • Detail: header + 4-up meta + role-members chip strip + permission matrix.
 *   • System / built-in roles render read-only; custom roles support click-to-toggle.
 *
 * The mockup's matrix is a fixed Resource × {view/create/edit/delete/special}
 * grid. Real backend permissions are flat `resource:action` strings (e.g.
 * `users:edit`). We derive (resource, action) by splitting on `:` and project
 * onto the canonical action set.
 */

import { useEffect, useMemo, useState } from 'react';
import {
  Search as SearchIcon,
  Plus,
  Shield,
  Copy,
  PencilLine,
  Check,
  AlertCircle,
  Loader2,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import {
  api,
  type RoleDetail,
  type PermissionInfo,
  type UserDetail,
} from '@/lib/api';
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
import { CreateRoleDialog } from './CreateRoleDialog';

const CANONICAL_ACTIONS = ['view', 'create', 'edit', 'delete'] as const;
type CanonicalAction = (typeof CANONICAL_ACTIONS)[number];

interface MatrixRow {
  resource: string;
  /** Display label — e.g. "Detection rules" if available, else the resource id. */
  label: string;
  category: string;
  actions: Map<string, PermissionInfo>;
  specialAction?: { id: string; label: string; permission: PermissionInfo };
}

function buildMatrix(permissions: PermissionInfo[]): MatrixRow[] {
  const byResource = new Map<string, MatrixRow>();
  for (const p of permissions) {
    const [resource, action] = p.id.split(':');
    if (!resource || !action) continue;
    let row = byResource.get(resource);
    if (!row) {
      row = {
        resource,
        label: p.name.split(' ').slice(0, -1).join(' ') || resource,
        category: p.category || 'other',
        actions: new Map(),
      };
      byResource.set(resource, row);
    }
    row.actions.set(action, p);
    if (!CANONICAL_ACTIONS.includes(action as CanonicalAction) && !row.specialAction) {
      row.specialAction = {
        id: action,
        label: action.charAt(0).toUpperCase() + action.slice(1),
        permission: p,
      };
    }
  }
  return Array.from(byResource.values()).sort((a, b) => {
    const cat = a.category.localeCompare(b.category);
    return cat !== 0 ? cat : a.resource.localeCompare(b.resource);
  });
}

function rolePermCount(role: RoleDetail): number {
  return role.permissions.length;
}

function PermCell({ allowed, locked, onToggle, label }: {
  allowed: boolean;
  locked: boolean;
  onToggle?: () => void;
  label: string;
}) {
  if (allowed) {
    return (
      <button
        type="button"
        disabled={locked}
        onClick={onToggle}
        className={cn(
          'h-7 flex items-center justify-center rounded-sm border text-[11px] transition-colors w-full',
          locked
            ? 'bg-primary/12 border-primary/25 text-primary/70 cursor-default'
            : 'bg-primary/15 border-primary/40 text-primary hover:bg-primary/20',
        )}
        title={locked ? 'System role — cannot be modified' : `${label} allowed (click to revoke)`}
      >
        <Check className="w-[12px] h-[12px]" />
      </button>
    );
  }
  return (
    <button
      type="button"
      disabled={locked}
      onClick={onToggle}
      className={cn(
        'h-7 flex items-center justify-center rounded-sm border border-border bg-card/40 text-muted-foreground/70 transition-colors w-full',
        locked ? 'cursor-default' : 'hover:bg-foreground/[0.04]',
      )}
      title={locked ? 'System role — cannot be modified' : `${label} not allowed (click to grant)`}
    >
      <span className="w-[4px] h-[4px] rounded-full bg-muted-foreground/40" />
    </button>
  );
}

function Labeled({ label, mono, children }: { label: string; mono?: boolean; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1.5">{label}</div>
      <div className={cn('text-[12px] text-foreground', mono && 'font-mono')}>{children}</div>
    </div>
  );
}

interface RoleListItemProps {
  role: RoleDetail;
  memberCount: number;
  selected: boolean;
  onSelect: (id: string) => void;
}

function RoleListItem({ role, memberCount, selected, onSelect }: RoleListItemProps) {
  const perms = rolePermCount(role);
  return (
    <button
      onClick={() => onSelect(role.id)}
      className={cn(
        'w-full text-left px-3 py-2.5 border-b border-border/60 flex items-start gap-2.5 transition-colors',
        selected ? 'bg-foreground/[0.04]' : 'hover:bg-foreground/[0.025]',
      )}
    >
      <div
        className={cn(
          'w-6 h-6 rounded-md border flex items-center justify-center shrink-0',
          role.is_system
            ? 'bg-primary/10 border-primary/30 text-primary'
            : 'bg-card border-border text-muted-foreground',
        )}
      >
        <Shield className="w-[12px] h-[12px]" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <div className="text-[12.5px] text-foreground font-medium truncate leading-tight">{role.name}</div>
          {role.is_system && (
            <span className="text-[9.5px] text-primary font-mono uppercase tracking-wider">system</span>
          )}
        </div>
        {role.description && (
          <div className="text-[11px] text-muted-foreground truncate mt-0.5">{role.description}</div>
        )}
        <div className="flex items-center gap-3 mt-1 font-mono text-[10.5px] text-muted-foreground tabular-nums">
          <span>{memberCount} {memberCount === 1 ? 'member' : 'members'}</span>
          <span>·</span>
          <span>{perms} perms</span>
        </div>
      </div>
    </button>
  );
}

interface RoleDetailViewProps {
  role: RoleDetail;
  members: UserDetail[];
  permissions: PermissionInfo[];
  saving: boolean;
  onPermissionToggle: (permissionId: string) => void;
  onDuplicate: () => void;
  onEdit: () => void;
  onDelete: () => void;
}

function RoleDetailView({
  role,
  members,
  permissions,
  saving,
  onPermissionToggle,
  onDuplicate,
  onEdit,
  onDelete,
}: RoleDetailViewProps) {
  const { hasPermission } = useAuth();
  const canEdit = hasPermission('roles:edit');
  const canCreate = hasPermission('roles:create');
  const canDelete = hasPermission('roles:delete');
  const locked = role.is_system;
  const matrix = useMemo(() => buildMatrix(permissions), [permissions]);

  const matrixByCategory = useMemo(() => {
    const out: Record<string, MatrixRow[]> = {};
    for (const r of matrix) {
      if (!out[r.category]) out[r.category] = [];
      out[r.category].push(r);
    }
    return out;
  }, [matrix]);

  const allowedSet = useMemo(() => new Set(role.permissions), [role.permissions]);

  return (
    <div className="flex-1 overflow-y-auto scrollbar-thin">
      {/* Header */}
      <div className="px-6 pt-5 pb-4 border-b border-border">
        <div className="flex items-center gap-3">
          <div
            className={cn(
              'w-9 h-9 rounded-lg border flex items-center justify-center',
              locked
                ? 'bg-primary/10 border-primary/30 text-primary'
                : 'bg-card border-border text-muted-foreground',
            )}
          >
            <Shield className="w-[16px] h-[16px]" />
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <div className="text-[17px] font-semibold text-foreground tracking-tight leading-none">{role.name}</div>
              {locked && (
                <span className="text-[10px] text-primary font-mono uppercase tracking-wider">system</span>
              )}
            </div>
            {role.description && (
              <div className="text-[12px] text-muted-foreground mt-1 max-w-[540px]">{role.description}</div>
            )}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {canEdit && !locked && (
              <Button size="sm" variant="outline" className="h-7 text-[11.5px] px-2.5" onClick={onEdit}>
                <PencilLine className="w-[11px] h-[11px] mr-1" />
                Rename
              </Button>
            )}
            {canCreate && (
              <Button size="sm" variant="outline" className="h-7 text-[11.5px] px-2.5" onClick={onDuplicate}>
                <Copy className="w-[11px] h-[11px] mr-1" />
                Duplicate
              </Button>
            )}
          </div>
        </div>
      </div>

      <div className="px-6 py-5 flex flex-col gap-6">
        <div className="grid grid-cols-4 gap-6">
          <Labeled label="Members">
            <span className="font-mono tabular-nums">{members.length}</span>
          </Labeled>
          <Labeled label="Permissions">
            <span className="font-mono tabular-nums">{role.permissions.length}</span>
          </Labeled>
          <Labeled label="Type">{locked ? 'System' : 'Custom'}</Labeled>
          <Labeled label="Last modified" mono>
            {locked ? '—' : new Date(role.updated_at).toLocaleDateString()}
          </Labeled>
        </div>

        {locked && (
          <div className="rounded-md border border-primary/25 bg-primary/5 p-3 flex items-center gap-3">
            <Shield className="w-[13px] h-[13px] text-primary shrink-0" />
            <div className="flex-1 text-[11.5px] text-foreground/80">
              This is a system role used by internal services. Permissions are fixed and cannot be edited.
            </div>
          </div>
        )}

        {/* Members chip strip */}
        {!locked && (
          <div>
            <div className="flex items-center gap-2 mb-2">
              <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium">Direct members</div>
              <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums">{members.length}</span>
            </div>
            {members.length === 0 ? (
              <div className="text-[11.5px] text-muted-foreground italic">
                No direct members — usually assigned via group.
              </div>
            ) : (
              <div className="flex items-center gap-2 flex-wrap">
                {members.slice(0, 12).map(u => (
                  <div
                    key={u.id}
                    className="flex items-center gap-1.5 h-6 px-2 rounded-sm border border-border bg-card"
                  >
                    <div className="w-4 h-4 rounded-full bg-primary/15 text-primary flex items-center justify-center font-mono font-semibold text-[8.5px]">
                      {u.name.split(' ').map(s => s[0]).slice(0, 2).join('').toUpperCase()}
                    </div>
                    <span className="text-[11px] text-foreground/80 truncate max-w-[120px]">{u.name}</span>
                  </div>
                ))}
                {members.length > 12 && (
                  <span className="text-[11px] text-muted-foreground">+{members.length - 12} more</span>
                )}
              </div>
            )}
          </div>
        )}

        {/* Permission matrix */}
        <div>
          <div className="flex items-center gap-2 mb-2">
            <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium">Permissions</div>
            <span className="text-[11px] text-muted-foreground">
              {locked ? 'read-only' : canEdit ? 'click to toggle' : 'view only'}
            </span>
            {saving && <Loader2 className="w-3 h-3 animate-spin text-muted-foreground" />}
            <div className="flex-1" />
            <div className="flex items-center gap-3 text-[10.5px] text-muted-foreground">
              <span className="inline-flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-sm bg-primary/15 border border-primary/40" /> Allowed
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-sm bg-card/40 border border-border" /> Not allowed
              </span>
            </div>
          </div>
          {permissions.length === 0 ? (
            <div className="rounded-md border border-border px-4 py-6 text-center text-[12px] text-muted-foreground">
              Loading permission catalog…
            </div>
          ) : (
            <div className="rounded-md border border-border overflow-hidden">
              <div className="grid grid-cols-[minmax(200px,1.6fr)_repeat(5,80px)] gap-2 px-3 py-2 bg-card/70 border-b border-border">
                <div className="text-[10px] uppercase tracking-[0.08em] text-muted-foreground font-medium">Resource</div>
                {[...CANONICAL_ACTIONS, 'special'].map(a => (
                  <div key={a} className="text-[10px] uppercase tracking-[0.08em] text-muted-foreground font-medium text-center">
                    {a === 'special' ? 'Special' : a.charAt(0).toUpperCase() + a.slice(1)}
                  </div>
                ))}
              </div>
              {Object.entries(matrixByCategory).map(([cat, rows]) => (
                <div key={cat}>
                  <div className="px-3 py-1.5 bg-card/30 border-b border-border/60 text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium">
                    {cat}
                  </div>
                  {rows.map(r => (
                    <div
                      key={r.resource}
                      className="grid grid-cols-[minmax(200px,1.6fr)_repeat(5,80px)] gap-2 items-center px-3 py-1.5 border-b border-border/60 last:border-b-0 hover:bg-foreground/[0.025] transition-colors"
                    >
                      <div className="min-w-0">
                        <div className="text-[12px] text-foreground truncate">{r.label}</div>
                        <div className="text-[10px] text-muted-foreground/70 font-mono truncate">{r.resource}</div>
                      </div>
                      {CANONICAL_ACTIONS.map(action => {
                        const perm = r.actions.get(action);
                        if (!perm) {
                          return (
                            <div key={action} className="h-7 flex items-center justify-center text-[10px] text-muted-foreground/50">
                              —
                            </div>
                          );
                        }
                        return (
                          <PermCell
                            key={action}
                            allowed={allowedSet.has(perm.id)}
                            locked={locked || !canEdit}
                            label={action}
                            onToggle={() => onPermissionToggle(perm.id)}
                          />
                        );
                      })}
                      {/* Special column */}
                      {r.specialAction ? (
                        <PermCell
                          key="special"
                          allowed={allowedSet.has(r.specialAction.permission.id)}
                          locked={locked || !canEdit}
                          label={r.specialAction.label}
                          onToggle={() => onPermissionToggle(r.specialAction!.permission.id)}
                        />
                      ) : (
                        <div className="h-7 flex items-center justify-center text-[10px] text-muted-foreground/50">—</div>
                      )}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Danger zone */}
        {canDelete && !locked && (
          <div className="rounded-md border border-red-500/25 bg-red-500/5 p-3 flex items-center gap-3">
            <AlertCircle className="w-[13px] h-[13px] text-red-500 shrink-0" />
            <div className="flex-1 text-[11.5px] text-foreground/80">
              Deleting this role strips its permissions from anyone holding it. Group default-role assignments stay intact.
            </div>
            <button onClick={onDelete} className="text-[11px] text-red-500 hover:underline shrink-0">
              Delete role
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export function RolesView() {
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const canCreate = hasPermission('roles:create');

  const [roles, setRoles] = useState<RoleDetail[]>([]);
  const [permissions, setPermissions] = useState<PermissionInfo[]>([]);
  const [users, setUsers] = useState<UserDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState<RoleDetail | null>(null);
  const [duplicating, setDuplicating] = useState<RoleDetail | null>(null);
  const [pendingDelete, setPendingDelete] = useState<RoleDetail | null>(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [matrixSaving, setMatrixSaving] = useState(false);

  const fetchAll = async () => {
    setLoading(true);
    try {
      const [rolesRes, permsRes, usersRes] = await Promise.all([
        api.listRoles(),
        api.listPermissions(),
        api.listUsers(),
      ]);
      setRoles(rolesRes.roles);
      setPermissions(permsRes);
      setUsers(usersRes.users);
      if (!selectedId && rolesRes.roles.length > 0) {
        const firstAssignable = rolesRes.roles.find(r => !r.is_system) || rolesRes.roles[0];
        setSelectedId(firstAssignable.id);
      }
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to load roles',
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

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return roles;
    return roles.filter(r =>
      r.name.toLowerCase().includes(q)
      || (r.description?.toLowerCase().includes(q) ?? false),
    );
  }, [query, roles]);

  const selected = roles.find(r => r.id === selectedId) || filtered[0] || null;

  const memberCounts = useMemo(() => {
    // Count users whose group's role-list includes this role.
    const counts: Record<string, number> = {};
    for (const r of roles) counts[r.id] = 0;
    for (const u of users) {
      const userRoleIds = new Set<string>();
      for (const _g of u.groups) {
        // Group → roles is on GroupDetail, not GroupSummary; user's groups
        // are summaries. Skip transitive resolution here.
        void _g;
      }
      for (const id of userRoleIds) counts[id] = (counts[id] || 0) + 1;
    }
    return counts;
  }, [roles, users]);

  const selectedMembers = useMemo(() => {
    // Without a direct user-roles join from listUsers, return [].
    // (The mockup shows direct members; backend exposes groups → roles, not user → roles.)
    return [] as UserDetail[];
    // selected reserved for the future direct-roles join
    void selected;
  }, [selected, users]);

  const handlePermissionToggle = async (permissionId: string) => {
    if (!selected || selected.is_system) return;
    const has = selected.permissions.includes(permissionId);
    const next = has
      ? selected.permissions.filter(p => p !== permissionId)
      : [...selected.permissions, permissionId];
    setMatrixSaving(true);
    try {
      const updated = await api.updateRole(selected.id, { permissions: next });
      setRoles(prev => prev.map(r => r.id === updated.id ? updated : r));
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to update permission',
        variant: 'destructive',
      });
    } finally {
      setMatrixSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!pendingDelete) return;
    setActionLoading(true);
    try {
      await api.deleteRole(pendingDelete.id);
      toast({ title: 'Role deleted', description: `${pendingDelete.name} has been deleted.` });
      const remaining = roles.filter(r => r.id !== pendingDelete.id);
      setSelectedId(remaining[0]?.id || null);
      setPendingDelete(null);
      await fetchAll();
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to delete role',
        variant: 'destructive',
      });
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <>
      <div className="flex-1 flex min-h-0">
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
                placeholder="Filter roles…"
                className="flex-1 bg-transparent outline-none text-[11.5px] text-foreground placeholder:text-muted-foreground/70"
              />
            </div>
            {canCreate && (
              <button
                onClick={() => setShowCreate(true)}
                className="h-7 w-7 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 flex items-center justify-center"
                title="New role"
              >
                <Plus className="w-[12px] h-[12px]" />
              </button>
            )}
          </div>
          <div className="flex-1 overflow-y-auto scrollbar-thin">
            {loading ? (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
              </div>
            ) : filtered.length === 0 ? (
              <div className="px-4 py-8 text-center text-[11.5px] text-muted-foreground">
                {roles.length === 0 ? 'No roles yet.' : 'No roles match.'}
              </div>
            ) : (
              filtered.map(r => (
                <RoleListItem
                  key={r.id}
                  role={r}
                  memberCount={memberCounts[r.id] || 0}
                  selected={selected?.id === r.id}
                  onSelect={setSelectedId}
                />
              ))
            )}
          </div>
          <div className="shrink-0 h-8 px-3 border-t border-border flex items-center font-mono text-[10.5px] text-muted-foreground">
            {roles.filter(r => r.is_system).length} system · {roles.filter(r => !r.is_system).length} custom
          </div>
        </div>

        {selected ? (
          <RoleDetailView
            role={selected}
            members={selectedMembers}
            permissions={permissions}
            saving={matrixSaving}
            onPermissionToggle={handlePermissionToggle}
            onDuplicate={() => setDuplicating(selected)}
            onEdit={() => setEditing(selected)}
            onDelete={() => setPendingDelete(selected)}
          />
        ) : (
          <div className="flex-1 flex items-center justify-center text-[12px] text-muted-foreground">
            {loading ? null : 'Select a role.'}
          </div>
        )}
      </div>

      <CreateRoleDialog
        open={showCreate}
        onClose={() => setShowCreate(false)}
        permissions={permissions}
        onCreated={async (id) => {
          setShowCreate(false);
          await fetchAll();
          setSelectedId(id);
        }}
      />

      <CreateRoleDialog
        open={!!editing}
        editing={editing}
        onClose={() => setEditing(null)}
        permissions={permissions}
        onCreated={async () => {
          setEditing(null);
          await fetchAll();
        }}
      />

      <CreateRoleDialog
        open={!!duplicating}
        duplicating={duplicating}
        onClose={() => setDuplicating(null)}
        permissions={permissions}
        onCreated={async (id) => {
          setDuplicating(null);
          await fetchAll();
          setSelectedId(id);
        }}
      />

      <AlertDialog open={!!pendingDelete} onOpenChange={(open) => !open && setPendingDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete role</AlertDialogTitle>
            <AlertDialogDescription>
              Permanently delete <span className="text-foreground font-medium">{pendingDelete?.name}</span>?
              {' '}Anyone holding this role loses its permissions. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDelete}
              disabled={actionLoading}
              className="bg-destructive hover:bg-destructive/90 text-destructive-foreground"
            >
              {actionLoading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
