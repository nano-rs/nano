// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Create / Edit / Duplicate Role dialog.
 * Mirrors `design-ref/shadcn/settings-create-role.jsx` (760px) but slims the
 * permission picker into a categorised checklist with category-level
 * select-all/clear — the full matrix toggle lives in the detail view.
 */

import { useEffect, useMemo, useState } from 'react';
import { Shield, Loader2, Check } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import {
  api,
  type RoleDetail,
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

interface CreateRoleDialogProps {
  open: boolean;
  /** Edit mode — hydrate from this role and call updateRole on submit. */
  editing?: RoleDetail | null;
  /** Duplicate mode — hydrate permissions from this role; create a new one. */
  duplicating?: RoleDetail | null;
  permissions: PermissionInfo[];
  onClose: () => void;
  onCreated: (id: string) => void | Promise<void>;
}

export function CreateRoleDialog({
  open,
  editing,
  duplicating,
  permissions,
  onClose,
  onCreated,
}: CreateRoleDialogProps) {
  const { toast } = useToast();
  const isEditing = !!editing;
  const isDuplicating = !!duplicating;
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [permIds, setPermIds] = useState<Set<string>>(new Set());
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open) return;
    if (editing) {
      setName(editing.name);
      setDescription(editing.description || '');
      setPermIds(new Set(editing.permissions));
    } else if (duplicating) {
      setName(`${duplicating.name} (copy)`);
      setDescription(duplicating.description || '');
      setPermIds(new Set(duplicating.permissions));
    } else {
      setName('');
      setDescription('');
      setPermIds(new Set());
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, editing?.id, duplicating?.id]);

  const groupedPermissions = useMemo(() => {
    const out: Record<string, PermissionInfo[]> = {};
    for (const p of permissions) {
      const cat = p.category || 'other';
      if (!out[cat]) out[cat] = [];
      out[cat].push(p);
    }
    for (const c of Object.keys(out)) {
      out[c].sort((a, b) => a.id.localeCompare(b.id));
    }
    return out;
  }, [permissions]);

  const togglePerm = (id: string) => {
    setPermIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const setCategory = (cat: string, on: boolean) => {
    setPermIds(prev => {
      const next = new Set(prev);
      for (const p of groupedPermissions[cat] || []) {
        if (on) next.add(p.id);
        else next.delete(p.id);
      }
      return next;
    });
  };

  const nameValid = name.trim().length >= 2;
  const permsValid = permIds.size > 0;
  const canSubmit = nameValid && permsValid && !saving;

  const handleSubmit = async () => {
    if (!canSubmit) return;
    setSaving(true);
    try {
      const payload = {
        name: name.trim(),
        description: description.trim() || undefined,
        permissions: [...permIds],
      };
      let id: string;
      if (isEditing && editing) {
        const updated = await api.updateRole(editing.id, payload);
        id = updated.id;
      } else {
        const created = await api.createRole(payload);
        id = created.id;
      }
      toast({
        title: isEditing ? 'Role updated' : 'Role created',
        description: `${payload.name} · ${permIds.size} permission(s)`,
      });
      await onCreated(id);
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to save role',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  const title = isEditing
    ? 'Edit role'
    : isDuplicating
    ? `Duplicate ${duplicating?.name}`
    : 'New role';

  return (
    <Sheet open={open} onOpenChange={(v) => !v && !saving && onClose()}>
      <SheetContent side="right" className="w-[720px] sm:max-w-[720px] p-0 gap-0 flex flex-col">
        <SheetHeader className="px-5 py-3.5 border-b border-border flex flex-row items-center gap-3 space-y-0 pr-12">
          <div className="w-8 h-8 rounded-md bg-primary/12 text-primary flex items-center justify-center shrink-0">
            <Shield className="w-[14px] h-[14px]" />
          </div>
          <div className="flex-1 min-w-0">
            <SheetTitle className="text-[14px] font-semibold leading-none">{title}</SheetTitle>
            <SheetDescription className="text-[11px] text-muted-foreground mt-1">
              Roles are reusable permission sets. Assign them to groups; users inherit through group membership.
            </SheetDescription>
          </div>
        </SheetHeader>

        <div className="overflow-y-auto scrollbar-thin px-5 py-4 flex flex-col gap-4 flex-1 min-h-0">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[11px] font-medium text-foreground/80 mb-1.5">Name</label>
              <input
                autoFocus
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="e.g. Threat Hunter"
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
                placeholder="One-line summary"
                className="w-full h-8 px-2.5 rounded-md border border-border bg-card text-[12px] text-foreground placeholder:text-muted-foreground/70 outline-none focus:border-primary/60"
              />
            </div>
          </div>

          <div>
            <div className="flex items-center gap-2 mb-2">
              <label className="text-[11px] font-medium text-foreground/80">Permissions</label>
              <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums">{permIds.size}</span>
              <div className="flex-1" />
              <button
                type="button"
                onClick={() => setPermIds(new Set(permissions.map(p => p.id)))}
                className="text-[10.5px] text-muted-foreground hover:text-foreground"
              >
                Select all
              </button>
              <span className="text-[10.5px] text-muted-foreground/40">·</span>
              <button
                type="button"
                onClick={() => setPermIds(new Set())}
                className="text-[10.5px] text-muted-foreground hover:text-foreground"
              >
                Clear
              </button>
            </div>

            {permissions.length === 0 ? (
              <div className="rounded-md border border-border px-4 py-6 text-center text-[12px] text-muted-foreground">
                Loading permission catalog…
              </div>
            ) : (
              <div className="rounded-md border border-border overflow-hidden divide-y divide-border/60">
                {Object.entries(groupedPermissions).map(([cat, perms]) => {
                  const allOn = perms.every(p => permIds.has(p.id));
                  const someOn = perms.some(p => permIds.has(p.id));
                  return (
                    <div key={cat}>
                      <div className="flex items-center gap-2 px-3 py-1.5 bg-card/50">
                        <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium">{cat}</div>
                        <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums">
                          {perms.filter(p => permIds.has(p.id)).length}/{perms.length}
                        </span>
                        <div className="flex-1" />
                        <button
                          type="button"
                          onClick={() => setCategory(cat, !allOn)}
                          className="text-[10.5px] text-muted-foreground hover:text-foreground"
                        >
                          {allOn ? 'Clear category' : someOn ? 'Select all in category' : 'Select all'}
                        </button>
                      </div>
                      <div className="grid grid-cols-2 gap-x-4">
                        {perms.map(p => {
                          const on = permIds.has(p.id);
                          return (
                            <button
                              key={p.id}
                              type="button"
                              role="checkbox"
                              aria-checked={on}
                              aria-label={`${p.id}${p.description ? ` — ${p.description}` : ''}`}
                              onClick={() => togglePerm(p.id)}
                              className={cn(
                                'flex items-center gap-2 px-3 h-8 transition-colors text-left',
                                on ? 'bg-primary/8' : 'hover:bg-foreground/[0.025]',
                              )}
                            >
                              <div className={cn(
                                'w-3.5 h-3.5 rounded-sm border flex items-center justify-center shrink-0',
                                on ? 'border-primary bg-primary text-primary-foreground' : 'border-border bg-card',
                              )}>
                                {on && <Check className="w-[9px] h-[9px]" />}
                              </div>
                              <div className="min-w-0 flex-1">
                                <div className="font-mono text-[11px] text-foreground truncate">{p.id}</div>
                                {p.description && (
                                  <div className="text-[10.5px] text-muted-foreground truncate leading-tight">{p.description}</div>
                                )}
                              </div>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        <SheetFooter className="border-t border-border px-5 py-3 flex flex-row items-center gap-2 sm:justify-end space-x-0">
          <div className="text-[10.5px] text-muted-foreground mr-auto">
            {permIds.size} permission(s) selected · changes apply immediately on save.
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} className="h-7 text-[11.5px]" disabled={saving}>
            Cancel
          </Button>
          <Button size="sm" onClick={handleSubmit} disabled={!canSubmit} className="h-7 text-[11.5px]">
            {saving && <Loader2 className="w-3 h-3 mr-1 animate-spin" />}
            {isEditing ? 'Save role' : isDuplicating ? 'Create copy' : 'Create role'}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
