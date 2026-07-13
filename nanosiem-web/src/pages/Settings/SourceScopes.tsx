// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Source Visibility — per-source RBAC scoping (NAN-1802, backend NAN-1789).
 *
 * Master/detail admin surface for the restricted-source registry:
 *   • LEFT   — the restricted-source registry. Each listed `source_type` is
 *              invisible-by-default; add via a picker of ingested source types
 *              (stores the raw string), remove with a ConfirmDialog.
 *   • RIGHT  — for the selected restricted source, its group grants. List
 *              granted groups, add a grant via a group picker, revoke with a
 *              ConfirmDialog. Granting the "Everyone" system group re-opens the
 *              source for all users — surfaced as a distinct "Visible to
 *              everyone" state, not a trick.
 *
 * Model: an EMPTY registry = allow-all (every source visible to everyone).
 * The enforceable unit is the event-borne `source_type` STRING.
 *
 * Read requires `source_scopes:view`; every mutation is gated on
 * `source_scopes:manage` (manage controls are hidden/disabled without it).
 */

import { useEffect, useMemo, useState } from 'react';
import {
  EyeOff,
  Plus,
  Loader2,
  Search as SearchIcon,
  ShieldCheck,
  Users as UsersIcon,
  Globe,
  AlertCircle,
  Trash2,
  Info,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import {
  api,
  EVERYONE_GROUP_ID,
  type RestrictedSource,
  type SourceScopeGrant,
  type GroupDetail,
} from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetFooter,
  SheetTitle,
  SheetDescription,
} from '@/components/ui/sheet';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { formatUTC } from '@/lib/date-utils';

function isEveryone(groupId: string): boolean {
  return groupId === EVERYONE_GROUP_ID;
}

/** Small mono help affordance — replaces inline "coming soon"/roadmap prose. */
function HelpDot({ text }: { text: React.ReactNode }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          className="inline-flex items-center justify-center text-muted-foreground/60 hover:text-muted-foreground transition-colors"
          aria-label="Help"
        >
          <Info className="w-[12px] h-[12px]" />
        </button>
      </TooltipTrigger>
      <TooltipContent side="bottom" className="max-w-[280px] text-[11px] leading-relaxed">
        {text}
      </TooltipContent>
    </Tooltip>
  );
}

// ---------------------------------------------------------------------------
// Registry list item (master)
// ---------------------------------------------------------------------------

function RegistryItem({
  source,
  selected,
  everyoneGranted,
  onSelect,
}: {
  source: RestrictedSource;
  selected: boolean;
  everyoneGranted: boolean | undefined;
  onSelect: (st: string) => void;
}) {
  return (
    <button
      onClick={() => onSelect(source.source_type)}
      className={cn(
        'w-full text-left px-3 py-2.5 border-b border-border/60 flex items-start gap-2.5 transition-colors',
        selected ? 'bg-foreground/[0.04]' : 'hover:bg-foreground/[0.025]',
      )}
    >
      <div className="w-6 h-6 rounded-md bg-card border border-border flex items-center justify-center shrink-0 mt-0.5">
        {everyoneGranted ? (
          <Globe className="w-[12px] h-[12px] text-emerald-500" />
        ) : (
          <EyeOff className="w-[12px] h-[12px] text-amber-500" />
        )}
      </div>
      <div className="min-w-0 flex-1">
        <div className="font-mono text-[12px] text-foreground truncate leading-tight">
          {source.source_type}
        </div>
        {source.description && (
          <div className="text-[11px] text-muted-foreground truncate mt-0.5">{source.description}</div>
        )}
        <div className="flex items-center gap-1.5 mt-1">
          {everyoneGranted ? (
            <span className="inline-flex items-center h-4 px-1.5 rounded-sm text-[9.5px] font-mono bg-emerald-500/12 text-emerald-500">
              Visible to everyone
            </span>
          ) : (
            <span className="inline-flex items-center h-4 px-1.5 rounded-sm text-[9.5px] font-mono bg-amber-500/12 text-amber-500">
              Restricted
            </span>
          )}
        </div>
      </div>
    </button>
  );
}

// ---------------------------------------------------------------------------
// Grants detail (right)
// ---------------------------------------------------------------------------

function GrantsDetail({
  source,
  grants,
  loading,
  canManage,
  onAddGrant,
  onRevoke,
  onRemoveRestricted,
}: {
  source: RestrictedSource;
  grants: SourceScopeGrant[];
  loading: boolean;
  canManage: boolean;
  onAddGrant: () => void;
  onRevoke: (grant: SourceScopeGrant) => void;
  onRemoveRestricted: () => void;
}) {
  const everyoneGrant = grants.find((g) => isEveryone(g.group_id));

  return (
    <div className="flex-1 overflow-y-auto scrollbar-thin">
      {/* Header */}
      <div className="px-6 pt-5 pb-4 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-card border border-border flex items-center justify-center">
            {everyoneGrant ? (
              <Globe className="w-[15px] h-[15px] text-emerald-500" />
            ) : (
              <EyeOff className="w-[15px] h-[15px] text-amber-500" />
            )}
          </div>
          <div className="min-w-0 flex-1">
            <div className="font-mono text-[15px] font-semibold text-foreground tracking-tight leading-none truncate">
              {source.source_type}
            </div>
            {source.description && (
              <div className="text-[12px] text-muted-foreground mt-1 max-w-[520px]">
                {source.description}
              </div>
            )}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {canManage && (
              <Button
                size="sm"
                variant="outline"
                className="h-7 text-[11.5px] px-2.5"
                onClick={onAddGrant}
              >
                <Plus className="w-[11px] h-[11px] mr-1" />
                Grant group
              </Button>
            )}
          </div>
        </div>
      </div>

      {/* Body */}
      <div className="px-6 py-5 flex flex-col gap-6">
        {/* Effective-state banner */}
        {everyoneGrant ? (
          <div className="rounded-md border border-emerald-500/25 bg-emerald-500/5 p-3 flex items-start gap-2.5">
            <Globe className="w-[14px] h-[14px] text-emerald-500 shrink-0 mt-0.5" />
            <div className="text-[11.5px] text-foreground/80 leading-relaxed">
              This source is granted to the{' '}
              <span className="text-foreground font-medium">Everyone</span> group, so it is{' '}
              <span className="text-emerald-500 font-medium">effectively un-restricted</span> — every
              user can see its events. Revoke the Everyone grant to re-restrict it to the specific
              groups below.
            </div>
          </div>
        ) : (
          <div className="rounded-md border border-amber-500/25 bg-amber-500/5 p-3 flex items-start gap-2.5">
            <EyeOff className="w-[14px] h-[14px] text-amber-500 shrink-0 mt-0.5" />
            <div className="text-[11.5px] text-foreground/80 leading-relaxed">
              Invisible by default. Only members of the{' '}
              <span className="text-foreground font-medium">{grants.length}</span> granted group
              {grants.length === 1 ? '' : 's'} below can see events from this source.
            </div>
          </div>
        )}

        {/* Meta grid */}
        <div className="grid grid-cols-3 gap-6">
          <div>
            <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1.5">
              Granted groups
            </div>
            <div className="font-mono text-[12px] text-foreground tabular-nums">{grants.length}</div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1.5">
              Restricted since
            </div>
            <div className="font-mono text-[12px] text-foreground">{formatUTC(source.created_at)}</div>
          </div>
          <div>
            <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1.5">
              Added by
            </div>
            <div className="font-mono text-[12px] text-foreground truncate">
              {source.created_by || '—'}
            </div>
          </div>
        </div>

        {/* Grants table */}
        <div>
          <div className="flex items-center gap-2 mb-2">
            <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium">
              Group grants
            </div>
            <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums">
              {grants.length}
            </span>
            <div className="flex-1" />
          </div>
          <div className="rounded-md border border-border overflow-hidden">
            <div className="grid grid-cols-[20px_minmax(160px,2fr)_minmax(120px,1fr)_120px_28px] gap-3 px-3 py-1.5 bg-card/50 border-b border-border text-[10px] uppercase tracking-[0.08em] text-muted-foreground font-medium">
              <span />
              <span>Group</span>
              <span>Granted by</span>
              <span>Granted</span>
              <span />
            </div>
            {loading ? (
              <div className="px-4 py-6 text-center">
                <Loader2 className="w-4 h-4 animate-spin text-muted-foreground inline" />
              </div>
            ) : grants.length === 0 ? (
              <div className="px-4 py-6 text-center text-[11.5px] text-muted-foreground">
                No groups granted yet — nobody can see this source.
              </div>
            ) : (
              grants.map((g) => {
                const everyone = isEveryone(g.group_id);
                return (
                  <div
                    key={g.group_id}
                    className="grid grid-cols-[20px_minmax(160px,2fr)_minmax(120px,1fr)_120px_28px] gap-3 items-center px-3 h-9 border-b border-border/60 last:border-b-0 hover:bg-foreground/[0.025] transition-colors"
                  >
                    {everyone ? (
                      <Globe className="w-[13px] h-[13px] text-emerald-500" />
                    ) : (
                      <UsersIcon className="w-[13px] h-[13px] text-muted-foreground" />
                    )}
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-[12px] text-foreground truncate">{g.group_name}</span>
                      {everyone && (
                        <span className="inline-flex items-center h-4 px-1.5 rounded-sm text-[9.5px] font-mono bg-emerald-500/12 text-emerald-500 shrink-0">
                          Un-restricted
                        </span>
                      )}
                    </div>
                    <div className="font-mono text-[10.5px] text-muted-foreground truncate">
                      {g.created_by || '—'}
                    </div>
                    <div className="font-mono text-[10.5px] text-muted-foreground truncate">
                      {formatUTC(g.created_at)}
                    </div>
                    {canManage ? (
                      <button
                        onClick={() => onRevoke(g)}
                        className="w-6 h-6 rounded flex items-center justify-center text-muted-foreground hover:text-red-500 hover:bg-red-500/10 transition-colors"
                        title={everyone ? 'Revoke — re-restrict this source' : 'Revoke grant'}
                      >
                        <Trash2 className="w-[12px] h-[12px]" />
                      </button>
                    ) : (
                      <span />
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Danger zone — remove restriction */}
        {canManage && (
          <div className="rounded-md border border-red-500/25 bg-red-500/5 p-3 flex items-center gap-3">
            <AlertCircle className="w-[13px] h-[13px] text-red-500 shrink-0" />
            <div className="flex-1 text-[11.5px] text-foreground/80">
              Removing the restriction deletes all grants and makes{' '}
              <span className="font-mono text-foreground">{source.source_type}</span> visible to
              everyone again.
            </div>
            <button
              onClick={onRemoveRestricted}
              className="text-[11px] text-red-500 hover:underline shrink-0"
            >
              Remove restriction
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Add-restricted dialog
// ---------------------------------------------------------------------------

function AddRestrictedDialog({
  open,
  onOpenChange,
  ingestedTypes,
  alreadyRestricted,
  onCreate,
  saving,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  ingestedTypes: string[];
  alreadyRestricted: Set<string>;
  onCreate: (sourceType: string, description: string) => void;
  saving: boolean;
}) {
  const [sourceType, setSourceType] = useState('');
  const [description, setDescription] = useState('');

  useEffect(() => {
    if (open) {
      setSourceType('');
      setDescription('');
    }
  }, [open]);

  // Suggest ingested types that aren't already restricted, but allow any string.
  const suggestions = useMemo(
    () => ingestedTypes.filter((t) => !alreadyRestricted.has(t)),
    [ingestedTypes, alreadyRestricted],
  );

  const trimmed = sourceType.trim();
  const dup = alreadyRestricted.has(trimmed);
  const canSubmit = trimmed.length > 0 && !dup && !saving;

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="w-full sm:max-w-md gap-0 p-0 bg-card border-border flex flex-col"
      >
        <SheetHeader className="space-y-1.5 border-b border-border px-5 py-4 text-left">
          <SheetTitle className="flex items-center gap-2 text-[14px] font-semibold">
            <EyeOff className="w-[14px] h-[14px] text-amber-500" />
            Restrict a source
          </SheetTitle>
          <SheetDescription className="text-[11.5px] leading-relaxed text-muted-foreground">
            Listing a <span className="font-mono text-foreground/80">source_type</span> hides its
            events from everyone by default. You then grant the groups that should see it.
          </SheetDescription>
        </SheetHeader>

        <div className="px-5 py-4 flex flex-col gap-4 flex-1 overflow-y-auto">
          <div>
            <label className="text-[11px] uppercase tracking-[0.1em] text-muted-foreground font-medium mb-1.5 block">
              Source type
            </label>
            <Input
              value={sourceType}
              onChange={(e) => setSourceType(e.target.value)}
              placeholder="e.g. windows_event_log"
              list="source-scopes-ingested-types"
              className="font-mono text-[12px]"
              autoFocus
            />
            <datalist id="source-scopes-ingested-types">
              {suggestions.map((t) => (
                <option key={t} value={t} />
              ))}
            </datalist>
            {dup ? (
              <div className="text-[10.5px] text-amber-500 mt-1">
                This source is already restricted.
              </div>
            ) : (
              <div className="text-[10.5px] text-muted-foreground/70 mt-1">
                Pick an ingested source type or type any value — the raw string is stored.
              </div>
            )}
          </div>

          <div>
            <label className="text-[11px] uppercase tracking-[0.1em] text-muted-foreground font-medium mb-1.5 block">
              Description <span className="text-muted-foreground/60 normal-case">(optional)</span>
            </label>
            <Input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Why is this source restricted?"
              className="text-[12px]"
            />
          </div>
        </div>

        <SheetFooter className="border-t border-border px-5 py-3">
          <Button
            variant="outline"
            size="sm"
            className="h-8 text-[11.5px]"
            onClick={() => onOpenChange(false)}
            disabled={saving}
          >
            Cancel
          </Button>
          <Button
            size="sm"
            className="h-8 text-[11.5px] gap-1.5"
            disabled={!canSubmit}
            onClick={() => onCreate(trimmed, description.trim())}
          >
            {saving ? (
              <Loader2 className="w-[12px] h-[12px] animate-spin" />
            ) : (
              <EyeOff className="w-[12px] h-[12px]" />
            )}
            Restrict source
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}

// ---------------------------------------------------------------------------
// Add-grant dialog
// ---------------------------------------------------------------------------

function AddGrantDialog({
  open,
  onOpenChange,
  sourceType,
  groups,
  grantedGroupIds,
  onGrant,
  saving,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  sourceType: string;
  groups: GroupDetail[];
  grantedGroupIds: Set<string>;
  onGrant: (groupId: string) => void;
  saving: boolean;
}) {
  const [groupId, setGroupId] = useState('');

  useEffect(() => {
    if (open) setGroupId('');
  }, [open]);

  const available = useMemo(
    () => groups.filter((g) => !grantedGroupIds.has(g.id)),
    [groups, grantedGroupIds],
  );

  const selectedIsEveryone = isEveryone(groupId);
  const canSubmit = groupId.length > 0 && !saving;

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="w-full sm:max-w-md gap-0 p-0 bg-card border-border flex flex-col"
      >
        <SheetHeader className="space-y-1.5 border-b border-border px-5 py-4 text-left">
          <SheetTitle className="flex items-center gap-2 text-[14px] font-semibold">
            <UsersIcon className="w-[14px] h-[14px] text-muted-foreground" />
            Grant group access
          </SheetTitle>
          <SheetDescription className="text-[11.5px] leading-relaxed text-muted-foreground">
            Give a group visibility of{' '}
            <span className="font-mono text-foreground/80">{sourceType}</span>.
          </SheetDescription>
        </SheetHeader>

        <div className="px-5 py-4 flex flex-col gap-3 flex-1 overflow-y-auto">
          <div>
            <label className="text-[11px] uppercase tracking-[0.1em] text-muted-foreground font-medium mb-1.5 block">
              Group
            </label>
            <Select value={groupId} onValueChange={setGroupId}>
              <SelectTrigger className="h-8 text-[12px]">
                <SelectValue placeholder="Select a group…" />
              </SelectTrigger>
              <SelectContent>
                {available.length === 0 ? (
                  <div className="px-2 py-2 text-[11.5px] text-muted-foreground">
                    All groups already granted.
                  </div>
                ) : (
                  available.map((g) => (
                    <SelectItem key={g.id} value={g.id} className="text-[12px]">
                      <span className="flex items-center gap-2">
                        {isEveryone(g.id) ? (
                          <Globe className="w-[12px] h-[12px] text-emerald-500" />
                        ) : (
                          <UsersIcon className="w-[12px] h-[12px] text-muted-foreground" />
                        )}
                        {g.name}
                        {g.is_system && (
                          <span className="font-mono text-[9.5px] text-muted-foreground/70">
                            system
                          </span>
                        )}
                      </span>
                    </SelectItem>
                  ))
                )}
              </SelectContent>
            </Select>
          </div>

          {selectedIsEveryone && (
            <div className="rounded-md border border-emerald-500/25 bg-emerald-500/5 p-2.5 flex items-start gap-2 text-[11px] text-foreground/80 leading-relaxed">
              <Globe className="w-[13px] h-[13px] text-emerald-500 shrink-0 mt-0.5" />
              <span>
                Granting <span className="font-medium text-foreground">Everyone</span> un-restricts
                this source — every user will see its events again.
              </span>
            </div>
          )}
        </div>

        <SheetFooter className="border-t border-border px-5 py-3">
          <Button
            variant="outline"
            size="sm"
            className="h-8 text-[11.5px]"
            onClick={() => onOpenChange(false)}
            disabled={saving}
          >
            Cancel
          </Button>
          <Button
            size="sm"
            className="h-8 text-[11.5px] gap-1.5"
            disabled={!canSubmit}
            onClick={() => onGrant(groupId)}
          >
            {saving ? (
              <Loader2 className="w-[12px] h-[12px] animate-spin" />
            ) : (
              <Plus className="w-[12px] h-[12px]" />
            )}
            Grant access
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function SourceScopes() {
  useDocumentTitle('Source Visibility');
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const canManage = hasPermission('source_scopes:manage');

  const [restricted, setRestricted] = useState<RestrictedSource[]>([]);
  const [groups, setGroups] = useState<GroupDetail[]>([]);
  const [ingestedTypes, setIngestedTypes] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<string | null>(null);

  // Grants for the selected source_type.
  const [grants, setGrants] = useState<SourceScopeGrant[]>([]);
  const [grantsLoading, setGrantsLoading] = useState(false);

  // Everyone-granted status per source_type, resolved lazily as sources are
  // opened, so the master list can render the "Visible to everyone" state.
  const [everyoneMap, setEveryoneMap] = useState<Record<string, boolean>>({});

  const [showAddRestricted, setShowAddRestricted] = useState(false);
  const [showAddGrant, setShowAddGrant] = useState(false);
  const [pendingRemove, setPendingRemove] = useState<RestrictedSource | null>(null);
  const [pendingRevoke, setPendingRevoke] = useState<SourceScopeGrant | null>(null);
  const [saving, setSaving] = useState(false);

  const fetchRestricted = async (keepSelection = true) => {
    setLoading(true);
    try {
      const [res, groupsRes, types] = await Promise.all([
        api.sourceScopes.listRestricted(),
        api.listGroups(),
        api.getSourceTypes().catch(() => [] as [string, number][]),
      ]);
      setRestricted(res.restricted);
      setGroups(groupsRes.groups);
      setIngestedTypes(types.map(([st]) => st));
      if (!keepSelection || selected == null) {
        setSelected(res.restricted[0]?.source_type ?? null);
      } else if (!res.restricted.some((r) => r.source_type === selected)) {
        setSelected(res.restricted[0]?.source_type ?? null);
      }
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to load source scopes',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void fetchRestricted(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Load grants whenever the selection changes.
  useEffect(() => {
    if (selected == null) {
      setGrants([]);
      return;
    }
    let cancelled = false;
    setGrantsLoading(true);
    api.sourceScopes
      .listGrants(selected)
      .then((res) => {
        if (cancelled) return;
        setGrants(res);
        setEveryoneMap((prev) => ({
          ...prev,
          [selected]: res.some((g) => isEveryone(g.group_id)),
        }));
      })
      .catch((err) => {
        if (cancelled) return;
        setGrants([]);
        toast({
          title: 'Error',
          description: err instanceof Error ? err.message : 'Failed to load grants',
          variant: 'destructive',
        });
      })
      .finally(() => {
        if (!cancelled) setGrantsLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return restricted;
    return restricted.filter(
      (r) =>
        r.source_type.toLowerCase().includes(q) ||
        (r.description?.toLowerCase().includes(q) ?? false),
    );
  }, [query, restricted]);

  const selectedSource = restricted.find((r) => r.source_type === selected) ?? null;
  const grantedGroupIds = useMemo(() => new Set(grants.map((g) => g.group_id)), [grants]);
  const restrictedSet = useMemo(
    () => new Set(restricted.map((r) => r.source_type)),
    [restricted],
  );

  const reloadGrants = async (sourceType: string) => {
    setGrantsLoading(true);
    try {
      const res = await api.sourceScopes.listGrants(sourceType);
      setGrants(res);
      setEveryoneMap((prev) => ({
        ...prev,
        [sourceType]: res.some((g) => isEveryone(g.group_id)),
      }));
    } catch {
      /* toast already surfaced by the effect path; keep prior grants */
    } finally {
      setGrantsLoading(false);
    }
  };

  const handleCreateRestricted = async (sourceType: string, description: string) => {
    setSaving(true);
    try {
      await api.sourceScopes.addRestricted({
        source_type: sourceType,
        ...(description ? { description } : {}),
      });
      toast({ title: 'Source restricted', description: `${sourceType} is now invisible by default.` });
      setShowAddRestricted(false);
      await fetchRestricted(false);
      setSelected(sourceType);
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to restrict source',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleRemoveRestricted = async () => {
    if (!pendingRemove) return;
    setSaving(true);
    try {
      await api.sourceScopes.removeRestricted(pendingRemove.source_type);
      toast({
        title: 'Restriction removed',
        description: `${pendingRemove.source_type} is visible to everyone again.`,
      });
      setPendingRemove(null);
      await fetchRestricted(false);
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to remove restriction',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleAddGrant = async (groupId: string) => {
    if (!selected) return;
    setSaving(true);
    try {
      await api.sourceScopes.addGrant({ source_type: selected, group_id: groupId });
      toast({ title: 'Grant added' });
      setShowAddGrant(false);
      await reloadGrants(selected);
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to add grant',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleRevoke = async () => {
    if (!pendingRevoke || !selected) return;
    setSaving(true);
    try {
      await api.sourceScopes.removeGrant(pendingRevoke.source_type, pendingRevoke.group_id);
      toast({ title: 'Grant revoked' });
      setPendingRevoke(null);
      await reloadGrants(selected);
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to revoke grant',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  const modelHelp = (
    <>
      An <span className="font-medium">empty</span> registry means every source is visible to
      everyone (allow-all). Listing a source_type hides it by default; it is then visible only to
      the groups you grant. Granting the <span className="font-medium">Everyone</span> group
      re-opens it for all users.
    </>
  );

  return (
    <TooltipProvider delayDuration={200}>
      <div className="h-full flex flex-col min-h-0">
        {/* Title + subtitle (breadcrumb comes from the global Settings TopBar) */}
        <div className="shrink-0 px-6 pt-5 pb-4 border-b border-border">
          <div className="flex items-center gap-2">
            <h1 className="text-[18px] font-semibold tracking-tight text-foreground">
              Source Visibility
            </h1>
            <HelpDot text={modelHelp} />
          </div>
          <p className="text-[11.5px] text-muted-foreground mt-0.5">
            Restrict which analyst groups can see events from a{' '}
            <span className="font-mono">source_type</span>. Empty registry = visible to everyone.
          </p>
        </div>

        <div className="flex-1 flex min-h-0">
          {/* Master — restricted registry */}
          <div
            className="w-[320px] shrink-0 flex flex-col border-r border-border"
            style={{ background: 'var(--panel)' }}
          >
            <div className="shrink-0 px-3 py-3 flex items-center gap-2 border-b border-border">
              <div className="h-7 flex-1 rounded-md border border-border bg-card flex items-center gap-2 px-2">
                <SearchIcon className="w-[12px] h-[12px] text-muted-foreground" />
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Filter restricted sources…"
                  className="flex-1 bg-transparent outline-none text-[11.5px] text-foreground placeholder:text-muted-foreground/70"
                />
              </div>
              {canManage && (
                <button
                  onClick={() => setShowAddRestricted(true)}
                  className="h-7 w-7 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 flex items-center justify-center"
                  title="Restrict a source"
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
                <div className="px-4 py-10 text-center">
                  <ShieldCheck className="w-8 h-8 text-muted-foreground/40 mx-auto mb-2" />
                  <div className="text-[12px] font-medium text-foreground">
                    {restricted.length === 0 ? 'Nothing restricted' : 'No matches'}
                  </div>
                  <div className="text-[11px] text-muted-foreground mt-1 max-w-[220px] mx-auto leading-relaxed">
                    {restricted.length === 0
                      ? 'Every source is visible to everyone. Restrict a source to scope it to specific groups.'
                      : 'No restricted sources match your filter.'}
                  </div>
                </div>
              ) : (
                filtered.map((r) => (
                  <RegistryItem
                    key={r.source_type}
                    source={r}
                    selected={selected === r.source_type}
                    everyoneGranted={everyoneMap[r.source_type]}
                    onSelect={setSelected}
                  />
                ))
              )}
            </div>
            <div className="shrink-0 h-8 px-3 border-t border-border flex items-center font-mono text-[10.5px] text-muted-foreground">
              {restricted.length} restricted
            </div>
          </div>

          {/* Detail — grants */}
          {selectedSource ? (
            <GrantsDetail
              source={selectedSource}
              grants={grants}
              loading={grantsLoading}
              canManage={canManage}
              onAddGrant={() => setShowAddGrant(true)}
              onRevoke={setPendingRevoke}
              onRemoveRestricted={() => setPendingRemove(selectedSource)}
            />
          ) : (
            <div className="flex-1 flex items-center justify-center text-[12px] text-muted-foreground">
              {loading ? null : restricted.length === 0 ? (
                <div className="text-center max-w-[360px] px-6">
                  <Globe className="w-9 h-9 text-emerald-500/50 mx-auto mb-3" />
                  <div className="text-[13px] font-medium text-foreground">Allow-all</div>
                  <div className="text-[11.5px] text-muted-foreground mt-1 leading-relaxed">
                    No sources are restricted, so every user sees events from every source. Restrict
                    a source to begin scoping visibility to specific groups.
                  </div>
                  {canManage && (
                    <Button
                      size="sm"
                      className="h-8 text-[11.5px] gap-1.5 mt-4"
                      onClick={() => setShowAddRestricted(true)}
                    >
                      <Plus className="w-[12px] h-[12px]" />
                      Restrict a source
                    </Button>
                  )}
                </div>
              ) : (
                'Select a restricted source.'
              )}
            </div>
          )}
        </div>
      </div>

      <AddRestrictedDialog
        open={showAddRestricted}
        onOpenChange={setShowAddRestricted}
        ingestedTypes={ingestedTypes}
        alreadyRestricted={restrictedSet}
        onCreate={handleCreateRestricted}
        saving={saving}
      />

      {selectedSource && (
        <AddGrantDialog
          open={showAddGrant}
          onOpenChange={setShowAddGrant}
          sourceType={selectedSource.source_type}
          groups={groups}
          grantedGroupIds={grantedGroupIds}
          onGrant={handleAddGrant}
          saving={saving}
        />
      )}

      <ConfirmDialog
        open={!!pendingRemove}
        onOpenChange={(open) => !open && setPendingRemove(null)}
        variant="danger"
        title="Remove restriction"
        description={
          <>
            Make <span className="font-mono text-foreground font-medium">{pendingRemove?.source_type}</span>{' '}
            visible to everyone again? All {' '}
            <span className="text-foreground font-medium">group grants for this source are deleted</span>.
            This cannot be undone.
          </>
        }
        confirmLabel="Remove restriction"
        loadingLabel="Removing…"
        loading={saving}
        onConfirm={handleRemoveRestricted}
      />

      <ConfirmDialog
        open={!!pendingRevoke}
        onOpenChange={(open) => !open && setPendingRevoke(null)}
        variant={pendingRevoke && isEveryone(pendingRevoke.group_id) ? 'warning' : 'danger'}
        title="Revoke grant"
        description={
          pendingRevoke && isEveryone(pendingRevoke.group_id) ? (
            <>
              Revoke the <span className="text-foreground font-medium">Everyone</span> grant? This
              re-restricts{' '}
              <span className="font-mono text-foreground font-medium">{pendingRevoke?.source_type}</span>{' '}
              to only the other granted groups.
            </>
          ) : (
            <>
              Revoke <span className="text-foreground font-medium">{pendingRevoke?.group_name}</span>'s
              access to{' '}
              <span className="font-mono text-foreground font-medium">{pendingRevoke?.source_type}</span>?
            </>
          )
        }
        confirmLabel="Revoke"
        loadingLabel="Revoking…"
        loading={saving}
        onConfirm={handleRevoke}
      />
    </TooltipProvider>
  );
}

export default SourceScopes;
