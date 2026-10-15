// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Source visibility — hosted-shared lake (NAN-2361 wave 8).
 *
 * On the lake every event carries `metadata.log_source`: the slug of the
 * ingest route it arrived on (`hec_windows`, `otlp_trace`, …). Events with no
 * declared source are stored as `unknown`; the model restricts the same
 * bucket as `default`. They are ONE option here, "Unattributed" (NAN-2602):
 * restricting it hides both spellings.
 * Visibility is GROUP-based — a restriction is (group, source): members of
 * that group cannot see events from the source. Per-member exceptions
 * (`restrict` / `allow`) handle one-offs. Everything is visible by default.
 *
 *   rows    = the tenant's real sources (mono slugs, plus Unattributed)
 *   columns = the tenant's groups
 *   cell    = restricted toggle
 *   drawer  = a member's exceptions + their effective (computed) view
 *
 * Read requires `source_scopes:view`; every mutation `source_scopes:manage`.
 */

import { Fragment, useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { AlertCircle, Eye, EyeOff, KeyRound, Search as SearchIcon, ShieldCheck, UserCog, Users as UsersIcon, X } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { cn } from '@/lib/utils';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import { useSharedTenant } from '@/hooks/use-shared-tenant';
import { SourceWritersCard } from '@/components/add-data/SourceWritersCard';
import {
  api,
  type SourceVisibilityModel,
  type VisibilityMember,
  type MemberSourceExceptionInput,
  type SourceExceptionMode,
} from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { formatUTC } from '@/lib/date-utils';

function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

function protocolLabel(protocol: string): string {
  switch (protocol) {
    case 'hec':
      return 'HEC';
    case 'otlp_http':
      return 'OTLP';
    case 'nano_https':
      return 'HTTPS';
    case 'default':
      return 'unknown · default';
    case 'observed':
      return 'observed';
    case 'registry':
      return 'registry';
    case 'restricted':
      return 'not seen';
    default:
      return protocol;
  }
}

/**
 * NAN-2602: the Unattributed label. Stored rows with no declared source carry
 * `unknown`; the model restricts `default`. Both spellings are ONE label:
 * restricting either hides both.
 */
const UNATTRIBUTED_SLUG = 'default';
const UNATTRIBUTED_ALIASES = ['default', 'unknown'];

function canonicalSlug(slug: string): string {
  const s = slug.trim().toLowerCase();
  return UNATTRIBUTED_ALIASES.includes(s) ? UNATTRIBUTED_SLUG : s;
}

/** Display name: "Unattributed" for either spelling, the slug otherwise. */
function sourceLabel(slug: string): string {
  return canonicalSlug(slug) === UNATTRIBUTED_SLUG ? 'Unattributed' : slug;
}

function isUnattributed(slug: string): boolean {
  return canonicalSlug(slug) === UNATTRIBUTED_SLUG;
}

/**
 * Effective deny set — the same rule the API and the search service apply
 * (groups ∪ restrict − allow, over canonical slugs, then Unattributed expanded
 * to both spellings), so it compares equal to the server's set.
 */
function effectiveDenied(fromGroups: Iterable<string>, exceptions: MemberSourceExceptionInput[]): string[] {
  const denied = new Set([...fromGroups].map(canonicalSlug));
  for (const e of exceptions) if (e.mode === 'restrict') denied.add(canonicalSlug(e.source_slug));
  for (const e of exceptions) if (e.mode === 'allow') denied.delete(canonicalSlug(e.source_slug));
  if (denied.has(UNATTRIBUTED_SLUG)) for (const alias of UNATTRIBUTED_ALIASES) denied.add(alias);
  return [...denied].sort();
}

/** One chip per label: the `unknown` spelling folds into Unattributed. */
function displaySlugs(slugs: string[]): string[] {
  return slugs.filter((s) => !(s === 'unknown' && slugs.includes(UNATTRIBUTED_SLUG)));
}

function effectiveFor(model: SourceVisibilityModel, member: VisibilityMember): string[] {
  if (member.view_all) return [];
  const groups = new Set(member.group_ids);
  return effectiveDenied(
    model.restrictions.filter((r) => groups.has(r.group_id)).map((r) => r.source_slug),
    model.exceptions.filter((e) => e.user_id === member.id),
  );
}

// ---------------------------------------------------------------------------
// Member exceptions drawer
// ---------------------------------------------------------------------------

function ExceptionsDrawer({
  open,
  onOpenChange,
  model,
  member,
  canManage,
  onSaved,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  model: SourceVisibilityModel;
  member: VisibilityMember | null;
  canManage: boolean;
  onSaved: () => Promise<void>;
}) {
  const { toast } = useToast();
  const [draft, setDraft] = useState<MemberSourceExceptionInput[]>([]);
  const [slug, setSlug] = useState('');
  const [mode, setMode] = useState<SourceExceptionMode>('restrict');
  const [saving, setSaving] = useState(false);
  const [serverEffective, setServerEffective] = useState<string[] | null>(null);

  useEffect(() => {
    if (!open || !member) return;
    setDraft(
      model.exceptions
        .filter((e) => e.user_id === member.id)
        .map((e) => ({ source_slug: e.source_slug, mode: e.mode })),
    );
    setSlug('');
    setMode('restrict');
    setServerEffective(null);
    api.sourceVisibility
      .effective(member.id)
      .then((r) => setServerEffective(r.restricted_sources))
      .catch(() => setServerEffective(null));
  }, [open, member, model.exceptions]);

  if (!member) return null;

  const groupsOf = model.groups.filter((g) => member.group_ids.includes(g.id));
  const fromGroups = new Set(
    model.restrictions.filter((r) => member.group_ids.includes(r.group_id)).map((r) => canonicalSlug(r.source_slug)),
  );
  const preview = member.view_all ? [] : effectiveDenied(fromGroups, draft);
  const previewLabels = displaySlugs(preview);
  const dirty =
    JSON.stringify(draft) !==
    JSON.stringify(
      model.exceptions.filter((e) => e.user_id === member.id).map((e) => ({ source_slug: e.source_slug, mode: e.mode })),
    );
  const available = model.sources
    .map((s) => s.slug)
    .filter((s) => !draft.some((d) => canonicalSlug(d.source_slug) === canonicalSlug(s)));

  const addException = () => {
    if (!slug) return;
    setDraft((d) => [...d.filter((e) => canonicalSlug(e.source_slug) !== canonicalSlug(slug)), { source_slug: slug, mode }]);
    setSlug('');
  };

  const save = async () => {
    setSaving(true);
    try {
      await api.sourceVisibility.setMemberExceptions(member.id, { exceptions: draft });
      toast({ title: 'Exceptions saved', description: `${member.name || member.email}: ${draft.length} exception${draft.length === 1 ? '' : 's'}.` });
      await onSaved();
      onOpenChange(false);
    } catch (err) {
      toast({ title: 'Error', description: err instanceof Error ? err.message : 'Failed to save exceptions', variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-lg gap-0 p-0 bg-card border-border flex flex-col">
        <SheetHeader className="space-y-1.5 border-b border-border px-5 py-4 text-left">
          <SheetTitle className="flex items-center gap-2 text-[14px] font-semibold">
            <UserCog className="w-[14px] h-[14px] text-muted-foreground" />
            Exceptions for {member.name || member.email}
          </SheetTitle>
          <SheetDescription className="text-[11.5px] leading-relaxed text-muted-foreground">
            One-off overrides for this member only. <span className="text-foreground/80">restrict</span> hides a
            source regardless of groups; <span className="text-foreground/80">allow</span> shows it regardless of groups.
          </SheetDescription>
        </SheetHeader>

        <div className="px-5 py-4 flex flex-col gap-5 flex-1 overflow-y-auto scrollbar-thin">
          {/* Member facts */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1">Member</div>
              <div className="font-mono text-[11px] text-foreground truncate">{member.email}</div>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1">Groups</div>
              <div className="text-[11.5px] text-foreground truncate">
                {groupsOf.length === 0 ? <span className="text-muted-foreground">none</span> : groupsOf.map((g) => g.name).join(', ')}
              </div>
            </div>
          </div>

          {member.view_all && (
            <div className="rounded-md border border-emerald-500/25 bg-emerald-500/5 p-3 flex items-start gap-2.5">
              <Eye className="w-[14px] h-[14px] text-emerald-500 shrink-0 mt-0.5" />
              <div className="text-[11.5px] text-foreground/80 leading-relaxed">
                Holds <span className="font-mono">source_scopes:view_all</span>: sees every source. Group restrictions and
                exceptions do not apply to this member.
              </div>
            </div>
          )}

          {/* Exceptions editor */}
          <div>
            <div className="flex items-center gap-2 mb-2">
              <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium">Exceptions</div>
              <span className="font-mono text-[10px] text-muted-foreground/70 tabular-nums">{draft.length}</span>
            </div>
            <div className="rounded-md border border-border overflow-hidden">
              {draft.length === 0 ? (
                <div className="px-3 py-4 text-center text-[11.5px] text-muted-foreground">No exceptions — groups decide.</div>
              ) : (
                draft.map((e) => (
                  <div
                    key={e.source_slug}
                    className="grid grid-cols-[1fr_96px_28px] gap-2 items-center px-3 h-8 border-b border-border/60 last:border-b-0"
                  >
                    <span className={cn('text-[11.5px] text-foreground truncate', !isUnattributed(e.source_slug) && 'font-mono')}>
                      {sourceLabel(e.source_slug)}
                    </span>
                    <span
                      className={cn(
                        'inline-flex items-center justify-center h-4 px-1.5 rounded-sm text-[9.5px] font-mono',
                        e.mode === 'restrict' ? 'bg-amber-500/12 text-amber-500' : 'bg-emerald-500/12 text-emerald-500',
                      )}
                    >
                      {e.mode}
                    </span>
                    {canManage ? (
                      <button
                        onClick={() => setDraft((d) => d.filter((x) => x.source_slug !== e.source_slug))}
                        className="w-6 h-6 rounded flex items-center justify-center text-muted-foreground hover:text-red-500 hover:bg-red-500/10"
                        title="Remove exception"
                      >
                        <X className="w-[12px] h-[12px]" />
                      </button>
                    ) : (
                      <span />
                    )}
                  </div>
                ))
              )}
            </div>
            {canManage && (
              <div className="mt-2 grid grid-cols-[1fr_110px_auto] gap-2">
                <Select value={slug} onValueChange={setSlug}>
                  <SelectTrigger className="h-8 text-[12px] font-mono">
                    <SelectValue placeholder="Source…" />
                  </SelectTrigger>
                  <SelectContent>
                    {available.length === 0 ? (
                      <div className="px-2 py-2 text-[11.5px] text-muted-foreground">Every source already has an exception.</div>
                    ) : (
                      available.map((s) => (
                        <SelectItem key={s} value={s} className={cn('text-[12px]', !isUnattributed(s) && 'font-mono')}>
                          {sourceLabel(s)}
                        </SelectItem>
                      ))
                    )}
                  </SelectContent>
                </Select>
                <Select value={mode} onValueChange={(v) => setMode(v as SourceExceptionMode)}>
                  <SelectTrigger className="h-8 text-[12px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="restrict" className="text-[12px]">restrict</SelectItem>
                    <SelectItem value="allow" className="text-[12px]">allow</SelectItem>
                  </SelectContent>
                </Select>
                <Button size="sm" variant="outline" className="h-8 text-[11.5px]" disabled={!slug} onClick={addException}>
                  Add
                </Button>
              </div>
            )}
          </div>

          {/* Effective view */}
          <div>
            <div className="flex items-center gap-2 mb-2">
              <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium">Effective view</div>
              {dirty && <span className="font-mono text-[9.5px] text-amber-500">preview (unsaved)</span>}
            </div>
            <div className="rounded-md border border-border p-3">
              {previewLabels.length === 0 ? (
                <div className="flex items-center gap-2 text-[11.5px] text-foreground/80">
                  <Eye className="w-[13px] h-[13px] text-emerald-500" />
                  Sees every source.
                </div>
              ) : (
                <div className="flex flex-col gap-1.5">
                  <div className="text-[11.5px] text-foreground/80">
                    Cannot see events from <span className="text-foreground font-medium">{previewLabels.length}</span> source
                    {previewLabels.length === 1 ? '' : 's'}:
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {previewLabels.map((s) => (
                      <span
                        key={s}
                        className={cn(
                          'inline-flex items-center gap-1 h-5 px-1.5 rounded-sm text-[10.5px]',
                          !isUnattributed(s) && 'font-mono',
                          fromGroups.has(s) && !draft.some((d) => canonicalSlug(d.source_slug) === s)
                            ? 'bg-amber-500/12 text-amber-500'
                            : 'bg-amber-500/25 text-amber-500',
                        )}
                        title={fromGroups.has(s) ? 'from a group restriction' : 'from an exception'}
                      >
                        <EyeOff className="w-[10px] h-[10px]" />
                        {sourceLabel(s)}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {!dirty && serverEffective && JSON.stringify(serverEffective) !== JSON.stringify(preview) && (
                <div className="mt-2 flex items-start gap-1.5 text-[10.5px] text-amber-500">
                  <AlertCircle className="w-[11px] h-[11px] mt-0.5 shrink-0" />
                  The server computes a different set ({displaySlugs(serverEffective).map(sourceLabel).join(', ') || 'none'}). Reload the page.
                </div>
              )}
            </div>
          </div>
        </div>

        <SheetFooter className="border-t border-border px-5 py-3">
          <Button variant="outline" size="sm" className="h-8 text-[11.5px]" onClick={() => onOpenChange(false)} disabled={saving}>
            {canManage ? 'Cancel' : 'Close'}
          </Button>
          {canManage && (
            <Button size="sm" className="h-8 text-[11.5px] gap-1.5" disabled={!dirty || saving} onClick={save}>
              {saving ? <LoadingIcon className="w-[12px] h-[12px]" /> : <UserCog className="w-[12px] h-[12px]" />}
              Save exceptions
            </Button>
          )}
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export function SourceVisibility() {
  useDocumentTitle('Source visibility');
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const canManage = hasPermission('source_scopes:manage');
  // NAN-2597: on hosted-shared tenants a restricted source lists the ingest
  // credentials that can still write it (design §2.5), with revoke links.
  const shared = useSharedTenant();
  const canRevoke = hasPermission('log_sources:deploy');
  const [writersFor, setWritersFor] = useState<string | null>(null);

  const [model, setModel] = useState<SourceVisibilityModel | null>(null);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [pending, setPending] = useState<Set<string>>(new Set());
  const [memberFilter, setMemberFilter] = useState('');
  const [drawerMember, setDrawerMember] = useState<VisibilityMember | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const load = useCallback(async () => {
    try {
      const next = await api.sourceVisibility.get();
      setModel(next);
    } catch (err) {
      toast({ title: 'Error', description: err instanceof Error ? err.message : 'Failed to load source visibility', variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    void load();
  }, [load]);

  const restricted = useMemo(() => {
    const map = new Map<string, Set<string>>();
    for (const r of model?.restrictions ?? []) {
      if (!map.has(r.group_id)) map.set(r.group_id, new Set());
      // A stale `unknown` restriction is the Unattributed row (NAN-2602).
      map.get(r.group_id)!.add(canonicalSlug(r.source_slug));
    }
    return map;
  }, [model]);

  const sources = useMemo(() => {
    const q = query.trim().toLowerCase();
    const all = model?.sources ?? [];
    return q ? all.filter((s) => s.slug.includes(q) || sourceLabel(s.slug).toLowerCase().includes(q) || (isUnattributed(s.slug) && 'unknown'.includes(q))) : all;
  }, [model, query]);

  const members = useMemo(() => {
    const q = memberFilter.trim().toLowerCase();
    const all = model?.members ?? [];
    return q ? all.filter((m) => m.name.toLowerCase().includes(q) || m.email.toLowerCase().includes(q)) : all;
  }, [model, memberFilter]);

  const toggle = async (groupId: string, slug: string) => {
    if (!model || !canManage) return;
    const key = `${groupId}:${slug}`;
    if (pending.has(key)) return;
    const current = new Set(restricted.get(groupId) ?? []);
    const nowRestricted = !current.has(slug);
    if (nowRestricted) current.add(slug);
    else current.delete(slug);
    setPending((p) => new Set(p).add(key));
    // Optimistic.
    setModel((m) =>
      m
        ? {
            ...m,
            restrictions: [
              ...m.restrictions.filter((r) => r.group_id !== groupId),
              ...[...current].map((source_slug) => ({ group_id: groupId, source_slug })),
            ],
          }
        : m,
    );
    try {
      const saved = await api.sourceVisibility.setGroupRestrictions(groupId, { restricted_sources: [...current] });
      setModel((m) =>
        m
          ? {
              ...m,
              restrictions: [
                ...m.restrictions.filter((r) => r.group_id !== groupId),
                ...saved.restricted_sources.map((source_slug) => ({ group_id: groupId, source_slug })),
              ],
            }
          : m,
      );
    } catch (err) {
      toast({ title: 'Error', description: err instanceof Error ? err.message : 'Failed to update restriction', variant: 'destructive' });
      await load();
    } finally {
      setPending((p) => {
        const n = new Set(p);
        n.delete(key);
        return n;
      });
    }
  };

  const restrictionCount = model?.restrictions.length ?? 0;
  const exceptionCount = model?.exceptions.length ?? 0;
  const groups = model?.groups ?? [];

  return (
    <TooltipProvider delayDuration={200}>
      <div className="h-full flex flex-col min-h-0">
        {/* Title + meta (breadcrumb comes from the global Settings TopBar) */}
        <div className="shrink-0 px-6 pt-5 pb-4 border-b border-border">
          <div className="flex items-center gap-2">
            <h1 className="text-[18px] font-semibold tracking-tight text-foreground">Source visibility</h1>
            <Tooltip>
              <TooltipTrigger asChild>
                <button type="button" className="text-muted-foreground/60 hover:text-muted-foreground" aria-label="Help">
                  <ShieldCheck className="w-[12px] h-[12px]" />
                </button>
              </TooltipTrigger>
              <TooltipContent side="bottom" className="max-w-[300px] text-[11px] leading-relaxed">
                Everything is visible by default. Restricting a source for a group hides its events (
                <span className="font-mono">metadata.log_source</span>) from that group's members in search, dashboards,
                prevalence, risk drill-downs and exports. Detections keep evaluating every source. Per-member exceptions
                override groups.
              </TooltipContent>
            </Tooltip>
          </div>
          <p className="text-[11.5px] text-muted-foreground mt-0.5">
            Which groups can see events from each source. Sources are the tenant's ingest routes, plus Unattributed
            (events with no declared source, <span className="font-mono">unknown</span> or{' '}
            <span className="font-mono">default</span>).
          </p>
          <div className="flex items-center gap-4 mt-2 font-mono text-[10.5px] text-muted-foreground tabular-nums">
            <span>{model?.sources.length ?? 0} sources</span>
            <span>{groups.length} groups</span>
            <span className={cn(restrictionCount > 0 && 'text-amber-500')}>{restrictionCount} restrictions</span>
            <span className={cn(exceptionCount > 0 && 'text-amber-500')}>{exceptionCount} exceptions</span>
          </div>
        </div>

        <div className="flex-1 flex min-h-0">
          {/* Matrix */}
          <div className="flex-1 min-w-0 flex flex-col">
            <div className="shrink-0 px-4 py-2.5 flex items-center gap-2 border-b border-border">
              <div className="h-7 w-[260px] rounded-md border border-border bg-card flex items-center gap-2 px-2">
                <SearchIcon className="w-[12px] h-[12px] text-muted-foreground" />
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Filter sources…"
                  className="flex-1 bg-transparent outline-none text-[11.5px] font-mono text-foreground placeholder:text-muted-foreground/70 placeholder:font-sans"
                />
              </div>
              <div className="flex-1" />
              {!canManage && (
                <span className="text-[10.5px] text-muted-foreground">Read-only — needs source_scopes:manage to change.</span>
              )}
            </div>
            <div className="flex-1 overflow-auto scrollbar-thin">
              {loading ? (
                <div className="flex items-center justify-center py-12">
                  <LoadingIcon className="w-4 h-4 text-muted-foreground" />
                </div>
              ) : !model ? null : groups.length === 0 ? (
                <div className="px-6 py-12 text-center max-w-[420px] mx-auto">
                  <UsersIcon className="w-8 h-8 text-muted-foreground/40 mx-auto mb-2" />
                  <div className="text-[12px] font-medium text-foreground">No groups yet</div>
                  <div className="text-[11px] text-muted-foreground mt-1 leading-relaxed">
                    Restrictions are set per group. Create a group under{' '}
                    <Link to="/settings/access-control?tab=groups" className="text-foreground underline underline-offset-2">
                      Access Control › Groups
                    </Link>{' '}
                    and add members, then come back to restrict sources for it. Until then every member sees every source
                    (per-member exceptions still apply).
                  </div>
                </div>
              ) : (
                <table className="w-full text-[12px] border-collapse">
                  <thead className="sticky top-0 z-10 bg-background">
                    <tr className="border-b border-border">
                      <th className="text-left font-medium text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground pl-4 pr-3 py-2 min-w-[260px]">
                        Source
                      </th>
                      <th className="text-right font-medium text-[10px] font-mono uppercase tracking-[0.12em] text-muted-foreground px-3 py-2 w-[90px]">
                        24h
                      </th>
                      {groups.map((g) => (
                        <th key={g.id} className="text-center font-medium text-[10px] font-mono tracking-[0.04em] text-muted-foreground px-2 py-2 min-w-[96px]">
                          <div className="truncate max-w-[140px] mx-auto normal-case" title={g.name}>
                            {g.name}
                          </div>
                          <div className="text-[9.5px] text-muted-foreground/60 tabular-nums">
                            {g.member_count} member{g.member_count === 1 ? '' : 's'}
                          </div>
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {sources.length === 0 ? (
                      <tr>
                        <td colSpan={2 + groups.length} className="px-4 py-8 text-center text-[11.5px] text-muted-foreground">
                          {model.sources.length === 0 ? 'No sources yet — the lake has not admitted events for this tenant.' : 'No sources match your filter.'}
                        </td>
                      </tr>
                    ) : (
                      sources.map((s) => {
                        const restrictedFor = groups.filter((g) => restricted.get(g.id)?.has(s.slug)).length;
                        const writersOpen = writersFor === s.slug;
                        return (
                          <Fragment key={s.slug}>
                          <tr className="border-b border-border/60 hover:bg-foreground/[0.025] h-7">
                            <td className="pl-4 pr-3 py-0">
                              <div className="flex items-center gap-2 min-w-0">
                                {restrictedFor > 0 ? (
                                  <EyeOff className="w-[12px] h-[12px] text-amber-500 shrink-0" />
                                ) : (
                                  <Eye className="w-[12px] h-[12px] text-muted-foreground/50 shrink-0" />
                                )}
                                <span className={cn('text-[12px] text-foreground truncate', !isUnattributed(s.slug) && 'font-mono')}>
                                  {sourceLabel(s.slug)}
                                </span>
                                <span className="font-mono text-[9.5px] text-muted-foreground/70 shrink-0">{protocolLabel(s.protocol)}</span>
                                {shared && restrictedFor > 0 && (
                                  <button
                                    type="button"
                                    onClick={() => setWritersFor(writersOpen ? null : s.slug)}
                                    aria-expanded={writersOpen}
                                    aria-label={`Credentials that can write ${s.slug}`}
                                    title="Credentials that can write this restricted source"
                                    className={cn(
                                      'inline-flex items-center gap-1 h-4 px-1 rounded-sm border font-mono text-[9.5px] shrink-0',
                                      writersOpen ? 'border-primary/50 text-primary' : 'border-border text-muted-foreground hover:text-foreground',
                                    )}
                                  >
                                    <KeyRound className="w-[10px] h-[10px]" strokeWidth={1.5} /> writers
                                  </button>
                                )}
                                {s.last_seen_at && (
                                  <span className="font-mono text-[9.5px] text-muted-foreground/50 shrink-0 hidden xl:inline" title={formatUTC(s.last_seen_at)}>
                                    seen {formatUTC(s.last_seen_at)}
                                  </span>
                                )}
                              </div>
                            </td>
                            <td className="text-right px-3 font-mono text-[10.5px] text-muted-foreground tabular-nums">
                              {s.events_last_24h > 0 ? formatCount(s.events_last_24h) : '—'}
                            </td>
                            {groups.map((g) => {
                              const on = restricted.get(g.id)?.has(s.slug) ?? false;
                              const key = `${g.id}:${s.slug}`;
                              const busy = pending.has(key);
                              return (
                                <td key={g.id} className="text-center px-2 py-0">
                                  <button
                                    type="button"
                                    disabled={!canManage || busy}
                                    onClick={() => void toggle(g.id, s.slug)}
                                    aria-pressed={on}
                                    aria-label={`${on ? 'Unrestrict' : 'Restrict'} ${s.slug} for ${g.name}`}
                                    title={on ? `${g.name} cannot see ${s.slug} — click to allow` : `${g.name} sees ${s.slug} — click to restrict`}
                                    className={cn(
                                      'inline-flex items-center justify-center w-6 h-5 rounded-sm border transition-colors',
                                      on
                                        ? 'border-amber-500/40 bg-amber-500/15 text-amber-500'
                                        : 'border-border bg-card text-muted-foreground/40 hover:text-muted-foreground',
                                      !canManage && 'cursor-default',
                                      busy && 'opacity-60',
                                    )}
                                  >
                                    {busy ? (
                                      <LoadingIcon className="w-[10px] h-[10px]" />
                                    ) : on ? (
                                      <EyeOff className="w-[11px] h-[11px]" />
                                    ) : (
                                      <span className="w-1 h-1 rounded-full bg-current" />
                                    )}
                                  </button>
                                </td>
                              );
                            })}
                          </tr>
                          {writersOpen && (
                            <tr className="border-b border-border/60 bg-card/40">
                              <td colSpan={2 + groups.length} className="pl-4 pr-3 py-2">
                                <SourceWritersCard sourceSlug={s.slug} canRevoke={canRevoke} />
                              </td>
                            </tr>
                          )}
                          </Fragment>
                        );
                      })
                    )}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          {/* Members rail — exceptions + effective view */}
          <div className="w-[300px] shrink-0 flex flex-col border-l border-border" style={{ background: 'var(--panel)' }}>
            <div className="shrink-0 px-3 py-2.5 border-b border-border">
              <div className="text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-medium mb-1.5">Members</div>
              <div className="h-7 rounded-md border border-border bg-card flex items-center gap-2 px-2">
                <SearchIcon className="w-[12px] h-[12px] text-muted-foreground" />
                <input
                  value={memberFilter}
                  onChange={(e) => setMemberFilter(e.target.value)}
                  placeholder="Find a member…"
                  className="flex-1 bg-transparent outline-none text-[11.5px] text-foreground placeholder:text-muted-foreground/70"
                />
              </div>
            </div>
            <div className="flex-1 overflow-y-auto scrollbar-thin">
              {!model ? null : members.length === 0 ? (
                <div className="px-3 py-6 text-center text-[11px] text-muted-foreground">No members match.</div>
              ) : (
                members.map((m) => {
                  const effective = displaySlugs(effectiveFor(model, m));
                  const own = model.exceptions.filter((e) => e.user_id === m.id).length;
                  return (
                    <button
                      key={m.id}
                      onClick={() => {
                        setDrawerMember(m);
                        setDrawerOpen(true);
                      }}
                      className="w-full text-left px-3 py-1.5 border-b border-border/60 hover:bg-foreground/[0.025] transition-colors"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="text-[12px] text-foreground truncate flex-1">{m.name || m.email}</span>
                        {m.view_all ? (
                          <span className="font-mono text-[9.5px] text-emerald-500 shrink-0">view_all</span>
                        ) : effective.length > 0 ? (
                          <span className="inline-flex items-center gap-1 font-mono text-[9.5px] text-amber-500 shrink-0 tabular-nums">
                            <EyeOff className="w-[10px] h-[10px]" />
                            {effective.length}
                          </span>
                        ) : (
                          <span className="font-mono text-[9.5px] text-muted-foreground/50 shrink-0">all</span>
                        )}
                      </div>
                      <div className="flex items-center gap-2 mt-0.5 font-mono text-[10px] text-muted-foreground/70 truncate">
                        <span className="truncate">{m.email}</span>
                        {own > 0 && <span className="shrink-0 text-amber-500">{own} exc</span>}
                        {m.status === 'suspended' && <span className="shrink-0">suspended</span>}
                      </div>
                    </button>
                  );
                })
              )}
            </div>
            <div className="shrink-0 h-8 px-3 border-t border-border flex items-center font-mono text-[10.5px] text-muted-foreground tabular-nums">
              {model?.members.length ?? 0} members · click one for exceptions and its effective view
            </div>
          </div>
        </div>
      </div>

      {model && (
        <ExceptionsDrawer
          open={drawerOpen}
          onOpenChange={setDrawerOpen}
          model={model}
          member={drawerMember}
          canManage={canManage}
          onSaved={load}
        />
      )}
    </TooltipProvider>
  );
}

export default SourceVisibility;
