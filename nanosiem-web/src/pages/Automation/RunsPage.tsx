// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — Runs (mock soar3-runs.jsx Runs3): title + health chips, the 24h
 * histogram (runs / waiting / failed, 30-minute buckets, click to filter a
 * window), a searchable run list with All / Attention / Changes / Running and
 * Source / Case filters, and the selected run's trace. The first run is
 * selected by default.
 */
import { useMemo, useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { Clock, Play, RefreshCw, Search, X } from 'lucide-react';
import type { SoarRun, SoarRunVolume } from '@/lib/api/soar';
import { useAuth } from '@/contexts/AuthContext';
import { cn } from '@/lib/utils';
import { BUCKET_MS, actionIndex, bucketRuns, caseLabel, shortId, utcTime } from './soar-model';
import { Banner, EFF_TXT, FilterSeg, FilterSelect, GatedButton, ListState, Mono, PAGE_TITLE, RUN_DOT, xsButton } from './soar-kit';
import { useCatalog, useConnections, useFlows, useRunDetails, useRunVolume, useRuns, useWindowRuns } from './soar-queries';
import { useSoarGate } from './soar-gate';
import { RunTrace, type RunActionPreset } from './RunTrace';
import { RunActionDialog } from './RunActionDialog';
import { RUN_WORD, runView, shortTarget, type RunSource, type RunView } from './run-view';

type View = 'all' | 'attn' | 'changes' | 'run';
const ATTN = ['wait', 'amb', 'fail'];

function hhmm(ms: number) {
  return new Date(ms).toISOString().slice(11, 16);
}

function RunsVolume({ runs, views, volume, winAt, setWinAt, selAt }: { runs: SoarRun[]; views: Map<string, RunView>; volume?: SoarRunVolume; winAt: number | null; setWinAt: (start: number | null) => void; selAt: number | null }) {
  const [hov, setHov] = useState<number | null>(null);
  const B = useMemo(() => {
    // Server volume (NAN-4556) counts the whole day; same 30-minute boundaries as bucketRuns.
    if (volume && volume.bucket_minutes * 60_000 === BUCKET_MS && volume.buckets.length === 48) {
      return volume.buckets.map((b) => ({
        start: Date.parse(b.start), fail: b.failed, wait: b.waiting, run: b.running,
        ok: Math.max(0, b.runs - b.failed - b.waiting - b.running),
      }));
    }
    // Fallback: the loaded page only.
    const raw = bucketRuns(runs);
    // bucketRuns counts by run status; unknown outcomes (step-level) read as waiting, like the mock.
    return raw.map((b) => {
      const amb = runs.filter((r) => views.get(r.id)?.okey === 'amb' && Date.parse(r.created_at) >= b.start && Date.parse(r.created_at) < b.start + BUCKET_MS).length;
      return { ...b, fail: Math.max(0, b.fail - amb), wait: b.wait + amb };
    });
  }, [runs, views, volume]);
  // The selection is a bucket start, not an index, so a refetch that slides the
  // window by a bucket keeps the same time slot selected.
  const winIdx = winAt == null ? -1 : B.findIndex((b) => b.start === winAt);
  const win = winIdx < 0 ? null : winIdx;
  const tot = (b: (typeof B)[number]) => b.ok + b.fail + b.wait + b.run;
  const max = Math.max(1, ...B.map(tot));
  const sum = B.reduce((s, b) => ({ n: s.n + tot(b), fail: s.fail + b.fail, wait: s.wait + b.wait }), { n: 0, fail: 0, wait: 0 });
  const lbl = (i: number) => `${hhmm(B[i].start)}–${hhmm(B[i].start + BUCKET_MS)}`;
  const show = hov ?? win;
  const H = 56;
  const ticks = [0, 12, 24, 36, 47].map((i) => (i === 47 ? hhmm(B[47].start + BUCKET_MS) : hhmm(B[i].start)).slice(0, 2));
  return (
    <div className="flex flex-col gap-1.5" data-testid="runs-volume">
      <div className="flex h-4 items-center gap-3 overflow-hidden whitespace-nowrap font-mono text-[10.5px] text-muted-foreground [&>span]:shrink-0">
        {show != null ? (
          <>
            <span className="text-foreground">{lbl(show)}</span>
            <span>{tot(B[show])} runs</span>
            {B[show].fail > 0 && <span className="text-destructive">{B[show].fail} failed</span>}
            {B[show].wait > 0 && <span className="text-warn">{B[show].wait} waiting</span>}
            {win === show && hov == null && <span>· click again to clear</span>}
          </>
        ) : (
          <>
            <span>{sum.n.toLocaleString()} runs · 30 min buckets</span>
            <span className="flex-1" />
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-[1px] bg-fg-4" />runs</span>
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-[1px] bg-warning" />waiting</span>
            <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-[1px] bg-destructive" />failed</span>
          </>
        )}
      </div>
      <div className="relative flex items-end gap-px" style={{ height: H }} onMouseLeave={() => setHov(null)}>
        {[12, 24, 36].map((i) => <span key={i} className="pointer-events-none absolute inset-y-0 w-px bg-border/70" style={{ left: `${(i / 48) * 100}%` }} />)}
        {B.map((b, i) => {
          const h = (tot(b) / max) * H;
          const dim = win != null && win !== i;
          const px = (v: number) => Math.max(v ? 2 : 0, (v / max) * H);
          return (
            <button
              key={b.start}
              type="button"
              onMouseEnter={() => setHov(i)}
              onClick={() => setWinAt(win === i ? null : b.start)}
              className="group relative flex h-full flex-1 flex-col justify-end"
              aria-label={lbl(i)}
              aria-pressed={win === i}
            >
              <span className={cn('flex w-full flex-col justify-end overflow-hidden rounded-[1px] transition-opacity', dim ? 'opacity-25' : 'group-hover:opacity-80')} style={{ height: tot(b) ? Math.max(2, h) : 2 }}>
                {b.fail > 0 && <span className="w-full shrink-0 bg-destructive" style={{ height: px(b.fail) }} />}
                {b.wait > 0 && <span className="w-full shrink-0 bg-warning" style={{ height: px(b.wait) }} />}
                {b.run > 0 && <span className="w-full shrink-0 bg-primary" style={{ height: px(b.run) }} />}
                <span className={cn('w-full flex-1', tot(b) ? 'bg-fg-4' : 'bg-fg-4/30')} />
              </span>
              {selAt != null && selAt >= b.start && selAt < b.start + BUCKET_MS && (
                <span className="absolute -bottom-[5px] left-1/2 h-1 w-1 -translate-x-1/2 rounded-full bg-foreground" />
              )}
            </button>
          );
        })}
      </div>
      <div className="flex justify-between pt-1 font-mono text-[9.5px] text-fg-4">{ticks.map((t, i) => <span key={i}>{t}</span>)}</div>
    </div>
  );
}

export function RunsPage({ selectedId }: { selectedId?: string | null } = {}) {
  const params = useParams<{ id?: string }>();
  const id = selectedId === undefined ? params.id : selectedId ?? undefined;
  const navigate = useNavigate();
  const gate = useSoarGate();
  const { user, hasPermission } = useAuth();
  const enabled = gate.state === 'enabled';
  const runs = useRuns(gate.tenant, enabled);
  const volume = useRunVolume(gate.tenant, enabled);
  const catalog = useCatalog(gate.tenant, enabled);
  const flows = useFlows(gate.tenant, enabled);
  const canRun = !gate.demo && hasPermission('soar:run');
  const connections = useConnections(gate.tenant, enabled && !gate.demo);
  const index = useMemo(() => actionIndex(catalog.data), [catalog.data]);
  // Selected histogram bucket, by start time (ms).
  const [winStart, setWinStart] = useState<number | null>(null);
  // Server buckets (NAN-4556) anchor the window when present; a click lists
  // that bucket from the server, not just the loaded page.
  const serverBuckets = volume.data && volume.data.bucket_minutes * 60_000 === BUCKET_MS && volume.data.buckets.length === 48 ? volume.data.buckets : null;
  const winTotal = winStart == null || !serverBuckets ? null : serverBuckets.find((b) => Date.parse(b.start) === winStart)?.runs ?? null;
  const windowRuns = useWindowRuns(gate.tenant, enabled, winStart, BUCKET_MS);
  const all = useMemo(() => {
    const base = runs.data?.runs ?? [];
    const extra = windowRuns.data?.runs;
    if (!extra?.length) return base;
    const seen = new Set(base.map((r) => r.id));
    return [...base, ...extra.filter((r) => !seen.has(r.id))];
  }, [runs.data, windowRuns.data]);
  const details = useRunDetails(gate.tenant, all, enabled);
  const detailKey = [...details.keys()].join(',');
  const views = useMemo(() => {
    const m = new Map<string, RunView>();
    for (const r of all) m.set(r.id, runView(r, index, { me: user?.id, flows: flows.data?.flows, steps: details.get(r.id)?.steps }));
    return m;
  }, [all, index, user?.id, flows.data, detailKey]); // eslint-disable-line react-hooks/exhaustive-deps

  const [view, setView] = useState<View>('all');
  const [src, setSrc] = useState('all');
  const [search] = useSearchParams();
  // `?case=<id>` (from a case's "Related runs") preselects the Case filter.
  const [cs, setCs] = useState(() => search.get('case') || 'all');
  const [q, setQ] = useState('');
  const [runOpen, setRunOpen] = useState(false);
  const [preset, setPreset] = useState<RunActionPreset | undefined>(undefined);

  const qs = q.trim().toLowerCase();
  const connLabel = (cid: string | null | undefined) => connections.data?.connections.find((c) => c.id === cid)?.label;
  const hit = (v: RunView) => !qs || [v.run.id, v.name, v.verb, v.target?.value, v.who, v.source, v.run.case_id, v.run.pack_name, connLabel(v.run.connection_id)]
    .filter(Boolean).some((x) => String(x).toLowerCase().includes(qs));
  const inView = (v: RunView) => view === 'all' || (view === 'attn' ? ATTN.includes(v.okey) : view === 'changes' ? v.isChange : v.okey === 'run');
  const vs = all.map((r) => views.get(r.id)).filter((v): v is RunView => !!v);
  const inWin = (v: RunView) => winStart == null || (Date.parse(v.run.created_at) >= winStart && Date.parse(v.run.created_at) < winStart + BUCKET_MS);
  const rows = vs.filter((v) => hit(v) && inView(v) && (src === 'all' || v.source === (src as RunSource)) && (cs === 'all' || v.run.case_id === cs) && inWin(v));
  const nWin = winStart == null ? 0 : vs.filter(inWin).length;
  const sel = (id ? vs.find((v) => v.run.id === id) : undefined) ?? (id ? undefined : rows[0]);
  const selId = id ?? sel?.run.id;
  const nAttn = vs.filter((v) => ATTN.includes(v.okey)).length;
  const nRun = vs.filter((v) => v.okey === 'run').length;
  const nChange = vs.filter((v) => v.isChange).length;
  const clear = () => { setQ(''); setView('all'); setSrc('all'); setCs('all'); setWinStart(null); };
  const cases = [...new Set([...all.map((r) => r.case_id), cs !== 'all' ? cs : null].filter((c): c is string => !!c))];

  const amb = vs.filter((v) => v.okey === 'amb');
  const badConns = (connections.data?.connections ?? []).filter((c) => c.last_test_status === 'failed');
  const withdrawn = (catalog.data?.packs ?? []).filter((p) => p.withdrawn && p.installed);
  const openAction = (p?: RunActionPreset) => { setPreset(p); setRunOpen(true); };

  return (
    <div className="flex h-full min-h-0 flex-col" data-testid="runs-page">
      <div className="flex shrink-0 flex-col gap-3 border-b border-border px-5 pb-4 pt-4">
        <div className="flex flex-wrap items-baseline gap-3">
          <h1 className={PAGE_TITLE}>Runs</h1>
          <span className="shrink-0 whitespace-nowrap font-mono text-[11px] text-muted-foreground">last 24h · UTC{gate.demo ? ' · read-only demo' : ''}</span>
          <div className="ml-auto flex flex-wrap items-center gap-3 whitespace-nowrap font-mono text-[10.5px]">
            {amb.map((v) => (
              <button key={v.run.id} type="button" onClick={() => navigate(`/automation/runs/${v.run.id}`)} className="flex items-center gap-1.5 text-warn hover:underline">
                <span className="h-1.5 w-1.5 rounded-full bg-warning" />unknown outcome · {v.target ? shortTarget(v.target.value) : shortId(v.run.id)}
              </button>
            ))}
            {badConns.map((c) => (
              <button key={c.id} type="button" onClick={() => navigate('/automation/capabilities?tab=connections')} className="flex items-center gap-1.5 text-destructive hover:underline">
                <span className="h-1.5 w-1.5 rounded-full bg-destructive" />{c.label} failing
              </button>
            ))}
            {withdrawn.map((p) => (
              <button key={p.name} type="button" onClick={() => navigate('/automation/capabilities?tab=packs')} className="flex items-center gap-1.5 text-fg-2 hover:underline">
                <span className="h-1.5 w-1.5 rounded-full border border-muted-foreground" />{p.display_name} {p.installed_version} withdrawn
              </button>
            ))}
            {!gate.demo && (
              <GatedButton allowed={canRun} why="Requires soar:run" size="sm" variant="outline" className={xsButton} onClick={() => openAction()}>
                <Play className="h-3 w-3" strokeWidth={1.5} />
                Run action
              </GatedButton>
            )}
          </div>
        </div>
        {runs.data && <RunsVolume runs={all} views={views} volume={volume.data} winAt={winStart} setWinAt={setWinStart} selAt={sel ? Date.parse(sel.run.created_at) : null} />}
      </div>
      <div className="grid min-h-0 flex-1 grid-cols-1 grid-rows-[minmax(0,1fr)] lg:grid-cols-[300px_minmax(0,1fr)] xl:grid-cols-[360px_minmax(0,1fr)]">
        <div className={cn('flex min-h-0 flex-col border-r border-border', id && 'hidden lg:flex')}>
          <div className="flex flex-col gap-2 border-b border-border px-3 py-2">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" strokeWidth={1.5} />
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                onKeyDown={(e) => e.key === 'Escape' && setQ('')}
                placeholder="Search run ID, action, target, case, actor"
                aria-label="Search runs"
                className="h-8 w-full rounded-md border border-border-2 bg-background pl-8 pr-7 text-[12px] text-foreground placeholder:text-fg-4 focus:outline-none focus:ring-1 focus:ring-ring"
              />
              {q && (
                <button type="button" onClick={() => setQ('')} aria-label="Clear search" className="absolute right-1.5 top-1/2 flex h-5 w-5 -translate-y-1/2 items-center justify-center rounded text-muted-foreground hover:text-foreground">
                  <X className="h-3 w-3" strokeWidth={1.5} />
                </button>
              )}
            </div>
            <FilterSeg
              label="Run filter"
              value={view}
              onChange={setView}
              options={[['all', 'All', all.length], ['attn', 'Attention', nAttn], ['changes', 'Changes', nChange], ['run', 'Running', nRun]]}
            />
            <div className="flex flex-wrap items-center gap-1.5">
              <FilterSelect label="Source" value={src} onChange={setSrc} options={['user', 'trigger', 'pivt']} />
              <FilterSelect label="Case" value={cs} onChange={setCs} options={cases.map((c) => [c, caseLabel(c, all.find((r) => r.case_id === c)?.case_number)] as [string, string])} />
              {winStart != null && (
                <button type="button" onClick={() => setWinStart(null)} className="flex h-7 items-center gap-1.5 rounded-md border border-border-2 px-2 font-mono text-[10.5px] text-fg-2 hover:text-foreground">
                  {hhmm(winStart)} window{winTotal != null && nWin < winTotal ? ` · ${nWin} of ${winTotal.toLocaleString()}` : ''}<X className="h-3 w-3" strokeWidth={1.5} />
                </button>
              )}
            </div>
          </div>
          <div className="min-h-0 flex-1 overflow-auto">
            {runs.isRefetchError && runs.data && (
              <div className="px-3 py-2">
                <Banner
                  tone="warn"
                  icon={<Clock strokeWidth={1.5} />}
                  title={`Showing data from ${utcTime(new Date(runs.dataUpdatedAt).toISOString()).slice(0, 5)} UTC`}
                  action={
                    <button type="button" onClick={() => void runs.refetch()} className="flex h-6 items-center gap-1.5 rounded-md border border-border-2 px-2 text-[11px] text-foreground">
                      <RefreshCw className="h-3 w-3" strokeWidth={1.5} />Refresh
                    </button>
                  }
                >
                  Live refresh failed. Rows may not reflect recent decisions or run states.
                </Banner>
              </div>
            )}
            {runs.isPending ? (
              <ListState state="loading" cols={[80, 120, 60]} />
            ) : runs.isError && !runs.data ? (
              <ListState state="error" title="Could not load runs" body="Your filters are kept." onRetry={() => void runs.refetch()} />
            ) : all.length === 0 ? (
              <ListState state="empty" title="No runs yet" body="Runs appear when someone requests an action, a flow triggers, or pivt asks." />
            ) : rows.length === 0 ? (
              <ListState state="filtered" title="No runs match these filters" action={<button type="button" onClick={clear} className="h-7 rounded-md border border-border-2 px-2.5 text-[11.5px] text-foreground">Clear filters</button>} />
            ) : (
              rows.map((v) => {
                const w = RUN_WORD[v.okey];
                return (
                  <button
                    key={v.run.id}
                    type="button"
                    onClick={() => navigate(`/automation/runs/${v.run.id}`)}
                    aria-current={selId === v.run.id ? 'page' : undefined}
                    className={cn('flex w-full flex-col gap-1 border-b border-border px-3 py-2.5 text-left', selId === v.run.id ? 'bg-foreground/[0.06]' : 'hover:bg-foreground/[0.025]')}
                    data-testid="run-row"
                  >
                    <div className="flex min-w-0 items-center gap-2">
                      <span className={cn('h-1.5 w-1.5 shrink-0 rounded-full', RUN_DOT[v.okey])} />
                      <span className="truncate text-[12.5px] text-foreground">{v.name}</span>
                      {v.target && <Mono className="truncate text-[11px] text-muted-foreground">{shortTarget(v.target.value)}</Mono>}
                      {v.run.dry_run && <Mono className="shrink-0 text-[10px] text-muted-foreground">dry</Mono>}
                      <span className="flex-1" />
                      <Mono className="shrink-0 text-[10.5px] text-muted-foreground">{utcTime(v.run.created_at).slice(0, 5)}</Mono>
                    </div>
                    <div className="truncate pl-3.5 font-mono text-[10.5px] text-muted-foreground">
                      {w && <span className={w[1]}>{w[0]} · </span>}
                      {view === 'changes' && v.effect && <span className={EFF_TXT[v.effect]}>{v.effect} · </span>}
                      {v.source === 'user' ? v.who : v.source} · {v.duration}
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </div>
        <div className={cn('flex min-h-0 flex-col overflow-hidden', !id && 'hidden lg:flex')} data-testid="runs-detail-pane">
          {id && (
            <div className="border-b border-border px-5 py-2 lg:hidden">
              <button type="button" className="text-[11.5px] text-primary" onClick={() => navigate('/automation/runs')}>← All runs</button>
            </div>
          )}
          {selId ? (
            <RunTrace key={selId} id={selId} index={index} tenant={gate.tenant} demo={gate.demo} flows={flows.data?.flows} onRequestAction={canRun ? openAction : undefined} />
          ) : runs.data && all.length > 0 ? (
            <ListState state="empty" title="Select a run" body="Pick a run to see its steps, outputs and approval gates." />
          ) : null}
        </div>
      </div>
      {canRun && (
        <RunActionDialog
          open={runOpen}
          onOpenChange={setRunOpen}
          tenant={gate.tenant}
          catalog={catalog.data}
          connections={connections.data?.connections ?? []}
          preset={preset}
        />
      )}
    </div>
  );
}

export default RunsPage;
