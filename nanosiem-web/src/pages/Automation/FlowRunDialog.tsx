// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4540/4546 — run or dry-run a flow (POST /api/soar/flows/:id/run).
 *
 * NAN-4586: easy by default. Inputs come from
 *  - a real alert (dry run only): POST /api/soar/flows/:id/test with the
 *    alert id, so the server builds the exact production payload;
 *  - a recent case, mapped to the case event payload;
 *  - a short form with the trigger's production payload shape and sample
 *    values (alert rule fields come from a picked detection rule).
 * "Advanced JSON" shows the same inputs in a JSON editor with key
 * autocomplete and catalog checks.
 */
import { Suspense, useEffect, useId, useMemo, useState } from 'react';
import { ChevronDown } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import type { SoarFlow, SoarRun } from '@/lib/api/soar';
import type { Alert, DetectionRule } from '@/lib/api/types';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { lazyWithRetry } from '@/lib/lazyWithRetry';
import { cn } from '@/lib/utils';
import type { EventKind, FieldDef } from './soar-fields';
import {
  EVENT_FIELDS,
  EVENT_LABEL,
  buildInputs,
  checkInputsJson,
  checkValue,
  inputKey,
  inputsFromCase,
  kindOf,
  referencedInputPaths,
  triggerEvents,
} from './soar-fields';
import { toDoc } from './flow-editor-model';
import { FilterSeg, ListBox, Notice, PickRow, SearchBox, Spinner, inputCls, pickListState, smallButton, useListNav } from './soar-kit';
import { shortId, utcDateTime } from './soar-model';
import { effectErrorMessage, invalidateSoar } from './soar-queries';

const FlowInputsJsonEditor = lazyWithRetry(() => import('./FlowInputsJsonEditor'));

type Source = 'alert' | 'case' | 'form';
type Mode = 'easy' | 'json';
const UUID = /^[0-9a-f-]{36}$/i;
const NO_CASE = '__none';

/** Alert fields that describe the rule; in the form they come from a picked detection rule. */
const RULE_FIELDS: Record<string, (r: DetectionRule) => unknown> = {
  'flow_input.alert.rule_id': (r) => r.id,
  'flow_input.alert.tags': (r) => r.tags ?? [],
  'flow_input.alert.rule_name': (r) => r.name,
  'flow_input.alert.title': (r) => r.name,
};

/**
 * Form fields: the event's production payload fields a form can edit. Only a
 * manual flow (no event shape) adds the custom paths the flow reads.
 */
function formFields(ev: EventKind, extra: string[]): FieldDef[] {
  const base = EVENT_FIELDS[ev].filter((d) => d.type !== 'object' && !(d.type === 'array' && Array.isArray(d.sample) && typeof d.sample[0] === 'object'));
  if (ev !== 'manual') return base;
  return [...base, ...extra.map((p): FieldDef => ({ path: p, label: inputKey(p), group: 'Flow input', type: 'string', sample: '' }))];
}
const toText = (v: unknown) => (Array.isArray(v) ? v.join(', ') : v === undefined || v === null ? '' : String(v));
function fromText(d: FieldDef, raw: string): unknown {
  if (d.type === 'array') return raw.split(',').map((x) => x.trim()).filter(Boolean);
  if (d.type === 'number') return raw.trim() === '' || Number.isNaN(Number(raw)) ? null : Number(raw);
  if (d.type === 'boolean') return raw === 'true';
  // Alert entities are null when the alert has no such value.
  if (d.path.startsWith('flow_input.alert.entities.') && raw.trim() === '') return null;
  return raw;
}

const RECENT = 20;

function useRecentAlerts(tenant: string, enabled: boolean) {
  return useQuery({
    queryKey: ['soar', tenant, 'test-inputs', 'alerts'],
    queryFn: () => api.listAlerts({ limit: RECENT, kinds: ['detection'] }),
    enabled,
    staleTime: 30_000,
  });
}
function useRecentCases(tenant: string, enabled: boolean) {
  return useQuery({
    queryKey: ['soar', tenant, 'test-inputs', 'cases'],
    queryFn: async () => (await api.listCases({ limit: 10, sort: 'newest' })).cases,
    enabled,
    staleTime: 30_000,
    retry: false,
  });
}
/** A rule loaded by id: used for a "recent alert" rule, whose tags the alert does not carry. */
function useRule(tenant: string, id: string | null) {
  return useQuery({
    queryKey: ['soar', tenant, 'test-inputs', 'rule', id],
    queryFn: () => api.getDetection(id!),
    enabled: !!id,
    staleTime: 60_000,
    retry: false,
  });
}

const RULE_SEARCH_LIMIT = 20;
const RULE_SEARCH_DEBOUNCE_MS = 250;

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

interface RuleChoice { id: string; name: string; rule?: DetectionRule }

/**
 * Detection rule for the sample alert. Starts with the rules behind recent
 * detection alerts; typing searches all rules on the server
 * (GET /api/rules?search=…&limit=20), debounced.
 */
function RulePicker({ tenant, value, onChange, recent }: { tenant: string; value: RuleChoice | null; onChange: (r: RuleChoice | null) => void; recent: RuleChoice[] }) {
  const uid = useId();
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const term = useDebounced(q.trim(), RULE_SEARCH_DEBOUNCE_MS);
  const found = useQuery({
    queryKey: ['soar', tenant, 'test-inputs', 'rule-search', term],
    queryFn: () => api.listDetections({ search: term, limit: RULE_SEARCH_LIMIT }),
    enabled: open && term !== '',
    staleTime: 30_000,
    retry: false,
  });
  const searching = q.trim() !== '';
  const list: Array<RuleChoice | null> = searching
    ? (found.data ?? []).map((r) => ({ id: r.id, name: r.name, rule: r }))
    : [null, ...recent];
  const pick = (c: RuleChoice | null) => { onChange(c); setOpen(false); setQ(''); };
  const nav = useListNav(list.length, (i) => pick(list[i] ?? null), `${uid}-rule`);
  const listId = `${uid}-rules`;
  const pending = searching && (q.trim() !== term || found.isFetching);
  return (
    <Popover open={open} onOpenChange={(o) => { setOpen(o); if (!o) setQ(''); nav.setActive(0); }}>
      <PopoverTrigger asChild>
        <button type="button" aria-label="Rule" className={cn(inputCls(false), 'flex h-7 items-center gap-1.5 text-left text-[11.5px]')}>
          <span className="min-w-0 flex-1 truncate">{value ? value.name : 'Sample rule (Suspicious PowerShell)'}</span>
          <ChevronDown className="h-3 w-3 shrink-0 text-fg-4" strokeWidth={1.5} />
        </button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-80 p-0">
        <div className="border-b border-border p-1.5">
          <SearchBox label="Search rules" placeholder="Search all rules by name or ID" value={q} onChange={(v) => { setQ(v); nav.setActive(0); }} onKeyDown={nav.onKeyDown} listId={listId} activeId={nav.activeId} />
        </div>
        <div id={listId} role="listbox" aria-label="Rule options" className="max-h-64 overflow-auto py-1">
          {!searching && <div className="px-2.5 pb-0.5 pt-1 font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground">Recent alert rules</div>}
          {list.map((c, i) => (
            <div
              key={c?.id ?? 'sample'}
              id={nav.optionId(i)}
              role="option"
              aria-selected={(c?.id ?? null) === (value?.id ?? null)}
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => pick(c)}
              onMouseEnter={() => nav.setActive(i)}
              className={cn('flex cursor-pointer items-center gap-2 px-2.5 py-1 text-[12px]', i === nav.active && 'bg-accent')}
            >
              <span className="min-w-0 flex-1 truncate">{c ? c.name : 'Sample rule (Suspicious PowerShell)'}</span>
              {c && <span className="shrink-0 font-mono text-[10.5px] text-muted-foreground">{shortId(c.id)}</span>}
            </div>
          ))}
          {pending && <div className="flex items-center gap-2 px-2.5 py-1.5 text-[11.5px] text-muted-foreground"><Spinner />Searching…</div>}
          {searching && !pending && found.isError && <div className="px-2.5 py-1.5 text-[11.5px] text-destructive">Rule search failed.</div>}
          {searching && !pending && !found.isError && list.length === 0 && <div className="px-2.5 py-1.5 text-[11.5px] text-muted-foreground">No rules match.</div>}
          {searching && !pending && list.length === RULE_SEARCH_LIMIT && <div className="px-2.5 py-1.5 text-[10.5px] text-muted-foreground">First {RULE_SEARCH_LIMIT} matches. Type more to narrow.</div>}
          {!searching && recent.length === 0 && <div className="px-2.5 py-1.5 text-[10.5px] text-muted-foreground">Type to search all rules.</div>}
        </div>
      </PopoverContent>
    </Popover>
  );
}

export function RunFlowDialog({
  open,
  onOpenChange,
  flow,
  tenant,
  dryRun,
  onQueued,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  flow: SoarFlow;
  tenant: string;
  dryRun: boolean;
  /** Stay on the page (flow editor test) instead of opening the run. */
  onQueued?: (run: SoarRun) => void;
}) {
  const client = useQueryClient();
  const navigate = useNavigate();
  const uid = useId();
  const on = flow.trigger?.on ?? 'manual';
  const events = triggerEvents(on);
  const [ev, setEv] = useState<EventKind>(events[0]);
  // A real alert goes through the test endpoint (dry runs only), which needs soar:manage.
  const canTest = useAuth().hasPermission('soar:manage');
  const alertish = dryRun && (ev === 'alert' || ev === 'manual');
  const alertOk = alertish && canTest;
  // case.transitioned needs previous_status/change, which a case pick can only make up: dry runs only.
  const caseOk = (ev.startsWith('case.') || ev === 'manual') && (dryRun || ev !== 'case.transitioned');
  const [mode, setMode] = useState<Mode>('easy');
  const [source0, setSource] = useState<Source>(ev === 'alert' && dryRun ? 'alert' : ev.startsWith('case.') && caseOk ? 'case' : 'form');
  const source: Source = (source0 === 'alert' && !alertOk) || (source0 === 'case' && !caseOk) ? 'form' : source0;
  const [alertId, setAlertId] = useState<string | null>(null);
  const [eventCase, setEventCase] = useState<string | null>(null);
  const [attach, setAttach] = useState(dryRun);
  const [ruleChoice, setRuleChoice] = useState<RuleChoice | null>(null);
  const [form, setForm] = useState<Record<string, string>>({});
  const [json, setJson] = useState<string | null>(null);
  const [caseId, setCaseId] = useState('');

  const extra = useMemo(() => {
    const doc = toDoc(flow.definition, flow.name);
    return referencedInputPaths(doc, new Set(EVENT_FIELDS[ev].map((d) => d.path)));
  }, [flow.definition, flow.name, ev]);
  const allFields = useMemo(() => formFields(ev, extra), [ev, extra]);
  const fields = ev === 'alert' ? allFields.filter((d) => !(d.path in RULE_FIELDS)) : allFields;

  // Recent detection alerts feed both the real-alert list and the sample rule picker.
  const alerts = useRecentAlerts(tenant, open && (alertOk || ev === 'alert'));
  const cases = useRecentCases(tenant, open);
  const recentRules = useMemo(() => {
    const seen = new Map<string, RuleChoice>();
    for (const a of alerts.data ?? []) if (a.rule_id && !seen.has(a.rule_id)) seen.set(a.rule_id, { id: a.rule_id, name: a.rule_name ?? shortId(a.rule_id) });
    return [...seen.values()];
  }, [alerts.data]);
  // A searched rule arrives whole; a recent-alert rule is loaded by id for its tags.
  const rule = useRule(tenant, ev === 'alert' && ruleChoice && !ruleChoice.rule ? ruleChoice.id : null);
  const pickedAlert = alerts.data?.find((a) => a.id === alertId) ?? null;
  const pickedCase = cases.data?.find((c) => c.id === eventCase) ?? null;
  const pickedRule: DetectionRule | null = !ruleChoice ? null : ruleChoice.rule ?? (rule.data?.id === ruleChoice.id ? rule.data : null);
  const ruleLoading = ev === 'alert' && !!ruleChoice && !pickedRule;
  const testing = mode === 'easy' && source === 'alert';

  const easyInputs = useMemo(() => {
    if (source === 'alert') return {};
    if (source === 'case') return pickedCase ? inputsFromCase(pickedCase, ev === 'manual' ? 'case.created' : ev) : {};
    const rows: Array<[string, unknown]> = allFields.map((d) => {
      const rule = ev === 'alert' ? RULE_FIELDS[d.path] : undefined;
      if (rule) return [inputKey(d.path), pickedRule ? rule(pickedRule) : d.sample];
      return [inputKey(d.path), fromText(d, form[d.path] ?? toText(d.sample))];
    });
    return buildInputs(rows);
  }, [source, pickedCase, pickedRule, ev, allFields, form]);

  const jsonText = json ?? JSON.stringify(easyInputs, null, 2);
  const checked = useMemo(() => checkInputsJson(jsonText, on), [jsonText, on]);
  const formErrors = mode === 'easy' && source === 'form' ? fields.filter((d) => checkValue(kindOf(d.path, d), form[d.path] ?? toText(d.sample), d.values)) : [];
  const needsPick = mode === 'easy' && ((source === 'alert' && !pickedAlert) || (source === 'case' && !pickedCase));
  const inputs = mode === 'easy' ? easyInputs : checked.value;
  // Picking a case as the event never attaches the run silently: the checkbox decides.
  const runCase = mode === 'easy' && source === 'case' ? (attach && pickedCase ? pickedCase.id : '') : caseId.trim();
  const badCase = runCase !== '' && !UUID.test(runCase);
  const blocked = (!testing && !inputs) || badCase || needsPick || formErrors.length > 0 || (mode === 'easy' && source === 'form' && ruleLoading);

  const run = useMutation({
    mutationFn: (): Promise<SoarRun> =>
      testing && pickedAlert
        ? api.soar.testFlow(flow.id, { alert_id: pickedAlert.id })
        : api.soar.queueFlow(flow.id, { inputs: inputs ?? {}, ...(runCase ? { case_id: runCase } : {}), dry_run: dryRun }),
    onSuccess: (result) => {
      void invalidateSoar(client, tenant);
      onOpenChange(false);
      if (onQueued) onQueued(result);
      else navigate(`/automation/runs/${result.id}`);
    },
  });

  const toMode = (m: Mode) => {
    if (m === 'json' && mode === 'easy') setCaseId(runCase);
    setMode(m);
  };
  const sources: Array<[Source, string]> = [
    ...(alertOk ? [['alert', 'Real alert'] as [Source, string]] : []),
    ...(caseOk ? [['case', 'Recent case'] as [Source, string]] : []),
    ['form', allFields.length ? 'Sample values' : 'No inputs'],
  ];
  const caseOptions = cases.data ?? [];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl gap-0 p-0">
        <div className="border-b border-border px-5 py-4">
          <DialogTitle className="text-[14px] font-semibold">{dryRun ? 'Dry run' : 'Run'} {flow.name}</DialogTitle>
          <DialogDescription className="mt-1 text-[11.5px] text-muted-foreground">
            {testing
              ? 'Tests the flow against a real alert. Permitted read steps run live; other actions are only rendered.'
              : dryRun
                ? 'Walks the flow with placeholder outputs. No vendor is called.'
                : 'Queues a real run. Steps that need approval wait for an approver.'}
          </DialogDescription>
        </div>
        <div className="flex max-h-[62vh] flex-col gap-3 overflow-auto px-5 py-4">
          <div className="flex items-center gap-2">
            <span className="flex-1 text-[11.5px] text-fg-2">Test with {events.map((e) => EVENT_LABEL[e].toLowerCase()).join(' or ')} data</span>
            <FilterSeg<Mode> label="Input mode" value={mode} onChange={toMode} options={[['easy', 'Pick inputs'], ['json', 'Advanced JSON']]} />
          </div>

          {mode === 'easy' ? (
            <>
              {events.length > 1 && (
                <FilterSeg<EventKind> label="Event" value={ev} onChange={(e) => { setEv(e); setJson(null); }} options={events.map((e): [EventKind, string] => [e, EVENT_LABEL[e]])} />
              )}
              <FilterSeg<Source> label="Input source" value={source} onChange={(x) => { setSource(x); setJson(null); }} options={sources} />
              {alertish && !canTest && <div className="text-[10.5px] text-muted-foreground" data-testid="real-alert-hint">Testing with real alerts needs soar:manage.</div>}
              {source === 'alert' && (
                <>
                  <ListBox label="Recent alerts" state={pickListState(alerts)}>
                    {(alerts.data ?? []).map((a: Alert) => (
                      <PickRow key={a.id} label={`Alert ${a.rule_name ?? shortId(a.id)}`} selected={a.id === alertId} onClick={() => { setAlertId(a.id); setJson(null); }}>
                        <span className="w-[74px] shrink-0 font-mono text-[10.5px] uppercase text-fg-2">{a.severity}</span>
                        <span className="min-w-0 flex-1 truncate">{a.rule_name ?? 'Alert'}</span>
                        <span className="font-mono text-[10.5px] text-muted-foreground">{shortId(a.id)} · {utcDateTime(a.created_at)}</span>
                      </PickRow>
                    ))}
                  </ListBox>
                  <div className="text-[10.5px] text-muted-foreground">The server builds the same inputs a real alert trigger would. Test runs never attach to a case.</div>
                </>
              )}
              {source === 'case' && (
                <>
                  <ListBox label="Recent cases" state={pickListState(cases)}>
                    {caseOptions.map((c) => (
                      <PickRow key={c.id} label={`Case ${c.case_number}`} selected={c.id === eventCase} onClick={() => { setEventCase(c.id); setJson(null); }}>
                        <span className="w-[52px] shrink-0 font-mono text-[10.5px] text-fg-2">#{c.case_number}</span>
                        <span className="min-w-0 flex-1 truncate">{c.title}</span>
                        <span className="font-mono text-[10.5px] text-muted-foreground">{c.severity} · {c.status}</span>
                      </PickRow>
                    ))}
                  </ListBox>
                  {ev === 'case.transitioned' && <div className="text-[10.5px] text-warn">Previous status and change are sample values made up from the case's current status.</div>}
                  <label className="flex items-center gap-2 text-[11.5px] text-fg-2">
                    <Checkbox aria-label="Attach run to case" checked={attach} onCheckedChange={(v) => setAttach(v === true)} className="h-3.5 w-3.5" />
                    Attach run to {pickedCase ? <span className="font-mono">#{pickedCase.case_number}</span> : 'the picked case'}
                    {!dryRun && <span className="text-muted-foreground">· the run's steps can change it</span>}
                  </label>
                </>
              )}
              {source === 'form' && (
                allFields.length ? (
                  <div className="flex flex-col gap-2" data-testid="inputs-form">
                    {ev === 'alert' && (
                      <label className="grid grid-cols-[150px_1fr] items-center gap-2">
                        <span className="flex min-w-0 flex-col">
                          <span className="truncate text-[11.5px] text-fg-2">Alert · Rule</span>
                          <span className="truncate font-mono text-[10px] text-muted-foreground">rule_id, rule_name, title, tags</span>
                        </span>
                        <span className="flex flex-col gap-0.5">
                          <RulePicker tenant={tenant} value={ruleChoice} recent={recentRules} onChange={(c) => { setRuleChoice(c); setJson(null); }} />
                          {ruleLoading && rule.isError && <span className="text-[10.5px] text-destructive">That rule could not be loaded. Pick another or use the sample rule.</span>}
                          {ruleLoading && !rule.isError && <span className="flex items-center gap-1 text-[10.5px] text-muted-foreground"><Spinner className="h-2.5 w-2.5" />Loading rule…</span>}
                        </span>
                      </label>
                    )}
                    {fields.map((d) => {
                      const v = form[d.path] ?? toText(d.sample);
                      const err = checkValue(kindOf(d.path, d), v, d.values);
                      const errId = `${uid}-${d.path}-err`;
                      const set = (x: string) => { setForm((f) => ({ ...f, [d.path]: x })); setJson(null); };
                      return (
                        <label key={d.path} className="grid grid-cols-[150px_1fr] items-center gap-2">
                          <span className="flex min-w-0 flex-col">
                            <span className="truncate text-[11.5px] text-fg-2">{d.group} · {d.label}</span>
                            <span className="truncate font-mono text-[10px] text-muted-foreground">{inputKey(d.path)}</span>
                          </span>
                          <span className="flex flex-col gap-0.5">
                            {d.values ? (
                              <Select value={v} onValueChange={set}>
                                <SelectTrigger aria-label={inputKey(d.path)} className="h-7 font-mono text-[11.5px] shadow-none"><SelectValue /></SelectTrigger>
                                <SelectContent>{d.values.map((o) => <SelectItem key={o} value={o} className="font-mono text-[11.5px]">{o}</SelectItem>)}</SelectContent>
                              </Select>
                            ) : (
                              <Input aria-label={inputKey(d.path)} aria-invalid={!!err} aria-describedby={err ? errId : undefined} value={v} placeholder={d.type === 'array' ? 'a, b, c' : d.path.startsWith('flow_input.alert.entities.') ? 'empty = null' : ''} onChange={(e) => set(e.target.value)} className={cn('h-7 font-mono text-[11.5px]', err && 'border-destructive/60')} />
                            )}
                            {err && <span id={errId} className="text-[10.5px] text-destructive">{err}</span>}
                          </span>
                        </label>
                      );
                    })}
                    {ev === 'case.triage_verdict' && <div className="text-[10.5px] text-muted-foreground">Top entities start empty. Add them in Advanced JSON.</div>}
                  </div>
                ) : (
                  <div className="text-[11.5px] text-muted-foreground">This trigger passes no event data and the flow reads no inputs. Add any in Advanced JSON.</div>
                )
              )}
              {source !== 'case' && !testing && (
                <label className="flex flex-col gap-1">
                  <span className="text-[11px] text-muted-foreground">Attach to case · optional</span>
                  <Select value={caseOptions.some((c) => c.id === caseId) ? caseId : NO_CASE} onValueChange={(v) => setCaseId(v === NO_CASE ? '' : v)}>
                    <SelectTrigger aria-label="Case" className="h-7 text-[12px] shadow-none"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value={NO_CASE} className="text-[12px]">No case</SelectItem>
                      {caseOptions.map((c) => <SelectItem key={c.id} value={c.id} className="text-[12px]"><span className="font-mono text-[11px]">#{c.case_number}</span> {c.title}</SelectItem>)}
                    </SelectContent>
                  </Select>
                  {caseId && !caseOptions.some((c) => c.id === caseId) && <span className="font-mono text-[10.5px] text-muted-foreground">Case {caseId} (set in Advanced JSON)</span>}
                </label>
              )}
              {!testing && (
                <details className="text-[11px] text-muted-foreground">
                  <summary className="cursor-pointer select-none">Inputs that will be sent</summary>
                  <pre data-testid="inputs-preview" className="mt-1 max-h-40 overflow-auto rounded-md border border-border bg-background px-2.5 py-2 font-mono text-[10.5px] leading-[1.6] text-fg-2">{JSON.stringify(easyInputs, null, 2)}</pre>
                </details>
              )}
            </>
          ) : (
            <>
              <div className="flex flex-col gap-1">
                <span className="text-[11px] text-muted-foreground">Inputs · JSON object{json === null ? ' · from your picked inputs' : ''}</span>
                <Suspense fallback={<div className="flex h-[160px] items-center gap-2 rounded-md border border-border px-2.5 text-[11.5px] text-muted-foreground"><Spinner />Loading editor…</div>}>
                  <FlowInputsJsonEditor label="Flow inputs" on={on} value={jsonText} onChange={setJson} />
                </Suspense>
                {checked.issues.length > 0 && (
                  <ul className="flex flex-col gap-0.5" data-testid="inputs-issues">
                    {checked.issues.map((i) => <li key={i.message} className={cn('text-[11px]', i.severity === 'error' ? 'text-destructive' : 'text-warn')}>{i.message}</li>)}
                  </ul>
                )}
              </div>
              <label className="flex flex-col gap-1">
                <span className="text-[11px] text-muted-foreground">Case ID · optional</span>
                <Input value={caseId} onChange={(e) => setCaseId(e.target.value)} aria-invalid={badCase || undefined} className={cn('h-7 font-mono text-[11.5px]', badCase && 'border-destructive/60')} aria-label="Case ID" />
              </label>
            </>
          )}
          {run.isError && <Notice tone="danger" title="Run failed to queue">{effectErrorMessage(run.error, 'The flow could not be queued.')}</Notice>}
        </div>
        <div className="flex items-center justify-end gap-2 border-t border-border bg-[var(--card-2)] px-5 py-3">
          {needsPick && <span className="mr-auto text-[11px] text-muted-foreground">Pick {source === 'alert' ? 'an alert' : 'a case'} or use sample values.</span>}
          <Button variant="ghost" size="sm" className={smallButton} onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button size="sm" className={smallButton} disabled={blocked || run.isPending} onClick={() => run.mutate()}>
            {run.isPending ? 'Queuing…' : testing ? 'Test with alert' : dryRun ? 'Start dry run' : 'Run flow'}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
