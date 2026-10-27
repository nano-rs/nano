// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — step inspector (port of soar-flows.jsx StepSettings /
 * TriggerSettings / SettingsHead) writing the Windmill-subset fields.
 */
import { useId, useMemo, useState, type ReactNode } from 'react';
import { Lock, X } from 'lucide-react';
import type { SoarActionInput, SoarFlowTrigger } from '@/lib/api/soar';
import { cn } from '@/lib/utils';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import type { Ctx, FlowDoc, Json, RawModule, Transform } from './flow-editor-model';
import {
  LIMITS,
  actionOf,
  cronEvery,
  everyMinutes,
  retryAttempts,
  staticNumber,
  suspendSecs,
  transform,
  typeOf,
} from './flow-editor-model';
import { AdvancedToggle, EffectBadge, FilterSeg, H, Mono, inputCls } from './soar-kit';
import { asEffect, utcDateTime } from './soar-model';
import type { FieldDef } from './soar-fields';
import type { SearchStepScope } from './soar-fields';
import { evidenceScopeProblem, fieldFor, fieldLabel, isPath, judgeEvidenceFields, scopeFields, searchStepScope } from './soar-fields';
import { JUDGE, TTL_PRESETS, evidencePath, judgeEvidence, judgeLabels, labelProblem, ttlSecs } from './judge-rules';
import { ConditionEditor, ExprInput, FieldPicker, PathOrExpr } from './flow-easy';
import { SearchQueryField } from './FlowSearchQuery';

export type Upd = (fn: (m: RawModule) => void, key: string) => void;

function Head({ kind, title }: { kind: string; title: ReactNode }) {
  return (
    <div className="border-b border-border px-4 py-3">
      <H>{kind}</H>
      <div className="mt-0.5 text-[13.5px] font-semibold text-foreground">{title}</div>
    </div>
  );
}

function F({ label, required, hint, error, children }: { label: string; required?: boolean; hint?: ReactNode; error?: string | null; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="flex items-center gap-1 text-[11.5px] text-fg-2">
        {label}
        {required && <span className="text-destructive">*</span>}
      </span>
      {children}
      {error ? <span className="text-[11px] text-destructive">{error}</span> : hint ? <span className="text-[11px] text-muted-foreground">{hint}</span> : null}
    </div>
  );
}

function TextIn({ value, onChange, mono, error, type = 'text', label, disabled, area, describedBy }: { value: string | number; onChange: (v: string) => void; mono?: boolean; error?: boolean; type?: string; label: string; disabled?: boolean; area?: boolean; describedBy?: string }) {
  if (area) {
    return <textarea aria-label={label} aria-invalid={error || undefined} aria-describedby={describedBy} disabled={disabled} value={value} rows={4} spellCheck={false} onChange={(e) => onChange(e.target.value)} className={cn(inputCls(error), 'h-auto py-1.5', mono && 'font-mono text-[12px]')} />;
  }
  return <input aria-label={label} aria-invalid={error || undefined} aria-describedby={describedBy} type={type} disabled={disabled} value={value} onChange={(e) => onChange(e.target.value)} className={cn(inputCls(error), mono && 'font-mono text-[12px]')} />;
}

function SelectIn({ value, onChange, options, label, disabled }: { value: string; onChange: (v: string) => void; options: Array<[string, string]>; label: string; disabled?: boolean }) {
  return (
    <Select value={value} onValueChange={onChange} disabled={disabled}>
      <SelectTrigger aria-label={label} className="h-8 text-[12.5px] shadow-none"><SelectValue /></SelectTrigger>
      <SelectContent>
        {options.map(([v, l]) => <SelectItem key={v} value={v} className="text-[12px]">{l}</SelectItem>)}
      </SelectContent>
    </Select>
  );
}

function Radio({ checked, onChange, disabled, children }: { checked: boolean; onChange: () => void; disabled?: boolean; children: ReactNode }) {
  return (
    <label className={cn('flex items-start gap-2 text-[12px] text-foreground', disabled && 'opacity-60')}>
      <input type="radio" checked={checked} onChange={onChange} disabled={disabled} className="mt-[3px] accent-[var(--primary)]" />
      <span>{children}</span>
    </label>
  );
}

const minutesOf = (secs: number | null, fallback: number) => (secs === null ? fallback : Math.round((secs / 60) * 10) / 10);

export function TriggerSettings({ t, set, ro, nextRun }: { t: SoarFlowTrigger; set: (p: SoarFlowTrigger, key: string) => void; ro: boolean; nextRun: string | null }) {
  const every = t.cron ? everyMinutes(t.cron) : null;
  return (
    <div>
      <Head kind="Trigger" title="When this flow runs" />
      <fieldset disabled={ro} className="flex flex-col gap-3 px-4 py-3.5">
        <F label="Trigger type" required>
          <SelectIn
            label="Trigger type"
            disabled={ro}
            value={t.on}
            onChange={(on) => set(on === 'schedule' ? { on, cron: t.cron || '0 0 */6 * * * *', match: null } : on === 'manual' ? { on, match: null, cron: null } : { on, match: t.match ?? null, cron: null }, 'trigger.on')}
            options={[['manual', 'Manual'], ['alert', 'Alert committed'], ['case', 'Case event'], ['case.triage_verdict', 'Case triage verdict'], ['schedule', 'Schedule']]}
          />
        </F>
        {(t.on === 'alert' || t.on === 'case' || t.on === 'case.triage_verdict') && (
          <F label="Event match" hint={<>Event fields with <Mono>=</Mono> or <Mono>in [..]</Mono>, joined by <Mono>&amp;&amp;</Mono>{t.on === 'case.triage_verdict' ? <>; <Mono>confidence ≥ 0.8</Mono> thresholds</> : null}. Empty matches every event.</>}>
            <TextIn label="Event match" mono value={t.match ?? ''} onChange={(v) => set({ ...t, match: v || null }, 'trigger.match')} />
          </F>
        )}
        {t.on === 'schedule' && (
          <>
            <F label="Every (minutes)" error={every !== null && every < 5 ? 'Minimum interval is 5 minutes.' : null} hint={every === null ? 'Custom cron below.' : 'Minimum 5 minutes.'}>
              <TextIn label="Every (minutes)" mono type="number" value={every ?? ''} error={every !== null && every < 5} onChange={(v) => set({ ...t, cron: cronEvery(Number(v) || 0) }, 'trigger.cron')} />
            </F>
            <F label="Cron · UTC" required hint="sec min hour day month weekday year">
              <TextIn label="Cron" mono value={t.cron ?? ''} onChange={(v) => set({ ...t, cron: v }, 'trigger.cron')} />
            </F>
            <div className="text-[11.5px] text-fg-2">Next run: <Mono>{nextRun ? utcDateTime(nextRun) : '—'}</Mono></div>
          </>
        )}
        {t.on === 'manual' && <div className="text-[11.5px] text-muted-foreground">Runs only when someone starts it from this page or the API.</div>}
      </fieldset>
    </div>
  );
}

function setTransform(m: RawModule, field: string, key: string, t: Json | null) {
  const map = { ...((m.value[field] as Json | undefined) ?? {}) };
  if (t) map[key] = t;
  else delete map[key];
  m.value[field] = map;
}

/** NAN-4660: what the judge inspector needs about where the step sits. */
export interface JudgeScope {
  /** Fields the judge may cite (visible scope, alert.* only under an alert trigger). */
  fields: FieldDef[];
  /** Why one evidence reference cannot be read here, or null. */
  problem: (reference: string) => string | null;
}

export function StepSettings({ s, upd, ro, ctx, fields = [], scope, judge }: { s: RawModule; upd: Upd; ro: boolean; ctx: Ctx; fields?: FieldDef[]; scope?: SearchStepScope; judge?: JudgeScope }) {
  const v = s.value;
  const t = typeOf(s);
  if (t === 'judge') return <JudgeSettings s={s} upd={upd} ro={ro} judge={judge ?? { fields, problem: () => null }} />;
  if (t === 'action') {
    const found = actionOf(s, ctx.index);
    const fx = asEffect(found?.action.effect) ?? 'write';
    const conns = ctx.connections.filter((c) => c.pack_name === v.pack);
    const connId = String(v.connection ?? '');
    const connOpts: Array<[string, string]> = conns.map((c) => [c.id, c.label]);
    if (connId && !conns.some((c) => c.id === connId)) connOpts.push([connId, connId === 'default' ? 'Pack default' : connId]);
    const map = (v.input_transforms as Json | undefined) ?? {};
    const secs = staticNumber(s.timeout);
    const forced = fx === 'destructive' || !!found?.action.approval_forced;
    const retries = retryAttempts(s);
    return (
      <div>
        <Head kind={`Step ${s.id} · vendor action`} title={found?.action.display_name ?? `${String(v.pack)}.${String(v.action)}`} />
        <fieldset disabled={ro} className="flex flex-col gap-3.5 px-4 py-3.5">
          <div className="flex items-center gap-2">
            <EffectBadge effect={fx} />
            <span className="truncate text-[11.5px] text-muted-foreground">{found?.pack.display_name ?? String(v.pack)} · {conns.find((c) => c.id === connId)?.label ?? (connId || '—')}</span>
          </div>
          <F label="Connection" required error={!connId ? 'Connection is required.' : null}>
            <SelectIn label="Connection" disabled={ro} value={connId} onChange={(c) => upd((m) => { m.value.connection = c; }, 'connection')} options={connOpts.length ? connOpts : [['default', 'Pack default']]} />
          </F>
          <div className="flex flex-col gap-2">
            <H>Input mappings</H>
            {(found?.action.inputs ?? []).map((i) => (
              <MappingRow key={i.name} input={i} tr={transform(map[i.name])} fields={fields} ro={ro} upd={upd} />
            ))}
            {!found && <div className="text-[11.5px] text-destructive">This action is not in the installed catalog.</div>}
            <div className="text-[10.5px] text-muted-foreground">
              Pick a field from the trigger event or an earlier step, or type a fixed value. Advanced accepts helpers <Mono>coalesce</Mono>, <Mono>first</Mono>, <Mono>join</Mono>, <Mono>lower</Mono>.
            </div>
          </div>
          <div className="flex flex-col gap-1.5">
            <H>Approval policy</H>
            {forced ? (
              <div className="flex items-center gap-2 text-[12px] text-fg-2"><Lock className="h-3 w-3" strokeWidth={1.5} />Always required · {fx === 'destructive' ? 'destructive actions' : 'this action'} cannot auto-approve</div>
            ) : fx === 'read' ? (
              <>
                <div className="text-[12px] text-fg-2">Read action · no approval for trigger runs.</div>
                <Radio checked={v.approval === 'required'} onChange={() => upd((m) => { m.value.approval = m.value.approval === 'required' ? 'default' : 'required'; }, 'approval')} disabled={ro}>Always require approval</Radio>
              </>
            ) : (
              <>
                <Radio checked={v.approval !== 'auto'} onChange={() => upd((m) => { m.value.approval = 'default'; }, 'approval')} disabled={ro}>Require approval <span className="text-muted-foreground">(default)</span></Radio>
                <Radio checked={v.approval === 'auto'} onChange={() => upd((m) => { m.value.approval = 'auto'; }, 'approval')} disabled={ro}>
                  Allow automatic approval
                  <div className="text-[11px] text-muted-foreground">Applies to trigger runs only. AI-requested runs always need a human.</div>
                </Radio>
              </>
            )}
          </div>
          <TimeoutRetry s={s} upd={upd} secs={secs} retries={retries} safe={!!found?.action.idempotent} />
        </fieldset>
      </div>
    );
  }
  if (t === 'forloopflow') {
    const it = transform(v.iterator);
    const par = staticNumber(v.parallelism) ?? 1;
    return (
      <div>
        <Head kind={`Step ${s.id} · bounded loop`} title={`For each in ${it?.type === 'expr' ? it.expr || '…' : '…'}`} />
        <fieldset disabled={ro} className="flex flex-col gap-3 px-4 py-3.5">
          <F label="Repeat for each item in" required error={!(it?.type === 'expr' && it.expr) ? 'Choose a list to repeat over.' : null}>
            <PathOrExpr
              label="Items"
              ro={ro}
              fields={fields}
              filter={(d) => d.type === 'array' || d.type === 'object' || d.group === 'Flow input'}
              value={it?.type === 'expr' ? it.expr : ''}
              error={!(it?.type === 'expr' && it.expr)}
              onChange={(x) => upd((m) => { m.value.iterator = { type: 'expr', expr: x }; }, 'iterator')}
            />
          </F>
          <F label="Max iterations" hint="Server limit 100. Lists longer than 100 items fail the step.">
            <TextIn label="Max iterations" mono value={LIMITS.iterations} disabled onChange={() => {}} />
          </F>
          <F label="Mode" required>
            <SelectIn label="Mode" disabled={ro} value={v.parallel ? 'parallel' : 'sequential'} onChange={(x) => upd((m) => {
              m.value.parallel = x === 'parallel';
              if (x === 'parallel' && !m.value.parallelism) m.value.parallelism = { type: 'static', value: 2 };
              if (x !== 'parallel') delete m.value.parallelism;
            }, 'mode')} options={[['sequential', 'Sequential'], ['parallel', 'Parallel']]} />
          </F>
          {!!v.parallel && (
            <F label="Concurrency" required error={par > LIMITS.parallelism ? 'Server limit is 4.' : null} hint="Server limit 4.">
              <TextIn label="Concurrency" mono type="number" value={par} error={par > LIMITS.parallelism} onChange={(x) => upd((m) => { m.value.parallelism = { type: 'static', value: Number(x) || 1 }; }, 'parallelism')} />
            </F>
          )}
          <label className="flex items-center gap-2 text-[12px] text-foreground">
            <input type="checkbox" checked={!!v.skip_failures} onChange={(e) => upd((m) => { m.value.skip_failures = e.target.checked; }, 'skip_failures')} className="accent-[var(--primary)]" />
            Continue past failed items
          </label>
        </fieldset>
      </div>
    );
  }
  if (t === 'branchone') {
    const b0 = ((v.branches as Json[] | undefined) ?? [])[0] ?? {};
    const write = (expr: string) =>
      upd((m) => {
        const branches = (m.value.branches as Json[] | undefined) ?? [];
        if (!branches[0]) branches[0] = { expr: '', summary: 'then', modules: [] };
        branches[0].expr = expr;
        m.value.branches = branches;
      }, 'condition');
    return (
      <div>
        <Head kind={`Step ${s.id} · condition`} title="Branch on a value" />
        <fieldset disabled={ro} className="flex flex-col gap-3 px-4 py-3.5">
          <ConditionEditor expr={String(b0.expr ?? '')} onChange={write} fields={fields} ro={ro} />
          <div className="text-[11.5px] text-muted-foreground">Two paths: then / else. Nesting counts toward depth limit 4.</div>
        </fieldset>
      </div>
    );
  }
  if (t === 'approval') {
    const opts = Array.isArray(v.options) ? (v.options as string[]) : [];
    const exp = minutesOf(suspendSecs(s), 1440);
    return (
      <div>
        <Head kind={`Step ${s.id} · approval`} title="Pause for a human decision" />
        <fieldset disabled={ro} className="flex flex-col gap-3 px-4 py-3.5">
          <F label="Message to approver" required error={!String(v.prompt ?? '').trim() ? 'Message to approver is required.' : null}>
            <TextIn label="Message to approver" value={String(v.prompt ?? '')} onChange={(x) => upd((m) => { m.value.prompt = x; m.summary = x; }, 'prompt')} />
          </F>
          <F label="Choices" hint="Comma separated. Empty means approve / reject.">
            <TextIn label="Choices" mono value={opts.join(', ')} onChange={(x) => upd((m) => { m.value.options = x.split(',').map((o) => o.trim()).filter(Boolean); }, 'options')} />
          </F>
          {opts.length > 0 && (
            <F label="Note required on">
              <SelectIn label="Note required on" disabled={ro} value={String(v.note_required_on ?? '__none')} onChange={(x) => upd((m) => { if (x === '__none') delete m.value.note_required_on; else m.value.note_required_on = x; }, 'note')} options={[['__none', 'No choice'], ...opts.map((o): [string, string] => [o, o])]} />
            </F>
          )}
          <F label="Eligible approvers" hint="Holders of soar:approve. Self-approval is always prohibited.">
            <TextIn label="Eligible approvers" value="soar:approve" disabled onChange={() => {}} />
          </F>
          <F label="Expires after (min)" required hint="Counts toward the 24h total run time." error={exp * 60 > LIMITS.wallSecs ? 'Max 1440 minutes.' : null}>
            <TextIn label="Expires after" mono type="number" value={exp} error={exp * 60 > LIMITS.wallSecs} onChange={(x) => upd((m) => { m.suspend = { required_events: 1, resume_form: 'none', ...((m.suspend as Json | undefined) ?? {}), timeout_secs: Math.round(Number(x) * 60) || 60 }; }, 'expiry')} />
          </F>
        </fieldset>
      </div>
    );
  }
  if (t === 'search') {
    return (
      <div>
        <Head kind={`Step ${s.id} · nPL search`} title={s.summary || 'nPL search'} />
        <fieldset disabled={ro} className="flex flex-col gap-3 px-4 py-3.5">
          <F label="Query" required>
            <SearchQueryField
              value={String(v.query ?? '')}
              onChange={(x) => upd((m) => { m.value.query = x; }, 'query')}
              fields={fields}
              ro={ro}
              step={{ window: String(v.window ?? '24h'), limit: Number(v.limit ?? 100), scope: scope ?? { priorSteps: [], inLoop: false } }}
            />
          </F>
          <SearchOptions v={v} upd={upd} ro={ro} />
        </fieldset>
      </div>
    );
  }
  if (t === 'notify.email') {
    return (
      <div>
        <Head kind={`Step ${s.id} · email`} title={`Email ${String(v.to || '…')}`} />
        <fieldset disabled={ro} className="flex flex-col gap-3 px-4 py-3.5">
          <F label="To" required hint="A recipient from Settings → SOAR."><TextIn label="To" mono value={String(v.to ?? '')} onChange={(x) => upd((m) => { m.value.to = x; }, 'to')} /></F>
          <F label="Subject" required><TextIn label="Subject" value={String(v.subject ?? '')} onChange={(x) => upd((m) => { m.value.subject = x; }, 'subject')} /></F>
          <F label="Body" required><TextIn area label="Body" value={String(v.body ?? '')} onChange={(x) => upd((m) => { m.value.body = x; }, 'body')} /></F>
          <div className="flex flex-col gap-1.5">
            <H>Approval policy</H>
            <Radio checked={v.approval !== 'auto'} onChange={() => upd((m) => { m.value.approval = 'default'; }, 'approval')} disabled={ro}>Require approval <span className="text-muted-foreground">(default)</span></Radio>
            <Radio checked={v.approval === 'auto'} onChange={() => upd((m) => { m.value.approval = 'auto'; }, 'approval')} disabled={ro}>Allow automatic approval</Radio>
          </div>
        </fieldset>
      </div>
    );
  }
  if (t === 'identity') {
    return (
      <div>
        <Head kind={`Step ${s.id} · pass-through`} title={s.summary || 'Pass-through'} />
        <fieldset disabled={ro} className="flex flex-col gap-3 px-4 py-3.5">
          <F label="Label"><TextIn label="Label" value={s.summary ?? ''} onChange={(x) => upd((m) => { m.summary = x; }, 'summary')} /></F>
          <div className="text-[12px] text-fg-2">Passes inputs through unchanged. Useful as an explicit no-op branch.</div>
        </fieldset>
      </div>
    );
  }
  return (
    <div>
      <Head kind={`Step ${s.id} · ${t || 'step'}`} title={s.summary || t} />
      <div className="px-4 py-3.5">
        <div className="mb-2 text-[11.5px] text-muted-foreground">This step type is edited through the API. Shown read-only.</div>
        <pre className="overflow-auto rounded-md border border-border bg-background px-2.5 py-2 font-mono text-[10.5px] leading-[1.6] text-fg-2">{JSON.stringify(v, null, 2)}</pre>
      </div>
    </div>
  );
}

/**
 * NAN-4660 — the AI judge (server: soar/flow/judge.rs). The question and
 * labels are fixed authored text; only the evidence reads flow scope.
 */
function JudgeSettings({ s, upd, ro, judge }: { s: RawModule; upd: Upd; ro: boolean; judge: JudgeScope }) {
  const v = s.value;
  const question = typeof v.question === 'string' ? v.question : '';
  const labels = judgeLabels(v);
  const evidence = judgeEvidence(v);
  const cap = v.token_cap ?? JUDGE.tokenCap.default;
  const ttl = typeof v.cache_ttl === 'string' ? v.cache_ttl : JUDGE.defaultTtl;
  const [draft, setDraft] = useState('');
  const draftErr = draft ? labelProblem(draft, labels) : null;
  const qBytes = new TextEncoder().encode(question).length;
  const qErr = !question.trim() ? 'Question is required.' : qBytes > JUDGE.questionBytes ? `Question is longer than ${JUDGE.questionBytes} bytes.` : question.includes('\0') ? 'Question contains a NUL character.' : null;
  const labelsErr = labels.length < JUDGE.minLabels
    ? `At least ${JUDGE.minLabels} labels are required.`
    : labels.length > JUDGE.maxLabels
      ? `At most ${JUDGE.maxLabels} labels.`
      : labels.map((l, i) => labelProblem(l, labels.slice(0, i))).find(Boolean) ?? null;
  const capErr = typeof cap !== 'number' || !Number.isInteger(cap) || cap < JUDGE.tokenCap.min || cap > JUDGE.tokenCap.max ? `Whole number from ${JUDGE.tokenCap.min} to ${JUDGE.tokenCap.max}.` : null;
  const ttlErr = ttlSecs(ttl) === null ? 'Seconds (90s) or hours (6h), at most 24h.' : null;
  const ttlOpts: Array<[string, string]> = TTL_PRESETS.some(([x]) => x === ttl) ? TTL_PRESETS : [...TTL_PRESETS, [ttl, ttl]];
  const chosen = new Set(evidence.map((r) => evidencePath(r) ?? r));
  const addLabel = () => {
    const l = draft.trim();
    if (!l || labelProblem(l, labels) || labels.length >= JUDGE.maxLabels) return;
    upd((m) => { m.value.labels = [...judgeLabels(m.value), l]; }, 'labels');
    setDraft('');
  };
  const entity = typeof v.entity === 'string' ? v.entity : null;
  return (
    <div>
      <Head kind={`Step ${s.id} · AI judge`} title={question.trim() || 'Ask the AI a fixed question'} />
      <fieldset disabled={ro} className="flex flex-col gap-3.5 px-4 py-3.5">
        <F label="Question" required error={qErr} hint="Fixed text; scope values are never interpolated. Cite them as evidence below.">
          <TextIn area label="Question" value={question} error={!!qErr} onChange={(x) => upd((m) => { m.value.question = x; }, 'question')} />
        </F>

        <div className="flex flex-col gap-1" data-testid="judge-labels">
          <span className="flex items-center gap-1 text-[11.5px] text-fg-2">Verdict labels<span className="text-destructive">*</span></span>
          <div className="flex flex-wrap items-center gap-1">
            {labels.map((l) => (
              <span key={l} className="inline-flex h-6 items-center gap-1 rounded-[3px] border border-border-2 px-1.5 font-mono text-[11.5px] text-foreground">
                {l}
                {!ro && (
                  <button
                    type="button"
                    aria-label={`Remove label ${l}`}
                    disabled={labels.length <= JUDGE.minLabels}
                    title={labels.length <= JUDGE.minLabels ? `A judge needs at least ${JUDGE.minLabels} labels` : undefined}
                    onClick={() => upd((m) => { m.value.labels = judgeLabels(m.value).filter((x) => x !== l); }, 'labels')}
                    className="text-fg-4 hover:text-foreground disabled:opacity-40"
                  >
                    <X className="h-3 w-3" strokeWidth={1.5} />
                  </button>
                )}
              </span>
            ))}
            <span className="inline-flex h-6 items-center rounded-[3px] border border-dashed border-border px-1.5 font-mono text-[11.5px] text-muted-foreground" title="Always available when the model cannot decide">unknown</span>
          </div>
          {!ro && (
            <div className="flex items-center gap-1.5">
              <input
                aria-label="New label"
                aria-invalid={!!draftErr || undefined}
                value={draft}
                placeholder="add a label"
                spellCheck={false}
                onChange={(e) => setDraft(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addLabel(); } }}
                className={cn(inputCls(!!draftErr), 'h-7 flex-1 font-mono text-[12px]')}
              />
              <button
                type="button"
                onClick={addLabel}
                disabled={!draft.trim() || !!draftErr || labels.length >= JUDGE.maxLabels}
                className="inline-flex h-7 items-center rounded-md border border-border px-2.5 text-[11.5px] text-fg-2 hover:text-foreground disabled:opacity-60"
              >
                Add
              </button>
            </div>
          )}
          {draftErr ? <span className="text-[11px] text-destructive">{draftErr}</span>
            : labelsErr ? <span className="text-[11px] text-destructive">{labelsErr}</span>
            : <span className="text-[11px] text-muted-foreground">Letters, digits, _ or -. Branch on <Mono>{`results.${s.id}.verdict`}</Mono>.</span>}
        </div>

        <div className="flex flex-col gap-1.5" data-testid="judge-evidence">
          <span className="flex items-center gap-1 text-[11.5px] text-fg-2">Evidence<span className="text-destructive">*</span><span className="ml-auto font-mono text-[10.5px] text-fg-4">{evidence.length}/{JUDGE.maxEvidence}</span></span>
          {evidence.map((r) => {
            const path = evidencePath(r);
            const problem = !path ? 'Not a flow scope path.' : judge.problem(r);
            const known = path ? fieldFor(path, judge.fields) : undefined;
            return (
              <div key={r} data-testid="judge-evidence-row" className="flex flex-col gap-0.5">
                <div className={cn('flex h-7 items-center gap-2 rounded-md border px-2', problem ? 'border-destructive/60' : 'border-border')}>
                  <span className="min-w-0 truncate text-[12px] text-foreground">{known && path ? fieldLabel(path, judge.fields) : r}</span>
                  {known && <span className="ml-auto min-w-0 truncate font-mono text-[10.5px] text-muted-foreground">{r}</span>}
                  {!ro && (
                    <button type="button" aria-label={`Remove evidence ${r}`} onClick={() => upd((m) => { m.value.evidence = judgeEvidence(m.value).filter((x) => x !== r); }, 'evidence')} className={cn('shrink-0 text-fg-4 hover:text-foreground', !known && 'ml-auto')}>
                      <X className="h-3 w-3" strokeWidth={1.5} />
                    </button>
                  )}
                </div>
                {problem && <span className="text-[11px] text-destructive">{problem.charAt(0).toUpperCase() + problem.slice(1)}{/[.;]$/.test(problem) ? '' : '.'}</span>}
              </div>
            );
          })}
          {!ro && evidence.length < JUDGE.maxEvidence && (
            <div>
              <FieldPicker
                variant="button"
                label="Add evidence"
                placeholder="Add evidence"
                fields={judge.fields}
                filter={(d) => !chosen.has(d.path)}
                value=""
                onChange={(p) => upd((m) => { if (!judgeEvidence(m.value).includes(p)) m.value.evidence = [...judgeEvidence(m.value), p]; }, 'evidence')}
              />
            </div>
          )}
          {evidence.length === 0
            ? <span className="text-[11px] text-destructive">Pick at least one evidence field.</span>
            : <span className="text-[11px] text-muted-foreground">Sent as JSON data, capped at 32 KiB. Prefer search summaries to row sets.</span>}
        </div>

        <div className="grid grid-cols-2 gap-3">
          <F label="Token cap" required error={capErr} hint={`${JUDGE.tokenCap.min}–${JUDGE.tokenCap.max} completion tokens`}>
            <TextIn label="Token cap" mono type="number" value={typeof cap === 'number' ? cap : ''} error={!!capErr} onChange={(x) => upd((m) => { m.value.token_cap = x === '' ? 0 : Number(x); }, 'token_cap')} />
          </F>
          <F label="Cache verdicts for" required error={ttlErr} hint="Same evidence reuses the verdict">
            <SelectIn label="Cache TTL" disabled={ro} value={ttl} onChange={(x) => upd((m) => { m.value.cache_ttl = x; }, 'cache_ttl')} options={ttlOpts} />
          </F>
        </div>
        {entity && (
          <div className="text-[11.5px] text-muted-foreground">Cache entity <Mono className="text-fg-2">{entity}</Mono> (set through the API).</div>
        )}
        <div className="text-[11.5px] text-muted-foreground">Read step: runs in dry runs and on triggers, metered against the daily SOAR AI token budget. A verdict never approves a later action.</div>
      </fieldset>
    </div>
  );
}

function TimeoutRetry({ s, upd, secs, retries, safe }: { s: RawModule; upd: Upd; secs: number | null; retries: number; safe: boolean }) {
  const min = minutesOf(secs, 15);
  const over = min * 60 > LIMITS.activeSecs;
  return (
    <>
      <div className="grid grid-cols-2 gap-3">
        <F label="Step timeout (min)" required error={over ? 'Max 15 minutes active time.' : null}>
          <TextIn label="Step timeout" mono type="number" value={min} error={over} onChange={(x) => upd((m) => { m.timeout = { type: 'static', value: Math.max(1, Math.round(Number(x) * 60) || 1) }; }, 'timeout')} />
        </F>
        <F label="Automatic retries" required>
          <TextIn
            label="Automatic retries"
            mono
            type="number"
            value={safe ? retries : 0}
            disabled={!safe}
            onChange={(x) => upd((m) => {
              const n = Math.max(0, Math.min(5, Number(x) || 0));
              if (n === 0) { delete m.retry; return; }
              const r = (m.retry as Json | undefined) ?? {};
              const kind = r.exponential ? 'exponential' : 'constant';
              const cur = (r[kind] as Json | undefined) ?? { seconds: 5 };
              m.retry = { [kind]: { ...cur, attempts: n } };
            }, 'retry')}
          />
        </F>
      </div>
      <div className={cn('-mt-1.5 text-[11.5px]', safe ? 'text-muted-foreground' : 'text-warn')}>
        {safe
          ? 'This action declares itself safe to retry (idempotent). Retries back off exponentially.'
          : 'This action is not safe to retry. Automatic retries are off; a failed send becomes an ambiguous outcome that needs verification.'}
      </div>
      {s.continue_on_error === true && <div className="text-[11.5px] text-muted-foreground">Continues on error (set through the API).</div>}
    </>
  );
}

export function FlowInspector({ sel, s, doc, trigger, setTrigger, upd, ro, ctx, nextRun }: {
  sel: string;
  doc: FlowDoc;
  s: RawModule | null;
  trigger: SoarFlowTrigger;
  setTrigger: (t: SoarFlowTrigger, key: string) => void;
  upd: Upd;
  ro: boolean;
  ctx: Ctx;
  nextRun: string | null;
}) {
  const fields = useMemo(() => (s ? scopeFields(doc, trigger.on, s.id, ctx.index) : []), [doc, trigger.on, s, ctx.index]);
  const scope = useMemo(() => (s ? searchStepScope(doc, trigger.on, s.id) : undefined), [doc, trigger.on, s]);
  const judge = useMemo<JudgeScope | undefined>(
    () => (s && typeOf(s) === 'judge' ? { fields: judgeEvidenceFields(doc, trigger.on, s.id, ctx.index), problem: (r) => evidenceScopeProblem(doc, trigger.on, s.id, r) } : undefined),
    [doc, trigger.on, s, ctx.index],
  );
  if (sel === 'trigger') return <TriggerSettings t={trigger} set={setTrigger} ro={ro} nextRun={nextRun} />;
  if (!s) return <div className="px-4 py-3.5 text-[12px] text-muted-foreground">This step no longer exists.</div>;
  return <StepSettings key={s.id} s={s} upd={upd} ro={ro} ctx={ctx} fields={fields} scope={scope} judge={judge} />;
}

const WINDOWS: Array<[string, string]> = [['15m', 'Last 15 minutes'], ['1h', 'Last hour'], ['6h', 'Last 6 hours'], ['24h', 'Last 24 hours'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days']];

/** Search window (easy: presets) plus raw window/limit in advanced. */
function SearchOptions({ v, upd, ro }: { v: Json; upd: Upd; ro: boolean }) {
  const win = String(v.window ?? '');
  const preset = WINDOWS.some(([w]) => w === win);
  const [adv, setAdv] = useState(!preset);
  const advanced = adv || !preset;
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-end gap-2">
        <div className="flex-1">
          {advanced ? (
            <div className="grid grid-cols-2 gap-3">
              <F label="Time range" required hint="s, m, h or d · ≤ 30d"><TextIn label="Window" mono value={win} onChange={(x) => upd((m) => { m.value.window = x; }, 'window')} /></F>
              <F label="Row limit" required hint="≤ 1000"><TextIn label="Row limit" mono type="number" value={Number(v.limit ?? 0)} onChange={(x) => upd((m) => { m.value.limit = Number(x) || 0; }, 'limit')} /></F>
            </div>
          ) : (
            <F label="Time range" required>
              <SelectIn label="Window" disabled={ro} value={win} onChange={(x) => upd((m) => { m.value.window = x; }, 'window')} options={WINDOWS} />
            </F>
          )}
        </div>
        <div className={advanced ? 'pb-[22px]' : 'pb-1'}>
          <AdvancedToggle label="Advanced search options" on={advanced} onChange={setAdv} disabled={!preset} title={!preset ? 'Custom time range; edit as text.' : undefined} />
        </div>
      </div>
      {!advanced && <div className="text-[11px] text-muted-foreground">Returns up to <Mono>{Number(v.limit ?? 0)}</Mono> rows. Change the limit in Advanced.</div>}
    </div>
  );
}

/** One action input: "Type a value" | "Use a field", or the raw expression in advanced. */
/** Static values are checked against the declared input type only. */
function staticTypeError(type: string, text: string): string | null {
  const t = text.trim();
  if (!t) return null;
  if (type === 'integer') return /^-?\d+$/.test(t) ? null : 'Enter a whole number.';
  if (type === 'number') return Number.isFinite(Number(t)) ? null : 'Enter a number.';
  return null;
}

function MappingRow({ input: i, tr: tr0, fields, ro, upd }: { input: SoarActionInput; tr: Transform | null; fields: FieldDef[]; ro: boolean; upd: Upd }) {
  const tr = tr0 ?? { type: 'static' as const, value: '' };
  const text = tr.type === 'expr' ? tr.expr : tr.value === undefined || tr.value === null ? '' : typeof tr.value === 'string' ? tr.value : JSON.stringify(tr.value);
  const easyOk = tr.type === 'static' || text === '' || isPath(text);
  const [adv, setAdv] = useState(!easyOk);
  const advanced = adv || !easyOk;
  const missing = i.required && !text;
  const write = (kind: 'static' | 'expr', raw: string) =>
    upd((m) => {
      if (!raw && !i.required) return setTransform(m, 'input_transforms', i.name, null);
      const num = (i.type === 'integer' || i.type === 'number') && raw !== '' && !Number.isNaN(Number(raw));
      setTransform(m, 'input_transforms', i.name, kind === 'expr' ? { type: 'expr', expr: raw } : { type: 'static', value: num ? Number(raw) : raw });
    }, `input.${i.name}`);
  // Switching kind keeps a path-shaped value; anything else starts empty.
  const switchTo = (k: 'static' | 'expr') => !ro && k !== tr.type && write(k, k === 'expr' && isPath(text) ? text : '');
  const valueErr = tr.type === 'static' ? staticTypeError(i.type, text) : null;
  const errId = useId();
  const msg = missing ? `${i.name} is required.` : valueErr;
  return (
    <div className="flex flex-col gap-1" data-testid={`mapping-${i.name}`}>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[11.5px]">
        <Mono className="text-foreground">{i.name}</Mono>
        <span className="font-mono text-[10px] text-fg-4">{i.type}</span>
        {i.required && <span className="text-destructive">*</span>}
        <span className="ml-auto flex items-center gap-1.5">
        <FilterSeg
          label={`${i.name} mode`}
          value={tr.type}
          onChange={switchTo}
          options={advanced ? [['static', 'Value'], ['expr', 'Expression']] : [['static', 'Type a value'], ['expr', 'Use a field']]}
        />
        <AdvancedToggle label={`${i.name} advanced`} on={advanced} onChange={setAdv} disabled={!easyOk} title={!easyOk ? 'Uses helpers or literals, so it can only be edited as text.' : undefined} />
        </span>
      </div>
      {tr.type === 'expr' ? (
        advanced ? (
          <ExprInput braces label={`${i.name} expression`} value={text} onChange={(x) => write('expr', x)} fields={fields} error={missing} describedBy={msg ? errId : undefined} disabled={ro} />
        ) : (
          <FieldPicker variant="input" label={`${i.name} field`} fields={fields} value={text} onChange={(p) => write('expr', p)} disabled={ro} describedBy={msg ? errId : undefined} />
        )
      ) : (
        <TextIn label={`${i.name} value`} mono value={text} error={!!msg} describedBy={msg ? errId : undefined} onChange={(x) => write('static', x)} />
      )}
      {msg && <span id={errId} className="text-[11px] text-destructive">{msg}</span>}
      {!easyOk && <span className="text-[11px] text-muted-foreground">Shown as text because it uses helpers or literals. It is kept as written.</span>}
    </div>
  );
}
