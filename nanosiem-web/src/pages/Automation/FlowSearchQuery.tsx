// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4586 — nPL query field for the Search step: the Search page's
 * CodeMirror editor (lazy), an "Insert field" picker that writes
 * `{{flow_input.…}}` bindings, and a Validate button.
 *
 * Validate posts the step to POST /api/soar/flows/validate-search, which
 * compiles it exactly as flow save does (bindings, scope, window, limit) and
 * runs nothing. Only when that endpoint is absent (older API: 404/405) does
 * it fall back to a local mirror of the compile's template pass plus the
 * nPL parser at /api/rules/validate; that path only proves syntax, so it
 * never says the step is valid.
 */
import { Suspense, useRef, useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { lazyWithRetry } from '@/lib/lazyWithRetry';
import { cn } from '@/lib/utils';
import type { FieldDef, SearchStepScope } from './soar-fields';
import type { SoarSearchDiagnostic, SoarValidateSearchRequest } from '@/lib/api/soar';
import { errorStatus } from './soar-queries';
import { insertBinding, outerTimeModifiers, searchSkeleton } from './soar-fields';
import { FieldPicker } from './flow-easy';
import { AdvancedToggle, Spinner } from './soar-kit';

const FlowNplEditor = lazyWithRetry(() => import('./FlowNplEditor'));

export interface SearchStepContext {
  window: string;
  limit: number;
  scope: SearchStepScope;
}

interface Checked { source: 'server' | 'local'; valid: boolean; errors: string[] }

/** "line 1, column 7: message" (field-prefixed for window/limit). */
function diagnosticText(d: SoarSearchDiagnostic): string {
  const where = d.line != null ? `line ${d.line}${d.column != null ? `, column ${d.column}` : ''}: ` : '';
  const field = d.field && d.field !== 'query' ? `${d.field === 'window' ? 'Time range' : d.field === 'limit' ? 'Row limit' : d.field}: ` : '';
  return `${field}${where}${d.message}`;
}

/** Offline fallback for an API without validate-search: syntax only. */
async function localCheck(q: string): Promise<Checked> {
  const sk = searchSkeleton(q);
  if ('error' in sk) return { source: 'local', valid: false, errors: [sk.error] };
  const times = outerTimeModifiers(sk.skeleton);
  if (times.length) return { source: 'local', valid: false, errors: [`Remove ${times.join(', ')}. The step's time window sets the search range.`] };
  const r = await api.validateDetection(sk.skeleton, 'scheduled');
  return { source: 'local', valid: r.valid, errors: r.valid ? [] : r.errors.length ? r.errors : ['The query does not parse.'] };
}

export function SearchQueryField({ value, onChange, fields, ro, step }: { value: string; onChange: (v: string) => void; fields: FieldDef[]; ro: boolean; step: SearchStepContext }) {
  const cursor = useRef<number | null>(null);
  const [adv, setAdv] = useState(false);
  const [checked, setChecked] = useState<string | null>(null);
  const request: SoarValidateSearchRequest = {
    query: value,
    window: step.window,
    limit: step.limit,
    ...(step.scope.trigger ? { trigger: step.scope.trigger } : {}),
    prior_steps: step.scope.priorSteps,
    in_loop: step.scope.inLoop,
  };
  const key = JSON.stringify(request);
  const validate = useMutation({
    mutationFn: async (req: SoarValidateSearchRequest): Promise<Checked> => {
      try {
        const r = await api.soar.validateSearch(req);
        return { source: 'server', valid: r.valid, errors: r.errors.map(diagnosticText) };
      } catch (e) {
        const status = errorStatus(e);
        if (status === 404 || status === 405) return localCheck(req.query);
        throw e;
      }
    },
    onSuccess: (_r, req) => setChecked(JSON.stringify(req)),
  });
  const result = validate.data && checked === key ? validate.data : null;
  const errors = result && !result.valid ? (result.errors.length ? result.errors : ['The search step does not compile.']) : [];
  const stale = !!validate.data && checked !== key;

  return (
    <div className="flex flex-col gap-1.5" data-testid="search-query">
      <div className={cn('rounded-md border bg-background px-1 py-0.5 focus-within:ring-1 focus-within:ring-ring', errors.length ? 'border-destructive/60' : 'border-border-2', ro && 'pointer-events-none opacity-70')}>
        <Suspense fallback={<div className="flex h-8 items-center gap-2 px-2 text-[11.5px] text-muted-foreground"><Spinner />Loading editor…</div>}>
          <FlowNplEditor value={value} onChange={(v) => { if (!ro) onChange(v); }} fields={fields} chips={!adv} onCursor={(p) => { cursor.current = p; }} />
        </Suspense>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <FieldPicker
          variant="button"
          label="Insert field"
          placeholder="Insert field"
          fields={fields}
          value=""
          disabled={ro}
          onChange={(path) => {
            const { text, caret } = insertBinding(value, cursor.current ?? value.length, path);
            cursor.current = caret;
            onChange(text);
          }}
        />
        <button
          type="button"
          disabled={!value.trim() || validate.isPending}
          onClick={() => validate.mutate(request)}
          className="inline-flex h-6 items-center gap-1 rounded-[3px] border border-border px-1.5 text-[11px] text-fg-2 hover:text-foreground disabled:opacity-60"
        >
          {validate.isPending && <Spinner className="h-2.5 w-2.5" />}
          Validate query
        </button>
        <span className="ml-auto"><AdvancedToggle label="Advanced query" on={adv} onChange={setAdv} /></span>
      </div>
      {result?.valid && result.source === 'server' && <span className="text-[11px] text-good" data-testid="query-valid">The flow will accept this search step.</span>}
      {result?.valid && result.source === 'local' && <span className="text-[11px] text-fg-2" data-testid="query-checked">No nPL syntax errors found. The flow's Validate runs the full check.</span>}
      {stale && <span className="text-[11px] text-muted-foreground">Edited since the last check.</span>}
      {errors.length > 0 && (
        <ul className="flex flex-col gap-0.5" data-testid="query-errors">
          {errors.map((e) => <li key={e} className="font-mono text-[11px] text-destructive">{e}</li>)}
        </ul>
      )}
      {validate.isError && (
        <div className="text-[11px] text-destructive">
          {errorStatus(validate.error) === 403 ? 'Checking a search step needs soar:manage.' : 'Validation is unavailable right now.'}
        </div>
      )}
      <div className="text-[10.5px] text-muted-foreground">
        {adv
          ? <>Fields are bound as literal values, e.g. <span className="font-mono">{'host={{flow_input.alert.entities.host}}'}</span>. Validate checks the query around them.</>
          : 'Inserted fields fill in a value from the event when the flow runs. The step\u2019s time window sets the range.'}
      </div>
    </div>
  );
}
