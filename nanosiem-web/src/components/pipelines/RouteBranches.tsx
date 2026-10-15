// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from 'react';
import { Plus, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { canonicalInput } from '@/lib/pipeline-model';
import type { PipelineLaneInput } from '@/lib/pipeline-types';

type Route = Record<string, unknown>;

const KIND_LABEL: Record<PipelineLaneInput['kind'], string> = { push: 'Push', pull: 'Pull', feed: 'Feed' };

function routeInputsOf(route: Route): string[] {
  return Array.isArray(route.inputs) ? route.inputs.filter((value): value is string => typeof value === 'string') : [];
}

/**
 * NAN-3625: ordered route branches. Each branch matches an expression or
 * "Input is" one or more of the lane's inputs (push credentials, pull sources,
 * connector feeds by their ingest credential). Input matching reads the
 * platform-stamped input identity, never the event body.
 */
export function RouteBranches({
  routes,
  inputs,
  disabled,
  onChange,
}: {
  routes: unknown;
  inputs: PipelineLaneInput[];
  disabled: boolean;
  onChange: (routes: Route[]) => void;
}) {
  const list: Route[] = Array.isArray(routes) ? routes.filter((route): route is Route => !!route && typeof route === 'object' && !Array.isArray(route)) : [];
  const update = (index: number, next: Route) => onChange(list.map((route, i) => (i === index ? next : route)));
  const usedLabels = new Set(list.map((route) => String(route.label ?? '')));
  const freshLabel = () => {
    for (let n = list.length + 1; ; n++) if (!usedLabels.has(`branch_${n}`)) return `branch_${n}`;
  };
  return (
    <div className="space-y-2">
      <span className="block text-[11px] font-medium text-muted-foreground">Ordered routes</span>
      {list.map((route, index) => (
        <RouteBranch
          key={index}
          index={index}
          route={route}
          inputs={inputs}
          disabled={disabled}
          onChange={(next) => update(index, next)}
          onRemove={list.length > 1 ? () => onChange(list.filter((_, i) => i !== index)) : undefined}
        />
      ))}
      <Button
        variant="outline"
        className="h-7 text-[11.5px]"
        disabled={disabled || list.length >= 16}
        onClick={() => onChange([...list, { label: freshLabel(), predicate: 'true', drop: false }])}
      >
        <Plus className="h-3.5 w-3.5" strokeWidth={1.5} />
        Add branch
      </Button>
    </div>
  );
}

function RouteBranch({
  index,
  route,
  inputs,
  disabled,
  onChange,
  onRemove,
}: {
  index: number;
  route: Route;
  inputs: PipelineLaneInput[];
  disabled: boolean;
  onChange: (route: Route) => void;
  onRemove?: () => void;
}) {
  const n = index + 1;
  const selected = routeInputsOf(route);
  const byInput = route.inputs !== undefined;
  const [manual, setManual] = useState('');
  const [manualError, setManualError] = useState<string | null>(null);
  // Inputs the branch already names stay visible even when the lane no longer lists them.
  const listed = new Map(inputs.map((input) => [input.id, input]));
  const options: PipelineLaneInput[] = [
    ...inputs,
    ...selected.filter((id) => !listed.has(id)).map((id) => ({ id, kind: id.startsWith('pull:') ? 'pull' as const : 'push' as const, label: 'Not listed for this lane' })),
  ];
  const without = (key: string): Route => Object.fromEntries(Object.entries(route).filter(([name]) => name !== key));
  // "Input is" replaces the expression; switching back restores a predicate.
  const setInputs = (next: string[]) => onChange({ ...without('predicate'), inputs: next });
  const setMode = (mode: string) => {
    if (mode === 'input') setInputs(selected);
    else onChange({ ...without('inputs'), predicate: typeof route.predicate === 'string' ? route.predicate : 'true' });
  };
  const addManual = () => {
    try {
      const id = canonicalInput(manual);
      if (!selected.includes(id)) setInputs([...selected, id]);
      setManual(''); setManualError(null);
    } catch (error) {
      setManualError(error instanceof Error ? error.message : String(error));
    }
  };
  return (
    <div className="space-y-2 border border-border p-2" data-testid={`route-branch-${n}`}>
      <div className="flex items-center gap-2">
        <span className="font-mono text-[10.5px] text-muted-foreground">{n}</span>
        <Input
          aria-label={`Branch ${n} label`}
          className="h-7 flex-1 font-mono text-[11.5px]"
          disabled={disabled}
          value={String(route.label ?? '')}
          onChange={(event) => onChange({ ...route, label: event.target.value })}
        />
        <select
          aria-label={`Branch ${n} condition`}
          className="h-7 rounded-md border border-border bg-input px-2 text-[11.5px]"
          disabled={disabled}
          value={byInput ? 'input' : 'expression'}
          onChange={(event) => setMode(event.target.value)}
        >
          <option value="expression">Expression</option>
          <option value="input">Input is</option>
        </select>
        <label className="flex items-center gap-1 text-[11px] text-muted-foreground">
          <Checkbox
            aria-label={`Branch ${n} drop`}
            checked={route.drop === true}
            disabled={disabled}
            onCheckedChange={(checked) => onChange({ ...route, drop: checked === true })}
          />
          Drop
        </label>
        {onRemove && (
          <Button variant="ghost" className="h-7 w-7 p-0" aria-label={`Remove branch ${n}`} disabled={disabled} onClick={onRemove}>
            <X className="h-3.5 w-3.5" strokeWidth={1.5} />
          </Button>
        )}
      </div>
      {!byInput ? (
        <Input
          aria-label={`Branch ${n} predicate`}
          className="h-7 font-mono text-[11.5px]"
          disabled={disabled}
          value={String(route.predicate ?? '')}
          placeholder={'.severity_id >= 4'}
          onChange={(event) => onChange({ ...route, predicate: event.target.value })}
        />
      ) : (
        <div className="space-y-1">
          {options.length === 0 && (
            <p className="text-[10.5px] text-muted-foreground">No inputs are listed for this lane yet. Add an input id below.</p>
          )}
          {options.map((input) => (
            <label key={input.id} className="flex items-center gap-2 text-[11.5px]">
              <Checkbox
                aria-label={`Branch ${n} input ${input.label}`}
                checked={selected.includes(input.id)}
                disabled={disabled}
                onCheckedChange={(checked) => setInputs(checked === true ? [...selected, input.id] : selected.filter((id) => id !== input.id))}
              />
              <span className="w-9 font-mono text-[10.5px] text-muted-foreground">{KIND_LABEL[input.kind]}</span>
              <span className="min-w-0 truncate">{input.label}</span>
              <span className="ml-auto truncate font-mono text-[10.5px] text-muted-foreground">{input.id}</span>
            </label>
          ))}
          <div className="flex items-center gap-2">
            <Input
              aria-label={`Branch ${n} input id`}
              className="h-7 flex-1 font-mono text-[11.5px]"
              disabled={disabled}
              value={manual}
              placeholder="push:<credential id> or pull:<pull source id>"
              onChange={(event) => setManual(event.target.value)}
              onKeyDown={(event) => { if (event.key === 'Enter') { event.preventDefault(); addManual(); } }}
            />
            <Button variant="outline" className="h-7 text-[11.5px]" disabled={disabled || !manual.trim()} onClick={addManual}>Add input</Button>
          </div>
          {manualError && <span role="alert" className="block text-[10.5px] text-destructive">{manualError}</span>}
          {selected.length === 0 && <span className="block text-[10.5px] text-destructive">Choose at least one input.</span>}
        </div>
      )}
    </div>
  );
}
