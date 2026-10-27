// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4586 — easy-mode building blocks for the flow inspector: field picker,
 * sentence tokens, and an autocompleting expression input for advanced mode.
 * All suggestions come from soar-fields.ts.
 */
import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { Check, ChevronDown, X } from 'lucide-react';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { cn } from '@/lib/utils';
import type { BindingPart, FieldDef, EasyOp, ValueKind } from './soar-fields';
import {
  EASY_OP_LABEL,
  checkValue,
  conditionValueProblem,
  completeExpression,
  fieldFor,
  fieldLabel,
  formatEasyCondition,
  isPath,
  kindOf,
  parseEasyCondition,
} from './soar-fields';
import { AdvancedToggle, SearchBox, inputCls, tokenCls, useListNav } from './soar-kit';

const scrollToOption = (id: string | undefined) => {
  if (!id) return;
  const el = document.getElementById(id) as (HTMLElement & { scrollIntoView?: (o: object) => void }) | null;
  el?.scrollIntoView?.({ block: 'nearest' });
};

// ── Autocompleting expression input ─────────────────────────────────────

/**
 * Suggestions open only once the user types (or presses Ctrl+Space / ↓), so
 * tabbing through the inspector never changes anything. Enter accepts the
 * highlighted suggestion; Tab accepts only after the user arrowed into the
 * list, otherwise it moves focus as usual.
 */
export function ExprInput({ value, onChange, fields, label, error, braces, placeholder, disabled, describedBy }: {
  value: string;
  onChange: (v: string) => void;
  fields: FieldDef[];
  label: string;
  error?: boolean;
  /** Show the `{{ }}` frame used for input mappings. */
  braces?: boolean;
  placeholder?: string;
  disabled?: boolean;
  describedBy?: string;
}) {
  const ref = useRef<HTMLInputElement>(null);
  const uid = useId();
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState(0);
  const [active, setActive] = useState(0);
  const [navigated, setNavigated] = useState(false);
  const comp = open && !disabled ? completeExpression(value, Math.min(pos, value.length), fields) : null;
  const opts = comp?.options ?? [];
  const listId = `${uid}-suggestions`;
  const optId = (i: number) => `${uid}-opt-${i}`;
  const cur = opts.length ? Math.min(active, opts.length - 1) : -1;
  const activeId = cur >= 0 ? optId(cur) : undefined;
  useEffect(() => scrollToOption(activeId), [activeId]);

  const close = () => { setOpen(false); setNavigated(false); setActive(0); };
  const sync = () => setPos(ref.current?.selectionStart ?? value.length);
  const accept = (i: number) => {
    const s = opts[i];
    if (!s || !comp) return;
    const next = value.slice(0, comp.from) + s.apply + value.slice(comp.to);
    const caret = comp.from + s.apply.length;
    onChange(next);
    setPos(caret);
    setActive(0);
    setNavigated(false);
    setOpen(s.kind === 'helper');
    requestAnimationFrame(() => ref.current?.setSelectionRange(caret, caret));
  };
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (!opts.length) {
      if ((e.key === ' ' && e.ctrlKey) || e.key === 'ArrowDown') { e.preventDefault(); sync(); setOpen(true); }
      return;
    }
    if (e.key === 'ArrowDown') { e.preventDefault(); setNavigated(true); setActive((cur + 1) % opts.length); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setNavigated(true); setActive((cur - 1 + opts.length) % opts.length); }
    else if (e.key === 'Enter') { e.preventDefault(); accept(cur); }
    else if (e.key === 'Tab') { if (navigated && !e.shiftKey) { e.preventDefault(); accept(cur); } else close(); }
    else if (e.key === 'Escape') { e.preventDefault(); close(); }
  };

  const input = (
    <input
      ref={ref}
      aria-label={label}
      role="combobox"
      aria-expanded={opts.length > 0}
      aria-controls={listId}
      aria-activedescendant={activeId}
      aria-autocomplete="list"
      aria-invalid={error || undefined}
      aria-describedby={describedBy}
      autoComplete="off"
      spellCheck={false}
      disabled={disabled}
      placeholder={placeholder}
      value={value}
      onChange={(e) => { onChange(e.target.value); setPos(e.target.selectionStart ?? e.target.value.length); setOpen(true); setActive(0); setNavigated(false); }}
      onBlur={close}
      onClick={sync}
      onKeyUp={(e) => { if (e.key === 'ArrowLeft' || e.key === 'ArrowRight' || e.key === 'Home' || e.key === 'End') sync(); }}
      onKeyDown={onKey}
      className={braces ? 'min-w-0 flex-1 bg-transparent px-1.5 font-mono text-[12px] text-primary outline-none' : cn(inputCls(error), 'font-mono text-[12px]')}
    />
  );
  return (
    <div className="relative">
      {braces ? (
        <div className={cn('flex h-8 items-center rounded-md border px-2 font-mono text-[12px]', error ? 'border-destructive/60' : 'border-border-2')}>
          <span className="text-fg-4">{'{{'}</span>
          {input}
          <span className="text-fg-4">{'}}'}</span>
        </div>
      ) : input}
      {opts.length > 0 && (
        <div id={listId} role="listbox" aria-label={`${label} suggestions`} className="absolute left-0 right-0 top-full z-50 mt-1 max-h-60 overflow-auto rounded-md border border-border bg-popover py-1 shadow-md">
          {opts.map((o, i) => (
            <div
              key={`${o.kind}:${o.label}`}
              id={optId(i)}
              role="option"
              aria-selected={i === cur}
              onMouseDown={(e) => { e.preventDefault(); accept(i); }}
              onMouseEnter={() => setActive(i)}
              className={cn('flex cursor-pointer flex-col px-2.5 py-1', i === cur && 'bg-accent')}
            >
              <span className={cn('break-all font-mono text-[11.5px] leading-[1.35]', o.kind === 'helper' ? 'text-ai' : 'text-foreground')}>{o.label}</span>
              <span className="truncate text-[10.5px] text-muted-foreground">{o.detail}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Field picker ────────────────────────────────────────────────────────

export function FieldPicker({ fields, value, onChange, label, disabled, variant = 'token', placeholder = 'choose a field', filter, onPicked, describedBy }: {
  fields: FieldDef[];
  value: string;
  onChange: (path: string) => void;
  label: string;
  disabled?: boolean;
  /** token = inline sentence pill; input = full-width field; button = small action button. */
  variant?: 'token' | 'input' | 'button';
  placeholder?: ReactNode;
  filter?: (d: FieldDef) => boolean;
  onPicked?: () => void;
  describedBy?: string;
}) {
  const uid = useId();
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const shown = useMemo(() => {
    const ql = q.trim().toLowerCase();
    return fields.filter((d) => (!filter || filter(d)) && (!ql || d.path.toLowerCase().includes(ql) || d.label.toLowerCase().includes(ql) || d.group.toLowerCase().includes(ql)));
  }, [fields, filter, q]);
  const groups = useMemo(() => {
    const m = new Map<string, FieldDef[]>();
    for (const d of shown) m.set(d.group, [...(m.get(d.group) ?? []), d]);
    return [...m.entries()];
  }, [shown]);
  const custom = q.trim() && isPath(q.trim()) && !fieldFor(q.trim(), fields) ? q.trim() : null;
  // Keyboard order = visual order: grouped fields, then the custom path.
  const order = useMemo(() => [...groups.flatMap(([, list]) => list.map((d) => d.path)), ...(custom ? [custom] : [])], [groups, custom]);
  const known = value ? fieldFor(value, fields) : undefined;
  const pick = (p: string) => { onChange(p); setOpen(false); setQ(''); onPicked?.(); };
  const nav = useListNav(order.length, (i) => order[i] !== undefined && pick(order[i]), `${uid}-field`);
  useEffect(() => scrollToOption(nav.activeId), [nav.activeId]);
  const listId = `${uid}-list`;

  const display = !value ? (
    <span className="text-fg-4">{placeholder}</span>
  ) : known ? (
    <span className="truncate">{fieldLabel(value, fields)}</span>
  ) : (
    <span className="truncate font-mono text-[11.5px]">{value}</span>
  );
  return (
    <Popover open={open} onOpenChange={(o) => { setOpen(o); if (!o) setQ(''); nav.setActive(0); }}>
      <PopoverTrigger asChild disabled={disabled}>
        <button
          type="button"
          aria-label={label}
          aria-describedby={describedBy}
          title={value || undefined}
          className={
            variant === 'input'
              ? cn(inputCls(false), 'flex items-center gap-1.5 text-left disabled:opacity-60')
              : variant === 'button'
                ? 'inline-flex h-6 items-center gap-1 rounded-[3px] border border-border px-1.5 text-[11px] text-fg-2 hover:text-foreground disabled:opacity-60'
                : tokenCls
          }
        >
          {variant === 'button' ? placeholder : display}
          <ChevronDown className="ml-auto h-3 w-3 shrink-0 text-fg-4" strokeWidth={1.5} />
        </button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-80 p-0">
        <div className="border-b border-border p-1.5">
          <SearchBox
            label="Search fields"
            placeholder="Search fields or type a path"
            value={q}
            onChange={(v) => { setQ(v); nav.setActive(0); }}
            onKeyDown={nav.onKeyDown}
            listId={listId}
            activeId={nav.activeId}
          />
        </div>
        <div id={listId} role="listbox" aria-label={`${label} options`} className="max-h-72 overflow-auto py-1">
          {groups.map(([g, list]) => (
            <div key={g} role="group" aria-label={g} className="py-0.5">
              <div className="px-2.5 pb-0.5 pt-1 font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground">{g}</div>
              {list.map((d) => {
                const i = order.indexOf(d.path);
                return (
                  <div
                    key={d.path}
                    id={nav.optionId(i)}
                    role="option"
                    aria-selected={d.path === value}
                    onMouseDown={(e) => e.preventDefault()}
                    onClick={() => pick(d.path)}
                    onMouseEnter={() => nav.setActive(i)}
                    className={cn('flex w-full cursor-pointer items-center gap-2 px-2.5 py-1 text-left', i === nav.active ? 'bg-accent' : d.path === value && 'bg-accent/60')}
                  >
                    <span className="shrink-0 whitespace-nowrap text-[12px] text-foreground">{d.label}</span>
                    {d.only && <span className="text-[10.5px] text-muted-foreground">({d.only} only)</span>}
                    <span className="ml-auto min-w-0 truncate font-mono text-[10.5px] text-muted-foreground">{d.path}</span>
                  </div>
                );
              })}
            </div>
          ))}
          {custom && (
            <div
              id={nav.optionId(order.length - 1)}
              role="option"
              aria-selected={false}
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => pick(custom)}
              onMouseEnter={() => nav.setActive(order.length - 1)}
              className={cn('flex w-full cursor-pointer items-center gap-2 px-2.5 py-1 text-left', nav.active === order.length - 1 && 'bg-accent')}
            >
              <span className="text-[12px] text-foreground">Use</span>
              <span className="font-mono text-[11px] text-primary">{custom}</span>
            </div>
          )}
          {!groups.length && !custom && <div className="px-2.5 py-2 text-[11.5px] text-muted-foreground">No matching fields. Type a full path such as <span className="font-mono">flow_input.host</span>.</div>}
        </div>
      </PopoverContent>
    </Popover>
  );
}

// ── Sentence tokens ─────────────────────────────────────────────────────

function MenuToken({ label, display, options, selected, onPick, multi, disabled, mono, describedBy }: {
  label: string;
  display: ReactNode;
  options: Array<[string, string]>;
  selected: string[];
  onPick: (v: string) => void;
  multi?: boolean;
  disabled?: boolean;
  mono?: boolean;
  describedBy?: string;
}) {
  const uid = useId();
  const [open, setOpen] = useState(false);
  const choose = (i: number) => {
    const o = options[i];
    if (!o) return;
    onPick(o[0]);
    if (!multi) setOpen(false);
  };
  const nav = useListNav(options.length, choose, `${uid}-menu`);
  return (
    <Popover
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (o) nav.setActive(Math.max(0, options.findIndex(([v]) => selected.includes(v))));
      }}
    >
      <PopoverTrigger asChild disabled={disabled}>
        <button type="button" aria-label={label} aria-describedby={describedBy} className={cn(tokenCls, mono && 'font-mono text-[11.5px]')}>
          {display}
          <ChevronDown className="h-3 w-3 shrink-0 text-fg-4" strokeWidth={1.5} />
        </button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-48 p-1">
        <div
          role="listbox"
          tabIndex={0}
          aria-label={`${label} options`}
          aria-multiselectable={multi || undefined}
          aria-activedescendant={nav.activeId}
          onKeyDown={nav.onKeyDown}
          className="outline-none"
        >
          {options.map(([v, l], i) => (
            <div
              key={v}
              id={nav.optionId(i)}
              role="option"
              aria-selected={selected.includes(v)}
              onClick={() => choose(i)}
              onMouseEnter={() => nav.setActive(i)}
              className={cn('flex h-6 w-full cursor-pointer items-center gap-2 rounded-[3px] px-2 text-left text-[12px]', i === nav.active && 'bg-accent', mono && 'font-mono text-[11.5px]')}
            >
              <Check className={cn('h-3 w-3', selected.includes(v) ? 'opacity-100' : 'opacity-0')} strokeWidth={1.5} />
              {l}
            </div>
          ))}
        </div>
      </PopoverContent>
    </Popover>
  );
}

/**
 * Free-text value token. Keystrokes edit a local draft; only valid drafts are
 * written to the expression, so a stray `"` never flips the editor to
 * advanced. The draft's problem is reported through `onProblem`.
 */
function FreeToken({ value, onChange, kind, values, label, disabled, describedBy, onProblem }: {
  value: string;
  onChange: (v: string) => void;
  kind: ValueKind;
  values?: readonly string[];
  label: string;
  disabled?: boolean;
  describedBy?: string;
  onProblem: (p: string | null) => void;
}) {
  const [draft, setDraft] = useState(value);
  const [prev, setPrev] = useState(value);
  if (value !== prev) { setPrev(value); setDraft(value); }
  const err = conditionValueProblem(kind, draft, values);
  return (
    <input
      aria-label={label}
      aria-invalid={!!err}
      aria-describedby={describedBy}
      disabled={disabled}
      value={draft}
      placeholder="value"
      spellCheck={false}
      size={Math.max(6, Math.min(28, draft.length + 1))}
      onChange={(e) => {
        const v = e.target.value;
        const p = conditionValueProblem(kind, v, values);
        setDraft(v);
        onProblem(p);
        if (!p) onChange(v);
      }}
      onBlur={() => { if (err) { setDraft(value); onProblem(null); } }}
      className={cn('h-6 rounded-[3px] border bg-transparent px-1.5 align-middle font-mono text-[11.5px] text-foreground outline-none focus:ring-1 focus:ring-ring', err ? 'border-destructive/60 underline decoration-destructive decoration-wavy' : 'border-border-2')}
    />
  );
}

/** "is one of" values as chips. A comma is never part of a value. */
function ChipsToken({ values, onChange, kind, label, disabled, describedBy, onProblem }: {
  values: string[];
  onChange: (v: string[]) => void;
  kind: ValueKind;
  label: string;
  disabled?: boolean;
  describedBy?: string;
  onProblem: (p: string | null) => void;
}) {
  const [draft, setDraft] = useState('');
  const problem = (v: string) => (v.includes(',') ? 'One value per chip. Commas are not allowed in a value.' : v ? conditionValueProblem(kind, v) : null);
  const err = problem(draft);
  const edit = (v: string) => { setDraft(v); onProblem(problem(v)); };
  const add = () => {
    const v = draft.trim();
    if (!v || err) return;
    if (!values.includes(v)) onChange([...values, v]);
    edit('');
  };
  return (
    <span className="inline-flex flex-wrap items-center gap-1 align-middle">
      {values.map((v) => (
        <span key={v} className="inline-flex h-6 items-center gap-1 rounded-[3px] border border-border-2 px-1.5 font-mono text-[11.5px]">
          {v}
          {!disabled && (
            <button type="button" aria-label={`Remove ${v}`} onClick={() => onChange(values.filter((x) => x !== v))} className="text-fg-4 hover:text-foreground">
              <X className="h-3 w-3" strokeWidth={1.5} />
            </button>
          )}
        </span>
      ))}
      <input
        aria-label={label}
        aria-invalid={!!err}
        aria-describedby={describedBy}
        disabled={disabled}
        value={draft}
        placeholder="add value ↵"
        spellCheck={false}
        size={Math.max(9, Math.min(24, draft.length + 1))}
        onChange={(e) => edit(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') { e.preventDefault(); add(); }
          else if (e.key === ',' && draft.trim() && !err) { e.preventDefault(); add(); }
        }}
        onBlur={add}
        className={cn('h-6 rounded-[3px] border bg-transparent px-1.5 font-mono text-[11.5px] outline-none focus:ring-1 focus:ring-ring', err ? 'border-destructive/60 underline decoration-destructive decoration-wavy' : 'border-dashed border-border-2')}
      />
    </span>
  );
}

// ── Branch condition ────────────────────────────────────────────────────

/** The easy sentence "When [field] [is] [value]" with an Advanced raw-expression mode. */
export function ConditionEditor({ expr, onChange, fields, ro }: { expr: string; onChange: (expr: string) => void; fields: FieldDef[]; ro: boolean }) {
  const errId = useId();
  const easy = parseEasyCondition(expr);
  const [adv, setAdv] = useState(easy === null);
  const [draftProblem, setDraftProblem] = useState<string | null>(null);
  const advanced = adv || easy === null;
  const toggle = (
    <AdvancedToggle
      label="Advanced condition"
      on={advanced}
      disabled={easy === null}
      title={easy === null ? 'This condition can only be edited as text.' : undefined}
      onChange={(a) => { setAdv(a); setDraftProblem(null); }}
    />
  );
  if (advanced) {
    const empty = !expr.trim();
    return (
      <div className="flex flex-col gap-1.5" data-testid="condition-advanced">
        <div className="flex items-center gap-2">
          <span className="flex-1 text-[11.5px] text-fg-2">Condition</span>
          {toggle}
        </div>
        <ExprInput label="Condition" value={expr} onChange={onChange} fields={fields} error={empty} describedBy={empty ? errId : undefined} disabled={ro} placeholder="flow_input.alert.severity in [high, critical]" />
        {empty && <div id={errId} className="text-[11px] text-destructive">Write a condition.</div>}
        {easy === null && !empty && (
          <div className="text-[11px] text-muted-foreground">Shown as text because the simple editor can't represent it exactly. It is kept as written.</div>
        )}
        <div className="text-[10.5px] text-muted-foreground">
          Forms: <span className="font-mono">path = value</span>, <span className="font-mono">path in [a, b]</span>, or a true/false <span className="font-mono">path</span>.
        </div>
      </div>
    );
  }
  const c = easy!;
  const d = c.path ? fieldFor(c.path, fields) : undefined;
  const kind = kindOf(c.path, d);
  // A bare path must resolve to a boolean at run time, so only boolean fields offer "is true".
  const ops: Array<[EasyOp, string]> = [
    ['is', EASY_OP_LABEL.is],
    ['one_of', EASY_OP_LABEL.one_of],
    ...(d?.type === 'boolean' || c.op === 'true' ? [['true', EASY_OP_LABEL.true] as [EasyOp, string]] : []),
  ];
  const write = (next: typeof c) => onChange(formatEasyCondition(next));
  const setField = (path: string) => {
    const nd = fieldFor(path, fields);
    const keep = nd?.values ? c.values.filter((v) => nd.values!.includes(v)) : c.values;
    const op: EasyOp = c.op === 'true' && nd?.type !== 'boolean' ? 'is' : c.op;
    setDraftProblem(null);
    write({ path, op, values: op === 'is' ? keep.slice(0, 1) : keep });
  };
  const setOp = (op: EasyOp) => { setDraftProblem(null); write({ ...c, op, values: op === 'true' ? [] : op === 'is' ? c.values.slice(0, 1) : c.values }); };
  const committedErr = c.op === 'is' ? checkValue(kind, c.values[0] ?? '', d?.values) : c.op === 'one_of' ? c.values.map((v) => checkValue(kind, v, d?.values)).find(Boolean) ?? null : null;
  const err = draftProblem ?? committedErr;
  const missing = !err && !!c.path && c.op !== 'true' && !c.values.some((v) => v !== '');
  const msg = err ?? (missing ? 'Choose a value.' : null);
  const describedBy = msg ? errId : undefined;
  let value: ReactNode = null;
  if (c.path && c.op !== 'true') {
    if (d?.values) {
      const opts = d.values.map((v): [string, string] => [v, v]);
      value = c.op === 'is' ? (
        <MenuToken label="Condition value" mono display={c.values[0] || <span className="text-fg-4">choose</span>} options={opts} selected={c.values} onPick={(v) => write({ ...c, values: [v] })} disabled={ro} describedBy={describedBy} />
      ) : (
        <MenuToken
          label="Condition values"
          mono
          multi
          display={c.values.length ? c.values.join(', ') : <span className="text-fg-4">choose</span>}
          options={opts}
          selected={c.values}
          onPick={(v) => write({ ...c, values: c.values.includes(v) ? c.values.filter((x) => x !== v) : d.values!.filter((x) => x === v || c.values.includes(x)) })}
          disabled={ro}
          describedBy={describedBy}
        />
      );
    } else if (c.op === 'is') {
      value = <FreeToken label="Condition value" kind={kind} value={c.values[0] ?? ''} onChange={(v) => write({ ...c, values: [v] })} onProblem={setDraftProblem} disabled={ro} describedBy={describedBy} />;
    } else {
      value = <ChipsToken label="Condition values" kind={kind} values={c.values} onChange={(vs) => write({ ...c, values: vs })} onProblem={setDraftProblem} disabled={ro} describedBy={describedBy} />;
    }
  }
  return (
    <div className="flex flex-col gap-1.5" data-testid="condition-easy">
      {/* One sentence: tokens flow inline like words and wrap only when the line is full. */}
      <div className="text-[12.5px] leading-[28px] text-foreground [&>*]:mr-1">
        <span className="float-right !mr-0 ml-1.5">{toggle}</span>
        <span className="text-fg-2">When</span>
        <FieldPicker label="Condition field" fields={fields} value={c.path} onChange={setField} disabled={ro} />
        {c.path && (
          <MenuToken label="Condition operator" display={EASY_OP_LABEL[c.op]} options={ops} selected={[c.op]} onPick={(v) => setOp(v as EasyOp)} disabled={ro} />
        )}
        {value}
      </div>
      {msg && <div id={errId} role={err ? 'alert' : undefined} className="text-[11px] text-destructive">{msg}</div>}
      {!c.path && <div className="text-[11px] text-muted-foreground">Pick the field this step checks. Matching runs the then path, everything else runs else.</div>}
    </div>
  );
}

// ── Single-field easy/advanced value (action inputs, loop items) ────────

/**
 * A field picker that falls back to the raw expression. Easy mode only
 * shows bare paths; anything else opens in advanced and is never rewritten.
 */
export function PathOrExpr({ value, onChange, fields, label, ro, filter, braces, error }: {
  value: string;
  onChange: (v: string) => void;
  fields: FieldDef[];
  label: string;
  ro: boolean;
  filter?: (d: FieldDef) => boolean;
  braces?: boolean;
  error?: boolean;
}) {
  const easyOk = value === '' || isPath(value);
  const [adv, setAdv] = useState(!easyOk);
  const advanced = adv || !easyOk;
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-center gap-2">
        <div className="min-w-0 flex-1">
          {advanced ? (
            <ExprInput label={`${label} expression`} value={value} onChange={onChange} fields={fields} braces={braces} error={error} disabled={ro} />
          ) : (
            <FieldPicker label={`${label} field`} variant="input" fields={fields} value={value} onChange={onChange} disabled={ro} filter={filter} />
          )}
        </div>
        <AdvancedToggle label={`${label} advanced`} on={advanced} onChange={setAdv} disabled={!easyOk} title={!easyOk ? 'Uses helpers or literals, so it can only be edited as text.' : undefined} />
      </div>
      {!easyOk && <div className="text-[11px] text-muted-foreground">Shown as text because it uses helpers or literals. It is kept as written.</div>}
    </div>
  );
}

// ── Read-only rendering of bindings and fields (canvas) ────────────────

/** A friendly field name, or the mono raw path when the catalog doesn't know it. */
export function FieldName({ label, path }: { label: string | null; path: string }) {
  return label ? <span title={path}>{label}</span> : <span className="font-mono">{path}</span>;
}

/** Query text with `{{path}}` bindings shown as chips. */
export function BoundText({ parts }: { parts: BindingPart[] }) {
  return (
    <>
      {parts.map((p, i) =>
        'text' in p ? (
          <span key={i}>{p.text}</span>
        ) : (
          <span key={i} data-binding={p.path} title={p.path} className={cn('mx-px rounded-[3px] border px-1', p.label ? 'border-primary/40 bg-primary/10 font-sans text-primary' : 'border-border-2 font-mono')}>
            {p.label ?? p.path}
          </span>
        ),
      )}
    </>
  );
}
