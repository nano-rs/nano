// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4546 — Run action sheet (mock soar-run-action.jsx RunActionSheet).
 * Typed inputs with a "provide one of" target group, an effect-tinted
 * summary, a dry-run preview that follows the queued preview run, and a
 * destructive confirm with an explicit acknowledgement.
 *
 * Posts to `/api/soar/actions/run` only; the server owns authZ (`soar:run`),
 * the demo fence, approval policy, schema validation and case privacy.
 * "Preview" is a dry run (no vendor call). "Request run" queues a real run;
 * write and destructive actions then wait at the approval gate server-side.
 */
import { useMemo, useState, type ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Check, ChevronRight, Eye } from 'lucide-react';
import { api } from '@/lib/api';
import type { SoarCatalog, SoarConnection, SoarStepResult } from '@/lib/api/soar';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Sheet, SheetContent, SheetDescription, SheetTitle } from '@/components/ui/sheet';
import { cn } from '@/lib/utils';
import { asEffect, isTerminal, packUsable, shortId, verbOf } from './soar-model';
import { ActionChip, EffectBadge, Field, H, Mono, Note, Notice, Spinner, inputCls, smallButton } from './soar-kit';
import { effectErrorMessage, invalidateSoar, useRun } from './soar-queries';
import {
  approvalPolicyText,
  coerceInput,
  formTarget,
  rollbackAction,
  TYPE_HINT,
  validateInputs,
} from './case-model';

export interface RunActionPreset {
  pack?: string;
  action?: string;
  /** Preferred connection; otherwise the pack's first ready connection. */
  connectionId?: string;
  /** Input name → value to prefill, e.g. an entity from a case. */
  inputs?: Record<string, string>;
  caseId?: string;
  /** Display label for the preset case, e.g. "CASE-1042 · Suspicious PowerShell". */
  caseLabel?: string;
}

export interface RunActionSheetProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  tenant: string;
  catalog: SoarCatalog | undefined;
  connections: SoarConnection[];
  preset?: RunActionPreset;
}

const EFFECT_LABEL = { read: 'Read', write: 'Write', destructive: 'Destructive' } as const;

export function RunActionSheet({ open, onOpenChange, tenant, catalog, connections, preset }: RunActionSheetProps) {
  const client = useQueryClient();
  const navigate = useNavigate();
  const usablePacks = useMemo(() => (catalog?.packs ?? []).filter(packUsable), [catalog]);
  const usable = useMemo(
    () => connections.filter((c) => usablePacks.some((p) => p.name === c.pack_name)),
    [connections, usablePacks],
  );

  const [connectionId, setConnectionId] = useState('');
  const [actionName, setActionName] = useState('');
  const [values, setValues] = useState<Record<string, string>>({});
  const [caseId, setCaseId] = useState('');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [confirm, setConfirm] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const [preview, setPreview] = useState<string | null>(null);

  // Reset each time the sheet opens; later refetches must not wipe typing.
  const [openedFor, setOpenedFor] = useState(false);
  if (open !== openedFor) {
    setOpenedFor(open);
    if (open) {
      const byPack = usable.filter((c) => c.pack_name === preset?.pack);
      const conn =
        usable.find((c) => c.id === preset?.connectionId) ?? byPack.find((c) => c.ready) ?? byPack[0] ?? (preset?.pack ? undefined : usable[0]);
      setConnectionId(conn?.id ?? '');
      const p = usablePacks.find((x) => x.name === conn?.pack_name);
      setActionName(preset?.action ?? p?.actions[0]?.name ?? '');
      setValues(preset?.inputs ?? {});
      setCaseId(preset?.caseId ?? '');
      setErrors({});
      setConfirm(false);
      setAcknowledged(false);
      setPreview(null);
    }
  }

  const connection = usable.find((c) => c.id === connectionId);
  const pack = usablePacks.find((p) => p.name === connection?.pack_name);
  const action = pack?.actions.find((a) => a.name === actionName);
  const effect = asEffect(action?.effect);
  const inverse = rollbackAction(pack, action);
  const target = formTarget(action, values);
  const alt = new Set(action?.require_one_of.flat() ?? []);
  const altGroups = action?.require_one_of.filter((g) => g.length > 1) ?? [];
  const inGroup = new Set(altGroups.flat());
  const live = action ? validateInputs(action, values, caseId) : {};
  const ready = !!connection && !!action && Object.keys(live).length === 0;

  const body = (dryRun: boolean) => ({
    connection_id: connectionId,
    action: actionName,
    inputs: Object.fromEntries(
      (action?.inputs ?? []).filter((i) => values[i.name]?.trim()).map((i) => [i.name, coerceInput(i.type, values[i.name])]),
    ),
    ...(caseId.trim() ? { case_id: caseId.trim() } : {}),
    dry_run: dryRun,
  });

  const run = useMutation({
    mutationFn: (dryRun: boolean) => api.soar.queueAction(body(dryRun)),
    onSuccess: (result, dryRun) => {
      void invalidateSoar(client, tenant);
      if (dryRun) {
        setPreview(result.id);
        return;
      }
      setConfirm(false);
      onOpenChange(false);
      navigate(`/automation/runs/${result.id}`);
    },
  });

  const check = () => {
    if (!action) return false;
    const e = validateInputs(action, values, caseId);
    setErrors(e);
    return Object.keys(e).length === 0;
  };
  const doPreview = () => check() && run.mutate(true);
  const doRequest = () => {
    if (!check()) return;
    if (effect === 'destructive') {
      setAcknowledged(false);
      setConfirm(true);
    } else run.mutate(false);
  };
  const set = (name: string, v: string) => {
    setValues((prev) => ({ ...prev, [name]: v }));
    setPreview(null);
    if (errors[name] || errors._alt) setErrors(({ [name]: _drop, _alt: _a, ...rest }) => rest);
  };
  const requesting = run.isPending && run.variables === false;
  const previewing = run.isPending && run.variables === true;
  const verb = action ? verbOf(action.name, action.display_name) : '';
  const targetText = target?.value ?? '—';

  return (
    <>
      <Sheet open={open} onOpenChange={(o) => !requesting && onOpenChange(o)}>
        <SheetContent
          side="right"
          hideClose
          overlayClassName="bg-black/40 backdrop-blur-none"
          // Bottom sheet below the mobile breakpoint, like DetailSheet.
          className="flex w-[600px] max-w-[calc(100vw-24px)] flex-col gap-0 bg-card p-0 text-foreground shadow-xl sm:max-w-[calc(100vw-24px)] max-sm:inset-x-0 max-sm:bottom-0 max-sm:top-auto max-sm:h-auto max-sm:max-h-[88vh] max-sm:w-full max-sm:max-w-full max-sm:rounded-t-md max-sm:border-l-0 max-sm:border-t"
          data-testid="run-action-dialog"
        >
          <header className="shrink-0 border-b border-border px-4 pb-3 pt-3.5">
            <div className="flex items-start gap-3">
              <div className="min-w-0 flex-1">
                <H className="mb-1">Run action</H>
                <SheetTitle className="truncate text-[15px] font-semibold tracking-[-0.01em]">{action?.display_name ?? 'Choose an action'}</SheetTitle>
                <SheetDescription asChild>
                  <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11.5px] text-muted-foreground">
                    {effect && <EffectBadge effect={effect} />}
                    <span>{connection?.label ?? 'No connection selected'}</span>
                  </div>
                </SheetDescription>
              </div>
              <button
                type="button"
                onClick={() => !requesting && onOpenChange(false)}
                aria-label="Close"
                title="Close (esc)"
                className="flex h-7 w-7 items-center justify-center rounded-md text-muted-foreground hover:bg-foreground/5 hover:text-foreground"
              >
                <svg viewBox="0 0 24 24" className="h-[14px] w-[14px]" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden>
                  <path d="M6 6l12 12M18 6 6 18" />
                </svg>
              </button>
            </div>
          </header>

          <div className="flex flex-1 flex-col gap-4 overflow-y-auto px-4 py-3.5">
            {usable.length === 0 ? (
              <Notice title="No runnable packs">
                Install a pack and add a ready connection under Capabilities before requesting actions.
              </Notice>
            ) : (
              <>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <Field label="Connection" required>
                    <Select
                      value={connectionId}
                      onValueChange={(v) => {
                        setConnectionId(v);
                        const nextPack = usablePacks.find((p) => p.name === usable.find((c) => c.id === v)?.pack_name);
                        if (!nextPack?.actions.some((a) => a.name === actionName)) setActionName(nextPack?.actions[0]?.name ?? '');
                        setValues({});
                        setErrors({});
                        setPreview(null);
                      }}
                    >
                      <SelectTrigger className="h-8 text-[12.5px] shadow-none" aria-label="Connection">
                        <SelectValue placeholder="Choose a connection" />
                      </SelectTrigger>
                      <SelectContent>
                        {usable.map((c) => (
                          <SelectItem key={c.id} value={c.id} className="text-[12px]">
                            {c.label}
                            {c.ready ? '' : ' (not ready)'}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </Field>
                  <Field label="Action" required>
                    <Select
                      value={actionName}
                      onValueChange={(v) => {
                        setActionName(v);
                        setValues({});
                        setErrors({});
                        setPreview(null);
                      }}
                      disabled={!pack}
                    >
                      <SelectTrigger className="h-8 text-[12.5px] shadow-none" aria-label="Action">
                        <SelectValue placeholder={pack ? 'Choose an action' : 'Choose a connection first'} />
                      </SelectTrigger>
                      <SelectContent>
                        {(pack?.actions ?? []).map((a) => {
                          const fx = asEffect(a.effect);
                          return (
                            <SelectItem key={a.name} value={a.name} className="text-[12px]">
                              {a.display_name} · {fx ? EFFECT_LABEL[fx] : a.effect}
                            </SelectItem>
                          );
                        })}
                      </SelectContent>
                    </Select>
                  </Field>
                </div>
                {action?.description && <div className="-mt-1 text-[12px] text-muted-foreground">{action.description}</div>}

                {action && (
                  <div className="flex flex-col gap-3">
                    <H>Inputs</H>
                    {altGroups.map((group, gi) => (
                      <div
                        key={gi}
                        className={cn('flex flex-col gap-2 rounded-md border p-2.5', errors._alt ? 'border-destructive/50' : 'border-border')}
                      >
                        <div className="text-[11.5px] text-fg-2">Target · provide one of</div>
                        <div className="grid items-end gap-2" style={{ gridTemplateColumns: group.map(() => 'minmax(0,1fr)').join(' auto ') }}>
                          {group.map((name, n) => {
                            const i = action.inputs.find((x) => x.name === name);
                            if (!i) return null;
                            return (
                              <FragmentWithOr key={name} or={n > 0}>
                                <TypedInput name={i.name} type={i.type} value={values[i.name] ?? ''} error={errors[i.name]} required="alt" onChange={(v) => set(i.name, v)} />
                              </FragmentWithOr>
                            );
                          })}
                        </div>
                        {errors._alt && <div className="text-[11px] text-destructive">{errors._alt}</div>}
                      </div>
                    ))}
                    {action.inputs
                      .filter((i) => !inGroup.has(i.name))
                      .map((i) => (
                        <TypedInput
                          key={i.name}
                          name={i.name}
                          type={i.type}
                          value={values[i.name] ?? ''}
                          error={errors[i.name]}
                          required={alt.has(i.name) ? 'alt' : i.required}
                          onChange={(v) => set(i.name, v)}
                        />
                      ))}
                    {errors._alt && altGroups.length === 0 && <div className="text-[11px] text-destructive">{errors._alt}</div>}
                    <Field label="Attach to case" required={false} hint={
                        caseId.trim() && caseId.trim() === preset?.caseId && preset?.caseLabel
                          ? `${preset.caseLabel} · results and approvals post to the case wall.`
                          : 'Results and approvals post to the case wall.'
                      }
                      error={errors._case}
                    >
                      <input
                        value={caseId}
                        onChange={(e) => {
                          setCaseId(e.target.value);
                          if (errors._case) setErrors(({ _case: _c, ...rest }) => rest);
                        }}
                        placeholder="No case"
                        className={cn(inputCls(!!errors._case || !!live._case), 'font-mono text-[12px]')}
                        aria-label="Case ID"
                      />
                    </Field>
                  </div>
                )}

                {action && (
                  <div
                    className={cn(
                      'rounded-md border px-3 py-2.5',
                      effect === 'destructive' ? 'border-destructive/35 bg-destructive/[0.05]' : effect === 'write' ? 'border-warning/30 bg-warning/[0.04]' : 'border-border',
                    )}
                    data-testid="run-action-summary"
                  >
                    <H className="mb-1.5">Summary</H>
                    <ActionChip
                      e={effect}
                      verb={verb}
                      t={target?.kind}
                      v={target?.value ?? '—'}
                      p={pack?.name}
                      vendor={pack?.vendor}
                      conn={connection?.label}
                      inv={!!inverse}
                    />
                    <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11.5px] text-fg-2">
                      <EffectBadge effect={effect} />
                      <span>Approval: {approvalPolicyText(action)}</span>
                      {inverse && <span>Inverse: {inverse.display_name}</span>}
                    </div>
                  </div>
                )}

                {previewing && (
                  <div className="flex items-center gap-2 rounded-md border border-border px-3 py-3 text-[12px] text-fg-2">
                    <Spinner />
                    Queuing dry run…
                  </div>
                )}
                {preview && (
                  <PreviewBlock
                    tenant={tenant}
                    runId={preview}
                    onOpen={() => {
                      onOpenChange(false);
                      navigate(`/automation/runs/${preview}`);
                    }}
                  />
                )}
                {run.isError && (
                  <Notice tone="danger" title="Request failed">
                    {effectErrorMessage(run.error, 'The action could not be queued.')}
                  </Notice>
                )}
                <Note>
                  Response-dependent values are labelled “Resolved during execution”, never shown as known. The preview result arrives through
                  the queued dry run, not inline.
                </Note>
              </>
            )}
          </div>

          <footer className="flex shrink-0 items-center gap-2 border-t border-border px-4 py-3">
            <span className="flex-1 text-[11px] text-muted-foreground">Approval follows server policy. Accepted ≠ succeeded.</span>
            <Button size="sm" variant="outline" className={smallButton} disabled={!action || previewing || requesting} onClick={doPreview}>
              {previewing ? (
                <>
                  <Spinner />
                  Previewing…
                </>
              ) : (
                'Preview'
              )}
            </Button>
            <Button
              size="sm"
              variant={effect === 'destructive' ? 'destructive' : 'default'}
              className={smallButton}
              disabled={!action || previewing || requesting || (!ready && Object.keys(errors).length > 0)}
              onClick={doRequest}
            >
              {requesting ? (
                <>
                  <Spinner />
                  Requesting…
                </>
              ) : (
                'Request run'
              )}
            </Button>
          </footer>
        </SheetContent>
      </Sheet>

      <ConfirmDialog
        open={confirm}
        onOpenChange={(o) => !o && setConfirm(false)}
        variant="danger"
        title={`${action?.display_name ?? 'Run'} ${targetText}?`}
        confirmLabel={`${action?.display_name ?? 'Run'} ${targetText}`}
        loading={requesting}
        loadingLabel="Requesting…"
        confirmDisabled={!acknowledged}
        onConfirm={() => run.mutate(false)}
        description="This is a destructive action. Requesting it creates a run that waits for an approver; it does not execute yet."
      >
        <div className="flex flex-col gap-3 text-[12px]">
          {inverse && (
            <div className="text-muted-foreground">
              If executed, “{inverse.display_name}” is available as a separate governed run. It is not an automatic rollback.
            </div>
          )}
          <label className="flex items-start gap-2 rounded-md border border-destructive/35 px-3 py-2 text-[11.5px]">
            <Checkbox checked={acknowledged} onCheckedChange={(v) => setAcknowledged(v === true)} aria-label="Acknowledge destructive action" />
            <span>
              I understand this requests “{action?.display_name}” on <span className="font-mono">{targetText}</span> via {connection?.label}.
            </span>
          </label>
        </div>
      </ConfirmDialog>
    </>
  );
}

function FragmentWithOr({ or, children }: { or: boolean; children: ReactNode }) {
  return (
    <>
      {or && <div className="flex h-8 items-center font-mono text-[10.5px] text-muted-foreground">or</div>}
      {children}
    </>
  );
}

function TypedInput({
  name,
  type,
  value,
  error,
  required,
  onChange,
}: {
  name: string;
  type: string;
  value: string;
  error?: string;
  required: boolean | 'alt';
  onChange: (v: string) => void;
}) {
  const hint = type !== 'string' ? TYPE_HINT[type] : undefined;
  let control: ReactNode;
  if (type === 'boolean') {
    control = (
      <label className="flex h-8 items-center gap-2 text-[12.5px]">
        <Checkbox checked={value === 'true'} onCheckedChange={(v) => onChange(v === true ? 'true' : '')} aria-label={name} />
        {name}
      </label>
    );
  } else {
    control = (
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        inputMode={type === 'integer' || type === 'number' ? 'numeric' : undefined}
        placeholder={type === 'array' || type === 'string[]' ? 'comma,separated' : undefined}
        className={cn(inputCls(!!error), type !== 'string' && 'font-mono text-[12px]')}
        aria-label={name}
        aria-invalid={!!error}
      />
    );
  }
  return (
    <Field
      label={
        <>
          <span className="font-mono text-fg-2">{name}</span>
          <span className="ml-1 font-mono text-[10px] text-fg-4">{type}</span>
        </>
      }
      required={required}
      error={error}
      hint={hint}
    >
      {control}
    </Field>
  );
}

function PreviewBlock({ tenant, runId, onOpen }: { tenant: string; runId: string; onOpen: () => void }) {
  const detail = useRun(tenant, runId, true);
  const done = !!detail.data && isTerminal(detail.data.status);
  const steps: SoarStepResult[] = detail.data?.steps ?? [];
  const rendered = steps.find((s) => s.rendered_request)?.rendered_request;
  const [tech, setTech] = useState(false);
  return (
    <div className="flex flex-col rounded-md border border-primary/30" data-testid="run-action-preview">
      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        <Eye className="h-3.5 w-3.5 text-primary" strokeWidth={1.5} />
        <span className="flex-1 text-[12.5px] font-medium text-foreground">Preview · dry run</span>
        <Mono className="text-[10.5px] text-muted-foreground">{shortId(runId)}</Mono>
        <Button size="sm" variant="ghost" className="h-6 px-2 text-[11px] shadow-none" onClick={onOpen}>
          Open preview
        </Button>
      </div>
      <div className="flex flex-col gap-2 px-3 py-2.5">
        {!done ? (
          <div className="flex items-center gap-2 text-[12px] text-fg-2">
            <Spinner />
            <span>Dry run queued</span>
            <Mono className="text-[11px]">{shortId(runId)}</Mono>
            <span className="text-muted-foreground">· polling result…</span>
          </div>
        ) : (
          <>
            <div className="flex items-center gap-1.5 text-[11.5px] text-good">
              <Check className="h-3 w-3" strokeWidth={1.5} />
              No vendor requests sent. No changes made.
            </div>
            {steps.length > 0 && (
              <ol className="flex flex-col gap-1.5 text-[12px]">
                {steps.map((s, n) => (
                  <li key={s.id} className="flex gap-2">
                    <Mono className="text-muted-foreground">{n + 1}</Mono>
                    <span className="flex-1 font-mono text-[11.5px]">{s.module_id}</span>
                    {s.output_is_placeholder && <span className="italic text-warn">Resolved during execution</span>}
                    <span className="font-mono text-[10.5px] text-muted-foreground">{s.status.replace(/_/g, ' ')}</span>
                  </li>
                ))}
              </ol>
            )}
          </>
        )}
        {rendered != null && (
          <div className="rounded-md border border-border">
            <button type="button" onClick={() => setTech((t) => !t)} className="flex w-full items-center gap-1.5 px-2.5 py-1.5 font-mono text-[11px] text-muted-foreground hover:text-foreground" aria-expanded={tech}>
              <ChevronRight className={cn('h-3 w-3 transition-transform', tech && 'rotate-90')} strokeWidth={1.5} />
              Technical details · redacted
            </button>
            {tech && (
              <pre className="whitespace-pre-wrap border-t border-border px-2.5 py-2 font-mono text-[11px] leading-[1.6] text-fg-2">
                {typeof rendered === 'string' ? rendered : JSON.stringify(rendered, null, 2)}
              </pre>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
