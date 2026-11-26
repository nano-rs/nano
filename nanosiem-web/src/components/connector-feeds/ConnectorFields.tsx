// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5903: the pull feed form's config fields and its setup confirm, shared
 * by Log sources > Pull feeds and the Marketplace collector cards.
 *
 * - Each config and credential key shows its plain-English label with the
 *   help in a tooltip (`config_field_info` / `credential_field_info` from
 *   `GET /api/connector-specs`), never the raw key.
 * - A list field with known values (Google Workspace apps, Netskope event
 *   types) is a multi-select with the usual ones ticked.
 * - Submitting first asks the server what the feed needs
 *   (`POST /api/connector-feeds/plan`). When log sources must be created or
 *   changed, a confirm names them; the create then sets them up
 *   (`set_up_log_sources: true`) and the success message says what it made.
 */

import { useRef, useState } from 'react';
import { Checkbox } from '@/components/ui/checkbox';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { InfoTip } from '@/components/ui/info-tip';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { api } from '@/lib/api';
import type {
  ConnectorFeedCreated,
  ConnectorFeedSetupPlan,
  ConnectorFieldInfo,
  ConnectorSpecInfo,
  CreateConnectorFeedRequest,
  LaneSourceStep,
} from '@/lib/api/connector-feeds';
import { cn } from '@/lib/utils';

/** Fallback label for a key the server sent no metadata for: `ADMIN_EMAIL` -> `Admin email`. */
export function humanKey(key: string): string {
  const words = key.toLowerCase().replace(/_/g, ' ').trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

export function configFieldInfo(spec: ConnectorSpecInfo | undefined, key: string): ConnectorFieldInfo | undefined {
  return spec?.config_field_info?.find((f) => f.key === key);
}

export function credentialFieldInfo(spec: ConnectorSpecInfo | undefined, key: string): ConnectorFieldInfo | undefined {
  return spec?.credential_field_info?.find((f) => f.key === key);
}

export function fieldLabel(info: ConnectorFieldInfo | undefined, key: string): string {
  return info?.label || humanKey(key);
}

/** A new feed's config: each list field starts with its default values ticked. */
export function defaultConfig(spec: ConnectorSpecInfo | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const f of spec?.config_field_info ?? []) {
    if (f.choices.length > 0) out[f.key] = f.choices.filter((c) => c.default).map((c) => c.value).join(',');
  }
  return out;
}

function splitList(value: string): string[] {
  return value.split(',').map((s) => s.trim()).filter(Boolean);
}

/** Label plus tooltip. The tip sits next to the label, never inside it. */
export function FieldLabel({
  htmlFor,
  info,
  fieldKey,
  optional,
  className,
}: {
  htmlFor?: string;
  info: ConnectorFieldInfo | undefined;
  fieldKey: string;
  optional?: boolean;
  className?: string;
}) {
  const label = fieldLabel(info, fieldKey);
  return (
    <div className="flex items-center gap-1">
      <Label htmlFor={htmlFor} className={className}>
        {label}
        {optional && <span className="font-normal text-muted-foreground"> (optional)</span>}
      </Label>
      {info?.help && (
        <InfoTip label={`About ${label}`} side="top" contentClassName="max-w-[280px]">
          {info.help}
        </InfoTip>
      )}
    </div>
  );
}

/** A comma-separated list field as a multi-select of its known values. */
export function ChoiceList({
  id,
  info,
  value,
  onChange,
  disabled,
}: {
  id: string;
  info: ConnectorFieldInfo;
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
}) {
  const picked = new Set(splitList(value));
  const toggle = (v: string, on: boolean) => {
    const next = info.choices.map((c) => c.value).filter((c) => (c === v ? on : picked.has(c)));
    onChange(next.join(','));
  };
  return (
    <div
      role="group"
      aria-label={info.label}
      data-testid={`choices-${info.key}`}
      className="grid grid-cols-2 gap-x-3 gap-y-0.5 rounded-md border border-border px-2.5 py-1.5"
    >
      {info.choices.map((c) => {
        const cid = `${id}-${c.value}`;
        return (
          <label key={c.value} htmlFor={cid} className="flex h-6 cursor-pointer items-center gap-1.5 text-[12px]">
            <Checkbox
              id={cid}
              data-choice={c.value}
              checked={picked.has(c.value)}
              disabled={disabled}
              onCheckedChange={(v) => toggle(c.value, v === true)}
            />
            <span className="truncate">{c.label}</span>
            <span className="ml-auto font-mono text-[10.5px] text-muted-foreground">{c.value}</span>
          </label>
        );
      })}
    </div>
  );
}

/** One config field: a text input, or a multi-select when it has known values. */
export function ConfigField({
  spec,
  fieldKey,
  id,
  value,
  onChange,
  disabled,
  labelClassName,
  inputClassName,
}: {
  spec: ConnectorSpecInfo;
  fieldKey: string;
  id: string;
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
  labelClassName?: string;
  inputClassName?: string;
}) {
  const info = configFieldInfo(spec, fieldKey);
  const optional = spec.optional_config_fields.includes(fieldKey);
  return (
    <div className="space-y-1">
      <FieldLabel htmlFor={info?.choices.length ? undefined : id} info={info} fieldKey={fieldKey} optional={optional} className={labelClassName} />
      {info && info.choices.length > 0 ? (
        <ChoiceList id={id} info={info} value={value} onChange={onChange} disabled={disabled} />
      ) : (
        <Input
          id={id}
          data-config-key={fieldKey}
          aria-label={fieldLabel(info, fieldKey)}
          className={cn('h-8 font-mono text-[12px]', inputClassName)}
          value={value}
          disabled={disabled}
          placeholder={info?.placeholder ?? undefined}
          onChange={(e) => onChange(e.target.value)}
        />
      )}
    </div>
  );
}

function lanes(list: string[]): string {
  return list.join(', ');
}

/** One plain sentence per log source setup changes. */
export function describeStep(step: LaneSourceStep): string {
  switch (step.action) {
    case 'create':
      return `Create the log source "${step.log_source_name}" from the ${step.parser ?? 'matching'} parser, for ${lanes(step.added_lanes)}.`;
    case 'extend':
      return `Add ${lanes(step.added_lanes)} to the log source "${step.log_source_name}" and deploy it again.`;
    case 'turn_on':
      return `Turn on the log source "${step.log_source_name}" for ${lanes(step.lanes)}.`;
    default:
      return `Use the log source "${step.log_source_name}" for ${lanes(step.lanes)}.`;
  }
}

/** The confirm title: "This will also create 1 log source". */
export function setupTitle(plan: ConnectorFeedSetupPlan): string {
  const changed = plan.log_sources.filter((s) => s.action !== 'reuse' && s.action !== 'create').length;
  if (plan.creates > 0) return `This will also create ${plan.creates} log source${plan.creates === 1 ? '' : 's'}`;
  return `This will also change ${changed} log source${changed === 1 ? '' : 's'}`;
}

/** The success line for a created feed: what it set up, if anything. */
export function setupSummary(created: ConnectorFeedCreated | undefined): string | undefined {
  const made = (created?.log_sources ?? []).filter((s) => s.action !== 'reuse');
  if (made.length === 0) return undefined;
  return made
    .map((s) =>
      s.action === 'create'
        ? `Created the log source "${s.log_source_name}" for ${lanes(s.added_lanes)}.`
        : s.action === 'extend'
          ? `Added ${lanes(s.added_lanes)} to the log source "${s.log_source_name}".`
          : `Turned on the log source "${s.log_source_name}".`,
    )
    .join(' ');
}

function permissionMessage(missing: string[]): string {
  return `Setting up the log sources this feed needs also takes the ${missing.join(', ')} permission${missing.length === 1 ? '' : 's'}. Ask an admin to give you ${missing.length === 1 ? 'it' : 'them'}, or to set up these log sources under Log sources first.`;
}

/** A feed's stored config as a plan request takes it. */
export function feedConfig(feed: { config: Record<string, unknown> }): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  for (const [k, v] of Object.entries(feed.config ?? {})) {
    if (typeof v === 'string' || typeof v === 'boolean') out[k] = v;
    else if (v != null) out[k] = String(v);
  }
  return out;
}

interface PendingSetup {
  plan: ConnectorFeedSetupPlan;
  run: () => void;
}

/**
 * The one setup confirm every way a pull feed starts goes through (create,
 * resume, adopting a spec update, the Marketplace's install and enable):
 * ask the server what starting needs (`plan`), confirm when log sources
 * would be created or changed, then `run(setUp)` with consent. Nothing to
 * set up runs at once, without a dialog.
 */
export function useLaneSetup() {
  const [pending, setPending] = useState<PendingSetup | null>(null);
  const [busy, setBusy] = useState(false);
  // Set synchronously on confirm: the dialog's own close-on-confirm must not
  // dismiss it while the setup runs (it shows the progress line).
  const running = useRef(false);
  const start = async <R,>({
    plan,
    run,
    onDone,
    onError,
  }: {
    /** What starting would set up; `null` when nothing can need it (pausing). */
    plan: () => Promise<ConnectorFeedSetupPlan | null>;
    run: (setUp: boolean) => Promise<R>;
    onDone: (result: R, plan: ConnectorFeedSetupPlan | null) => void;
    onError: (error: Error) => void;
  }) => {
    const fail = (e: unknown) => onError(e instanceof Error ? e : new Error(String(e)));
    const go = async (p: ConnectorFeedSetupPlan | null) => {
      running.current = true;
      setBusy(true);
      try {
        onDone(await run(!!p?.changes_log_sources), p);
      } catch (e) {
        fail(e);
      } finally {
        running.current = false;
        setBusy(false);
        setPending(null);
      }
    };
    setBusy(true);
    let p: ConnectorFeedSetupPlan | null;
    try {
      p = await plan();
    } catch (e) {
      setBusy(false);
      fail(e);
      return;
    }
    setBusy(false);
    if (p?.changes_log_sources) setPending({ plan: p, run: () => void go(p) });
    else await go(p);
  };
  const confirm = pending && (
    <ConfirmDialog
      open
      onOpenChange={(open) => !open && !busy && !running.current && setPending(null)}
      title={setupTitle(pending.plan)}
      description="This feed's events need log sources to land in. Before it goes on, nano will:"
      confirmLabel="Set up and continue"
      loading={busy}
      loadingLabel="Setting up…"
      confirmDisabled={pending.plan.missing_permissions.length > 0}
      onConfirm={pending.run}
    >
      <div className="space-y-2" data-testid="feed-setup-confirm">
        <ul className="list-disc space-y-1 pl-4 text-[12px]">
          {pending.plan.log_sources
            .filter((s) => s.action !== 'reuse')
            .map((s) => (
              <li key={`${s.action}-${s.log_source_name}`}>{describeStep(s)}</li>
            ))}
        </ul>
        {pending.plan.log_sources.some((s) => s.action === 'reuse') && (
          <p className="text-[11px] text-muted-foreground">
            Already set up:{' '}
            {pending.plan.log_sources
              .filter((s) => s.action === 'reuse')
              .map((s) => `"${s.log_source_name}" (${lanes(s.lanes)})`)
              .join('; ')}
            .
          </p>
        )}
        <p className="text-[11px] text-muted-foreground">
          nano checks each new log source with its parser&apos;s sample events before turning it on.
        </p>
        {busy && (
          <p role="status" data-testid="feed-setup-progress" className="text-[11px] text-foreground">
            Setting up log sources… this can take a few minutes.
          </p>
        )}
        {pending.plan.missing_permissions.length > 0 && (
          <p role="alert" className="text-[11px] text-destructive">
            {permissionMessage(pending.plan.missing_permissions)}
          </p>
        )}
      </div>
    </ConfirmDialog>
  );
  return { start, isPending: busy, confirm };
}

/** Create a feed through the setup confirm. */
export function useFeedSubmit({
  onCreated,
  onError,
}: {
  onCreated: (created: ConnectorFeedCreated) => void;
  onError: (error: Error) => void;
}) {
  const setup = useLaneSetup();
  return {
    submit: (request: CreateConnectorFeedRequest) =>
      void setup.start({
        plan: () => api.connectorFeeds.plan(request.connector, request.config),
        // Consent only after the confirm: if a source disappears between the
        // plan and the create, the server refuses (LOG_SOURCES_MISSING)
        // instead of setting it up unasked.
        run: (setUp) => api.connectorFeeds.create({ ...request, set_up_log_sources: setUp }),
        onDone: (created) => onCreated(created),
        onError,
      }),
    isPending: setup.isPending,
    confirm: setup.confirm,
  };
}
