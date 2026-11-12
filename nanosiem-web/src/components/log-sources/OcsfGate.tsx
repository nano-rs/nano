// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5079: OCSF sample gate UI for Log Sources.
 *
 * On an OCSF deployment a changed parser goes live (publish, or a source's
 * first deploy) only after one representative raw event passes VRL execution
 * and OCSF validation, or when an earlier passing test of the same stored
 * generation left a receipt. A first go-live may skip the sample on an
 * explicit, audited acknowledgement.
 */

import { Check, AlertTriangle, ShieldQuestion } from 'lucide-react';
import { Textarea } from '@/components/ui/textarea';
import { Checkbox } from '@/components/ui/checkbox';
import type { OcsfAttestationStatus, OcsfGateRequest, OcsfValidationResult } from '@/lib/api/types';

export interface OcsfGateDraft {
  sample: string;
  acknowledgeUnattested: boolean;
}

export const EMPTY_OCSF_GATE: OcsfGateDraft = { sample: '', acknowledgeUnattested: false };

/** Whether the gate asks for input: OCSF deployment, no current receipt. */
export function ocsfGateNeeded(attestation: OcsfAttestationStatus | undefined): boolean {
  return !!attestation && attestation.status !== 'current';
}

/** Each non-blank line of the sample box is one raw event. */
export function ocsfGateRequest(draft: OcsfGateDraft, firstGoLive: boolean): OcsfGateRequest {
  const ocsfSampleLogs = draft.sample
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  return {
    ocsfSampleLogs,
    acknowledgeUnattested: firstGoLive && ocsfSampleLogs.length === 0 && draft.acknowledgeUnattested,
  };
}

export function OcsfGateFields({
  draft,
  onChange,
  firstGoLive,
}: {
  draft: OcsfGateDraft;
  onChange: (draft: OcsfGateDraft) => void;
  firstGoLive: boolean;
}) {
  const hasSample = draft.sample.trim().length > 0;
  return (
    <div className="space-y-2">
      <div className="text-[11px] text-muted-foreground leading-relaxed">
        OCSF check: this parser has no passing sample. Paste one or more raw events (one per line). Each must parse
        and validate against OCSF before it goes live.
      </div>
      <Textarea
        value={draft.sample}
        onChange={(e) => onChange({ ...draft, sample: e.target.value })}
        placeholder="Raw event"
        className="font-mono text-[11px] min-h-[72px]"
        spellCheck={false}
      />
      {firstGoLive && (
        <label className="flex items-start gap-2 text-[11px] text-muted-foreground cursor-pointer">
          <Checkbox
            checked={draft.acknowledgeUnattested}
            disabled={hasSample}
            onCheckedChange={(v) => onChange({ ...draft, acknowledgeUnattested: v === true })}
            className="mt-0.5"
          />
          <span>
            Go live without a sample (first logs first). This is audited, and the next parser change needs a passing
            sample.
          </span>
        </label>
      )}
    </div>
  );
}

export function OcsfAttestationBadge({ attestation }: { attestation: OcsfAttestationStatus | undefined }) {
  if (!attestation) return null;
  const base = 'inline-flex items-center gap-1 text-[10.5px] font-mono rounded px-1.5 py-0.5';
  if (attestation.status === 'current') {
    const count = attestation.sample_count ?? 0;
    return (
      <span
        className={`${base} text-primary bg-primary/15`}
        title={`OCSF ${attestation.schema_version ?? ''} validated on ${count} sample${count === 1 ? '' : 's'}${
          attestation.validated_at ? ` at ${attestation.validated_at}` : ''
        }`}
      >
        <Check className="w-3 h-3" /> OCSF {attestation.schema_version} · {count}
      </span>
    );
  }
  if (attestation.status === 'stale') {
    return (
      <span className={`${base} text-amber-500 bg-amber-500/15`} title="The parser changed since its last passing OCSF sample">
        <AlertTriangle className="w-3 h-3" /> OCSF stale
      </span>
    );
  }
  return (
    <span
      className={`${base} text-foreground/80 bg-foreground/[0.03] border border-border`}
      title="No passing OCSF sample on record for this parser"
    >
      <ShieldQuestion className="w-3 h-3" /> OCSF unattested
    </span>
  );
}

/** Path-exact OCSF findings for one test result. */
export function OcsfValidationErrors({ validation }: { validation: OcsfValidationResult | undefined }) {
  if (!validation || validation.valid || validation.errors.length === 0) return null;
  const shown = validation.errors.slice(0, 20);
  return (
    <div className="px-3 py-2 border-t border-border/40">
      <div className="text-[10.5px] font-mono text-red-400 mb-1">
        OCSF {validation.schema_version} · {validation.errors.length} error{validation.errors.length === 1 ? '' : 's'}
      </div>
      <ul className="space-y-0.5">
        {shown.map((e, i) => (
          <li key={`${e.attribute_path}-${e.code}-${i}`} className="text-[10.5px] leading-snug">
            <span className="font-mono text-foreground">{e.attribute_path || '(event)'}</span>
            <span className="font-mono text-muted-foreground"> {e.code}</span>
            <span className="text-muted-foreground"> · {e.message}</span>
          </li>
        ))}
      </ul>
      {validation.errors.length > shown.length && (
        <div className="text-[10.5px] font-mono text-muted-foreground mt-1">
          +{validation.errors.length - shown.length} more
        </div>
      )}
    </div>
  );
}
