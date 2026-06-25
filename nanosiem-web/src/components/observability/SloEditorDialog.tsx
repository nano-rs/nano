// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * SloEditorDialog (NAN-1536)
 *
 * Dense create/edit form for a service-level objective. Backs the SLO error
 * budget cards in SlosTab. On submit it calls the parent-provided `onSubmit`
 * (api.observability.createSlo / updateSlo) with a validated `SloInput`.
 *
 * The objective target is entered as a percentage (e.g. 99.9) for ergonomics
 * and converted to the 0..1 fraction the API expects. `latency_threshold_ms`
 * is required for `latency` SLIs and omitted for `availability`.
 */

import { useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';

import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import type { Slo, SloInput, SloKind } from '@/lib/api/observability';

export interface SloEditorDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** When set, the dialog edits an existing SLO; otherwise it creates one. */
  slo?: Slo | null;
  /** Persist the form. Throws on failure (the dialog surfaces the message). */
  onSubmit: (input: SloInput) => Promise<unknown>;
}

interface FormState {
  name: string;
  service: string;
  sli_kind: SloKind;
  /** Objective target as a percentage string (e.g. "99.9"). */
  targetPct: string;
  windowDays: string;
  latencyMs: string;
}

const EMPTY: FormState = {
  name: '',
  service: '',
  sli_kind: 'availability',
  targetPct: '99.9',
  windowDays: '30',
  latencyMs: '500',
};

function fromSlo(slo: Slo): FormState {
  return {
    name: slo.name,
    service: slo.service,
    sli_kind: slo.sli_kind,
    targetPct: (slo.target * 100).toString(),
    windowDays: slo.window_days.toString(),
    latencyMs: slo.latency_threshold_ms != null ? slo.latency_threshold_ms.toString() : '500',
  };
}

const FIELD_LABEL = 'text-[10px] uppercase tracking-[0.1em] text-fg-3 font-medium';

export function SloEditorDialog({ open, onOpenChange, slo, onSubmit }: SloEditorDialogProps) {
  const editing = slo != null;
  const [form, setForm] = useState<FormState>(EMPTY);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Reset the form whenever the dialog (re)opens for a different target.
  useEffect(() => {
    if (open) {
      setForm(slo != null ? fromSlo(slo) : EMPTY);
      setError(null);
    }
  }, [open, slo]);

  const set = <K extends keyof FormState>(k: K, v: FormState[K]) =>
    setForm((f) => ({ ...f, [k]: v }));

  const targetNum = Number(form.targetPct);
  const windowNum = Number(form.windowDays);
  const latencyNum = Number(form.latencyMs);
  const isLatency = form.sli_kind === 'latency';

  const targetValid = Number.isFinite(targetNum) && targetNum > 0 && targetNum < 100;
  const windowValid = Number.isInteger(windowNum) && windowNum >= 1 && windowNum <= 90;
  const latencyValid = !isLatency || (Number.isFinite(latencyNum) && latencyNum > 0);
  const valid =
    form.name.trim().length > 0 &&
    form.service.trim().length > 0 &&
    targetValid &&
    windowValid &&
    latencyValid;

  const handleSubmit = async () => {
    if (!valid || submitting) return;
    setSubmitting(true);
    setError(null);
    const input: SloInput = {
      name: form.name.trim(),
      service: form.service.trim(),
      sli_kind: form.sli_kind,
      target: targetNum / 100,
      window_days: windowNum,
      ...(isLatency ? { latency_threshold_ms: latencyNum } : {}),
    };
    try {
      await onSubmit(input);
      onOpenChange(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full sm:max-w-[460px] flex flex-col overflow-y-auto gap-0 p-0 bg-card border-border text-foreground">
        <SheetHeader className="space-y-1.5 border-b border-border px-5 py-4 text-left">
          <SheetTitle>{editing ? 'Edit SLO' : 'New SLO'}</SheetTitle>
          <SheetDescription>
            Error-budget objective computed from spans over the rolling window.
          </SheetDescription>
        </SheetHeader>

        <div className="flex flex-col gap-3.5 px-5 py-4">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="slo-name" className={FIELD_LABEL}>
              Name
            </Label>
            <Input
              id="slo-name"
              value={form.name}
              onChange={(e) => set('name', e.target.value)}
              placeholder="Checkout availability"
              autoFocus
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="slo-service" className={FIELD_LABEL}>
              Service
            </Label>
            <Input
              id="slo-service"
              value={form.service}
              onChange={(e) => set('service', e.target.value)}
              placeholder="checkout-api"
              className="font-mono"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1.5">
              <Label className={FIELD_LABEL}>SLI kind</Label>
              <Select
                value={form.sli_kind}
                onValueChange={(v) => set('sli_kind', v as SloKind)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="availability">Availability</SelectItem>
                  <SelectItem value="latency">Latency</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="slo-target" className={FIELD_LABEL}>
                Target %
              </Label>
              <Input
                id="slo-target"
                type="number"
                inputMode="decimal"
                step="0.01"
                min={0}
                max={100}
                value={form.targetPct}
                onChange={(e) => set('targetPct', e.target.value)}
                className="font-mono tabular-nums"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="slo-window" className={FIELD_LABEL}>
                Window (days)
              </Label>
              <Input
                id="slo-window"
                type="number"
                inputMode="numeric"
                step="1"
                min={1}
                max={90}
                value={form.windowDays}
                onChange={(e) => set('windowDays', e.target.value)}
                className="font-mono tabular-nums"
              />
            </div>
            {isLatency && (
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="slo-latency" className={FIELD_LABEL}>
                  Threshold (ms)
                </Label>
                <Input
                  id="slo-latency"
                  type="number"
                  inputMode="numeric"
                  step="1"
                  min={1}
                  value={form.latencyMs}
                  onChange={(e) => set('latencyMs', e.target.value)}
                  className="font-mono tabular-nums"
                />
              </div>
            )}
          </div>

          {error != null && (
            <div className="rounded-md border border-danger/30 bg-danger/[0.06] px-3 py-2 text-[11px] text-danger">
              {error}
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-border px-5 py-3">
          <Button
            variant="outline"
            className="h-8 text-[11.5px]"
            onClick={() => onOpenChange(false)}
            disabled={submitting}
          >
            Cancel
          </Button>
          <Button
            className="h-8 gap-1.5 text-[11.5px]"
            onClick={handleSubmit}
            disabled={!valid || submitting}
          >
            {submitting && <Loader2 className="h-[11px] w-[11px] animate-spin" />}
            {editing ? 'Save changes' : 'Create SLO'}
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  );
}

export default SloEditorDialog;
