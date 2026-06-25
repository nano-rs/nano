// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * SyntheticEditorDialog (NAN-1538)
 *
 * Dense create/edit form for a synthetic HTTP check. Backs the checks list in
 * SyntheticsTab. On submit it calls the parent-provided `onSubmit`
 * (api.observability.createSynthetic / updateSynthetic) with a validated
 * payload.
 *
 * Validation mirrors the backend contract: target_url must be http(s),
 * interval_secs ∈ [30, 3600], expected_status ∈ [100, 599]. The check type is
 * pinned to "http" (the only type the runner supports today).
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
import type { SyntheticCheck, SyntheticCheckInput } from '@/lib/api/observability';

export interface SyntheticEditorDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** When set, the dialog edits an existing check; otherwise it creates one. */
  check?: SyntheticCheck | null;
  /**
   * Persist the form. The parent routes the payload to createSynthetic (new) or
   * updateSynthetic (edit) — the dialog only ever sends the four editable
   * fields, which are valid for both. Throws on failure (surfaced inline).
   */
  onSubmit: (input: SyntheticCheckInput) => Promise<unknown>;
}

interface FormState {
  name: string;
  target_url: string;
  intervalSecs: string;
  expectedStatus: string;
}

const EMPTY: FormState = {
  name: '',
  target_url: '',
  intervalSecs: '60',
  expectedStatus: '200',
};

function fromCheck(c: SyntheticCheck): FormState {
  return {
    name: c.name,
    target_url: c.target_url,
    intervalSecs: c.interval_secs.toString(),
    expectedStatus: c.expected_status.toString(),
  };
}

const FIELD_LABEL = 'text-[10px] uppercase tracking-[0.1em] text-fg-3 font-medium';

function isHttpUrl(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

export function SyntheticEditorDialog({
  open,
  onOpenChange,
  check,
  onSubmit,
}: SyntheticEditorDialogProps) {
  const editing = check != null;
  const [form, setForm] = useState<FormState>(EMPTY);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Reset the form whenever the dialog (re)opens for a different target.
  useEffect(() => {
    if (open) {
      setForm(check != null ? fromCheck(check) : EMPTY);
      setError(null);
    }
  }, [open, check]);

  const set = <K extends keyof FormState>(k: K, v: FormState[K]) =>
    setForm((f) => ({ ...f, [k]: v }));

  const intervalNum = Number(form.intervalSecs);
  const statusNum = Number(form.expectedStatus);

  const urlValid = isHttpUrl(form.target_url.trim());
  const intervalValid =
    Number.isInteger(intervalNum) && intervalNum >= 30 && intervalNum <= 3600;
  const statusValid = Number.isInteger(statusNum) && statusNum >= 100 && statusNum <= 599;
  const valid = form.name.trim().length > 0 && urlValid && intervalValid && statusValid;

  const handleSubmit = async () => {
    if (!valid || submitting) return;
    setSubmitting(true);
    setError(null);
    const input: SyntheticCheckInput = {
      name: form.name.trim(),
      target_url: form.target_url.trim(),
      interval_secs: intervalNum,
      expected_status: statusNum,
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
          <SheetTitle>{editing ? 'Edit check' : 'New synthetic check'}</SheetTitle>
          <SheetDescription>
            An HTTP GET probe run on a schedule from the platform. Uptime and
            latency are computed from recorded runs.
          </SheetDescription>
        </SheetHeader>

        <div className="flex flex-col gap-3.5 px-5 py-4">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="syn-name" className={FIELD_LABEL}>
              Name
            </Label>
            <Input
              id="syn-name"
              value={form.name}
              onChange={(e) => set('name', e.target.value)}
              placeholder="Homepage uptime"
              autoFocus
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <Label htmlFor="syn-url" className={FIELD_LABEL}>
              Target URL
            </Label>
            <Input
              id="syn-url"
              value={form.target_url}
              onChange={(e) => set('target_url', e.target.value)}
              placeholder="https://example.com/health"
              className="font-mono"
            />
            {form.target_url.trim().length > 0 && !urlValid && (
              <span className="text-[10px] text-danger">Must be an http(s) URL.</span>
            )}
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="syn-interval" className={FIELD_LABEL}>
                Interval (s)
              </Label>
              <Input
                id="syn-interval"
                type="number"
                inputMode="numeric"
                step="1"
                min={30}
                max={3600}
                value={form.intervalSecs}
                onChange={(e) => set('intervalSecs', e.target.value)}
                className="font-mono tabular-nums"
              />
              {form.intervalSecs.length > 0 && !intervalValid && (
                <span className="text-[10px] text-danger">30–3600 seconds.</span>
              )}
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="syn-status" className={FIELD_LABEL}>
                Expected status
              </Label>
              <Input
                id="syn-status"
                type="number"
                inputMode="numeric"
                step="1"
                min={100}
                max={599}
                value={form.expectedStatus}
                onChange={(e) => set('expectedStatus', e.target.value)}
                className="font-mono tabular-nums"
              />
              {form.expectedStatus.length > 0 && !statusValid && (
                <span className="text-[10px] text-danger">100–599.</span>
              )}
            </div>
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
            {editing ? 'Save changes' : 'Create check'}
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  );
}

export default SyntheticEditorDialog;
