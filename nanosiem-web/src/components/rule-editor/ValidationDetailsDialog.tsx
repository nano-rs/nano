// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-487 — Validation details dialog.
//
// The CODE lens toolbar shows just Valid/Invalid at a glance; this modal
// opens when an analyst wants to see *why* the rule is invalid: friendly
// error formatting, detection-mode implications, plus the latest match
// count from the linter's cached result (TestDrawer remains the full test
// harness for range-scoped runs).

import { AlertTriangle, CheckCircle2, Info, Zap, Clock } from 'lucide-react';
import { DetailSheet } from '@/components/ui/detail-sheet';
import { Button } from '@/components/ui/button';
import type { ValidationState } from '@/components/editor/detection-linter';

interface ValidationDetailsDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  validation: ValidationState | null;
  onRunTest?: () => void;
}

export function ValidationDetailsDialog({
  open,
  onOpenChange,
  validation,
  onRunTest,
}: ValidationDetailsDialogProps) {
  const status: 'valid' | 'invalid' | 'unchecked' = !validation
    ? 'unchecked'
    : validation.valid
      ? 'valid'
      : 'invalid';

  return (
    <DetailSheet
      open={open}
      onOpenChange={onOpenChange}
      size="md"
      breadcrumb={['Rule', 'Validation']}
      icon={
        <>
          {status === 'valid' && <CheckCircle2 className="w-4 h-4 text-[var(--success)]" strokeWidth={1.5} />}
          {status === 'invalid' && <AlertTriangle className="w-4 h-4 text-[var(--destructive)]" strokeWidth={1.5} />}
          {status === 'unchecked' && <Info className="w-4 h-4 text-muted-foreground" strokeWidth={1.5} />}
        </>
      }
      title={
        status === 'valid' ? 'Rule is valid' : status === 'invalid' ? 'Rule has errors' : 'Not yet validated'
      }
      description={
        status === 'valid'
          ? 'The query parses and compiles cleanly. Run a test to preview matches over a time range.'
          : status === 'invalid'
            ? 'Fix the issues below, then save to re-validate.'
            : 'Edit the query or run the linter to see a fresh validation result.'
      }
      footer={
        <>
          <Button
            variant="outline"
            size="sm"
            onClick={() => onOpenChange(false)}
            className="h-7 text-[11.5px]"
          >
            Close
          </Button>
          {onRunTest && (
            <Button
              size="sm"
              onClick={() => {
                onOpenChange(false);
                onRunTest();
              }}
              className="h-7 text-[11.5px] gap-1.5"
            >
              <Zap className="w-[11px] h-[11px]" strokeWidth={1.5} />
              Run test
            </Button>
          )}
        </>
      }
    >
      <div className="space-y-3">
        {validation?.error && (
          <section>
            <div className="text-[10px] font-mono uppercase tracking-[0.12em] font-semibold text-[var(--destructive)] mb-1.5">
              Error
            </div>
            <pre className="bg-[var(--card-2,var(--card))] border border-border rounded-md p-3 text-[11.5px] font-mono text-foreground whitespace-pre-wrap break-words leading-relaxed">
              {validation.error}
            </pre>
          </section>
        )}
        {validation?.warning && (
          <section>
            <div className="text-[10px] font-mono uppercase tracking-[0.12em] font-semibold text-[var(--warning,_#D08770)] mb-1.5">
              Warning
            </div>
            <div className="text-[11.5px] leading-relaxed text-foreground">{validation.warning}</div>
          </section>
        )}
        {validation?.info && (
          <section>
            <div className="text-[10px] font-mono uppercase tracking-[0.12em] font-semibold text-muted-foreground mb-1.5">
              Notes
            </div>
            <div className="text-[11.5px] leading-relaxed text-muted-foreground">{validation.info}</div>
          </section>
        )}
        {validation?.detectionMode && (
          <section className="flex items-center gap-2 text-[11.5px] text-muted-foreground">
            {validation.detectionMode === 'realtime' ? (
              <Zap className="w-3.5 h-3.5 text-[var(--primary)]" strokeWidth={1.75} />
            ) : (
              <Clock className="w-3.5 h-3.5 text-[var(--success)]" strokeWidth={1.75} />
            )}
            <span className="font-mono">
              {validation.detectionMode === 'realtime'
                ? 'Real-time — streams via materialized view'
                : 'Scheduled — runs on cron'}
            </span>
            {validation.createsMaterializedView && (
              <span className="font-mono text-[10.5px] text-[var(--primary)]">
                creates materialized view
              </span>
            )}
          </section>
        )}
        {validation?.matchCount !== undefined && (
          <section className="flex items-center gap-2 text-[11.5px] text-muted-foreground">
            <CheckCircle2 className="w-3.5 h-3.5 text-[var(--success)]" strokeWidth={1.75} />
            <span>
              Last linter preview matched{' '}
              <span className="font-mono text-foreground">{validation.matchCount.toLocaleString()}</span>{' '}
              event{validation.matchCount === 1 ? '' : 's'}.
            </span>
          </section>
        )}
        {!validation && (
          <div className="text-[11.5px] text-muted-foreground leading-relaxed">
            No validation result yet. The linter runs automatically after edits — keep typing, or
            click Test rule to run a full preview.
          </div>
        )}
      </div>
    </DetailSheet>
  );
}
