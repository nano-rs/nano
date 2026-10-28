// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4754: the Review step's validation gate. Renders exactly what
 * `computeDeployGate` decided: one row per check, the fix link for a blocked
 * check, the warnings with their acknowledge checkbox (only when there are
 * warnings), and a footer line naming the real reason activation is held.
 */
import type { ReactNode } from 'react';
import { AlertTriangle, Check, Loader2, X } from 'lucide-react';
import { Checkbox } from '@/components/ui/checkbox';
import { cn } from '@/lib/utils';
import type { DeployGate, GateAction, GateCheck } from './deploy-gate';

const ACTION_LABEL: Record<GateAction, string> = {
  step1: 'Go to step 1',
  step2: 'Go to step 2',
  'run-tests': 'Run tests',
};

function GateIcon({ check, acknowledged }: { check: GateCheck; acknowledged: boolean }) {
  const tone =
    check.status === 'ok' || (check.status === 'warn' && acknowledged)
      ? 'bg-emerald-500/20 text-emerald-500'
      : check.status === 'block'
        ? 'bg-destructive/20 text-destructive'
        : check.status === 'pending'
          ? 'bg-muted text-muted-foreground'
          : 'bg-amber-500/20 text-amber-500';
  return (
    <span className={cn('w-3.5 h-3.5 rounded-full flex items-center justify-center shrink-0', tone)}>
      {check.status === 'ok' ? (
        <Check className="w-2 h-2" />
      ) : check.status === 'block' ? (
        <X className="w-2 h-2" />
      ) : check.status === 'pending' ? (
        <Loader2 className="w-2 h-2 animate-spin" />
      ) : (
        <AlertTriangle className="w-2 h-2" />
      )}
    </span>
  );
}

export function DeployGatePanel({
  gate,
  acknowledged,
  setAcknowledged,
  onAction,
  shared,
  children,
}: {
  gate: DeployGate;
  acknowledged: boolean;
  setAcknowledged: (v: boolean) => void;
  onAction: (action: GateAction) => void;
  shared?: boolean;
  /** Notes rendered under the checks (hosted build note, rollout status). */
  children?: ReactNode;
}) {
  const verb = shared ? 'Activate' : 'Deploy';
  return (
    <div className="rounded-lg border border-border bg-background overflow-hidden" data-testid="deploy-gate">
      <div className="px-3 py-2 border-b border-border bg-card/40">
        <div className="text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/60">Validation gate</div>
      </div>
      <div className="px-3 py-3 space-y-2.5">
        {gate.checks.map((check) => (
          <div key={check.id} data-testid={`gate-${check.id}`} data-status={check.status}>
            <div className="flex items-center gap-2">
              <GateIcon check={check} acknowledged={acknowledged} />
              <span className="text-[11px] text-foreground/80">{check.label}</span>
              {check.action && check.status === 'block' && (
                <button
                  type="button"
                  onClick={() => onAction(check.action!)}
                  className="ml-auto text-[10.5px] font-mono text-primary hover:underline shrink-0"
                >
                  {ACTION_LABEL[check.action]}
                </button>
              )}
            </div>
            {check.status === 'warn' && check.details && check.details.length > 0 && (
              <ul className="mt-1 ml-[22px] space-y-0.5">
                {check.details.map((d, i) => (
                  <li key={i} className="text-[10.5px] text-muted-foreground leading-relaxed break-words">
                    {d}
                  </li>
                ))}
              </ul>
            )}
          </div>
        ))}
      </div>
      {children}
      {gate.warnings.length > 0 && (
        <div className="px-3 py-3 border-t border-border bg-amber-500/[0.04]">
          <label className="flex items-start gap-2.5 cursor-pointer">
            <Checkbox
              checked={acknowledged}
              onCheckedChange={(checked) => setAcknowledged(checked === true)}
              className="mt-0.5 h-3.5 w-3.5 cursor-pointer"
              aria-label={`${verb} anyway with these warnings`}
            />
            <div>
              <div className="text-[11.5px] text-foreground leading-snug">
                {verb} anyway with <span className="text-amber-500 font-medium">these warnings</span>
              </div>
              <div className="text-[10.5px] text-muted-foreground mt-0.5 leading-relaxed">
                {gate.warnings.map((w) => w.label).join(' · ')}
              </div>
            </div>
          </label>
        </div>
      )}
      <div className="px-3 py-2 border-t border-border bg-card/40 flex items-center gap-2">
        <span
          data-testid="gate-status"
          className={cn(
            'inline-flex items-center gap-1.5 text-[10.5px] font-mono',
            gate.canDeploy ? 'text-emerald-500' : 'text-amber-500',
          )}
        >
          <span className={cn('w-1.5 h-1.5 rounded-full', gate.canDeploy ? 'bg-emerald-500' : 'bg-amber-500')} />
          {gate.status}
        </span>
      </div>
    </div>
  );
}
