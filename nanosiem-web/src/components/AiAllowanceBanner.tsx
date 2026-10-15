// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3512: monthly AI allowance notices (the lean AI soft cap).
 *
 * - 80%: dismissable warning with the used / limit counts.
 * - 100%: the pause notice. Auto-triage, pivt and the AI wizards pause until
 *   the next UTC month or until the AI allowance is raised; search, detection
 *   and alerting keep running. Not dismissable.
 * - Allowance 0 ("No AI", or an ended plan): the AI-disabled notice, matching
 *   the server's 403 text. Dismissable; not a pause.
 *
 * Driven by the tier status (`ai_usage.credits_used` / `credits_limit`); a
 * null limit is unlimited and renders nothing. The "Raise AI" link goes to
 * the plan page in the nano portal (hosted-shared tenants only).
 */

import { useEffect, useState } from 'react';
import { AlertTriangle, X } from 'lucide-react';
import { useTierContext } from '@/hooks/use-tier';
import { useCapabilities } from '@/hooks/use-capabilities';
import { AI_NOT_ENABLED_MESSAGE, aiAllowancePausedMessage, aiAllowanceState, RAISE_AI_URL } from '@/lib/ai-allowance';

const REFRESH_MS = 5 * 60_000;

const fmt = (n: number) => n.toLocaleString('en-US');

interface AiAllowanceNoticeProps {
  used: number;
  limit: number | null;
  /** Show the "Raise AI" link (hosted-shared tenants buy AI in the portal). */
  canRaise: boolean;
  now?: Date;
}

export function AiAllowanceNotice({ used, limit, canRaise, now = new Date() }: AiAllowanceNoticeProps) {
  const [dismissed, setDismissed] = useState(false);
  const state = aiAllowanceState(used, limit);
  if (state === 'ok' || limit === null) return null;
  if (state !== 'paused' && dismissed) return null;

  const paused = state === 'paused';
  const off = state === 'off';
  const pct = limit > 0 ? Math.min(100, Math.floor((used / limit) * 100)) : 100;
  const tone = off
    ? 'border-border bg-muted/40 text-muted-foreground'
    : paused
      ? 'border-red-200 bg-red-50/80 text-red-800 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-300'
      : 'border-amber-200 bg-amber-50/80 text-amber-800 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-300';

  return (
    <div
      role={paused ? 'alert' : 'status'}
      data-testid="ai-allowance-banner"
      data-state={state}
      className={`mx-3 mt-2 flex items-center justify-between gap-3 rounded-md border px-3 py-1.5 text-[12px] ${tone}`}
    >
      <div className="flex min-w-0 items-center gap-2">
        <AlertTriangle className="h-3.5 w-3.5 shrink-0" strokeWidth={1.5} />
        {!off && (
          <span className="shrink-0 font-mono text-[10.5px]">
            AI {fmt(used)} / {fmt(limit)} ({pct}%)
          </span>
        )}
        <span className="min-w-0">
          {off
            ? `${AI_NOT_ENABLED_MESSAGE}. Search, detection and alerting keep running.`
            : paused
              ? aiAllowancePausedMessage(now)
              : `You've used ${pct}% of this month's AI allowance. At 100%, auto-triage, pivt and AI wizards pause; search, detection and alerting keep running.`}
        </span>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        {canRaise && (
          <a
            href={RAISE_AI_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="rounded border border-current px-2 py-0.5 text-[11px] font-medium hover:bg-black/5 dark:hover:bg-white/5"
          >
            Raise AI
          </a>
        )}
        {!paused && (
          <button
            type="button"
            onClick={() => setDismissed(true)}
            className="rounded p-0.5 opacity-70 hover:opacity-100"
            aria-label="Dismiss AI allowance notice"
          >
            <X className="h-3.5 w-3.5" strokeWidth={1.5} />
          </button>
        )}
      </div>
    </div>
  );
}

/** App-shell mount: reads the shared tier status and refreshes it periodically. */
export function AiAllowanceBanner() {
  const { aiCreditsUsed, aiCreditsLimit, refetch } = useTierContext();
  const { tenantPlan } = useCapabilities();

  useEffect(() => {
    const interval = setInterval(() => void refetch(), REFRESH_MS);
    return () => clearInterval(interval);
  }, [refetch]);

  return <AiAllowanceNotice used={aiCreditsUsed} limit={aiCreditsLimit} canRaise={!!tenantPlan} />;
}
