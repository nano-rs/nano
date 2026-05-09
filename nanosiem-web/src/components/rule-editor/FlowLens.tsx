// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-484 PR 2 — FLOW lens. Thin chrome around the existing
// `RuleFlowEditor` (which already renders the parsed nPL DAG via
// `parseNplFlow` + `buildFlowGraph`). We add the redesign toolbar + empty
// state so the lens matches `design-ref/shadcn/editor-flow.jsx` while
// re-using the real parser instead of the mock's `parsePipeline` hack.

import { lazy, Suspense } from 'react';
import { Share2, Loader2 } from 'lucide-react';
import { cronHuman } from './helpers';

const RuleFlowEditor = lazy(() => import('@/components/detection/editor/RuleFlowEditor'));

interface FlowLensProps {
  query: string;
  schedule?: string;
  lookback?: string;
}

export function FlowLens({ query, schedule, lookback }: FlowLensProps) {
  return (
    <div className="flex-1 min-w-0 h-full flex flex-col min-h-0">
      <div className="h-8 flex items-center px-3 gap-3 border-b border-border bg-background/60 text-[10.5px] font-mono shrink-0">
        <span className="inline-flex items-center gap-1.5 text-muted-foreground">
          <Share2 className="w-3 h-3 rotate-90" strokeWidth={1.75} />
          FLOW
        </span>
        <span className="text-muted-foreground/60">·</span>
        <span className="text-muted-foreground">auto-generated from query — edits land in CODE</span>
        <div className="flex-1" />
        {(schedule || lookback) && (
          <span className="inline-flex items-center gap-1.5 text-muted-foreground">
            {schedule && (
              <>
                every <span className="text-foreground">{cronHuman(schedule)}</span>
              </>
            )}
            {lookback && (
              <>
                <span className="text-muted-foreground/60">·</span>
                lookback <span className="text-foreground">{lookback}</span>
              </>
            )}
          </span>
        )}
      </div>
      <div className="flex-1 min-h-0 bg-background">
        <Suspense
          fallback={
            <div className="h-full flex items-center justify-center text-muted-foreground">
              <Loader2 className="w-5 h-5 animate-spin" />
            </div>
          }
        >
          <RuleFlowEditor query={query} />
        </Suspense>
      </div>
    </div>
  );
}
