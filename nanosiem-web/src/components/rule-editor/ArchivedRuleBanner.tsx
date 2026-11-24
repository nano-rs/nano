// SPDX-License-Identifier: AGPL-3.0-or-later

import { Archive } from 'lucide-react';
import { Button } from '@/components/ui/button';

/**
 * NAN-5683 — shown under the top bar of an archived (deleted) rule opened by
 * URL. The page is read-only; Unarchive is the one action, offered only when
 * the viewer may unarchive.
 */
export function ArchivedRuleBanner({ onUnarchive }: { onUnarchive?: () => void }) {
  return (
    <div
      role="status"
      data-testid="archived-rule-banner"
      className="h-8 shrink-0 flex items-center gap-2 px-4 border-b border-border bg-muted/40 text-[11.5px]"
    >
      <Archive className="w-3.5 h-3.5 text-muted-foreground shrink-0" strokeWidth={1.5} />
      <span className="font-mono text-[10.5px] font-semibold tracking-[0.08em] uppercase text-muted-foreground">
        Archived
      </span>
      <span className="text-muted-foreground truncate">
        Doesn&apos;t run and is read-only. Matches and alerts are kept.
      </span>
      <div className="flex-1" />
      {onUnarchive && (
        <Button variant="outline" size="sm" className="h-6 text-[11px] px-2" onClick={onUnarchive}>
          Unarchive rule
        </Button>
      )}
    </div>
  );
}
