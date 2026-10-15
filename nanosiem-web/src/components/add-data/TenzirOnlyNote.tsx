// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3844: one-line note shown where a Vector-dependent surface is hidden or
 * disabled on an `install.sh --tenzir` install (no Vector). Keep the wording in
 * step with the API's `VECTOR_NOT_INSTALLED` message.
 */

import { Info } from 'lucide-react';
import { cn } from '@/lib/utils';

export const TENZIR_ONLY_NOTE = 'This install ingests via Tenzir; re-run install.sh --add-vector to enable';

export function TenzirOnlyNote({ className, testId = 'tenzir-only-note' }: { className?: string; testId?: string }) {
  return (
    <div
      className={cn('flex items-center gap-2 border border-border px-3 h-7 text-[11.5px] text-muted-foreground', className)}
      role="note"
      data-testid={testId}
    >
      <Info className="w-3.5 h-3.5 shrink-0" strokeWidth={1.5} />
      <span className="truncate">
        This install ingests via Tenzir; re-run{' '}
        <span className="font-mono text-[10.5px] text-foreground">install.sh --add-vector</span> to enable
      </span>
    </div>
  );
}
