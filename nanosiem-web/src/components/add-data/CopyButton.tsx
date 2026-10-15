// SPDX-License-Identifier: AGPL-3.0-or-later

import { forwardRef, useEffect, useRef, useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { copyText } from '@/lib/clipboard';
import { cn } from '@/lib/utils';

/** Dense copy button: "Copy" → "Copied" for 1.4 s. */
export const CopyButton = forwardRef<
  HTMLButtonElement,
  { text: string; label?: string; className?: string; onCopied?: () => void; 'aria-label'?: string }
>(function CopyButton({ text, label = 'Copy', className, onCopied, ...rest }, ref) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);
  return (
    <button
      ref={ref}
      type="button"
      aria-label={rest['aria-label'] ?? label}
      onClick={async () => {
        const ok = await copyText(text);
        setState(ok ? 'copied' : 'failed');
        if (ok) onCopied?.();
        if (timer.current) clearTimeout(timer.current);
        timer.current = setTimeout(() => setState('idle'), 1400);
      }}
      className={cn(
        'inline-flex items-center gap-1 h-6 px-2 rounded border border-border bg-card text-[11px] text-foreground/80',
        'hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary',
        className,
      )}
    >
      {state === 'copied' ? (
        <>
          <Check className="w-3 h-3 text-emerald-500" strokeWidth={1.5} /> Copied
        </>
      ) : state === 'failed' ? (
        <>
          <Copy className="w-3 h-3 text-amber-500" strokeWidth={1.5} /> Select and copy
        </>
      ) : (
        <>
          <Copy className="w-3 h-3" strokeWidth={1.5} /> {label}
        </>
      )}
    </button>
  );
});
