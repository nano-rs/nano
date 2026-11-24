// SPDX-License-Identifier: AGPL-3.0-or-later

import { useLayoutEffect, useRef, useState, type ReactNode } from 'react';

import { cn } from '@/lib/utils';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

/** True when `el`'s content is wider than its box (a CSS ellipsis is showing). */
export function isTruncated(el: Element | null | undefined): boolean {
  return !!el && el.scrollWidth > el.clientWidth;
}

/**
 * One line of text that ellipsizes in its container, with the full value in
 * the app Tooltip (NAN-5777 / NAN-5783; same rules as SelectIn, NAN-5787):
 *
 * - the tooltip opens on hover and on keyboard focus, and only while the text
 *   is actually cut;
 * - the text takes focus (tabIndex 0) only while it is cut, so a value that
 *   fits adds no tab stop;
 * - the DOM text is always the full value, so screen readers read it once:
 *   the tooltip repeats it and is aria-hidden, and Radix's aria-describedby
 *   lands on a non-focusable wrapper (focus bubbles to it), never on the
 *   focused text itself.
 */
export function TruncatedText({
  text,
  children,
  className,
  tooltipClassName,
  side = 'top',
  testId,
}: {
  /** The full value (tooltip text). */
  text: string;
  /** What to render, when it differs from `text` (defaults to `text`). */
  children?: ReactNode;
  className?: string;
  tooltipClassName?: string;
  side?: 'top' | 'bottom' | 'left' | 'right';
  testId?: string;
}) {
  const ref = useRef<HTMLSpanElement>(null);
  const [cut, setCut] = useState(false);
  const [open, setOpen] = useState(false);

  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const update = () => setCut(isTruncated(el));
    update();
    if (typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, [text]);

  return (
    <Tooltip open={open && cut} onOpenChange={(o) => setOpen(o && isTruncated(ref.current))}>
      <TooltipTrigger asChild>
        <span className="block min-w-0 max-w-full">
          <span
            ref={ref}
            tabIndex={cut ? 0 : undefined}
            data-truncated={cut ? 'true' : undefined}
            data-testid={testId}
            className={cn(
              'block min-w-0 truncate rounded-[2px] outline-none focus-visible:ring-1 focus-visible:ring-ring',
              className,
            )}
          >
            {children ?? text}
          </span>
        </span>
      </TooltipTrigger>
      <TooltipContent
        aria-hidden="true"
        side={side}
        align="start"
        className={cn('max-w-[420px] font-mono text-[11px] [overflow-wrap:anywhere]', tooltipClassName)}
      >
        {text}
      </TooltipContent>
    </Tooltip>
  );
}
