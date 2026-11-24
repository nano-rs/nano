// SPDX-License-Identifier: AGPL-3.0-or-later

import * as React from 'react';
import { Info } from 'lucide-react';

import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';

/**
 * NAN-5796: the one help affordance for explanatory text that does not earn a
 * permanent spot on the page. An info icon button that opens the help text.
 *
 * Use it instead of hand-composing `Tooltip` + a lucide `Info` / `HelpCircle`
 * icon; the `nano/no-hand-built-info-tip` eslint rule fails the build when
 * those icons appear inside a tooltip trigger anywhere else, and when an
 * InfoTip sits inside a heading or a `<label>`.
 *
 * Two shapes, one look:
 * - Text only: a tooltip that opens on hover, keyboard focus or tap. Radix
 *   wires `aria-describedby` to the body while it is open.
 * - With `learnMoreHref`: a popover that opens on click, Enter or Space, so the
 *   "Learn more" link is in the tab order. Escape closes it and returns focus.
 *
 * The button's accessible name is `label` only; the body is its description,
 * never repeated as screen-reader text on the trigger.
 *
 * Placement: put an InfoTip next to a heading or label, never inside one. A
 * button inside `<h1>` joins the heading's name, and inside `<label>` it
 * steals the label's control.
 *
 * - `variant="default"`: 12px icon for 11 to 13px body text.
 * - `variant="inline"`: 10px icon for 9 to 10.5px mono / uppercase labels.
 *
 * Clicks never bubble (from the button or the popover body), so a tip in a
 * sortable header or a clickable row does not trigger the parent.
 */

export interface InfoTipProps {
  /** Help body. Plain text or rich content. */
  children: React.ReactNode;
  /** Accessible name for the icon button, e.g. "About feed state". */
  label?: string;
  side?: 'top' | 'right' | 'bottom' | 'left';
  align?: 'start' | 'center' | 'end';
  sideOffset?: number;
  /**
   * Optional docs link rendered under the body as "Learn more". https links
   * and same-origin paths only; anything else is dropped.
   */
  learnMoreHref?: string;
  learnMoreLabel?: string;
  variant?: 'default' | 'inline';
  /** Extra classes for the icon button. */
  className?: string;
  /** Extra classes for the help body (e.g. a wider `max-w-*`). */
  contentClassName?: string;
  'data-testid'?: string;
}

const ICON_SIZE: Record<NonNullable<InfoTipProps['variant']>, string> = {
  default: 'h-3 w-3',
  inline: 'h-2.5 w-2.5',
};

const BOX_SIZE: Record<NonNullable<InfoTipProps['variant']>, string> = {
  default: 'h-4 w-4',
  inline: 'h-3.5 w-3.5',
};

/** The tooltip surface; the popover variant matches it. */
const BODY_CLASS =
  'max-w-[280px] px-2.5 py-1.5 text-[11px] font-sans font-normal normal-case leading-snug tracking-normal';

// ASCII control characters (tab and newline are stripped by URL parsing) and
// backslashes (normalized to `/` in special schemes) can turn a path into a
// protocol-relative cross-origin URL.
// eslint-disable-next-line no-control-regex
const UNSAFE_HREF_CHARS = /[\u0000-\u001f\u007f\\]/;

interface SafeLink {
  href: string;
  external: boolean;
}

/**
 * Resolve a Learn more href against the current origin. Same-origin links
 * stay in the tab; cross-origin links must be https and open in a new tab.
 * Returns null for anything else (`javascript:`, `data:`, `http:` elsewhere,
 * protocol-relative tricks).
 */
function resolveLearnMoreHref(href: string | undefined, origin = window.location.origin): SafeLink | null {
  if (!href || UNSAFE_HREF_CHARS.test(href)) return null;
  let url: URL;
  try {
    url = new URL(href, origin);
  } catch {
    return null;
  }
  if (url.origin === origin && (url.protocol === 'https:' || url.protocol === 'http:')) {
    return { href: url.pathname + url.search + url.hash, external: false };
  }
  if (url.protocol === 'https:') return { href: url.href, external: true };
  return null;
}

function TriggerButton({
  label,
  variant,
  className,
  testId,
  ...rest
}: React.ComponentPropsWithoutRef<'button'> & {
  label: string;
  variant: NonNullable<InfoTipProps['variant']>;
  testId?: string;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      data-testid={testId}
      {...rest}
      className={cn(
        'inline-flex shrink-0 items-center justify-center rounded-sm align-middle text-muted-foreground/70 transition-colors',
        'hover:text-foreground focus-visible:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring',
        BOX_SIZE[variant],
        className,
      )}
    >
      <Info aria-hidden="true" className={ICON_SIZE[variant]} strokeWidth={1.5} />
    </button>
  );
}

const stop = (e: React.SyntheticEvent) => e.stopPropagation();

export function InfoTip({
  children,
  label = 'More info',
  side = 'top',
  align = 'center',
  sideOffset = 4,
  learnMoreHref,
  learnMoreLabel = 'Learn more',
  variant = 'default',
  className,
  contentClassName,
  'data-testid': testId,
}: InfoTipProps) {
  const link = learnMoreHref ? resolveLearnMoreHref(learnMoreHref) : null;
  if (link) {
    return (
      <LinkedInfoTip
        {...{ label, side, align, sideOffset, variant, className, contentClassName, testId, link, learnMoreLabel }}
      >
        {children}
      </LinkedInfoTip>
    );
  }
  return (
    <TextInfoTip {...{ label, side, align, sideOffset, variant, className, contentClassName, testId }}>
      {children}
    </TextInfoTip>
  );
}

type ShapeProps = Required<Pick<InfoTipProps, 'label' | 'side' | 'align' | 'sideOffset' | 'variant'>> &
  Pick<InfoTipProps, 'className' | 'contentClassName' | 'children'> & { testId?: string };

function TextInfoTip({ children, label, side, align, sideOffset, variant, className, contentClassName, testId }: ShapeProps) {
  const [open, setOpen] = React.useState(false);
  // Radix closes the tooltip on pointerdown / click. Remember what the user
  // was looking at when the press started so a tap can toggle it (touch has
  // no hover), and a mouse click keeps it open.
  const pressRef = React.useRef<{ wasOpen: boolean; pointerType: string } | null>(null);

  return (
    <Tooltip open={open} onOpenChange={setOpen} delayDuration={150}>
      <TooltipTrigger asChild>
        <TriggerButton
          label={label}
          variant={variant}
          className={className}
          testId={testId}
          onPointerDown={(e) => {
            pressRef.current = { wasOpen: open, pointerType: e.pointerType };
          }}
          onClick={(e) => {
            // preventDefault skips Radix's own close-on-click handler.
            e.preventDefault();
            e.stopPropagation();
            const press = pressRef.current;
            pressRef.current = null;
            if (press?.pointerType === 'mouse') setOpen(true);
            else setOpen(!(press ? press.wasOpen : open));
          }}
        />
      </TooltipTrigger>
      <TooltipContent
        side={side}
        align={align}
        sideOffset={sideOffset}
        collisionPadding={8}
        onClick={stop}
        className={cn(BODY_CLASS, contentClassName)}
      >
        {children}
      </TooltipContent>
    </Tooltip>
  );
}

function LinkedInfoTip({
  children,
  label,
  side,
  align,
  sideOffset,
  variant,
  className,
  contentClassName,
  testId,
  link,
  learnMoreLabel,
}: ShapeProps & { link: SafeLink; learnMoreLabel: string }) {
  const [open, setOpen] = React.useState(false);
  const bodyId = React.useId();
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <TriggerButton
          label={label}
          variant={variant}
          className={className}
          testId={testId}
          aria-describedby={open ? bodyId : undefined}
          onClick={stop}
        />
      </PopoverTrigger>
      <PopoverContent
        side={side}
        align={align}
        sideOffset={sideOffset}
        collisionPadding={8}
        onClick={stop}
        className={cn('w-auto', BODY_CLASS, contentClassName)}
      >
        <div id={bodyId}>{children}</div>
        <a
          href={link.href}
          {...(link.external ? { target: '_blank', rel: 'noopener noreferrer' } : {})}
          className="mt-1 block rounded-sm text-primary underline underline-offset-2 hover:text-primary/80 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
        >
          {learnMoreLabel}
        </a>
      </PopoverContent>
    </Popover>
  );
}
