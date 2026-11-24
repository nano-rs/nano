// SPDX-License-Identifier: AGPL-3.0-or-later

import * as React from 'react';
import { createPortal } from 'react-dom';

import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { glossaryEntry, type GlossaryEntry, type GlossaryId } from '@/lib/glossary';
import { cn } from '@/lib/utils';

/**
 * NAN-5867: a domain term with its plain-English definition from the shared
 * glossary (src/lib/glossary). Renders the text with a subtle dotted underline.
 *
 *   <Term id="sweep">sweeps</Term>
 *   <Term id="eval" />            // label defaults to the glossary term
 *
 * Two shapes, like InfoTip:
 * - No docs link: a tooltip that opens on hover, keyboard focus or a tap.
 * - With a docs link: a popover. Hover previews it; click, Enter or Space opens
 *   it with focus inside, so the Docs link is in the tab order; Escape closes
 *   it and returns focus. The definition is always the term's accessible
 *   description, so a screen reader hears it on focus.
 *
 * Inside a control (a button, link, tab, menu item, or a <label> that names
 * an input) a term is never its own tab stop and never a popover. It opens
 * while the control (for a label, its input) has focus or on hover, and its
 * definition joins that element's aria-describedby. Clicks reach the control,
 * except inside a <label>, where a click on the term shows the definition
 * instead of toggling the input. A label that names no input is not a
 * control, so the term stays focusable. A focusable table row is a control
 * too, and in any table row a click on the term never opens the row. Control
 * detection comes from the DOM; `nested` never overrides it.
 *
 * Use it on the first appearance of a term in a component. The guard in
 * src/lib/glossary/glossary-guard.test.ts fails when a guarded term shows up
 * in a component's JSX text with no <Term> for it. Open-core files show
 * enterprise-only terms through <EnterpriseTerm> (src/enterprise/components/glossary).
 */
export interface TermProps {
  id: GlossaryId;
  /** The visible text. Defaults to the glossary term. */
  children?: React.ReactNode;
  side?: 'top' | 'right' | 'bottom' | 'left';
  align?: 'start' | 'center' | 'end';
  /**
   * A hint that the term sits in a control. The DOM decides: a term with no
   * control around it stays focusable, so this never makes a term unreachable.
   */
  nested?: boolean;
  className?: string;
  'data-testid'?: string;
}

/** A term inside one of these acts as part of that control. */
export const CONTROL_SELECTOR =
  'a, button, summary, label, [role="button"], [role="tab"], [role="link"], [role="menuitem"], [role="option"]';

/** Same surface as InfoTip: small, dense, no walls of text. */
const BODY_CLASS =
  'max-w-[280px] px-2.5 py-1.5 text-[11px] font-sans font-normal normal-case leading-snug tracking-normal';

const UNDERLINE =
  'cursor-help underline decoration-dotted decoration-muted-foreground/50 decoration-1 underline-offset-[3px] hover:decoration-foreground/60';
const FOCUS_RING = 'focus-visible:rounded-[2px] focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring';

const HOVER_OPEN_MS = 200;
const HOVER_CLOSE_MS = 150;

interface ShapeProps {
  id: GlossaryId;
  entry: GlossaryEntry;
  label: React.ReactNode;
  side: NonNullable<TermProps['side']>;
  align: NonNullable<TermProps['align']>;
  className?: string;
  testId?: string;
}

function Body({ entry, link }: { entry: GlossaryEntry; link: boolean }) {
  return (
    <>
      <span className="block">{entry.short}</span>
      {entry.more ? <span className="mt-1 block text-muted-foreground">{entry.more}</span> : null}
      {link && entry.docsHref ? (
        <a
          href={entry.docsHref}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-1 block rounded-sm text-primary underline underline-offset-2 hover:text-primary/80 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
        >
          Docs
        </a>
      ) : null}
    </>
  );
}

/**
 * The definition as hidden text, so aria-describedby always has something to
 * read. Portaled to <body> so it never joins the surrounding text (a heading's
 * or a row's textContent stays what the reader sees).
 */
function HiddenDescription({ id, entry }: { id: string; entry: GlossaryEntry }) {
  const node = (
    <span id={id} hidden>
      {entry.more ? `${entry.short} ${entry.more}` : entry.short}
    </span>
  );
  return typeof document === 'undefined' ? null : createPortal(node, document.body);
}

export function Term({ id, children, side = 'top', align = 'center', nested = false, className, 'data-testid': testId }: TermProps) {
  const entry = glossaryEntry(id);
  const probeRef = React.useRef<HTMLSpanElement>(null);
  const [control, setControl] = React.useState<HTMLElement | null>(null);

  // The control a term sits in. For a <label>, that is the input the label
  // names (wrapped or htmlFor), so focus and aria-describedby land on the
  // input. A label that names no input is not a control: the term stays its
  // own focusable tooltip so a keyboard can still reach it. A focusable table
  // row (tabIndex) counts as the control too, so the row is the one tab stop.
  // In any table row (rows are often clickable), the term keeps its own
  // clicks: they never open the row.
  const [inRow, setInRow] = React.useState(false);
  React.useLayoutEffect(() => {
    const start = probeRef.current?.parentElement ?? null;
    const el = start?.closest<HTMLElement>(CONTROL_SELECTOR) ?? null;
    const row = start?.closest<HTMLElement>('tr') ?? null;
    if (el instanceof HTMLLabelElement) {
      setControl(el.control);
    } else if (el) {
      setControl(el);
    } else if (row) {
      setInRow(true);
      // tabIndex -1 is focusable by script only, not a tab stop.
      setControl(row.tabIndex >= 0 ? row : null);
    }
  }, []);

  // An unknown id (a stale build) degrades to plain text rather than crashing.
  if (!entry) return <>{children ?? id}</>;

  const label = children ?? entry.term;
  const shape: ShapeProps = { id, entry, label, side, align, className, testId };
  // `nested` is a hint only: the DOM decides. A term with no control around
  // it stays focusable (and keeps its Docs link), whatever the caller passed.
  void nested;
  const inControl = control !== null;

  const term = inControl ? (
    <NestedTerm {...shape} control={control} />
  ) : entry.docsHref ? (
    <LinkedTerm {...shape} />
  ) : (
    <TooltipTerm {...shape} />
  );

  return (
    <>
      <span ref={probeRef} hidden />
      {inRow ? (
        // React events from the portaled tooltip or popover bubble through
        // this span too, so a click on the term or its Docs link never
        // reaches a clickable row.
        <span
          className="contents"
          onClick={(e) => e.stopPropagation()}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') e.stopPropagation();
          }}
        >
          {term}
        </span>
      ) : (
        term
      )}
    </>
  );
}

/** A standalone term with no docs link: a tooltip on hover, focus or tap. */
function TooltipTerm({ id, entry, label, side, align, className, testId }: ShapeProps) {
  const [open, setOpen] = React.useState(false);
  const pressRef = React.useRef<{ wasOpen: boolean; pointerType: string } | null>(null);
  return (
    <Tooltip open={open} onOpenChange={setOpen} delayDuration={HOVER_OPEN_MS}>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          data-term={id}
          data-testid={testId}
          className={cn(UNDERLINE, FOCUS_RING, className)}
          onPointerDown={(e) => {
            pressRef.current = { wasOpen: open, pointerType: e.pointerType };
          }}
          onClick={(e) => {
            // Radix closes a tooltip on click. A tap has no hover, so toggle;
            // a mouse click keeps it open. preventDefault also stops a parent
            // <label> from activating anything.
            const press = pressRef.current;
            pressRef.current = null;
            if (!press) {
              if ((e.currentTarget as HTMLElement).closest('label')) e.preventDefault();
              return;
            }
            e.preventDefault();
            setOpen(press.pointerType === 'mouse' ? true : !press.wasOpen);
          }}
        >
          {label}
        </span>
      </TooltipTrigger>
      <TooltipContent side={side} align={align} collisionPadding={8} className={BODY_CLASS}>
        <Body entry={entry} link={false} />
      </TooltipContent>
    </Tooltip>
  );
}

/**
 * A term inside a control. Not a tab stop and never interactive itself: it
 * opens while the control has focus or on hover, and describes the control.
 */
function NestedTerm({ id, entry, label, side, align, className, testId, control }: ShapeProps & { control: HTMLElement | null }) {
  const [open, setOpen] = React.useState(false);
  const pressRef = React.useRef<{ wasOpen: boolean; pointerType: string } | null>(null);
  const descId = React.useId();

  React.useEffect(() => {
    if (!control) return;
    const onFocus = () => setOpen(true);
    const onBlur = () => setOpen(false);
    control.addEventListener('focus', onFocus);
    control.addEventListener('blur', onBlur);
    const before = control.getAttribute('aria-describedby');
    control.setAttribute('aria-describedby', before ? `${before} ${descId}` : descId);
    return () => {
      control.removeEventListener('focus', onFocus);
      control.removeEventListener('blur', onBlur);
      const now = (control.getAttribute('aria-describedby') ?? '').split(/\s+/).filter((t) => t && t !== descId);
      if (now.length) control.setAttribute('aria-describedby', now.join(' '));
      else control.removeAttribute('aria-describedby');
    };
  }, [control, descId]);

  return (
    <Tooltip open={open} onOpenChange={setOpen} delayDuration={HOVER_OPEN_MS}>
      <TooltipTrigger asChild>
        <span
          data-term={id}
          data-testid={testId}
          className={cn(UNDERLINE, className)}
          onPointerDown={(e) => {
            pressRef.current = { wasOpen: open, pointerType: e.pointerType };
          }}
          onClick={(e) => {
            const press = pressRef.current;
            pressRef.current = null;
            // Inside a <label>, a click would toggle the label's input (a
            // checkbox that saves a setting, say), and inside a focusable row
            // the row's click is already stopped. Either way, show the
            // definition instead of doing nothing.
            if ((e.currentTarget as HTMLElement).closest('label') || control?.tagName === 'TR') {
              e.preventDefault();
              setOpen(press ? (press.pointerType === 'mouse' ? true : !press.wasOpen) : !open);
            }
            // Any other control keeps its click: never preventDefault there,
            // since Radix parents skip their handler on a prevented event.
          }}
        >
          {label}
        </span>
      </TooltipTrigger>
      <TooltipContent side={side} align={align} collisionPadding={8} className={BODY_CLASS}>
        <Body entry={entry} link={false} />
      </TooltipContent>
      <HiddenDescription id={descId} entry={entry} />
    </Tooltip>
  );
}

/**
 * A standalone term with a docs link: a popover, so the link is reachable by
 * keyboard and never sits inside role="tooltip". Hover previews it.
 */
function LinkedTerm({ id, entry, label, side, align, className, testId }: ShapeProps) {
  const [open, setOpen] = React.useState(false);
  const byHover = React.useRef(false);
  const openTimer = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const closeTimer = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const descId = React.useId();

  const clear = () => {
    if (openTimer.current) clearTimeout(openTimer.current);
    if (closeTimer.current) clearTimeout(closeTimer.current);
    openTimer.current = null;
    closeTimer.current = null;
  };
  React.useEffect(() => clear, []);

  const hoverIn = (e: React.PointerEvent) => {
    if (e.pointerType !== 'mouse') return;
    clear();
    if (!open) {
      openTimer.current = setTimeout(() => {
        byHover.current = true;
        setOpen(true);
      }, HOVER_OPEN_MS);
    }
  };
  const hoverOut = (e: React.PointerEvent) => {
    if (e.pointerType !== 'mouse') return;
    clear();
    if (byHover.current) closeTimer.current = setTimeout(() => setOpen(false), HOVER_CLOSE_MS);
  };
  const pin = () => {
    clear();
    byHover.current = false;
  };

  return (
    <Popover
      open={open}
      onOpenChange={(next) => {
        if (!next) byHover.current = false;
        setOpen(next);
      }}
    >
      <PopoverTrigger asChild>
        <span
          role="button"
          tabIndex={0}
          data-term={id}
          data-testid={testId}
          aria-describedby={descId}
          className={cn(UNDERLINE, FOCUS_RING, className)}
          onPointerEnter={hoverIn}
          onPointerLeave={hoverOut}
          onClick={(e) => {
            // A click on a hover preview pins it open instead of closing it.
            if (open && byHover.current) {
              e.preventDefault();
              pin();
            } else {
              pin();
            }
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              pin();
              setOpen((o) => !o);
            }
          }}
        >
          {label}
        </span>
      </PopoverTrigger>
      <PopoverContent
        side={side}
        align={align}
        sideOffset={4}
        collisionPadding={8}
        className={cn('w-auto', BODY_CLASS)}
        onPointerEnter={(e) => {
          if (e.pointerType === 'mouse') clear();
        }}
        onPointerLeave={hoverOut}
        // A hover preview must not steal focus, on open or on close.
        onOpenAutoFocus={(e) => {
          if (byHover.current) e.preventDefault();
        }}
        onCloseAutoFocus={(e) => {
          if (byHover.current) e.preventDefault();
        }}
      >
        <Body entry={entry} link />
      </PopoverContent>
      <HiddenDescription id={descId} entry={entry} />
    </Popover>
  );
}
