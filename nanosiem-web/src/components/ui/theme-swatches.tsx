// SPDX-License-Identifier: AGPL-3.0-or-later

import { useTheme } from 'next-themes';
import { useEffect, useRef, useState } from 'react';

import { THEMES, THEME_LABELS, THEME_SWATCH, type Theme } from '@/lib/theme';
import { cn } from '@/lib/utils';

/**
 * The theme picker as a row of circles, mirroring nano-desktop's accent row.
 *
 * Each swatch is two-tone — the theme's surface on one diagonal half, its brand
 * accent on the other — so it previews the theme instead of being an arbitrary
 * dot. Three near-black circles would be indistinguishable otherwise, which is
 * the whole reason Matte Black and Dark need the accent half to tell them apart.
 */
export function ThemeSwatches({
  className,
  size = 'md',
}: {
  className?: string;
  /** `sm` is the dense left-rail strip (16px swatches, NAN-5858); `md` is Settings > User. */
  size?: SwatchSize;
}) {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const dragRef = useRef<{
    pointerId: number;
    startX: number;
    scrollLeft: number;
    moved: boolean;
  } | null>(null);

  // `theme` is undefined until next-themes has read storage; rendering the
  // selection marker before then flashes the wrong swatch as selected.
  useEffect(() => setMounted(true), []);

  // When the row overflows, a chevron slot sits on each side of the scroller
  // (flex siblings, never absolutely positioned over it), so neither can cover
  // a swatch. `overflows` reserves both slots; `moreLeft` / `moreRight` enable
  // each chevron while there is more row to scroll to that way. The slots
  // appear only when the row does not fit without them, so toggling them
  // cannot oscillate.
  const [overflows, setOverflows] = useState(false);
  const [moreLeft, setMoreLeft] = useState(false);
  const [moreRight, setMoreRight] = useState(false);
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const update = () => {
      setOverflows(el.scrollWidth - el.clientWidth > 2);
      setMoreLeft(el.scrollLeft > 2);
      setMoreRight(el.scrollWidth - el.clientWidth - el.scrollLeft > 2);
    };
    update();
    el.addEventListener('scroll', update, { passive: true });
    // Guarded: the strip now mounts in every rail (NAN-5858), including test
    // environments without ResizeObserver; scroll events still keep it right.
    const ro = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(update);
    ro?.observe(el);
    return () => { el.removeEventListener('scroll', update); ro?.disconnect(); };
  }, [mounted]);

  const handlePointerDown = (e: React.PointerEvent<HTMLDivElement>) => {
    // Only drag on primary pointer down
    if (e.button !== 0) return;
    const el = containerRef.current;
    if (!el) return;

    dragRef.current = {
      pointerId: e.pointerId,
      startX: e.clientX,
      scrollLeft: el.scrollLeft,
      moved: false,
    };
    // Capture only once a real drag starts (see handlePointerMove): capturing
    // here would retarget the click to the row and swallow swatch selection.
  };

  const handlePointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    const drag = dragRef.current;
    if (!drag || drag.pointerId !== e.pointerId) return;
    const el = containerRef.current;
    if (!el) return;

    const dx = e.clientX - drag.startX;
    if (Math.abs(dx) > 4 && !drag.moved) {
      drag.moved = true;
      containerRef.current?.setPointerCapture(e.pointerId);
    }
    el.scrollLeft = drag.scrollLeft - dx;
  };

  const handlePointerUpOrCancel = (e: React.PointerEvent<HTMLDivElement>) => {
    const drag = dragRef.current;
    if (!drag || drag.pointerId !== e.pointerId) return;
    const el = containerRef.current;
    if (el && el.hasPointerCapture(e.pointerId)) {
      el.releasePointerCapture(e.pointerId);
    }
    // Release dragRef on next tick or immediately after click event
    setTimeout(() => {
      dragRef.current = null;
    }, 0);
  };

  // Roving tabindex (NAN-5858): the strip is ONE Tab stop, on the selected
  // swatch (the first when the theme is `system` or not yet known); arrows,
  // Home and End move within it. Without this, the rail strip that now sits
  // on every route would put nine swatches in every page's Tab order.
  const selectedIndex = mounted ? THEMES.indexOf(theme as Theme) : -1;
  const [focusIndex, setFocusIndex] = useState<number | null>(null);
  const tabStop = focusIndex ?? (selectedIndex >= 0 ? selectedIndex : 0);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(e.key)) return;
    const buttons = Array.from(
      containerRef.current?.querySelectorAll<HTMLButtonElement>('button') ?? []
    );
    if (!buttons.length) return;
    const activeIndex = buttons.indexOf(document.activeElement as HTMLButtonElement);
    if (activeIndex === -1) return;

    e.preventDefault();
    const last = buttons.length - 1;
    const nextIndex =
      e.key === 'Home' ? 0
        : e.key === 'End' ? last
          : e.key === 'ArrowRight' ? (activeIndex + 1) % buttons.length
            : (activeIndex - 1 + buttons.length) % buttons.length;
    buttons[nextIndex]?.focus();
  };

  return (
    <div className="flex w-full min-w-0 max-w-full items-center">
      {overflows && (
        <ScrollArrow direction="left" enabled={moreLeft} onScroll={() => containerRef.current?.scrollBy({ left: -SCROLL_STEP, behavior: 'smooth' })} />
      )}
    <div
      ref={containerRef}
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerUp={handlePointerUpOrCancel}
      onPointerCancel={handlePointerUpOrCancel}
      onKeyDown={handleKeyDown}
      // Tabbing back in lands on the selected swatch again, not the last one visited.
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setFocusIndex(null);
      }}
      className={cn(
        'flex min-w-0 flex-1 items-center overflow-x-auto select-none py-2 px-2 -my-2',
        size === 'sm' ? 'gap-2' : 'gap-2.5',
        // Pull the strip left only with no left arrow: with one, the margin
        // would slide the scroller over the arrow.
        !overflows && '-ml-2',
        '[scrollbar-width:none] [-ms-overflow-style:none] [&::-webkit-scrollbar]:hidden',
        '[webkit-overflow-scrolling:touch]',
        className
      )}
      style={{
        WebkitOverflowScrolling: 'touch',
        scrollbarWidth: 'none',
      }}
      role="group"
      aria-label="Theme"
    >
      {THEMES.map((name, i) => (
        <ThemeSwatch
          key={name}
          theme={name}
          size={size}
          tabIndex={i === tabStop ? 0 : -1}
          onFocus={() => setFocusIndex(i)}
          selected={mounted && theme === name}
          onSelect={() => {
            if (dragRef.current?.moved) return;
            setTheme(name);
          }}
        />
      ))}
    </div>
      {overflows && (
        <ScrollArrow direction="right" enabled={moreRight} onScroll={() => containerRef.current?.scrollBy({ left: SCROLL_STEP, behavior: 'smooth' })} />
      )}
    </div>
  );
}

const SCROLL_STEP = 120;

type SwatchSize = 'sm' | 'md';

/**
 * A chevron beside the swatch strip. DOM order is left arrow, swatches, right
 * arrow, so Tab order matches what is on screen. At the end of the row it is
 * `aria-disabled`, NOT `disabled`: a native disabled button loses focus, and
 * a keyboard user who pressed it would be dropped to document.body. Solid and
 * bordered (no fade: CLAUDE.md, no gradients), with a visible focus ring.
 */
function ScrollArrow({
  direction,
  enabled,
  onScroll,
}: {
  direction: 'left' | 'right';
  enabled: boolean;
  onScroll: () => void;
}) {
  return (
    <button
      type="button"
      aria-label={direction === 'left' ? 'Scroll themes left' : 'Scroll themes right'}
      aria-disabled={!enabled}
      onClick={() => {
        if (enabled) onScroll();
      }}
      className={cn(
        'flex h-6 w-6 shrink-0 items-center justify-center border-border text-muted-foreground hover:text-foreground',
        // An outline, not a ring-* box-shadow (no shadows; see ThemeSwatch).
        'focus-visible:outline-1 focus-visible:-outline-offset-1 focus-visible:outline-[var(--ring)]',
        'aria-disabled:cursor-default aria-disabled:opacity-40 aria-disabled:hover:text-muted-foreground',
        direction === 'left' ? 'border-r' : 'border-l',
      )}
    >
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d={direction === 'left' ? 'm15 6-6 6 6 6' : 'm9 6 6 6-6 6'} />
      </svg>
    </button>
  );
}

/**
 * A theme's two-tone dot: its surface on the top-left diagonal half, its accent
 * on the other. Two clipped SOLID fills, not a gradient (CLAUDE.md), so it can
 * also sit inside a menu item where a button cannot.
 */
export function SwatchDot({
  surface,
  accent,
  className,
}: {
  surface: string;
  accent: string;
  className?: string;
}) {
  return (
    <span
      aria-hidden="true"
      className={cn('block overflow-hidden rounded-full', className)}
      style={{ backgroundColor: accent }}
    >
      <span
        className="absolute inset-0 block"
        style={{ backgroundColor: surface, clipPath: 'polygon(0 0, 100% 0, 0 100%)' }}
      />
    </span>
  );
}

/** Menu-sized swatch for a theme id (the user menu's radio items). */
export function ThemeDot({ theme, className }: { theme: Theme; className?: string }) {
  const { surface, accent } = THEME_SWATCH[theme];
  return (
    <SwatchDot
      surface={surface}
      accent={accent}
      className={cn('relative size-3 shrink-0 border border-border', className)}
    />
  );
}

/**
 * One swatch. The selection marker is a real border on a separate ring element,
 * not a `ring-*` box-shadow: WebKit can leave partial arcs behind when it
 * transitions a box-shadow to none (the same reason nano-desktop's AccentSwatch
 * is built this way).
 */
export function ThemeSwatch({
  theme,
  selected,
  onSelect,
  size = 'md',
  tabIndex,
  onFocus,
}: {
  theme: Theme;
  selected: boolean;
  onSelect: () => void;
  size?: SwatchSize;
  tabIndex?: number;
  onFocus?: () => void;
}) {
  const { surface, accent } = THEME_SWATCH[theme];
  const label = THEME_LABELS[theme];

  return (
    <button
      type="button"
      onClick={onSelect}
      onFocus={onFocus}
      tabIndex={tabIndex}
      title={label}
      aria-label={label}
      aria-pressed={selected}
      className={cn(
        'relative shrink-0 rounded-full border border-border transition-opacity',
        'hover:opacity-100 focus-visible:outline-2 focus-visible:outline-primary',
        size === 'sm' ? 'size-4 focus-visible:outline-offset-[4px]' : 'size-[20px] focus-visible:outline-offset-[5px]',
        selected ? 'opacity-100' : 'opacity-60',
      )}
    >
      <SwatchDot surface={surface} accent={accent} className="absolute inset-0" />
      <span
        aria-hidden="true"
        className={cn(
          'pointer-events-none absolute rounded-full',
          size === 'sm' ? '-inset-[3px] border-[1.5px]' : '-inset-[4px] border-2',
          selected ? 'border-foreground' : 'border-transparent',
        )}
      />
    </button>
  );
}
