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
export function ThemeSwatches({ className }: { className?: string }) {
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

  // Show a chevron on the right edge while there is more row to scroll to.
  const [moreRight, setMoreRight] = useState(false);
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const update = () => setMoreRight(el.scrollWidth - el.clientWidth - el.scrollLeft > 2);
    update();
    el.addEventListener('scroll', update, { passive: true });
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => { el.removeEventListener('scroll', update); ro.disconnect(); };
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

  const handleKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
    const buttons = Array.from(
      containerRef.current?.querySelectorAll<HTMLButtonElement>('button') ?? []
    );
    if (!buttons.length) return;
    const activeIndex = buttons.indexOf(document.activeElement as HTMLButtonElement);
    if (activeIndex === -1) return;

    e.preventDefault();
    const nextIndex =
      e.key === 'ArrowRight'
        ? (activeIndex + 1) % buttons.length
        : (activeIndex - 1 + buttons.length) % buttons.length;
    buttons[nextIndex]?.focus();
  };

  return (
    <div className="relative w-full min-w-0 max-w-full">
    <div
      ref={containerRef}
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerUp={handlePointerUpOrCancel}
      onPointerCancel={handlePointerUpOrCancel}
      onKeyDown={handleKeyDown}
      className={cn(
        'flex max-w-full items-center gap-2.5 overflow-x-auto select-none py-2 px-2 -my-2 -mx-2',
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
      {THEMES.map((name) => (
        <ThemeSwatch
          key={name}
          theme={name}
          selected={mounted && theme === name}
          onSelect={() => {
            if (dragRef.current?.moved) return;
            setTheme(name);
          }}
        />
      ))}
    </div>
      {moreRight && (
        <button
          type="button"
          aria-label="Scroll themes right"
          onClick={() => containerRef.current?.scrollBy({ left: 120, behavior: 'smooth' })}
          className="absolute inset-y-0 -right-2 flex w-7 items-center justify-end pr-1 text-muted-foreground hover:text-foreground"
          style={{ background: 'linear-gradient(90deg, transparent, var(--popover) 60%)' }}
        >
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="m9 6 6 6-6 6" />
          </svg>
        </button>
      )}
    </div>
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
}: {
  theme: Theme;
  selected: boolean;
  onSelect: () => void;
}) {
  const { surface, accent } = THEME_SWATCH[theme];
  const label = THEME_LABELS[theme];

  return (
    <button
      type="button"
      onClick={onSelect}
      title={label}
      aria-label={label}
      aria-pressed={selected}
      className={cn(
        'relative size-[20px] shrink-0 rounded-full border border-border transition-opacity',
        'hover:opacity-100 focus-visible:outline-2 focus-visible:outline-offset-[5px] focus-visible:outline-primary',
        selected ? 'opacity-100' : 'opacity-60',
      )}
      style={{ background: `linear-gradient(135deg, ${surface} 0 50%, ${accent} 50% 100%)` }}
    >
      <span
        aria-hidden="true"
        className={cn(
          'pointer-events-none absolute -inset-[4px] rounded-full border-2',
          selected ? 'border-foreground' : 'border-transparent',
        )}
      />
    </button>
  );
}
