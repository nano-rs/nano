// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Theme controls in the left-rail footer (NAN-5858).
 *
 * The lake-era rail carried the theme swatch row as a sideways scroller in the
 * footer's user menu. This brings it back as a strip that sits in the footer
 * itself, next to the one light/dark toggle (the top-bar copy is gone). It is
 * built on the same `ThemeSwatches` as Settings > User, so the theme list,
 * the scroll arrows, the keyboard model and persistence (next-themes, the
 * `nanosiem-theme` localStorage key) are shared: picking a theme in either
 * place shows up in the other at once. It is the only theme control outside
 * Settings > User: the Settings top-bar toggle and the user-menu Theme
 * submenu are gone.
 *
 * - `RailThemeStrip`: expanded rail, Settings rail and mobile drawer.
 * - `RailThemeFlyout`: collapsed rail. One theme button that opens the strip
 *   in a small popover, following the rail section flyouts (NAN-5844). A
 *   mouse hover PEEKS (closes when the pointer leaves); a click, tap or key
 *   (Enter, Space, ArrowRight, ArrowDown) PINS it open and moves focus to the
 *   selected swatch. Escape anywhere closes it; Tab past either end closes it
 *   and moves on in page order; a press outside closes it.
 */

import { Moon, Palette, Sun } from 'lucide-react';
import { useTheme } from 'next-themes';
import { useCallback, useEffect, useRef, useState } from 'react';
import ReactDOM from 'react-dom';

import { ThemeSwatches } from '@/components/ui/theme-swatches';
import { THEMES, THEME_LABELS, isDarkAppearance, type Theme } from '@/lib/theme';
import { cn } from '@/lib/utils';

const ICON_BUTTON = cn(
  'flex shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors',
  'hover:bg-foreground/5 hover:text-foreground',
  // An outline, not a ring-* box-shadow (no shadows outside modals/popovers).
  'outline-none focus-visible:outline-1 focus-visible:-outline-offset-1 focus-visible:outline-[var(--ring)]',
);

/**
 * Binary light/dark flip. Every dark-appearance theme (matte, the accented
 * darks) reads as dark, so the button always offers the other side.
 */
export function LightDarkToggle({ className }: { className?: string }) {
  const { resolvedTheme, setTheme } = useTheme();
  const dark = isDarkAppearance(resolvedTheme);
  const label = dark ? 'Switch to light theme' : 'Switch to dark theme';
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      data-testid="rail-light-dark-toggle"
      onClick={() => setTheme(dark ? 'light' : 'dark')}
      className={cn(ICON_BUTTON, 'h-6 w-6', className)}
    >
      {dark ? (
        <Sun className="h-[13px] w-[13px]" strokeWidth={1.5} />
      ) : (
        <Moon className="h-[13px] w-[13px]" strokeWidth={1.5} />
      )}
    </button>
  );
}

/** The light/dark toggle plus the sideways theme strip, on one 28px row. */
export function RailThemeStrip({ className, testId = 'rail-theme' }: { className?: string; testId?: string }) {
  return (
    <div data-testid={testId} className={cn('flex h-7 min-w-0 items-center gap-1', className)}>
      <LightDarkToggle />
      <div className="min-w-0 flex-1 pl-1">
        <ThemeSwatches size="sm" />
      </div>
    </div>
  );
}

function isFocusVisible(el: Element): boolean {
  try {
    return el.matches(':focus-visible');
  } catch {
    return true; // no :focus-visible support: treat focus as keyboard focus
  }
}

/** Tabbable elements in `root`, in DOM order. */
function tabbables(root: ParentNode): HTMLElement[] {
  return Array.from(
    root.querySelectorAll<HTMLElement>(
      'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]',
    ),
  ).filter((el) => el.tabIndex >= 0 && !el.closest('[aria-hidden="true"], [inert]'));
}

/** Collapsed-rail theme button and its popover strip. */
export function RailThemeFlyout() {
  const { theme } = useTheme();
  // `hover`: opened by a mouse pointer resting on the button (a peek that
  // closes when it leaves). `pinned`: opened by a click, tap or key; stays
  // open until Escape, a second click, Tab out or a press outside.
  const [mode, setMode] = useState<'closed' | 'hover' | 'pinned'>('closed');
  const open = mode !== 'closed';
  const [pos, setPos] = useState({ bottom: 0, left: 0 });
  const triggerRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const focusOnOpenRef = useRef(false);

  useEffect(() => () => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
  }, []);

  // The trigger sits at the bottom of the rail: anchor the panel's bottom to
  // the trigger's bottom so it grows upward and stays on screen.
  const place = () => {
    if (triggerRef.current) {
      const rect = triggerRef.current.getBoundingClientRect();
      setPos({ bottom: window.innerHeight - rect.bottom, left: rect.right + 4 });
    }
  };
  const cancelClose = () => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    timeoutRef.current = null;
  };

  // Mouse only: a touch or pen "hover" fires right before its click, and
  // would turn the first tap into open-then-close.
  const onPointerEnter = (e: React.PointerEvent) => {
    if (e.pointerType !== 'mouse') return;
    cancelClose();
    if (mode === 'closed') {
      place();
      setMode('hover');
    }
  };
  const onPointerLeave = (e: React.PointerEvent) => {
    if (e.pointerType !== 'mouse' || mode !== 'hover') return;
    timeoutRef.current = setTimeout(() => setMode((m) => (m === 'hover' ? 'closed' : m)), 150);
  };

  const pin = () => {
    cancelClose();
    place();
    focusOnOpenRef.current = true;
    setMode('pinned');
  };
  const close = useCallback((returnFocus: boolean) => {
    setMode('closed');
    if (returnFocus) buttonRef.current?.focus();
  }, []);

  // Find the current theme's swatch by label, not aria-pressed: the strip
  // marks its selection only after its own mount effect, which may not have
  // committed yet on the frame the panel opens.
  const focusSelected = useCallback(() => {
    const swatches = Array.from(
      panelRef.current?.querySelectorAll<HTMLButtonElement>('[role="group"] button') ?? [],
    );
    const label = (THEMES as readonly string[]).includes(theme ?? '') ? THEME_LABELS[theme as Theme] : null;
    (swatches.find((b) => b.getAttribute('aria-label') === label) ?? swatches[0])?.focus();
  }, [theme]);
  useEffect(() => {
    if (mode !== 'pinned' || !focusOnOpenRef.current) return;
    focusOnOpenRef.current = false;
    // Wait a frame for the portaled panel and its strip to lay out.
    const id = requestAnimationFrame(focusSelected);
    return () => cancelAnimationFrame(id);
  }, [mode, focusSelected]);

  // While open: Escape anywhere dismisses it (hover content must be
  // dismissable without moving the pointer, WCAG 1.4.13), returning focus to
  // the button only if focus was inside; a press outside closes it.
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      const active = document.activeElement;
      const inside = !!active && (panelRef.current?.contains(active) || buttonRef.current === active);
      e.preventDefault();
      close(inside && active !== buttonRef.current);
    };
    const onPointerDown = (e: PointerEvent) => {
      const t = e.target as Node | null;
      if (t && (triggerRef.current?.contains(t) || panelRef.current?.contains(t))) return;
      close(false);
    };
    document.addEventListener('keydown', onKeyDown);
    document.addEventListener('pointerdown', onPointerDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.removeEventListener('pointerdown', onPointerDown);
    };
  }, [open, close]);

  const onTriggerClick = () => {
    // A click on a hover-peeked panel pins it; on a pinned one it closes.
    if (mode === 'pinned') close(false);
    else pin();
  };
  const onTriggerKeyDown = (e: React.KeyboardEvent<HTMLButtonElement>) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowRight') {
      e.preventDefault();
      if (mode === 'pinned') focusSelected();
      else pin();
    } else if (e.key === 'Tab' && !e.shiftKey && open) {
      // The panel is portaled to the end of <body>: step into it explicitly.
      const first = panelRef.current && tabbables(panelRef.current)[0];
      if (first) {
        e.preventDefault();
        cancelClose();
        setMode('pinned');
        first.focus();
      }
    }
    // Enter and Space reach onTriggerClick as a native button click.
  };

  // Tab past either end of the panel closes it and continues in page order:
  // Shift+Tab off the first control returns to the button, Tab off the last
  // goes to whatever follows the button in the rail.
  const onPanelKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== 'Tab' || !panelRef.current) return;
    const items = tabbables(panelRef.current);
    if (!items.length) return;
    const active = document.activeElement as HTMLElement | null;
    if (e.shiftKey && active === items[0]) {
      e.preventDefault();
      close(true);
    } else if (!e.shiftKey && active === items[items.length - 1]) {
      e.preventDefault();
      const page = tabbables(document.body).filter((el) => !panelRef.current?.contains(el));
      const next = page[page.indexOf(buttonRef.current as HTMLElement) + 1];
      close(!next);
      next?.focus();
    }
  };
  // Focus moving to another element outside both the trigger and the
  // (portaled) panel closes it. A null target (a click on a non-focusable
  // surface) is the pointerdown listener's job.
  const onBlurWithin = (e: React.FocusEvent) => {
    const to = e.relatedTarget as Node | null;
    if (!to || triggerRef.current?.contains(to) || panelRef.current?.contains(to)) return;
    setMode('closed');
  };

  return (
    <>
      <div
        ref={triggerRef}
        onPointerEnter={onPointerEnter}
        onPointerLeave={onPointerLeave}
        data-testid="rail-theme-trigger"
      >
        <button
          ref={buttonRef}
          type="button"
          aria-label="Theme"
          title={open ? undefined : 'Theme'}
          aria-haspopup="dialog"
          aria-expanded={open}
          aria-controls={open ? 'rail-theme-flyout' : undefined}
          onClick={onTriggerClick}
          onKeyDown={onTriggerKeyDown}
          onBlur={onBlurWithin}
          className={cn(ICON_BUTTON, 'h-7 w-7', open && 'bg-foreground/5 text-foreground')}
        >
          <Palette className="h-[14px] w-[14px]" strokeWidth={1.5} />
        </button>
      </div>
      {open && ReactDOM.createPortal(
        <div
          ref={panelRef}
          id="rail-theme-flyout"
          role="dialog"
          aria-label="Choose theme"
          data-mode={mode}
          style={{ position: 'fixed', bottom: pos.bottom, left: pos.left }}
          className="z-[9999] w-[232px] rounded-md border bg-popover p-1 shadow-md animate-in fade-in-0 zoom-in-95 slide-in-from-left-2"
          data-testid="rail-theme-trigger-flyout"
          onPointerEnter={onPointerEnter}
          onPointerLeave={onPointerLeave}
          // Keyboard focus inside a peeked panel pins it. A mouse pick does
          // not: the peek still closes when that pointer leaves.
          onFocus={(e) => {
            if (mode === 'hover' && isFocusVisible(e.target)) setMode('pinned');
          }}
          onKeyDown={onPanelKeyDown}
          onBlur={onBlurWithin}
        >
          <div aria-hidden="true" className="px-2 py-1.5 text-xs font-semibold text-muted-foreground">
            Theme
          </div>
          <RailThemeStrip className="px-1.5 pb-1" testId="rail-theme-flyout-strip" />
        </div>,
        document.body,
      )}
    </>
  );
}
