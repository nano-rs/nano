// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * BetaBadge: the small "BETA" pill that marks an early-access surface
 * (Hunts, Automation). Used beside a rail label, in a collapsed-rail flyout
 * header, and beside a page title. Never in breadcrumbs.
 *
 * House style: Geist Mono, 10px uppercase, one 1px border, small radius, a
 * muted tint of the theme's primary so it reads in every light and dark theme.
 * The nano-desktop rail reuses it, so it sticks to tokens both apps define
 * (`primary`), and desktop's styles.css lists this file as a Tailwind @source.
 *
 * Screen readers hear the full phrase (the note's aria-label), not the bare
 * word "BETA". Inside a control, give the control its own aria-label (e.g.
 * "Automation (beta)") so the phrase does not become part of its name.
 */
import { cn } from '@/lib/utils';

export const BETA_BADGE_TEXT = 'BETA';
export const BETA_BADGE_DESCRIPTION = 'Beta: this feature is new and may change based on feedback.';

export function BetaBadge({ className }: { className?: string }) {
  return (
    <span
      role="note"
      aria-label={BETA_BADGE_DESCRIPTION}
      title={BETA_BADGE_DESCRIPTION}
      data-testid="beta-badge"
      className={cn(
        'inline-flex shrink-0 select-none items-center rounded-[3px] border border-primary/40 bg-primary/[0.07] px-[5px] py-px font-mono text-[10px] font-medium uppercase leading-[12px] tracking-[0.06em] text-primary',
        className,
      )}
    >
      <span aria-hidden="true">{BETA_BADGE_TEXT}</span>
    </span>
  );
}
