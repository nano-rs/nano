// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The house settings-form layout, as components (NAN-5881).
 *
 * Settings > Search, Risk Scoring, Prevalence and Case Management · General
 * share one structure; these components are that structure (Rarity
 * Thresholds and SOAR are built from them), so a page built from them matches
 * those pages exactly:
 *
 *   Title (18px)                                       ← SettingsPageHeader
 *   One-line description (11.5px), or meta · meta (mono 11px)
 *
 *   EYEBROW (10px uppercase)                           ← SettingsGroup
 *   One-line description (11.5px, max 720px)
 *   ───────────────────────────────────────────────
 *   Label                                  [control]   ← SettingsRow
 *   hint (11px)
 *   ───────────────────────────────────────────────
 *                          Unsaved · [Save something] ← SettingsActions
 *
 * Full width of the settings content area, 1px rules, no cards or shadows.
 * Lists inside a group use SettingsListHeader + rows with the same rules.
 */

import { useId, type ReactNode } from 'react';
import { cn } from '@/lib/utils';

export function SettingsPageHeader({
  title,
  description,
  meta,
  actions,
}: {
  title: ReactNode;
  /** A plain line under the title, saying what the page covers. */
  description?: ReactNode;
  /** Short mono facts under the title, joined with dots. */
  meta?: ReactNode[];
  actions?: ReactNode;
}) {
  const items = (meta ?? []).filter((m) => m !== null && m !== undefined && m !== false);
  return (
    <div className="flex flex-wrap items-start gap-x-3 gap-y-2">
      <div className="min-w-0 flex-1 basis-[280px]">
        <h1 className="text-[18px] font-semibold tracking-tight text-foreground">{title}</h1>
        {description && <p className="mt-0.5 text-[11.5px] text-muted-foreground">{description}</p>}
        {items.length > 0 && (
          <div
            className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 font-mono text-[11px] text-muted-foreground"
            data-testid="settings-meta"
          >
            {items.map((m, i) => (
              <span key={i} className="inline-flex items-center gap-2 whitespace-nowrap">
                {i > 0 && <span aria-hidden>·</span>}
                {m}
              </span>
            ))}
          </div>
        )}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-1.5">{actions}</div>}
    </div>
  );
}

/**
 * Groups that are separated by a 1px rule (SOAR); plain stacked groups (Search,
 * Rarity Thresholds) just sit in a `space-y-7` page.
 */
export function SettingsDividedGroups({ children }: { children: ReactNode }) {
  return (
    <div className="space-y-7 [&>section:not(:first-child)]:border-t [&>section:not(:first-child)]:border-border [&>section:not(:first-child)]:pt-5">
      {children}
    </div>
  );
}

/** One titled group of settings: a small uppercase title, an optional one-line description, then rows. */
export function SettingsGroup({
  title,
  description,
  actions,
  children,
  testId,
  className,
}: {
  title: ReactNode;
  description?: ReactNode;
  /** Small controls on the eyebrow line, such as "+ Add". */
  actions?: ReactNode;
  children: ReactNode;
  testId?: string;
  className?: string;
}) {
  const headingId = useId();
  return (
    <section
      aria-labelledby={headingId}
      className={cn('min-w-0', className)}
      data-testid={testId}
    >
      <div className="flex flex-wrap items-start gap-x-3 gap-y-1">
        <div className="min-w-0 flex-1">
          <h2 id={headingId} className="mb-1 text-[10px] font-medium uppercase tracking-[0.12em] text-muted-foreground">{title}</h2>
          {description && <div className="mb-3 max-w-[720px] text-[11.5px] text-muted-foreground">{description}</div>}
        </div>
        {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
      </div>
      {children}
    </section>
  );
}

/**
 * Label and hint on the left, the control on the right; stacks on a phone.
 * Pass `hintId` and put `aria-describedby={hintId}` on the control so screen
 * readers read the hint (and any error in it) with the field.
 */
export function SettingsRow({
  label,
  hint,
  hintId,
  htmlFor,
  children,
  testId,
}: {
  label: ReactNode;
  hint?: ReactNode;
  hintId?: string;
  /** The id of the control, so clicking the label focuses it. */
  htmlFor?: string;
  children?: ReactNode;
  testId?: string;
}) {
  const Label = htmlFor ? 'label' : 'div';
  return (
    <div
      className="flex flex-col gap-2 border-b border-border/60 py-3 sm:flex-row sm:items-start sm:justify-between sm:gap-4"
      data-testid={testId}
    >
      <div className="min-w-0 flex-1">
        <Label htmlFor={htmlFor} className={cn('text-[12.5px] font-medium text-foreground', htmlFor && 'cursor-pointer')}>
          {label}
        </Label>
        {hint && (
          <div id={hintId} className="mt-0.5 text-[11px] text-muted-foreground">
            {hint}
          </div>
        )}
      </div>
      {children !== undefined && (
        <div className="flex min-w-0 flex-wrap items-center gap-2 sm:shrink-0 sm:justify-end">{children}</div>
      )}
    </div>
  );
}

/** The column header line above a list of rows (Search > Resource budgets). */
export function SettingsListHeader({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={cn(
        'border-y border-border bg-card/50 px-3 py-1.5 text-[10px] font-medium uppercase tracking-[0.08em] text-muted-foreground',
        className,
      )}
    >
      {children}
    </div>
  );
}

/** Save buttons for the group above, right-aligned. */
export function SettingsActions({ children, note }: { children: ReactNode; note?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-end gap-2 pt-3">
      {note && <span className="mr-auto font-mono text-[10.5px] text-muted-foreground sm:mr-0">{note}</span>}
      {children}
    </div>
  );
}
