// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * DetailSheet / FormSheet — the canonical right-side flyout (NAN-3209).
 *
 * Use a sheet to inspect or edit an object in context, for drill-downs, for
 * forms with more than 3 fields, and for wizards acting on the page's
 * selection. Confirmations, destructive actions, short pick-lists and forms
 * with 3 or fewer fields stay centered Dialogs (`ConfirmDialog` / `Dialog`).
 *
 * Chrome (CLAUDE.md UI conventions):
 *   header  breadcrumb (mono 10.5px) → title (14px) + actions + 24px close → meta row (mono 10.5px)
 *   body    scroll region, px-4 py-3
 *   footer  sticky border-t bar, right-aligned
 *   sizes   sm 420 | md 560 | lg 760 | xl 960, clamped to calc(100vw-24px);
 *           bottom sheet below the mobile breakpoint
 *   frame   bg-card, one 1px border, overlay shadow only, light blur-free scrim
 *
 * Focus trap and Esc come from Radix Dialog. `guardDirty` intercepts every
 * close path the user can trigger (Esc, outside click, header X, FormSheet
 * Cancel) and asks before discarding. Programmatic closes (the caller setting
 * `open=false` after a successful save) are never intercepted.
 */

import * as React from 'react';
import { Sheet, SheetContent, SheetDescription, SheetTitle } from '@/components/ui/sheet';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Button } from '@/components/ui/button';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { useIsMobile } from '@/hooks/use-mobile';
import { cn } from '@/lib/utils';

export type DetailSheetSize = 'sm' | 'md' | 'lg' | 'xl';

// sm 420 | md 560 | lg 760 | xl 960. Literal class strings so Tailwind's scanner picks them up.
const SIZE_CLS: Record<DetailSheetSize, string> = {
  sm: 'w-[420px] max-w-[calc(100vw-24px)] sm:max-w-[calc(100vw-24px)]',
  md: 'w-[560px] max-w-[calc(100vw-24px)] sm:max-w-[calc(100vw-24px)]',
  lg: 'w-[760px] max-w-[calc(100vw-24px)] sm:max-w-[calc(100vw-24px)]',
  xl: 'w-[960px] max-w-[calc(100vw-24px)] sm:max-w-[calc(100vw-24px)]',
};

interface DetailSheetContextValue {
  /** Close through the dirty guard (use for in-body Cancel / Done buttons). */
  requestClose: () => void;
}

const DetailSheetContext = React.createContext<DetailSheetContextValue | null>(null);

/** Access the enclosing sheet's guarded close. */
// eslint-disable-next-line react-refresh/only-export-components -- hook is part of the primitive's API
export function useDetailSheet(): DetailSheetContextValue {
  const ctx = React.useContext(DetailSheetContext);
  if (!ctx) throw new Error('useDetailSheet must be used inside <DetailSheet>');
  return ctx;
}

export interface DetailSheetProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  size?: DetailSheetSize;
  /** Mono trail above the title, e.g. `['Risk', 'host']`. */
  breadcrumb?: React.ReactNode[];
  /** Rendered as the Radix `SheetTitle` (a11y name). */
  title: React.ReactNode;
  /** Optional leading icon in the title row. */
  icon?: React.ReactNode;
  /** Short prose under the title; also the a11y description. */
  description?: React.ReactNode;
  /** Mono meta row under the title (IDs, counts, timestamps). */
  meta?: React.ReactNode;
  /** Header-right controls, left of the close button. */
  actions?: React.ReactNode;
  /** Sticky footer content (right-aligned). */
  footer?: React.ReactNode;
  /** When true, user-initiated closes ask before discarding. */
  guardDirty?: boolean;
  discardTitle?: string;
  discardDescription?: React.ReactNode;
  /** Classes on the sheet frame. */
  className?: string;
  /** Classes on the scroll body (e.g. `p-0` for full-bleed tables). */
  bodyClassName?: string;
  /** Force a side; defaults to right (bottom below the mobile breakpoint). */
  side?: 'right' | 'bottom';
  children?: React.ReactNode;
}

function CloseIcon() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      className="h-3.5 w-3.5"
    >
      <path d="M6 6l12 12M18 6L6 18" />
    </svg>
  );
}

export function DetailSheet({
  open,
  onOpenChange,
  size = 'md',
  breadcrumb,
  title,
  icon,
  description,
  meta,
  actions,
  footer,
  guardDirty = false,
  discardTitle = 'Discard unsaved changes?',
  discardDescription = 'Closing this panel will lose the changes you made.',
  className,
  bodyClassName,
  side,
  children,
}: DetailSheetProps) {
  const isMobile = useIsMobile();
  const resolvedSide = side ?? (isMobile ? 'bottom' : 'right');
  const [confirmOpen, setConfirmOpen] = React.useState(false);

  const requestClose = React.useCallback(() => {
    if (guardDirty) {
      setConfirmOpen(true);
      return;
    }
    onOpenChange(false);
  }, [guardDirty, onOpenChange]);

  const handleOpenChange = React.useCallback(
    (next: boolean) => {
      if (next) {
        onOpenChange(true);
        return;
      }
      requestClose();
    },
    [onOpenChange, requestClose],
  );

  const ctx = React.useMemo(() => ({ requestClose }), [requestClose]);
  const crumbs = breadcrumb?.filter((c) => c != null && c !== '') ?? [];

  return (
    <>
      <Sheet open={open} onOpenChange={handleOpenChange}>
        <SheetContent
          side={resolvedSide}
          hideClose
          overlayClassName="bg-black/40 backdrop-blur-none"
          data-detail-sheet=""
          data-size={size}
          className={cn(
            'flex flex-col gap-0 bg-card p-0 text-foreground shadow-xl',
            resolvedSide === 'right'
              ? SIZE_CLS[size]
              : 'max-h-[88vh] w-full rounded-t-md',
            className,
          )}
          // No description → tell Radix there is none instead of warning.
          {...(description == null ? { 'aria-describedby': undefined } : {})}
        >
          <DetailSheetContext.Provider value={ctx}>
            <header className="shrink-0 border-b border-border px-4 pb-2.5 pt-3">
              {crumbs.length > 0 && (
                <nav
                  aria-label="Breadcrumb"
                  className="mb-1 flex min-w-0 items-center gap-1 font-mono text-[10.5px] text-muted-foreground"
                >
                  {crumbs.map((crumb, i) => (
                    <React.Fragment key={i}>
                      {i > 0 && <span aria-hidden="true" className="opacity-60">/</span>}
                      <span className={cn('truncate', i === crumbs.length - 1 && 'text-foreground/80')}>
                        {crumb}
                      </span>
                    </React.Fragment>
                  ))}
                </nav>
              )}
              <div className="flex min-w-0 items-center gap-2">
                {icon && <span className="shrink-0 text-muted-foreground">{icon}</span>}
                <SheetTitle className="min-w-0 flex-1 truncate text-[14px] font-semibold leading-6">
                  {title}
                </SheetTitle>
                {actions && <div className="flex shrink-0 items-center gap-1.5">{actions}</div>}
                <button
                  type="button"
                  onClick={requestClose}
                  aria-label="Close"
                  className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-sm text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                >
                  <CloseIcon />
                </button>
              </div>
              {description != null && (
                <SheetDescription className="mt-0.5 text-[11.5px] leading-relaxed text-muted-foreground">
                  {description}
                </SheetDescription>
              )}
              {meta != null && (
                <div
                  data-slot="meta"
                  className="mt-1 flex min-w-0 flex-wrap items-center gap-x-3 gap-y-0.5 font-mono text-[10.5px] text-muted-foreground"
                >
                  {meta}
                </div>
              )}
            </header>

            <div className={cn('min-h-0 flex-1 overflow-y-auto px-4 py-3 text-[12px]', bodyClassName)}>
              {children}
            </div>

            {footer != null && (
              <footer className="flex shrink-0 items-center justify-end gap-2 border-t border-border px-4 py-2.5">
                {footer}
              </footer>
            )}
          </DetailSheetContext.Provider>
        </SheetContent>
      </Sheet>
      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title={discardTitle}
        description={discardDescription}
        confirmLabel="Discard"
        cancelLabel="Keep editing"
        variant="danger"
        onConfirm={() => {
          setConfirmOpen(false);
          onOpenChange(false);
        }}
      />
    </>
  );
}

export interface FormSheetProps extends Omit<DetailSheetProps, 'footer'> {
  onSubmit: (event: React.FormEvent<HTMLFormElement>) => void;
  submitLabel?: React.ReactNode;
  cancelLabel?: React.ReactNode;
  /** Disables the buttons and shows a spinner on submit. */
  pending?: boolean;
  submitDisabled?: boolean;
  submitVariant?: 'default' | 'destructive';
  /** Extra footer content, left-aligned before Cancel / Submit (e.g. a Delete button). */
  footerStart?: React.ReactNode;
}

/**
 * DetailSheet with a form body and a Cancel / Submit footer. The submit
 * handler receives the native event with `preventDefault()` already called.
 * Cancel goes through the dirty guard.
 */
export function FormSheet({
  onSubmit,
  submitLabel = 'Save',
  cancelLabel = 'Cancel',
  pending = false,
  submitDisabled = false,
  submitVariant = 'default',
  footerStart,
  children,
  ...sheet
}: FormSheetProps) {
  const formId = React.useId();
  return (
    <DetailSheet
      {...sheet}
      footer={
        <>
          {footerStart != null && <div className="mr-auto flex items-center gap-2">{footerStart}</div>}
          <FormSheetCancel label={cancelLabel} disabled={pending} />
          <Button
            type="submit"
            form={formId}
            size="sm"
            variant={submitVariant}
            disabled={pending || submitDisabled}
            className="h-7 text-[11.5px]"
          >
            {pending && <LoadingIcon className="h-[11px] w-[11px]" />}
            {submitLabel}
          </Button>
        </>
      }
    >
      <form
        id={formId}
        onSubmit={(event) => {
          event.preventDefault();
          if (pending || submitDisabled) return;
          onSubmit(event);
        }}
        className="contents"
      >
        {children}
      </form>
    </DetailSheet>
  );
}

function FormSheetCancel({ label, disabled }: { label: React.ReactNode; disabled: boolean }) {
  const { requestClose } = useDetailSheet();
  return (
    <Button
      type="button"
      size="sm"
      variant="outline"
      onClick={requestClose}
      disabled={disabled}
      className="h-7 text-[11.5px]"
    >
      {label}
    </Button>
  );
}
