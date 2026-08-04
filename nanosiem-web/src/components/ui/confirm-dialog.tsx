// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * ConfirmDialog — the single, canonical "Are you sure?" confirmation modal.
 *
 * Implements the dense redesign chrome (matches PromoteDialog / OidcProviders /
 * SourceConfigurations) so every confirmation across the app reads identically:
 *   content  max-w-md gap-0 p-0, bg-card border-border
 *   header   border-b px-5 py-4, title text-[14px] semibold, body text-[11.5px]
 *   footer   border-t px-5 py-3, buttons h-8 text-[11.5px]
 *
 * The shadcn AlertDialog primitive defaults (max-w-lg p-6, text-lg title,
 * text-sm body) are too large/"bubbly" next to the rest of the UI — always use
 * this component for confirmations rather than hand-rolling an AlertDialog.
 *
 * Behaviour: confirming auto-closes the dialog (Radix default) and fires
 * onConfirm. `loading` disables the buttons and swaps in a spinner for callers
 * that keep the dialog open during an async action.
 */

import * as React from 'react';
import { Loader2 } from 'lucide-react';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { cn } from '@/lib/utils';

export type ConfirmDialogVariant = 'default' | 'danger' | 'warning';

const CONFIRM_VARIANT_CLS: Record<ConfirmDialogVariant, string> = {
  default: '',
  danger: 'bg-red-600 text-white hover:bg-red-700',
  warning: 'bg-yellow-600 text-white hover:bg-yellow-700',
};

export interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Title text (optionally with a leading `icon`). */
  title: React.ReactNode;
  /** Body prose. Embed emphasised values with `<span className="text-foreground font-medium">…</span>`. */
  description?: React.ReactNode;
  /** Extra body content rendered (padded) between the header and footer — e.g. a callout or a type-to-confirm input. */
  children?: React.ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  /** Label shown next to the spinner while `loading`. Defaults to `confirmLabel`. */
  loadingLabel?: string;
  onConfirm: () => void;
  /** Optional side-effect when the user cancels (the dialog still closes). */
  onCancel?: () => void;
  variant?: ConfirmDialogVariant;
  loading?: boolean;
  /** Extra gate on the confirm button (e.g. require typing a name). */
  confirmDisabled?: boolean;
  /** Optional leading icon in the title. */
  icon?: React.ReactNode;
  /** Optional icon inside the confirm button. */
  confirmIcon?: React.ReactNode;
  /** Extra classes on AlertDialogContent (e.g. a wider `max-w-lg`). */
  className?: string;
  /** Raise the confirmation above a desktop Studio portal. */
  layer?: 'default' | 'studio';
  /** Extra classes on the confirm button (for one-off colour overrides). */
  confirmClassName?: string;
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  loadingLabel,
  onConfirm,
  onCancel,
  variant = 'default',
  loading = false,
  confirmDisabled = false,
  icon,
  confirmIcon,
  className,
  layer = 'default',
  confirmClassName,
}: ConfirmDialogProps) {
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent
        overlayClassName={layer === 'studio' ? '!z-[180]' : undefined}
        className={cn(
          'max-w-md gap-0 p-0 bg-card border-border text-foreground',
          layer === 'studio' && '!z-[190]',
          className,
        )}
      >
        <AlertDialogHeader className="space-y-1.5 border-b border-border px-5 py-4 text-left">
          <AlertDialogTitle className="flex items-center gap-2 text-[14px] font-semibold">
            {icon}
            {title}
          </AlertDialogTitle>
          {description != null && (
            <AlertDialogDescription className="text-[11.5px] leading-relaxed text-muted-foreground">
              {description}
            </AlertDialogDescription>
          )}
        </AlertDialogHeader>

        {children != null && <div className="px-5 py-4">{children}</div>}

        <AlertDialogFooter className="border-t border-border px-5 py-3">
          <AlertDialogCancel
            className="mt-0 h-8 border-border bg-accent/50 text-[11.5px] text-foreground hover:bg-accent"
            disabled={loading}
            onClick={onCancel}
          >
            {cancelLabel}
          </AlertDialogCancel>
          <AlertDialogAction
            className={cn(
              'h-8 gap-1.5 text-[11.5px]',
              CONFIRM_VARIANT_CLS[variant],
              confirmClassName,
            )}
            onClick={onConfirm}
            disabled={loading || confirmDisabled}
          >
            {loading ? (
              <>
                <Loader2 className="h-[11px] w-[11px] animate-spin" />
                {loadingLabel ?? confirmLabel}
              </>
            ) : (
              <>
                {confirmIcon}
                {confirmLabel}
              </>
            )}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
