// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * CreateDashboardDialog — the core "new dashboard" surface (NAN-2356).
 *
 * Rendered by `Dashboards.tsx` whenever the meloD capability is absent, which
 * is every open-core build. The enterprise build keeps the richer
 * `DashboardGenerationWizard` (blank + generate in one sheet); both render the
 * same `BlankDashboardForm`, so the blank path cannot drift between editions.
 *
 * Deliberately NOT a stub in `src/enterprise-stubs/` — that tree is for
 * placeholders, and creating a dashboard is core functionality.
 */

import { useEffect, useState } from 'react';
import { Grid as GridIcon } from 'lucide-react';

import { Sheet, SheetContent } from '@/components/ui/sheet';

import {
  BlankDashboardForm,
  EMPTY_BLANK_DASHBOARD_DRAFT,
  type BlankDashboardDraft,
} from './BlankDashboardForm';

export interface CreateDashboardDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreate: (data: BlankDashboardDraft) => Promise<void>;
  creating?: boolean;
}

export function CreateDashboardDialog({
  open,
  onOpenChange,
  onCreate,
  creating = false,
}: CreateDashboardDialogProps) {
  const [draft, setDraft] = useState<BlankDashboardDraft>(EMPTY_BLANK_DASHBOARD_DRAFT);

  // Reset on open rather than on close: closing animates out, and wiping the
  // fields mid-animation is visible.
  useEffect(() => {
    if (open) setDraft(EMPTY_BLANK_DASHBOARD_DRAFT);
  }, [open]);

  const handleSubmit = async () => {
    if (!draft.name.trim()) return;
    // Dashboards.tsx owns the toast + navigate on success and re-throws on
    // failure, which leaves the sheet open with the draft intact so the
    // operator can retry without retyping.
    //
    // The re-throw is swallowed here on purpose: React does not catch promises
    // returned from event handlers, so awaiting it bare would surface an
    // unhandled rejection in the console for an error the caller has ALREADY
    // reported to the user via toast. Nothing further to do — just don't let a
    // handled failure look unhandled.
    try {
      await onCreate({
        name: draft.name.trim(),
        description: draft.description.trim(),
        visibility: draft.visibility,
      });
    } catch {
      // already surfaced by the caller's toast; sheet stays open for retry
    }
  };

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="w-[560px] max-w-[min(560px,calc(100vw-24px))] bg-card border-border p-0 overflow-hidden flex flex-col gap-0"
      >
        {/* Header — SheetContent renders its own close button at top-right */}
        <div className="px-4 py-3 pr-12 border-b border-border flex items-center gap-2">
          <GridIcon className="w-[13px] h-[13px] text-primary" />
          <div className="flex-1 min-w-0">
            <div className="font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground font-semibold">
              Dashboard Builder
            </div>
            <div className="text-[11px] text-muted-foreground mt-0.5">
              Name it, then add panels from the library.
            </div>
          </div>
        </div>

        <BlankDashboardForm
          draft={draft}
          onDraftChange={setDraft}
          onSubmit={handleSubmit}
          onCancel={() => onOpenChange(false)}
          submitting={creating}
        />
      </SheetContent>
    </Sheet>
  );
}

export default CreateDashboardDialog;
