// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * BlankDashboardForm — the name / description / visibility fields for creating
 * an empty dashboard.
 *
 * This lives in CORE on purpose (NAN-2356). It used to be inline JSX inside
 * `@/enterprise/components/dashboard/DashboardGenerationWizard`, which meant
 * open-core builds resolved the whole wizard to a `return null` stub and every
 * create affordance on `/dashboards` became inert — the header button, both
 * density cards, and the empty state. Creating a blank dashboard is core
 * functionality; only the meloD *generation* half is enterprise.
 *
 * Controlled on purpose: the enterprise wizard resets its draft from
 * `resetWizard()` on close, and the open dialog resets on open. Owning the
 * state here would make both of those impossible without a remount hack.
 */

import { Globe, Lock, Plus } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';
import { Term } from '@/components/ui/term';

export interface BlankDashboardDraft {
  name: string;
  description: string;
  visibility: 'private' | 'public';
}

export const EMPTY_BLANK_DASHBOARD_DRAFT: BlankDashboardDraft = {
  name: '',
  description: '',
  // NAN-5328: a new dashboard starts private; the author shares it explicitly.
  visibility: 'private',
};

export interface BlankDashboardFormProps {
  draft: BlankDashboardDraft;
  onDraftChange: (draft: BlankDashboardDraft) => void;
  onSubmit: () => void;
  onCancel: () => void;
  /** Disables the submit button and swaps its icon for a spinner. */
  submitting?: boolean;
}

export function BlankDashboardForm({
  draft,
  onDraftChange,
  onSubmit,
  onCancel,
  submitting = false,
}: BlankDashboardFormProps) {
  const patch = (next: Partial<BlankDashboardDraft>) => onDraftChange({ ...draft, ...next });

  return (
    <>
      <div className="flex-1 min-h-0 overflow-y-auto p-4 flex flex-col gap-4">
        <div>
          <label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold block mb-1.5">
            Name
          </label>
          <Input
            value={draft.name}
            onChange={e => patch({ name: e.target.value })}
            placeholder="e.g., Security Overview"
            className="h-[30px] text-[12.5px]"
          />
        </div>

        <div>
          <label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold block mb-1.5">
            Description
          </label>
          <textarea
            value={draft.description}
            onChange={e => patch({ description: e.target.value })}
            placeholder="What does this dashboard monitor?"
            className="w-full h-[80px] rounded-md border border-border bg-transparent px-3 py-2 text-[12px] text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-primary resize-none leading-[1.5]"
          />
        </div>

        <div>
          <label className="font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground font-semibold block mb-1.5">
            <Term id="dashboard-visibility">Visibility</Term>
          </label>
          <div className="grid grid-cols-2 gap-2">
            <button
              type="button"
              onClick={() => patch({ visibility: 'private' })}
              className={cn(
                'h-[60px] px-3 rounded-md border text-left transition-colors flex flex-col justify-center gap-0.5',
                draft.visibility === 'private'
                  ? 'border-primary bg-primary/10'
                  : 'border-border hover:bg-foreground/[0.04]',
              )}
            >
              <div className="flex items-center gap-1.5 text-[12px] font-medium text-foreground">
                <Lock className="w-[12px] h-[12px]" />
                Private
              </div>
              <p className="text-[10.5px] text-muted-foreground leading-[1.4]">
                Only you can view this dashboard.
              </p>
            </button>
            <button
              type="button"
              onClick={() => patch({ visibility: 'public' })}
              className={cn(
                'h-[60px] px-3 rounded-md border text-left transition-colors flex flex-col justify-center gap-0.5',
                draft.visibility === 'public'
                  ? 'border-primary bg-primary/10'
                  : 'border-border hover:bg-foreground/[0.04]',
              )}
            >
              <div className="flex items-center gap-1.5 text-[12px] font-medium text-foreground">
                <Globe className="w-[12px] h-[12px]" />
                Public
              </div>
              <p className="text-[10.5px] text-muted-foreground leading-[1.4]">
                Visible to anyone with dashboard access.
              </p>
            </button>
          </div>
        </div>
      </div>

      <div className="px-4 py-3 border-t border-border flex items-center justify-end gap-2">
        <Button variant="ghost" size="sm" className="h-[28px]" onClick={onCancel}>
          Cancel
        </Button>
        <Button
          size="sm"
          className="h-[28px]"
          onClick={onSubmit}
          disabled={submitting || !draft.name.trim()}
        >
          {submitting ? (
            <LoadingIcon className="w-[12px] h-[12px]" />
          ) : (
            // NAN-2362 / NAN-5541: AI-driven controls carry the pivt mark
            // (PivtIcon); sparkle icons are not used anywhere in the app. This
            // button makes an EMPTY dashboard, and in open builds there is no
            // AI at all, so it gets a plain Plus, not the pivt mark.
            <Plus className="w-[12px] h-[12px]" />
          )}
          Create blank
        </Button>
      </div>
    </>
  );
}

export default BlankDashboardForm;
