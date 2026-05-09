// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-484 PR 3 — right-side Inspector drawer.
//
// Collapsed: 40px icon rail (expand + AI / Tests / Docs entry buttons).
// Expanded: 360px panel with tab header + one of:
//   • AI      — AiTriageHintsEditor + RulePlaybookSelector + LinkedPlaybooksPreview
//   • Tests   — fires `POST /api/rules/:id/test` (or /api/rules/test for unsaved),
//               shows sample matched events + re-run
//   • Docs    — MITRE tactic/technique links + reference URL + related rules
//
// Mirrors `design-ref/shadcn/editor-inspector.jsx` structure but composes the
// existing AiTriageHintsEditor, RulePlaybookSelector, and LinkedPlaybooksPreview
// components so the AI / playbook feature set is preserved end-to-end.

import { useEffect, useState } from 'react';
import {
  ChevronRight,
  PanelRight,
  Shield,
  History,
} from 'lucide-react';
import { PivtIcon } from '@/enterprise/icons/PivtIcon';
import { cn } from '@/lib/utils';
import { ScrollArea } from '@/components/ui/scroll-area';
import type { AiTriageHints, CaseVisibility, TestDetectionResult } from '@/lib/api/types';
import { AiTriageHintsEditor } from '@/enterprise/components/detection/editor/AiTriageHintsEditor';
import { RulePlaybookSelector, type PlaybookSelectorMode } from '@/enterprise/components/detection/editor/RulePlaybookSelector';
import { LinkedPlaybooksPreview } from '@/enterprise/components/detection/editor/LinkedPlaybooksPreview';
import { InspectorCasesTab } from '@/enterprise/components/rule-editor/InspectorCasesTab';
import { InspectorVersionsTab } from './InspectorVersionsTab';

type TabId = 'ai' | 'cases' | 'versions';

interface InspectorDrawerProps {
  collapsed: boolean;
  onToggle: () => void;
  disabled?: boolean;

  // AI tab
  hints: AiTriageHints;
  onHintsChange: (hints: AiTriageHints) => void;
  ruleMeta: { name?: string; description?: string; query: string; mitreTactics?: string[]; mitreTechniques?: string[] };
  melodConnected?: boolean;
  playbookMode: PlaybookSelectorMode;
  onPlaybookModeChange: (mode: PlaybookSelectorMode) => void;
  playbookId: string | null;
  onPlaybookIdChange: (id: string | null) => void;
  ruleId?: string;
  readOnly?: boolean;

  // Tests tab
  lastTest: TestDetectionResult | null;
  onRunTest: () => void;
  testRunning: boolean;
  /** When true, the rule hasn't been saved yet — we use unsaved testQuery path. */
  isUnsaved: boolean;

  // Docs tab
  referenceUrl?: string;
  mitreTactics?: string[];
  mitreTechniques?: string[];
  description?: string;

  // Cases tab
  caseVisibility: CaseVisibility;
  caseGroupIds: string[];
  caseAssignedGroupId: string | null;
  onCaseVisibilityChange: (visibility: CaseVisibility) => void;
  onCaseGroupIdsChange: (groupIds: string[]) => void;
  onCaseAssignedGroupChange: (groupId: string | null) => void;

  // Versions tab
  currentQuery: string;
  onVersionReverted?: () => void;
  /**
   * Set by the parent when an external surface (e.g. BottomTray version
   * chip) wants to focus a specific version. The drawer reacts by switching
   * to the versions tab; the inner tab consumes the id and clears it via
   * `onPendingVersionConsumed`.
   */
  pendingVersionFocusId?: number | string | null;
  onPendingVersionConsumed?: () => void;
}

function TabButton({
  active,
  onClick,
  icon,
  label,
}: {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'flex-1 inline-flex items-center justify-center gap-1.5 h-8 text-[10.5px] font-mono font-semibold uppercase tracking-[0.1em] border-b-2 transition-colors',
        active ? 'border-[var(--primary)] text-[var(--primary)]' : 'border-transparent text-muted-foreground hover:text-foreground',
      )}
    >
      {icon}
      {label}
    </button>
  );
}

export function InspectorDrawer(props: InspectorDrawerProps) {
  const { collapsed, onToggle, disabled, pendingVersionFocusId } = props;
  const [tab, setTab] = useState<TabId>('ai');

  // When a parent surface requests a version focus, switch to the versions
  // tab so the inner tab can pick it up. The id itself stays in parent
  // state until `InspectorVersionsTab` consumes it.
  useEffect(() => {
    if (pendingVersionFocusId != null) setTab('versions');
  }, [pendingVersionFocusId]);

  if (collapsed) {
    return (
      <aside className="w-10 bg-[var(--panel)] border-l border-border flex flex-col items-center py-2 gap-1 shrink-0">
        <button
          type="button"
          onClick={onToggle}
          disabled={disabled}
          aria-label="Expand inspector"
          className="h-8 w-8 rounded hover:bg-[color-mix(in_srgb,var(--foreground)_5%,transparent)] text-muted-foreground hover:text-foreground inline-flex items-center justify-center disabled:opacity-40"
        >
          <PanelRight className="w-4 h-4" strokeWidth={1.75} />
        </button>
        <div className="h-px w-6 bg-border my-1" />
        <button
          type="button"
          onClick={() => {
            if (disabled) return;
            setTab('ai');
            onToggle();
          }}
          disabled={disabled}
          title="pivt triage guidance"
          className="h-8 w-8 rounded hover:bg-[color-mix(in_srgb,var(--foreground)_5%,transparent)] text-[var(--primary)] inline-flex items-center justify-center disabled:opacity-40"
        >
          <PivtIcon className="w-4 h-4" />
        </button>
        <button
          type="button"
          onClick={() => {
            if (disabled) return;
            setTab('cases');
            onToggle();
          }}
          disabled={disabled}
          title="Case permissions"
          className="h-8 w-8 rounded hover:bg-[color-mix(in_srgb,var(--foreground)_5%,transparent)] text-muted-foreground hover:text-foreground inline-flex items-center justify-center disabled:opacity-40"
        >
          <Shield className="w-4 h-4" strokeWidth={1.75} />
        </button>
        <button
          type="button"
          onClick={() => {
            if (disabled) return;
            setTab('versions');
            onToggle();
          }}
          disabled={disabled}
          title="Version history"
          className="h-8 w-8 rounded hover:bg-[color-mix(in_srgb,var(--foreground)_5%,transparent)] text-muted-foreground hover:text-foreground inline-flex items-center justify-center disabled:opacity-40"
        >
          <History className="w-4 h-4" strokeWidth={1.75} />
        </button>
      </aside>
    );
  }

  return (
    <aside className="w-[360px] bg-[var(--panel)] border-l border-border flex flex-col shrink-0 min-h-0">
      <div className="h-10 border-b border-border flex items-center px-2 shrink-0">
        <div className="flex-1 flex items-center gap-0">
          <TabButton active={tab === 'ai'} onClick={() => setTab('ai')} icon={<PivtIcon className="w-3 h-3" />} label="pivt" />
          <TabButton active={tab === 'cases'} onClick={() => setTab('cases')} icon={<Shield className="w-3 h-3" strokeWidth={1.75} />} label="Cases" />
          <TabButton active={tab === 'versions'} onClick={() => setTab('versions')} icon={<History className="w-3 h-3" strokeWidth={1.75} />} label="Versions" />
        </div>
        <button
          type="button"
          onClick={onToggle}
          aria-label="Collapse inspector"
          className="h-7 w-7 rounded hover:bg-[color-mix(in_srgb,var(--foreground)_5%,transparent)] text-muted-foreground hover:text-foreground inline-flex items-center justify-center ml-1"
        >
          <ChevronRight className="w-3.5 h-3.5" strokeWidth={1.75} />
        </button>
      </div>

      {tab === 'ai' && <AiTab {...props} />}
      {tab === 'cases' && (
        <InspectorCasesTab
          visibility={props.caseVisibility}
          groupIds={props.caseGroupIds}
          assignedGroupId={props.caseAssignedGroupId}
          onVisibilityChange={props.onCaseVisibilityChange}
          onGroupIdsChange={props.onCaseGroupIdsChange}
          onAssignedGroupChange={props.onCaseAssignedGroupChange}
          disabled={props.readOnly || props.disabled}
        />
      )}
      {tab === 'versions' && (
        <InspectorVersionsTab
          ruleId={props.ruleId}
          currentQuery={props.currentQuery}
          onReverted={props.onVersionReverted}
          disabled={props.readOnly || props.disabled}
          focusVersionId={props.pendingVersionFocusId}
          onFocusConsumed={props.onPendingVersionConsumed}
        />
      )}
    </aside>
  );
}

function AiTab({
  hints,
  onHintsChange,
  ruleMeta,
  melodConnected,
  playbookMode,
  onPlaybookModeChange,
  playbookId,
  onPlaybookIdChange,
  ruleId,
  readOnly,
}: InspectorDrawerProps) {
  return (
    <ScrollArea className="flex-1 min-h-0">
      <div className="p-3 space-y-4">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-[0.12em] font-semibold text-muted-foreground mb-2">
            pivt Triage Guidance
          </div>
          <div className="text-[11px] text-muted-foreground leading-relaxed mb-3">
            Guide pivt when it investigates alerts from this rule. Hints help reach a confident verdict faster.
          </div>
          <AiTriageHintsEditor
            hints={hints}
            onChange={onHintsChange}
            ruleMetadata={ruleMeta}
            melodConnected={melodConnected}
          />
        </div>

        <div className="pt-4 border-t border-border">
          <div className="text-[10px] font-mono uppercase tracking-[0.12em] font-semibold text-muted-foreground mb-2">
            Playbook assignment
          </div>
          <div className="text-[11px] text-muted-foreground leading-relaxed mb-3">
            What runs automatically when this rule fires and creates a case.
          </div>
          <RulePlaybookSelector
            mode={playbookMode}
            playbookId={playbookId}
            onModeChange={onPlaybookModeChange}
            onPlaybookIdChange={onPlaybookIdChange}
            disabled={readOnly}
          />
          <div className="mt-3">
            <LinkedPlaybooksPreview ruleId={ruleId} />
          </div>
        </div>
      </div>
    </ScrollArea>
  );
}

export { type TabId as InspectorTabId };
