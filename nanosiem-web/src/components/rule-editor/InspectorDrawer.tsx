// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-484 PR 3 — right-side Inspector drawer.
//
// Collapsed: 40px icon rail (expand + pivt / Cases / Versions entry buttons).
// Expanded: 360px panel with tab header + one of:
//   • pivt     — Hints / Playbook sub-views (AiTriageHintsEditor,
//                RulePlaybookSelector + LinkedPlaybooksPreview)
//   • Cases    — InspectorCasesTab (case visibility + default queue)
//   • Versions — InspectorVersionsTab (history, inline diff, revert)
//
// NAN-3023: styling follows the "Rules pivt Panel" handoff mapped onto the app
// type scale; shared pieces live in ./InspectorPrimitives.
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
import { PivtIcon } from '@/components/icons/PivtIcon';
import { cn } from '@/lib/utils';
import { useCapabilities } from '@/hooks/use-capabilities';
import { ScrollArea } from '@/components/ui/scroll-area';
import type { AiTriageHints, CaseVisibility, TestDetectionResult } from '@/lib/api/types';
import { AiTriageHintsEditor } from '@/enterprise/components/detection/editor/AiTriageHintsEditor';
import { RulePlaybookSelector, type PlaybookSelectorMode } from '@/enterprise/components/detection/editor/RulePlaybookSelector';
import { LinkedPlaybooksPreview } from '@/enterprise/components/detection/editor/LinkedPlaybooksPreview';
import { InspectorCasesTab } from '@/enterprise/components/rule-editor/InspectorCasesTab';
import { InspectorVersionsTab } from './InspectorVersionsTab';
import { CountBadge, HelperText } from './InspectorPrimitives';

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
  label,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        'flex-1 h-7 inline-flex items-center justify-center rounded-[4px] text-[10.5px] font-mono font-semibold uppercase tracking-[0.1em] transition-colors',
        active ? 'bg-foreground/[0.07] text-foreground' : 'text-muted-foreground hover:text-foreground',
      )}
    >
      {label}
    </button>
  );
}

export function InspectorDrawer(props: InspectorDrawerProps) {
  const { collapsed, onToggle, disabled, pendingVersionFocusId } = props;

  // NAN-2356: the pivt and Cases tabs render enterprise components that resolve
  // to `return null` stubs in open builds. Without these gates the tab buttons
  // still appeared and opened a blank panel.
  const { capabilities } = useCapabilities();
  const showAiTab = capabilities.melod;
  const showCasesTab = capabilities.cases;

  const [tab, setTab] = useState<TabId>(showAiTab ? 'ai' : 'versions');

  // Capabilities arrive from an async fetch and start at the enterprise-everywhere
  // fallback, so a tab chosen on the first render can become hidden a moment
  // later. Fall back to Versions (always core) rather than stranding the drawer
  // on an invisible tab.
  useEffect(() => {
    if ((tab === 'ai' && !showAiTab) || (tab === 'cases' && !showCasesTab)) {
      setTab('versions');
    }
  }, [tab, showAiTab, showCasesTab]);

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
          <PanelRight className="w-4 h-4" strokeWidth={1.5} />
        </button>
        <div className="h-px w-6 bg-border my-1" />
        {showAiTab && (
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
        )}
        {showCasesTab && (
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
            <Shield className="w-4 h-4" strokeWidth={1.5} />
          </button>
        )}
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
          <History className="w-4 h-4" strokeWidth={1.5} />
        </button>
      </aside>
    );
  }

  return (
    <aside className="w-[360px] bg-[var(--panel)] border-l border-border flex flex-col shrink-0 min-h-0">
      <div className="h-10 border-b border-border flex items-center gap-0.5 px-1.5 shrink-0">
        {showAiTab && <TabButton active={tab === 'ai'} onClick={() => setTab('ai')} label="pivt" />}
        {showCasesTab && <TabButton active={tab === 'cases'} onClick={() => setTab('cases')} label="Cases" />}
        <TabButton active={tab === 'versions'} onClick={() => setTab('versions')} label="Versions" />
        <button
          type="button"
          onClick={onToggle}
          aria-label="Collapse inspector"
          className="h-7 w-7 shrink-0 rounded hover:bg-[color-mix(in_srgb,var(--foreground)_5%,transparent)] text-muted-foreground hover:text-foreground inline-flex items-center justify-center ml-0.5"
        >
          <ChevronRight className="w-3.5 h-3.5" strokeWidth={1.5} />
        </button>
      </div>

      {tab === 'ai' && showAiTab && <AiTab {...props} />}
      {tab === 'cases' && showCasesTab && (
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

type PivtSubTab = 'hints' | 'playbook';

const PLAYBOOK_MODE_SHORT: Record<PlaybookSelectorMode, string> = {
  none: 'None',
  specific: 'Specific',
  adaptive: 'Adaptive',
};

function hintCount(hints: AiTriageHints): number {
  return (
    (hints.ignore_when?.length ?? 0) +
    (hints.suspicious_when?.length ?? 0) +
    (hints.context?.trim() ? 1 : 0)
  );
}

function SubTabButton({
  active,
  onClick,
  label,
  badge,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
  badge: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        'h-8 -mb-px inline-flex items-center gap-1.5 border-b-2 text-[12px] font-medium transition-colors',
        active
          ? 'border-ai-muted text-foreground'
          : 'border-transparent text-muted-foreground hover:text-foreground',
      )}
    >
      {label}
      <CountBadge>{badge}</CountBadge>
    </button>
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
  const { capabilities } = useCapabilities();
  const showPlaybooks = capabilities.playbooks;
  const [sub, setSub] = useState<PivtSubTab>('hints');
  // NAN-2356: playbooks are a SEPARATE capability from meloD. The tab is shown
  // on `melod`, so the Playbook sub-view is gated on its own capability.
  const activeSub: PivtSubTab = showPlaybooks ? sub : 'hints';

  return (
    <>
      <div className="flex items-center gap-4 px-3 border-b border-border shrink-0">
        <SubTabButton
          active={activeSub === 'hints'}
          onClick={() => setSub('hints')}
          label="Hints"
          badge={hintCount(hints)}
        />
        {showPlaybooks && (
          <SubTabButton
            active={activeSub === 'playbook'}
            onClick={() => setSub('playbook')}
            label="Playbook"
            badge={PLAYBOOK_MODE_SHORT[playbookMode]}
          />
        )}
      </div>
      <ScrollArea className="flex-1 min-h-0">
        {activeSub === 'hints' ? (
          <div className="p-3">
            <AiTriageHintsEditor
              hints={hints}
              onChange={onHintsChange}
              ruleMetadata={ruleMeta}
              melodConnected={melodConnected}
            />
          </div>
        ) : (
          <div className="p-3 flex flex-col gap-3">
            <HelperText>What runs when this rule opens a case.</HelperText>
            <RulePlaybookSelector
              mode={playbookMode}
              playbookId={playbookId}
              onModeChange={onPlaybookModeChange}
              onPlaybookIdChange={onPlaybookIdChange}
              disabled={readOnly}
            />
            <LinkedPlaybooksPreview ruleId={ruleId} />
          </div>
        )}
      </ScrollArea>
    </>
  );
}

export { type TabId as InspectorTabId };
