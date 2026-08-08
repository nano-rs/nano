// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-484 — redesigned /rules/editor/:id page.
//
// PR 1 scope (see NAN-484 ship plan): shell + left rule-rail + top bar with
// meta chips + CODE lens (CodeMirror) + bottom status strip + full save/load
// + lifecycle actions (pause/resume/archive/unarchive/delete/duplicate).
//
// Deferred to follow-on PRs in this issue: FORM + FLOW lenses (PR 2), MetaChip
// popover editing (PR 2), Inspector drawer — AI hints / Tests / Docs (PR 3),
// full TestDrawer (PR 4), sunset of the legacy editor (PR 5).
//
// Everything from `pages/RuleEditor.tsx` that isn't yet surfaced in the new
// chrome is preserved end-to-end: the YAML frontmatter round-trips via
// `serializeDetectionMetadata` / `parseDetectionMetadata`, `playbook_selector_mode`
// + `playbook_id` follow the YAML `playbook:` shorthand (NAN-452/NAN-453), and
// save posts the same full field set the legacy editor did.

import { useCallback, useEffect, useMemo, useRef, useState, Suspense } from 'react';
import { useNavigate, useParams, useSearchParams, useLocation } from 'react-router-dom';
import { Loader2, ShieldPlus } from 'lucide-react';
import { getAccessToken } from '@/lib/auth-token';

import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useBreadcrumbTitle } from '@/hooks/useBreadcrumbTitle';
import {
  useDetections,
  useDetection,
  useDetectionStats,
  useUpdateDetection,
  useCreateDetection,
  useDeleteDetection,
  usePauseDetection,
  useResumeDetection,
  usePromoteDetection,
  useDemoteDetection,
  useFormatQuery,
  useFolderSettings,
  useSetFolderIcon,
  useClearFolderIcon,
  useMelodStatus,
  useTestDetection,
  useTestQuery,
} from '@/hooks/use-api';
import { useMitreData, tacticsToOptions, techniquesToOptions } from '@/hooks/useMitreData';
import { useAuth } from '@/contexts/AuthContext';
import { setMitreTactics, setMitreTechniques } from '@/lib/yaml-autocomplete';
import { toast } from 'sonner';
import {
  parseDetectionMetadata,
  serializeDetectionMetadata,
  parseLookbackToMinutes,
  formatMinutesToDuration,
  createDetectionTemplate,
  MAX_LOOKBACK_MINUTES,
  encodePlaybookField,
  decodePlaybookField,
} from '@/lib/detection-metadata';
import { Button } from '@/components/ui/button';
import { resetValidationCache, type CodeMirrorEditorRef } from '@/components/editor';
import type { ValidationState } from '@/components/editor/detection-linter';
import {
  SaveConfirmDialog,
  DeleteConfirmDialog,
  ArchiveConfirmDialog,
} from '@/components/detection';
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

import {
  RuleRail,
  EditorTopBar,
  CodeLens,
  FormLens,
  FlowLens,
  BottomTray,
  InspectorDrawer,
  TestDrawer,
  ValidationDetailsDialog,

  type RuleVersionSummary,
  type ViewMode,
} from '@/components/rule-editor';
import { NewRuleAiPanel } from '@/enterprise/components/rule-editor/NewRuleAiPanel';
import { useCapabilities } from '@/hooks/use-capabilities';
import { UpstreamMergeModal } from '@/components/repositories/UpstreamMergeModal';
import { ruleDiffAccess } from '@/components/repositories/repository-action-policy';
import type { AiTriageHints, CaseVisibility, GeneratedDetection, TestDetectionResult } from '@/lib/api/types';
import type { PlaybookSelectorMode } from '@/enterprise/components/detection/editor/RulePlaybookSelector';

export function RuleEditorRedesign() {
  const navigate = useNavigate();
  const location = useLocation();
  const { id: routeId } = useParams();
  const [searchParams] = useSearchParams();
  const { user, hasPermission } = useAuth();

  const canEdit = hasPermission('detections:edit');
  const upstreamDiffAccess = ruleDiffAccess(hasPermission);
  const isNewMode = location.pathname.endsWith('/new') || routeId === 'new';
  const id = isNewMode ? undefined : routeId;

  // Seed params from AI / Sigma / duplicate flows — all handled identically to
  // the legacy editor so existing entry points keep working.
  const duplicateId = searchParams.get('duplicate');
  const initialContent = searchParams.get('content') || '';
  const initialQuery = searchParams.get('query') || '';
  const initialName = searchParams.get('name') || '';
  const initialDescription = searchParams.get('description') || '';
  const initialSeverity = (searchParams.get('severity') || 'medium') as 'critical' | 'high' | 'medium' | 'low';
  const initialNarrative = searchParams.get('narrative') || '';
  const initialTactics = searchParams.get('mitre_tactics')?.split(',').filter(Boolean) || [];
  const initialTechniques = searchParams.get('mitre_techniques')?.split(',').filter(Boolean) || [];
  const initialTags = searchParams.get('tags') || '';

  const { data: apiRules, loading: rulesLoading, refetch: refetchRules } = useDetections();
  const { data: apiRule, loading: ruleLoading, refetch: refetchRule } = useDetection(id);
  const { data: duplicateRule } = useDetection(duplicateId || undefined);
  const { mutate: updateDetection, loading: updating } = useUpdateDetection();
  const { mutate: createDetection, loading: creating } = useCreateDetection();
  const { mutate: deleteDetection } = useDeleteDetection();
  const { data: detectionStats } = useDetectionStats(28);
  const { mutate: pauseDetection } = usePauseDetection();
  const { mutate: resumeDetection } = useResumeDetection();
  const { mutate: promoteDetection } = usePromoteDetection();
  const { mutate: demoteDetection } = useDemoteDetection();
  const { mutate: formatQuery } = useFormatQuery();
  const { data: folderSettingsData, refetch: refetchFolderSettings } = useFolderSettings();
  const { mutate: setFolderIconMutation } = useSetFolderIcon();
  const { mutate: clearFolderIconMutation } = useClearFolderIcon();
  const folderSettings = folderSettingsData ?? {};
  const { data: mitreData } = useMitreData();
  const { data: melodStatus } = useMelodStatus();
  const { mutate: testDetectionMut, loading: testRunningSaved } = useTestDetection();
  const { mutate: testQueryMut, loading: testRunningUnsaved } = useTestQuery();

  useDocumentTitle(isNewMode ? 'Editor — New Rule' : apiRule?.name ? `Editor — ${apiRule.name}` : 'Rule Editor');
  useBreadcrumbTitle(isNewMode ? 'New Rule' : apiRule?.name || null);

  const editorRef = useRef<CodeMirrorEditorRef>(null);
  const [editorContent, setEditorContent] = useState(() => createDetectionTemplate(user?.name || ''));
  const [savedContent, setSavedContent] = useState<string>('');
  const [validation, setValidation] = useState<ValidationState | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>('code');
  const [showSaveConfirm, setShowSaveConfirm] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [showArchiveConfirm, setShowArchiveConfirm] = useState(false);
  // Inspector state — collapsed by default on saved rules, expanded on new so
  // authors see the AI hints prompt up front (same heuristic as legacy).
  const [inspectorCollapsed, setInspectorCollapsed] = useState(() => !isNewMode);
  const [triageHints, setTriageHints] = useState<AiTriageHints>({ ignore_when: [], suspicious_when: [] });
  const [triageHintsChanged, setTriageHintsChanged] = useState(false);
  const [playbookMode, setPlaybookMode] = useState<PlaybookSelectorMode>('none');
  const [playbookPickId, setPlaybookPickId] = useState<string | null>(null);
  // Case-permissions state — surfaced via the Inspector Cases tab. Rule load
  // seeds these from apiRule (see the load effect); save payload includes
  // them so the backend writes visibility / group_ids / assigned_group.
  const [caseVisibility, setCaseVisibility] = useState<CaseVisibility>('public');
  const [caseGroupIds, setCaseGroupIds] = useState<string[]>([]);
  const [caseAssignedGroupId, setCaseAssignedGroupId] = useState<string | null>(null);
  const [caseChanged, setCaseChanged] = useState(false);
  const [lastTest, setLastTest] = useState<TestDetectionResult | null>(null);
  const [testDrawerOpen, setTestDrawerOpen] = useState(false);
  const [validationDetailsOpen, setValidationDetailsOpen] = useState(false);
  // New-rule AI panel — shown by default in new-rule mode so the narrative /
  // batch-generation entry point is visible next to a blank template. Closable.
  // NAN-2356: NewRuleAiPanel is enterprise and renders nothing in open builds.
  // It used to default OPEN for a new rule, so an open-core operator started the
  // create flow with an invisible panel held open and no way to close it.
  const { capabilities } = useCapabilities();
  const [aiPanelOpen, setAiPanelOpen] = useState(isNewMode && capabilities.melod);
  // `?merge=upstream` entry point — Rule Repositories page sends analysts
  // here when they click "Merge upstream" on a forked rule. Open the modal
  // once; after they apply or close, we leave the URL param alone (clearing
  // it would re-trigger on back-nav).
  const [upstreamMergeOpen, setUpstreamMergeOpen] = useState(false);

  // Version history — loaded lazily when a rule is focused. Surfaces in the
  // expanded Bottom Tray card. Inline view / revert UX arrives with the
  // Inspector drawer + Docs tab in PR 3/4 — for this PR we render summaries
  // and link out to the legacy editor for the revert action.
  const [versions, setVersions] = useState<RuleVersionSummary[]>([]);
  // NAN-622 — when a BottomTray version chip is clicked we hand the id to
  // InspectorDrawer; the Versions tab consumes it and clears it via
  // `onPendingVersionConsumed` so the next click re-fires the effect even
  // for the same id.
  const [pendingVersionFocusId, setPendingVersionFocusId] = useState<
    number | string | null
  >(null);
  useEffect(() => {
    if (!id) {
      setVersions([]);
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const token = getAccessToken();
        const base = import.meta.env.VITE_API_URL ?? '';
        const resp = await fetch(`${base}/api/rules/${id}/versions`, {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        });
        if (!resp.ok || cancelled) return;
        type ApiVersion = {
          id: number;
          version_number?: number;
          created_at?: string;
          modified_by?: string;
          change_description?: string;
        };
        const raw = (await resp.json()) as ApiVersion[];
        if (cancelled || !Array.isArray(raw)) return;
        setVersions(
          raw.map((v) => ({
            id: v.id,
            label: v.version_number != null ? `v${v.version_number}` : `#${v.id}`,
            when: v.created_at ? relativeTime(v.created_at) : undefined,
            by: v.modified_by,
            msg: v.change_description,
          })),
        );
      } catch {
        if (!cancelled) setVersions([]);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [id]);

  // Populate MITRE autocomplete when the directory loads.
  useEffect(() => {
    if (mitreData) {
      if (mitreData.tactics?.length) setMitreTactics(tacticsToOptions(mitreData.tactics));
      if (mitreData.techniques?.length) setMitreTechniques(techniquesToOptions(mitreData.techniques));
    }
  }, [mitreData]);

  // Seed editor from (in priority order): Sigma content → AI query → duplicate
  // rule → apiRule → blank template. Each branch runs exactly once per rule ID.
  useEffect(() => {
    if (isNewMode && initialContent) {
      setEditorContent(initialContent);
      setSavedContent('');
    }
  }, [isNewMode, initialContent]);

  useEffect(() => {
    if (isNewMode && !initialContent && initialQuery) {
      const content = serializeDetectionMetadata(
        {
          title: initialName,
          description: initialDescription,
          author: user?.name || '',
          severity: initialSeverity,
          mode: 'staging',
          detection_mode: 'realtime',
          tags: initialTags,
          narrative: initialNarrative,
          mitre_tactics: initialTactics.join(', '),
          mitre_techniques: initialTechniques.join(', '),
        },
        initialQuery,
      );
      setEditorContent(content);
      setSavedContent('');
    }
    // initialTactics / initialTechniques are split arrays derived from the
    // query string once per mount — not reactive, so intentionally excluded
    // from the dependency list to avoid re-serializing on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    isNewMode,
    initialContent,
    initialQuery,
    initialName,
    initialDescription,
    initialSeverity,
    initialNarrative,
    initialTags,
    user?.name,
  ]);

  useEffect(() => {
    if (isNewMode && duplicateRule && duplicateId) {
      const severity = (duplicateRule.severity === 'informational' ? 'low' : duplicateRule.severity) as
        | 'critical'
        | 'high'
        | 'medium'
        | 'low';
      const lookback = duplicateRule.lookback_minutes
        ? formatMinutesToDuration(duplicateRule.lookback_minutes)
        : '15m';
      const content = serializeDetectionMetadata(
        {
          title: `${duplicateRule.name}_copy`,
          description: duplicateRule.description || '',
          author: user?.name || duplicateRule.author || '',
          severity,
          mode: 'staging',
          detection_mode: duplicateRule.detection_mode === 'scheduled' ? 'scheduled' : 'realtime',
          dataset: duplicateRule.dataset || 'logs',
          schedule: duplicateRule.schedule_cron || '',
          lookback,
          // Carry the source rule's folder into the duplicate so the new rule
          // lands in the same folder by default (NAN-729).
          folder: duplicateRule.folder || '',
          tags: duplicateRule.tags?.join(', ') || '',
          narrative: duplicateRule.narrative || '',
          mitre_tactics: duplicateRule.mitre_tactics?.join(', ') || '',
          mitre_techniques: duplicateRule.mitre_techniques?.join(', ') || '',
          reference_url: duplicateRule.reference_url || '',
          playbook: encodePlaybookField(duplicateRule.playbook_selector_mode, duplicateRule.playbook_id),
        },
        duplicateRule.query,
      );
      setEditorContent(content);
      setSavedContent(content);
      toast.success('Rule duplicated', {
        description: `Editing copy of "${duplicateRule.name}". Rename before saving.`,
      });
    }
  }, [isNewMode, duplicateRule, duplicateId, user?.name]);

  // Load existing rule → serialize to YAML → seed editor + dirty baseline.
  useEffect(() => {
    resetValidationCache();
    if (apiRule) {
      const severity = (apiRule.severity === 'informational' ? 'low' : apiRule.severity) as
        | 'critical'
        | 'high'
        | 'medium'
        | 'low';
      const lookback = apiRule.lookback_minutes ? formatMinutesToDuration(apiRule.lookback_minutes) : '15m';
      const content = serializeDetectionMetadata(
        {
          title: apiRule.name,
          description: apiRule.description || '',
          author: apiRule.author || user?.name || '',
          severity,
          mode: apiRule.mode,
          detection_mode: apiRule.detection_mode === 'scheduled' ? 'scheduled' : 'realtime',
          dataset: apiRule.dataset || 'logs',
          schedule: apiRule.schedule_cron || '',
          lookback,
          // NAN-729: round-trip folder through the YAML body so the meta-row
          // folder picker has a current value to display and the save payload
          // can persist picker changes via `buildPayload` below.
          folder: apiRule.folder || '',
          tags: apiRule.tags?.join(', ') || '',
          narrative: apiRule.narrative || '',
          mitre_tactics: apiRule.mitre_tactics?.join(', ') || '',
          mitre_techniques: apiRule.mitre_techniques?.join(', ') || '',
          reference_url: apiRule.reference_url || '',
          alert_mode: (apiRule.alert_mode || 'grouped') as 'grouped' | 'per_event',
          playbook: encodePlaybookField(apiRule.playbook_selector_mode, apiRule.playbook_id),
        },
        apiRule.query,
      );
      setEditorContent(content);
      setSavedContent(content);
      // Seed the Cases tab state from the loaded rule so edits round-trip.
      setCaseVisibility(apiRule.case_visibility ?? 'public');
      setCaseGroupIds((apiRule.case_groups || []).map((g) => g.id));
      setCaseAssignedGroupId(apiRule.case_assigned_group ?? null);
      setCaseChanged(false);
      // Inspector state follows the rule.
      if (apiRule.ai_triage_hints) {
        setTriageHints({
          ignore_when: apiRule.ai_triage_hints.ignore_when || [],
          suspicious_when: apiRule.ai_triage_hints.suspicious_when || [],
          context: apiRule.ai_triage_hints.context,
        });
      } else {
        setTriageHints({ ignore_when: [], suspicious_when: [] });
      }
      setTriageHintsChanged(false);
      setPlaybookMode(apiRule.playbook_selector_mode || 'none');
      setPlaybookPickId(apiRule.playbook_id ?? null);
    }
  }, [apiRule, user?.name]);


  // Reset draft when entering /new without any seed params.
  useEffect(() => {
    if (isNewMode && !duplicateId && !initialQuery && !initialContent) {
      const tpl = createDetectionTemplate(user?.name || '');
      setEditorContent(tpl);
      setSavedContent(tpl);
    }
  }, [isNewMode, duplicateId, initialQuery, initialContent, user?.name]);

  // Open the upstream-merge modal when the analyst arrives from the Rule
  // Repositories page with `?merge=upstream`. We fire once when a saved rule
  // is loaded so the modal has a concrete ID to fetch the diff against.
  useEffect(() => {
    if (!isNewMode && id && searchParams.get('merge') === 'upstream') {
      setUpstreamMergeOpen(true);
    }
  }, [isNewMode, id, searchParams]);

  // Auto-open the TestDrawer when arriving with `?test=1` (e.g. from the
  // Matches page's "Open test drawer" button — NAN-495). Fires once per
  // navigation; we don't strip the param so back-nav can re-open it if needed.
  useEffect(() => {
    if (!isNewMode && id && searchParams.get('test') === '1') {
      setTestDrawerOpen(true);
    }
  }, [isNewMode, id, searchParams]);

  const parsed = useMemo(() => parseDetectionMetadata(editorContent), [editorContent]);
  const metadata = parsed.metadata;
  const actualQuery = parsed.query;
  const titleValid = !metadata.title || /^[a-z0-9_-]+$/.test(metadata.title);
  const saving = updating || creating;

  // YAML → Inspector playbook picker sync. When the user edits `playbook:` in
  // the YAML (via CODE or FORM), the picker reflects it. Form→YAML sync lives
  // on the Inspector's onPlaybookModeChange / onPlaybookIdChange handlers.
  useEffect(() => {
    const { mode, playbookId: parsedId } = decodePlaybookField(metadata.playbook);
    if (mode !== playbookMode) setPlaybookMode(mode);
    if ((parsedId ?? null) !== (playbookPickId ?? null)) setPlaybookPickId(parsedId ?? null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [metadata.playbook]);

  const hasChanges = useMemo(() => {
    if (!isNewMode && ruleLoading) return false;
    if (!isNewMode && !savedContent) return false;
    return editorContent !== savedContent || triageHintsChanged || caseChanged;
  }, [editorContent, savedContent, isNewMode, ruleLoading, triageHintsChanged, caseChanged]);

  const detectionModeLens = useMemo<'realtime' | 'scheduled' | null>(() => {
    if (metadata.detection_mode === 'scheduled') return 'scheduled';
    if (metadata.detection_mode === 'realtime') return 'realtime';
    return null;
  }, [metadata.detection_mode]);

  // NAN-1688 — flip a scheduled rule to real-time from the validation-tray
  // nudge. Patches the YAML the same way FormLens's mode toggle does. Only
  // offered when the backend reports the query is real-time eligible (see
  // ValidateCard) AND the dataset supports the MV path — spans/metrics are
  // scheduled-only, mirroring FormLens's lockout.
  const switchToRealtime = useCallback(() => {
    if (!canEdit) return;
    setEditorContent(serializeDetectionMetadata({ ...metadata, detection_mode: 'realtime' }, actualQuery));
  }, [canEdit, metadata, actualQuery]);

  const realtimeNudgeAvailable =
    canEdit && detectionModeLens === 'scheduled' && (metadata.dataset || 'logs') === 'logs';

  // Browser close / refresh guard — mirrors the legacy editor.
  useEffect(() => {
    const shouldBlock = hasChanges || (isNewMode && (actualQuery.trim() || metadata.title));
    const handler = (e: BeforeUnloadEvent) => {
      if (!shouldBlock) return;
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, [hasChanges, isNewMode, actualQuery, metadata.title]);

  // In-app nav guard — the app uses BrowserRouter (not a data router) so
  // `useBlocker` isn't available. We intercept nav sources that can fire while
  // the editor is dirty (primarily the left rail) and prompt the user to
  // confirm before navigating away. Browser close / refresh is covered by the
  // beforeunload handler above.
  const shouldBlockNav = hasChanges || (isNewMode && (Boolean(actualQuery.trim()) || Boolean(metadata.title)));
  const [pendingNavPath, setPendingNavPath] = useState<string | null>(null);
  const requestNav = useCallback(
    (path: string) => {
      if (shouldBlockNav) {
        setPendingNavPath(path);
      } else {
        navigate(path);
      }
    },
    [shouldBlockNav, navigate],
  );

  const validateSaveReady = useCallback((): string | null => {
    const name = metadata.title?.trim();
    if (!name || !actualQuery.trim()) return 'Title and query are required.';
    if (!titleValid) {
      return 'Title must use snake_case (lowercase, numbers, underscores, hyphens only — no spaces).';
    }
    const missing: string[] = [];
    if (!metadata.description?.trim()) missing.push('description');
    if (!metadata.author?.trim()) missing.push('author');
    if (!metadata.severity) missing.push('severity');
    if (!metadata.mitre_tactics?.trim()) missing.push('mitre_tactics');
    if (!metadata.mitre_techniques?.trim()) missing.push('mitre_techniques');
    if (missing.length) return `Missing required fields: ${missing.join(', ')}`;
    // NAN-1825: pre-save mirror of the backend feedback-loop guard (NAN-1805).
    // A dataset=risk rule queries accumulated risk — a `| risk` command in its
    // body would feed the rule's own input, and the server rejects it. Catch
    // it here so the analyst gets the message before a failed save round-trip.
    // The regex matches the `| risk` COMMAND only: `risk\b` does not match
    // field references like `| where risk_score > 10` (word boundary fails
    // before the underscore).
    if (metadata.dataset === 'risk' && /\|\s*risk\b/.test(actualQuery)) {
      return 'Risk rules query accumulated risk — they cannot contain a `| risk` command (it would feed the rule\'s own input). Remove the `| risk` pipe.';
    }
    if (metadata.lookback) {
      const m = parseLookbackToMinutes(metadata.lookback);
      if (m !== null && m > MAX_LOOKBACK_MINUTES) {
        return 'Lookback cannot exceed 7 days (10080 minutes).';
      }
    }
    return null;
  }, [metadata, actualQuery, titleValid]);

  const buildPayload = useCallback(() => {
    const severity = (metadata.severity || 'medium') as 'critical' | 'high' | 'medium' | 'low';
    const mode = (metadata.mode || 'staging') as 'staging' | 'live' | 'alerting';
    const detectionMode = metadata.detection_mode === 'scheduled' ? 'scheduled' : 'real-time';
    const schedule = metadata.schedule || (detectionMode === 'real-time' ? '*/30 * * * * *' : '');
    const lookbackMinutes = metadata.lookback ? parseLookbackToMinutes(metadata.lookback) : undefined;
    const tags = metadata.tags ? metadata.tags.split(',').map((t) => t.trim()).filter(Boolean) : undefined;
    const mitreTactics = metadata.mitre_tactics
      ? metadata.mitre_tactics.split(',').map((t) => t.trim()).filter(Boolean)
      : undefined;
    const mitreTechniques = metadata.mitre_techniques
      ? metadata.mitre_techniques.split(',').map((t) => t.trim()).filter(Boolean)
      : undefined;
    return {
      name: metadata.title!.trim(),
      description: metadata.description || undefined,
      query: actualQuery,
      severity,
      mode,
      detection_mode: detectionMode as 'scheduled' | 'real-time',
      schedule_cron: schedule || undefined,
      lookback_minutes: lookbackMinutes || undefined,
      // NAN-1561/NAN-1825: send the dataset explicitly whenever the YAML sets
      // one — including 'logs'. Updates are patch-based server-side
      // (COALESCE keeps the stored value when omitted), so omitting 'logs'
      // made it impossible to flip a spans/metrics/risk rule back to logs.
      // Rules whose YAML has no dataset key keep omitting it (unchanged).
      dataset: metadata.dataset || undefined,
      // NAN-1825: mirror the backend feedback-loop guard (NAN-1805). A
      // dataset=risk rule's findings feed the risk dataset itself, so it must
      // not contribute risk: the server requires risk_score EXPLICITLY 0
      // (omitted falls back to a severity-derived nonzero default) and empty
      // risk_modifiers on the effective post-patch rule. Non-risk rules keep
      // omitting both so existing rule-level values are untouched.
      ...(metadata.dataset === 'risk' ? { risk_score: 0, risk_modifiers: [] } : {}),
      narrative: metadata.narrative || undefined,
      author: metadata.author || undefined,
      tags,
      mitre_tactics: mitreTactics,
      mitre_techniques: mitreTechniques,
      reference_url: metadata.reference_url || undefined,
      alert_mode: metadata.alert_mode || undefined,
      // NAN-729: persist folder edits made via the meta-row folder chip
      // (which round-trip through the YAML body) and the YAML editor
      // directly. RuleRail's drag-drop path also writes this field via a
      // separate eager-save, so dropping a value here just keeps the body
      // and column in lock-step on full saves.
      folder: metadata.folder?.trim() || undefined,
      // Explicit form state from the Inspector wins — the YAML ↔ form sync
      // effects upstream keep the two in lock-step. Mirrors legacy.
      playbook_selector_mode: playbookMode,
      playbook_id: playbookMode === 'specific' ? playbookPickId : null,
      // AI triage hints — editable via the Inspector AI tab.
      ai_triage_hints: triageHints,
      // Case-permissions round-trip — editable via the Inspector Cases tab.
      case_visibility: caseVisibility,
      case_group_ids: caseGroupIds,
      case_assigned_group: caseAssignedGroupId,
    };
  }, [
    metadata,
    actualQuery,
    playbookMode,
    playbookPickId,
    triageHints,
    caseVisibility,
    caseGroupIds,
    caseAssignedGroupId,
  ]);

  const handleConfirmSave = useCallback(async () => {
    if (!id) return;
    const err = validateSaveReady();
    if (err) {
      toast.error('Cannot save rule', { description: err });
      return;
    }
    try {
      const payload = buildPayload();
      const result = await updateDetection({ id, data: payload });
      if (result.warning) {
        toast.warning('Rule updated with changes', { description: result.warning, duration: 8000 });
      } else {
        toast.success('Rule updated');
      }
      setSavedContent(editorContent);
      setTriageHintsChanged(false);
      setCaseChanged(false);
      setShowSaveConfirm(false);
      refetchRules();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to update rule.';
      setShowSaveConfirm(false);
      toast.error('Save failed', { description: msg, duration: 10000 });
    }
  }, [id, validateSaveReady, buildPayload, updateDetection, editorContent, refetchRules]);

  const handleConfirmCreate = useCallback(async () => {
    const err = validateSaveReady();
    if (err) {
      toast.error('Cannot create rule', { description: err });
      return;
    }
    try {
      const payload = buildPayload();
      const result = await createDetection(payload);
      if (result.warning) {
        toast.warning('Rule created with changes', { description: result.warning, duration: 8000 });
      } else {
        toast.success('Rule created');
      }
      setSavedContent(editorContent);
      setTriageHintsChanged(false);
      setCaseChanged(false);
      refetchRules();
      navigate(`/rules/editor/${result.id}`, { replace: true });
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to create rule.';
      toast.error('Create failed', { description: msg, duration: 10000 });
    }
  }, [validateSaveReady, buildPayload, createDetection, editorContent, navigate, refetchRules]);

  const handleSave = useCallback(() => {
    if (isNewMode) {
      handleConfirmCreate();
    } else {
      setShowSaveConfirm(true);
    }
  }, [isNewMode, handleConfirmCreate]);

  const handleDiscard = useCallback(() => {
    if (apiRule) setEditorContent(savedContent);
  }, [apiRule, savedContent]);

  const handleFormat = useCallback(async () => {
    if (!actualQuery.trim()) {
      toast.error('Nothing to format', { description: 'Query is empty' });
      return;
    }
    try {
      const result = await formatQuery(actualQuery);
      const next = serializeDetectionMetadata(metadata, result.formatted_query);
      setEditorContent(next);
      toast.success('Query formatted');
    } catch (e: unknown) {
      toast.error('Format failed', { description: e instanceof Error ? e.message : 'Unknown error' });
    }
  }, [actualQuery, metadata, formatQuery]);

  // NAN-729: meta-row folder picker round-trips through the YAML body — the
  // edit becomes part of the editor's dirty state and ships with the next
  // save. Mirrors how every other meta field works (severity, mode, etc.).
  // RuleRail's drag-drop is a separate eager-save path; the two converge on
  // `apiRule.folder` after the next reload.
  const handleFolderChange = useCallback(
    (folder: string) => {
      const next = serializeDetectionMetadata(
        { ...metadata, folder: folder || '' },
        actualQuery,
      );
      setEditorContent(next);
    },
    [metadata, actualQuery],
  );

  // NAN-729: folder choices for the meta-row picker. Canonical five plus any
  // folder currently set on a rule (case-insensitive dedupe so "endpoint" and
  // "Endpoint" don't both show up). Custom folders the picker creates flow
  // through the YAML body; on save they show up in this list automatically.
  const availableFolders = useMemo(() => {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const r of apiRules || []) {
      const f = (r.folder || '').trim();
      if (!f) continue;
      const lower = f.toLowerCase();
      if (seen.has(lower)) continue;
      seen.add(lower);
      out.push(f);
    }
    return out;
  }, [apiRules]);

  const handleDelete = useCallback(async () => {
    if (!id) return;
    try {
      await deleteDetection(id);
      toast.success('Rule deleted');
      setShowDeleteConfirm(false);
      const tpl = createDetectionTemplate(user?.name || '');
      setEditorContent(tpl);
      setSavedContent(tpl);
      refetchRules();
      navigate('/rules/editor/new');
    } catch {
      toast.error('Failed to delete rule');
      setShowDeleteConfirm(false);
    }
  }, [id, deleteDetection, user?.name, refetchRules, navigate]);

  const handleArchive = useCallback(async () => {
    if (!id) return;
    try {
      await updateDetection({ id, data: { archived: true } });
      toast.success('Rule archived');
      refetchRules();
      navigate('/rules/editor/new');
    } catch {
      toast.error('Failed to archive rule');
    }
    setShowArchiveConfirm(false);
  }, [id, updateDetection, refetchRules, navigate]);

  const handleUnarchive = useCallback(async () => {
    if (!id) return;
    try {
      await updateDetection({ id, data: { archived: false, mode: 'staging' } });
      toast.success('Rule unarchived', { description: 'Detection rule moved to staging.' });
      refetchRules();
      refetchRule();
    } catch {
      toast.error('Failed to unarchive rule');
    }
  }, [id, updateDetection, refetchRules, refetchRule]);

  const handleTogglePause = useCallback(async () => {
    if (!id || !apiRule) return;
    try {
      if (apiRule.mode === 'paused') {
        await resumeDetection(id);
        toast.success('Rule resumed');
      } else {
        await pauseDetection(id);
        toast.success('Rule paused');
      }
      refetchRules();
      refetchRule();
    } catch {
      toast.error('Failed to update rule status');
    }
  }, [id, apiRule, pauseDetection, resumeDetection, refetchRules, refetchRule]);

  const handlePromote = useCallback(async () => {
    if (!id || !apiRule) return;
    try {
      const updated = await promoteDetection(id);
      toast.success(`Promoted to ${updated.mode}`);
      refetchRules();
      refetchRule();
    } catch {
      toast.error('Failed to promote rule');
    }
  }, [id, apiRule, promoteDetection, refetchRules, refetchRule]);

  const handleDemote = useCallback(async () => {
    if (!id || !apiRule) return;
    try {
      const updated = await demoteDetection(id);
      toast.success(`Demoted to ${updated.mode}`);
      refetchRules();
      refetchRule();
    } catch {
      toast.error('Failed to demote rule');
    }
  }, [id, apiRule, demoteDetection, refetchRules, refetchRule]);

  const handleOpenTune = useCallback(() => {
    // Route through the PIVT ambient assistant (NAN-407). The PIVT panel
    // listens globally for `pivt:open-tuning-wizard` and drives the
    // meloD tuning flow independently of any editor mount.
    window.dispatchEvent(new CustomEvent('pivt:open-tuning-wizard', { detail: { ruleId: id } }));
    toast.message('AI tuning opened in PIVT', {
      description: 'Press ⌘. to focus the PIVT panel if it collapsed.',
    });
  }, [id]);

  // Rail row actions — act on any rule in the list, not just the focused one.
  // Each short-circuits into the same mutation hooks the topbar uses.
  const railRowActions = useMemo(() => {
    if (!canEdit) return undefined;
    const findRule = (ruleId: string) => apiRules?.find((r) => r.id === ruleId);
    return {
      onViewMatches: (ruleId: string) => navigate(`/rules/${ruleId}/matches`),
      onDuplicate: (ruleId: string) => navigate(`/rules/editor/new?duplicate=${ruleId}`),
      onTogglePause: async (ruleId: string) => {
        const rule = findRule(ruleId);
        if (!rule) return;
        try {
          if (rule.mode === 'paused') {
            await resumeDetection(ruleId);
            toast.success('Rule resumed');
          } else {
            await pauseDetection(ruleId);
            toast.success('Rule paused');
          }
          refetchRules();
          if (ruleId === id) refetchRule();
        } catch {
          toast.error('Failed to update rule status');
        }
      },
      onPromote: async (ruleId: string) => {
        try {
          const updated = await promoteDetection(ruleId);
          toast.success(`Promoted to ${updated.mode}`);
          refetchRules();
          if (ruleId === id) refetchRule();
        } catch {
          toast.error('Failed to promote rule');
        }
      },
      onDemote: async (ruleId: string) => {
        try {
          const updated = await demoteDetection(ruleId);
          toast.success(`Demoted to ${updated.mode}`);
          refetchRules();
          if (ruleId === id) refetchRule();
        } catch {
          toast.error('Failed to demote rule');
        }
      },
      onArchive: async (ruleId: string) => {
        try {
          await updateDetection({ id: ruleId, data: { archived: true } });
          toast.success('Rule archived');
          refetchRules();
          if (ruleId === id) navigate('/rules/editor/new');
        } catch {
          toast.error('Failed to archive rule');
        }
      },
      onUnarchive: async (ruleId: string) => {
        try {
          await updateDetection({ id: ruleId, data: { archived: false, mode: 'staging' } });
          toast.success('Rule unarchived');
          refetchRules();
          if (ruleId === id) refetchRule();
        } catch {
          toast.error('Failed to unarchive rule');
        }
      },
      onDelete: async (ruleId: string) => {
        const rule = findRule(ruleId);
        const name = rule?.name || 'this rule';
        if (!window.confirm(`Delete ${name}? This can't be undone.`)) return;
        try {
          await deleteDetection(ruleId);
          toast.success('Rule deleted');
          refetchRules();
          if (ruleId === id) navigate('/rules/editor/new');
        } catch {
          toast.error('Failed to delete rule');
        }
      },
    };
  }, [
    canEdit,
    apiRules,
    id,
    navigate,
    pauseDetection,
    resumeDetection,
    promoteDetection,
    demoteDetection,
    updateDetection,
    deleteDetection,
    refetchRules,
    refetchRule,
  ]);

  const handleOpenTest = useCallback(() => {
    if (!actualQuery.trim()) {
      toast.error('Nothing to test', { description: 'Query is empty — write one in CODE first.' });
      return;
    }
    setTestDrawerOpen(true);
  }, [actualQuery]);

  const handleViewMode = useCallback((m: ViewMode) => {
    setViewMode(m);
  }, []);

  // Inspector → YAML playbook sync. When the picker changes, we mirror the
  // shorthand into `playbook:` so the CODE / FORM lens shows it in sync. The
  // YAML → picker direction is handled by the `metadata.playbook` effect above.
  const updatePlaybookYaml = useCallback(
    (mode: PlaybookSelectorMode, picked: string | null) => {
      const shorthand = encodePlaybookField(mode, picked);
      const current = metadata.playbook || '';
      if (current === shorthand) return;
      setEditorContent(serializeDetectionMetadata({ ...metadata, playbook: shorthand }, actualQuery));
    },
    [metadata, actualQuery],
  );

  const handlePlaybookModeChange = useCallback(
    (m: PlaybookSelectorMode) => {
      setPlaybookMode(m);
      updatePlaybookYaml(m, m === 'specific' ? playbookPickId : null);
    },
    [updatePlaybookYaml, playbookPickId],
  );

  const handlePlaybookIdChange = useCallback(
    (pid: string | null) => {
      setPlaybookPickId(pid);
      if (playbookMode === 'specific') updatePlaybookYaml('specific', pid);
    },
    [updatePlaybookYaml, playbookMode],
  );

  const handleHintsChange = useCallback((next: AiTriageHints) => {
    setTriageHints(next);
    setTriageHintsChanged(true);
  }, []);

  const handleRunTest = useCallback(async () => {
    try {
      let result: TestDetectionResult;
      if (id && !isNewMode) {
        result = await testDetectionMut({ id, days: 7 });
      } else {
        if (!actualQuery.trim()) {
          toast.error('Query is empty');
          return;
        }
        result = await testQueryMut({ query: actualQuery, days: 7 });
      }
      setLastTest(result);
      if (result.total_matches === 0) {
        toast.message('Test run complete — 0 matches in last 7 days');
      } else {
        toast.success(`Test run complete — ${result.total_matches} match${result.total_matches === 1 ? '' : 'es'}`);
      }
    } catch (e: unknown) {
      toast.error('Test failed', { description: e instanceof Error ? e.message : 'Unknown error' });
    }
  }, [id, isNewMode, actualQuery, testDetectionMut, testQueryMut]);

  const lastSavedLabel = useMemo(() => {
    if (!apiRule?.updated_at) return undefined;
    return relativeTime(apiRule.updated_at);
  }, [apiRule?.updated_at]);

  // Blank-slate conditions — mirror legacy.
  if (ruleLoading && !isNewMode && id) {
    return (
      <div className="h-full flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (id && !apiRule && !ruleLoading && !isNewMode) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-center">
          <ShieldPlus className="w-12 h-12 text-muted-foreground mx-auto mb-4" strokeWidth={1.5} />
          <p className="text-muted-foreground">Rule not found</p>
          <Button variant="outline" onClick={() => navigate('/rules/editor/new')} className="mt-4">
            Create new rule
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="-m-3 h-[calc(100%+1.5rem)] flex min-h-0 min-w-0 overflow-hidden bg-background relative">
      {/* Left rule-picker rail */}
      <div className="w-[260px] shrink-0 min-h-0 hidden md:block">
        <RuleRail
          rules={apiRules || []}
          selectedId={id}
          draft={
            isNewMode
              ? { name: metadata.title || 'Untitled Rule', severity: metadata.severity || 'medium' }
              : null
          }
          draftSelected={isNewMode}
          onSelect={(ruleId) => requestNav(`/rules/editor/${ruleId}`)}
          onCreateNew={() => requestNav('/rules/editor/new')}
          onMoveRule={
            canEdit
              ? async (ruleId, folder) => {
                  try {
                    await updateDetection({ id: ruleId, data: { folder: folder || undefined } });
                    // NAN-729: when the dragged rule is the one currently
                    // open in the editor, splice the new folder into the
                    // YAML body so the next save doesn't clobber the column
                    // we just updated. Other unsaved edits ride through via
                    // the metadata + actualQuery spread.
                    if (ruleId === id) {
                      setEditorContent(
                        serializeDetectionMetadata(
                          { ...metadata, folder: folder || '' },
                          actualQuery,
                        ),
                      );
                    }
                    toast.success(folder ? `Moved to ${folder}` : 'Moved to Uncategorized');
                    refetchRules();
                  } catch {
                    toast.error('Failed to move rule');
                  }
                }
              : undefined
          }
          rowActions={railRowActions}
          loading={rulesLoading}
          folderSettings={folderSettings}
          onSetFolderIcon={
            canEdit
              ? async (name, slug) => {
                  try {
                    if (slug) {
                      await setFolderIconMutation({ name, icon: slug });
                    } else {
                      await clearFolderIconMutation(name);
                    }
                    refetchFolderSettings();
                  } catch {
                    toast.error('Failed to update folder icon');
                  }
                }
              : undefined
          }
        />
      </div>

      {/* Main editor pane. */}
      <div className="flex-1 min-w-0 flex flex-col min-h-0">
        <EditorTopBar
          metadata={metadata}
          isNewMode={isNewMode}
          apiMode={apiRule?.mode}
          archived={apiRule?.archived}
          dirty={hasChanges}
          saving={saving}
          valid={!validation || validation.valid}
          viewMode={viewMode}
          onViewMode={handleViewMode}
          onBack={() => navigate(-1)}
          onSave={handleSave}
          onDiscard={canEdit && !isNewMode ? handleDiscard : undefined}
          onFormat={canEdit ? handleFormat : undefined}
          onOpenTest={handleOpenTest}
          onViewMatches={!isNewMode && id ? () => navigate(`/rules/${id}/matches`) : undefined}
          onDuplicate={!isNewMode && id ? () => navigate(`/rules/editor/new?duplicate=${id}`) : undefined}
          onTogglePause={!isNewMode && id && canEdit ? handleTogglePause : undefined}
          onPromote={!isNewMode && id && canEdit ? handlePromote : undefined}
          onDemote={!isNewMode && id && canEdit ? handleDemote : undefined}
          onArchive={!isNewMode && id && canEdit ? () => setShowArchiveConfirm(true) : undefined}
          onUnarchive={!isNewMode && id && canEdit && apiRule?.archived ? handleUnarchive : undefined}
          onDelete={!isNewMode && id && canEdit ? () => setShowDeleteConfirm(true) : undefined}
          onOpenTune={!isNewMode && id && canEdit ? handleOpenTune : undefined}
          enabledLenses={new Set<ViewMode>(['code', 'flow', 'form'])}
          availableFolders={availableFolders}
          onFolderChange={canEdit ? handleFolderChange : undefined}
          folderSettings={folderSettings}
        />

        <div className="flex-1 min-h-0 flex">
          {viewMode === 'code' && (
            <CodeLens
              ref={editorRef}
              value={editorContent}
              onChange={setEditorContent}
              onValidationChange={setValidation}
              readOnly={!canEdit}
              detectionMode={detectionModeLens}
              validation={validation}
              onOpenValidationDetails={() => setValidationDetailsOpen(true)}
              onFormat={canEdit ? handleFormat : undefined}
            />
          )}
          {viewMode === 'flow' && (
            <FlowLens query={actualQuery} schedule={metadata.schedule} lookback={metadata.lookback} />
          )}
          {viewMode === 'form' && (
            <FormLens value={editorContent} onChange={setEditorContent} readOnly={!canEdit} />
          )}
        </div>

        <BottomTray
          validation={validation}
          matchCount={apiRule?.match_count}
          lastSavedLabel={lastSavedLabel}
          versions={versions}
          dailyStats={id ? detectionStats?.[id] : undefined}
          ruleId={!isNewMode && id && canEdit ? id : undefined}
          readOnly={!canEdit}
          onSwitchToRealtime={realtimeNudgeAvailable ? switchToRealtime : undefined}
          onOpenTest={handleOpenTest}
          onOpenVersion={(v) => {
            setInspectorCollapsed(false);
            setPendingVersionFocusId(v.id);
          }}
        />
      </div>

      <InspectorDrawer
        collapsed={inspectorCollapsed}
        onToggle={() => setInspectorCollapsed((v) => !v)}
        hints={triageHints}
        onHintsChange={handleHintsChange}
        ruleMeta={{
          name: metadata.title,
          description: metadata.description,
          query: actualQuery,
          mitreTactics: metadata.mitre_tactics
            ? metadata.mitre_tactics.split(',').map((s) => s.trim()).filter(Boolean)
            : [],
          mitreTechniques: metadata.mitre_techniques
            ? metadata.mitre_techniques.split(',').map((s) => s.trim()).filter(Boolean)
            : [],
        }}
        melodConnected={melodStatus?.connected}
        playbookMode={playbookMode}
        onPlaybookModeChange={handlePlaybookModeChange}
        playbookId={playbookPickId}
        onPlaybookIdChange={handlePlaybookIdChange}
        ruleId={id}
        readOnly={!canEdit}
        lastTest={lastTest}
        onRunTest={handleRunTest}
        testRunning={testRunningSaved || testRunningUnsaved}
        isUnsaved={isNewMode}
        referenceUrl={metadata.reference_url}
        mitreTactics={
          metadata.mitre_tactics
            ? metadata.mitre_tactics.split(',').map((s) => s.trim()).filter(Boolean)
            : []
        }
        mitreTechniques={
          metadata.mitre_techniques
            ? metadata.mitre_techniques.split(',').map((s) => s.trim()).filter(Boolean)
            : []
        }
        description={metadata.description}
        caseVisibility={caseVisibility}
        caseGroupIds={caseGroupIds}
        caseAssignedGroupId={caseAssignedGroupId}
        onCaseVisibilityChange={(v) => {
          setCaseVisibility(v);
          setCaseChanged(true);
        }}
        onCaseGroupIdsChange={(ids) => {
          setCaseGroupIds(ids);
          setCaseChanged(true);
        }}
        onCaseAssignedGroupChange={(gid) => {
          setCaseAssignedGroupId(gid);
          setCaseChanged(true);
        }}
        currentQuery={actualQuery}
        onVersionReverted={() => {
          refetchRule();
          refetchRules();
        }}
        pendingVersionFocusId={pendingVersionFocusId}
        onPendingVersionConsumed={() => setPendingVersionFocusId(null)}
      />

      {isNewMode && aiPanelOpen && capabilities.melod && (
        <NewRuleAiPanel
          initialNarrative={initialNarrative}
          disabled={!canEdit}
          onClose={() => setAiPanelOpen(false)}
          onApply={(det) => {
            const content = serializeDetectionMetadata(
              {
                title: det.name,
                description: det.description || '',
                author: user?.name || '',
                severity: (det.severity || 'medium') as 'critical' | 'high' | 'medium' | 'low',
                mode: 'staging',
                detection_mode: 'realtime',
                tags: det.tags?.join(', '),
                mitre_tactics: det.mitre_tactics?.join(', '),
                mitre_techniques: det.mitre_techniques?.join(', '),
              },
              det.query,
            );
            setEditorContent(content);
          }}
          onBatchCreate={async (detections: GeneratedDetection[]) => {
            let created = 0;
            const failed: string[] = [];
            for (const det of detections) {
              try {
                await createDetection({
                  name: det.name,
                  description: det.description,
                  query: det.query,
                  severity: (det.severity || 'medium') as 'critical' | 'high' | 'medium' | 'low',
                  mode: 'staging',
                  detection_mode: 'real-time',
                  author: user?.name,
                  tags: det.tags,
                  mitre_tactics: det.mitre_tactics,
                  mitre_techniques: det.mitre_techniques,
                });
                created += 1;
              } catch {
                failed.push(det.name);
              }
            }
            if (created > 0) {
              toast.success(`Created ${created} draft rule${created === 1 ? '' : 's'}`);
              refetchRules();
            }
            if (failed.length > 0) {
              toast.error(`Failed to create ${failed.length} rule${failed.length === 1 ? '' : 's'}`, {
                description: failed.join(', '),
              });
            }
          }}
        />
      )}

      {/* Test drawer — absolute-positioned child of the content row so its
          backdrop dims the rule rail + main pane + inspector, and the
          panel itself slides up from the bottom of the whole row. Mirrors
          `design-ref/shadcn/editor-test-drawer.jsx`. */}
      <TestDrawer
        open={testDrawerOpen}
        onClose={() => setTestDrawerOpen(false)}
        query={actualQuery}
        ruleId={isNewMode ? undefined : id}
        runSavedTest={testDetectionMut}
        runUnsavedTest={testQueryMut}
        onApplyQuery={
          canEdit
            ? (nextQuery) => {
                // Rebuild the document with the drawer's working copy as the
                // new body. The YAML frontmatter carries over unchanged so
                // metadata the analyst set (severity, mode, MITRE, playbook)
                // keeps its edits. UNSAVED pill lights up on next render.
                setEditorContent(serializeDetectionMetadata(metadata, nextQuery));
                toast.success('Applied to editor', {
                  description: 'Switch to CODE or save to persist.',
                });
              }
            : undefined
        }
      />

      <Suspense fallback={null}>
        {/* Reused legacy dialogs — AlertDialog primitives shared with the redesign. */}
        <SaveConfirmDialog
          open={showSaveConfirm}
          onOpenChange={setShowSaveConfirm}
          onConfirm={handleConfirmSave}
          ruleName={metadata.title}
          mode={(metadata.mode || 'staging') as 'staging' | 'live' | 'alerting' | 'paused'}
          loading={updating}
        />
        <DeleteConfirmDialog
          open={showDeleteConfirm}
          onOpenChange={setShowDeleteConfirm}
          onConfirm={handleDelete}
          ruleName={apiRule?.name}
        />
        <ArchiveConfirmDialog
          open={showArchiveConfirm}
          onOpenChange={setShowArchiveConfirm}
          onConfirm={handleArchive}
          ruleName={apiRule?.name}
        />
      </Suspense>

      <ValidationDetailsDialog
        open={validationDetailsOpen}
        onOpenChange={setValidationDetailsOpen}
        validation={validation}
        onRunTest={actualQuery.trim() ? handleOpenTest : undefined}
      />

      {!isNewMode && id && (
        <UpstreamMergeModal
          detectionRuleId={id}
          open={upstreamMergeOpen}
          onOpenChange={setUpstreamMergeOpen}
          diffAccess={upstreamDiffAccess}
          onApplyMerge={(mergedQuery) => {
            const merged = serializeDetectionMetadata(metadata, mergedQuery);
            setEditorContent(merged);
            toast.success('Upstream changes applied', {
              description: 'Review and save to persist the merge.',
            });
          }}
        />
      )}

      <AlertDialog
        open={pendingNavPath !== null}
        onOpenChange={(open) => {
          if (!open) setPendingNavPath(null);
        }}
      >
        <AlertDialogContent className="max-w-md gap-0 p-0 bg-card border-border text-foreground">
          <AlertDialogHeader className="border-b border-border px-5 py-4">
            <AlertDialogTitle className="text-[14px] font-semibold">
              Discard unsaved changes?
            </AlertDialogTitle>
            <AlertDialogDescription className="font-mono text-[11px] text-muted-foreground leading-relaxed">
              You have unsaved edits on this rule. Leaving the editor now will lose them.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter className="border-t border-border px-5 py-3">
            <AlertDialogCancel
              className="h-8 text-[11.5px] bg-accent/50 border-border text-foreground hover:bg-accent"
              onClick={() => setPendingNavPath(null)}
            >
              Keep editing
            </AlertDialogCancel>
            <AlertDialogAction
              className="h-8 text-[11.5px]"
              onClick={() => {
                const target = pendingNavPath;
                setPendingNavPath(null);
                if (target) navigate(target);
              }}
            >
              Discard and leave
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

// Short relative-time helper for version history + "last saved" labels. Good
// enough for the tray; we can pull in date-fns if we need locale variance.
function relativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const diffMs = Date.now() - then;
  const sec = Math.max(1, Math.floor(diffMs / 1000));
  if (sec < 60) return 'just now';
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day < 30) return `${day}d ago`;
  const mo = Math.floor(day / 30);
  if (mo < 12) return `${mo}mo ago`;
  return `${Math.floor(mo / 12)}y ago`;
}
