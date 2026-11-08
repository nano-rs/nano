// SPDX-License-Identifier: AGPL-3.0-or-later

// Nano Pipe workspace state (NAN-4919; ported from main NAN-3418/3447/3452).
//
// Save / publish / history / rollback use the existing log-source endpoints;
// the plan is just the source's `parser_vrl`. Preview, recent samples and the
// live tap use the pipe endpoints. Events (tapped, loaded, pasted) live in
// this hook's memory only and are never persisted.

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { api as browserApi } from '@/lib/api';
import {
  draftFingerprint, draftFromSource, enabledKinds, parsePipelinePlan, pastedSampleEvents, pipelineDraftRecovery,
  pipelineDraftRecoveryKey, recentSampleEvents, releasesFromVersions, routeInputsOfDraft, serializePipeline,
  summaryFromSource, supportedStepKinds, tapEvents, withoutPreviewBoilerplate, MAX_PIPE_STEPS,
  type PipelineDraftRecovery,
} from '@/lib/pipeline-model';
import type {
  CapturedEvent, PipelineCapabilities, PipelineConflict, PipelineDraft, PipelineOperation, PipelineOperationErrors,
  PipelinePreview, PipelineReleasePlan, PipelineSample, PipelineStepKind, PipelineTap, PipelineTapOptions,
  PipelineValidation, PreviewOnlyKind,
} from '@/lib/pipeline-types';
import {
  assertPublicationSnapshot, boundedTapRequest, newerThanSnapshot, pipeAborted, pipeBusy, pipeConflict,
  pipeEndpointMissing, pipeErrorStatus, pipeEventAccessDenied, pipeRetryAfter, pipeUnavailable, publicationSnapshot,
  samePublicationSnapshot, DEFAULT_RECENT_EVENTS, MAX_RECENT_EVENTS, PipeSnapshotConflictError, TAP_MAX_EVENTS,
  TAP_MAX_SECONDS, type PipePreviewRequest, type PipePublicationSnapshot,
} from '@/lib/api/pipelines';
import type { LogSource, LogSourceWithDraftStatus } from '@/lib/api/types';

export type PipelineTransport = Pick<typeof browserApi,
  'pipelines' | 'getLogSourceDraftStatus' | 'getLogSourceVersions' | 'updateLogSource' | 'validateLogSourceVrl'
  | 'publishLogSource' | 'revertLogSourceVersion' | 'deployLogSource' | 'discardLogSourceDraft'>;

const MUTATIONS = new Set<string>(['save', 'publish', 'rollback', 'discard', 'reload']);
export const CONFLICT_MESSAGE = 'This pipeline was changed on the server after you loaded it (another editor, the API, or Log Sources). Saving and publishing are blocked until you choose how to continue.';
export const REVIEW_STALE_MESSAGE = 'The saved draft changed after you reviewed it. Nothing was published. Close this review and review the latest saved draft again.';
const errorMessage = (cause: unknown) => cause instanceof Error ? cause.message : String(cause);

// Preview request bounds (server: 100 events, 64 KiB per event, 1 MiB per request).
const PREVIEW_MAX_EVENTS = 100;
const PREVIEW_MAX_EVENT_BYTES = 64 * 1024;
const PREVIEW_MAX_REQUEST_BYTES = 1024 * 1024;
const PREVIEW_DEBOUNCE_MS = 450;

/** Retry text for a 429; never auto-queued. */
export function busyMessage(what: string, retryAfter: number | undefined): string {
  return retryAfter !== undefined ? `${what} is busy. Retry in ${Math.max(1, Math.ceil(retryAfter))}s.` : `${what} is busy. Retry in a few seconds.`;
}

/**
 * Per-event inputs for the preview. An explicit "preview as input" choice
 * applies to every event; otherwise each event keeps the input the tap
 * recorded. Omitted when no event has one.
 */
export function previewEventInputs(events: readonly Pick<CapturedEvent, 'nanoInput'>[], override: string | null): Array<string | null> | undefined {
  const inputs = events.map((event) => override ?? event.nanoInput ?? null);
  return inputs.some((input) => input !== null) ? inputs : undefined;
}

/** The preview request for a draft over a sample, kept inside the server bounds. */
export function boundedPreviewRequest(parserVrl: string, sample: PipelineSample, previewInput: string | null = null) {
  const encoder = new TextEncoder();
  const byteLength = (value: string) => encoder.encode(value).byteLength;
  const warnings: string[] = [];
  const request: PipePreviewRequest = { parser_vrl: parserVrl, events: [] };
  let requestBytes = byteLength(JSON.stringify(request));
  if (requestBytes >= PREVIEW_MAX_REQUEST_BYTES) throw new Error('The draft exceeds the 1 MiB preview request limit before any input can fit. Reduce its size before previewing.');
  if (previewInput !== null || sample.events.some((event) => event.nanoInput)) requestBytes += 20 + 48 * Math.min(sample.events.length, PREVIEW_MAX_EVENTS);
  const selected: CapturedEvent[] = [];
  for (const event of sample.events.slice(0, PREVIEW_MAX_EVENTS)) {
    if (!event.input || typeof event.input !== 'object' || Array.isArray(event.input)) throw new Error(`Sample event ${selected.length + 1} is not a JSON object.`);
    const eventBytes = byteLength(JSON.stringify(event.input));
    if (eventBytes > PREVIEW_MAX_EVENT_BYTES) throw new Error(`Sample event ${selected.length + 1} exceeds the 64 KiB preview event limit. Choose a smaller sample.`);
    const additional = eventBytes + (selected.length > 0 ? 1 : 0);
    if (requestBytes + additional > PREVIEW_MAX_REQUEST_BYTES) break;
    request.events.push(event.input);
    selected.push(event);
    requestBytes += additional;
  }
  if (selected.length === 0) throw new Error('The first input event cannot fit within the 1 MiB preview request limit with this draft.');
  const inputs = previewEventInputs(selected, previewInput);
  if (inputs) request.inputs = inputs;
  if (selected.length < sample.events.length) warnings.push(`Preview evaluates the first ${selected.length} of ${sample.events.length} input events to stay within the 100-event and 1 MiB request limits. Remaining inputs were not previewed; they are not dropped events.`);
  return { request, selected, warnings };
}

/** Enabled kinds in `steps` that this deployment previews but refuses to publish. */
export function previewOnlyInUse(steps: PipelineDraft['steps'], previewOnly: readonly PreviewOnlyKind[]): PreviewOnlyKind[] {
  const kinds = new Set(enabledKinds(steps));
  return previewOnly.filter((entry) => kinds.has(entry.kind));
}

/** Host supplies authenticated transport and scope; no browser HTTP or auth context. */
export function usePipelineWorkspaceCore(sourceId: string, { api, hasPermission, scope, toast }: {
  api: PipelineTransport;
  hasPermission: (permission: string) => boolean;
  scope: string;
  toast: (notice: { title: string; description: string; variant?: 'default' | 'destructive' }) => void;
}) {
  const queryClient = useQueryClient();
  const [eventAccessRevoked, setEventAccessRevoked] = useState(false);
  const eventAccessRevokedRef = useRef(false);
  const permissions = {
    view: hasPermission('log_sources:view'),
    edit: hasPermission('log_sources:edit'),
    events: hasPermission('search:execute') && !eventAccessRevoked,
    release: hasPermission('log_sources:deploy'),
  };
  const sourceKey = useMemo(() => ['pipe-source', scope, sourceId], [scope, sourceId]);
  const sourceQuery = useQuery({ queryKey: sourceKey, queryFn: () => api.getLogSourceDraftStatus(sourceId), enabled: !!sourceId && permissions.view });
  const runtimeQuery = useQuery({
    queryKey: ['pipe-capabilities', scope, sourceId], queryFn: () => api.pipelines.capabilities(sourceId),
    enabled: !!sourceId && permissions.view,
    // A 404 means this backend predates the pipe endpoints; retrying cannot change that.
    retry: (failures, cause) => !pipeEndpointMissing(cause) && !pipeEventAccessDenied(cause) && failures < 2,
  });
  const versionsQuery = useQuery({ queryKey: ['pipe-versions', scope, sourceId], queryFn: () => api.getLogSourceVersions(sourceId), enabled: !!sourceId && permissions.view });

  const recovered = useRef(queryClient.getQueryData<PipelineDraftRecovery>(pipelineDraftRecoveryKey(scope, sourceId))).current;
  const [draft, setDraft] = useState<PipelineDraft | null>(recovered?.draft ?? null);
  const [savedFingerprint, setSavedFingerprint] = useState(recovered?.savedFingerprint ?? '');
  const [tap, setTap] = useState<PipelineTap>({ state: 'ready', events: [] });
  const [sample, setSample] = useState<PipelineSample | null>(null);
  const [previewPending, setPreviewPending] = useState(false);
  const [preview, setPreview] = useState<PipelinePreview | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  /** 429: auto-preview pauses until this time (ms epoch); manual runs still go through. */
  const [previewRetryAt, setPreviewRetryAt] = useState<number | null>(null);
  const [previewDisabledByServer, setPreviewDisabledByServer] = useState(false);
  const [previewInput, setPreviewInput] = useState<string | null>(null);
  const [validation, setValidation] = useState<PipelineValidation | null>(null);
  const [plan, setPlan] = useState<PipelineReleasePlan | null>(null);
  const [busy, setBusy] = useState<PipelineOperation | null>(null);
  const [sampleNotice, setSampleNotice] = useState<string | null>(null);
  const [errors, setErrors] = useState<PipelineOperationErrors>({});
  const [conflict, setConflict] = useState<PipelineConflict | null>(null);
  const mutatingRef = useRef(false);
  const requestSeq = useRef(0);
  const previewAbortRef = useRef<AbortController | null>(null);
  const tapAbortRef = useRef<AbortController | null>(null);
  const alive = useRef(true);
  const draftRef = useRef(draft);
  const sourceRef = useRef(sourceQuery.data);
  const savedSourceSnapshotRef = useRef<PipePublicationSnapshot | null>(recovered?.sourceSnapshot ?? null);
  const savedFingerprintRef = useRef(savedFingerprint);
  draftRef.current = draft;
  sourceRef.current = sourceQuery.data;
  savedFingerprintRef.current = savedFingerprint;

  const setOperationError = useCallback((operation: PipelineOperation, message: string | null) => setErrors((previous) => {
    if ((previous[operation] ?? null) === message) return previous;
    const next = { ...previous };
    if (message === null) delete next[operation]; else next[operation] = message;
    return next;
  }), []);

  const rememberDraft = useCallback((current: PipelineDraft, saved: string, baseline: PipePublicationSnapshot) => {
    const key = pipelineDraftRecoveryKey(scope, sourceId);
    if (draftFingerprint(current) === saved) { queryClient.removeQueries({ queryKey: key, exact: true }); return; }
    // In-memory only (the query client); survives in-app navigation, never reaches disk.
    queryClient.setQueryDefaults(key, { gcTime: Infinity });
    queryClient.setQueryData(key, pipelineDraftRecovery(current, saved, baseline));
  }, [queryClient, scope, sourceId]);
  const forgetDraft = useCallback(() => queryClient.removeQueries({ queryKey: pipelineDraftRecoveryKey(scope, sourceId), exact: true }), [queryClient, scope, sourceId]);
  /** Replace the local draft and its CAS baseline with a server copy. Discards local edits. */
  const adoptSource = useCallback((source: LogSource) => {
    const next = draftFromSource(source);
    const fingerprint = draftFingerprint(next);
    const baseline = publicationSnapshot(source);
    draftRef.current = next; savedFingerprintRef.current = fingerprint; savedSourceSnapshotRef.current = baseline;
    setDraft(next); setSavedFingerprint(fingerprint); setConflict(null); setPlan(null); setValidation(null);
    setPreview((previous) => previous ? { ...previous, stale: true } : null);
    setErrors((previous) => { const rest = { ...previous }; // A refused publish stays visible after the editor follows the newer server copy.
    for (const key of ['save', 'validate', 'review'] as const) delete rest[key]; return rest; });
    rememberDraft(next, fingerprint, baseline);
  }, [rememberDraft]);
  const revokeEventAccess = useCallback(() => {
    eventAccessRevokedRef.current = true;
    tapAbortRef.current?.abort();
    setEventAccessRevoked(true);
    setTap({ state: 'forbidden', events: [], reason: 'Source event access is no longer permitted. Reload after access is restored.' });
    setSample((current) => current && current.origin !== 'pasted' ? null : current);
  }, []);

  useEffect(() => {
    if (!draft && sourceQuery.data) {
      const initial = draftFromSource(sourceQuery.data);
      setDraft(initial);
      setSavedFingerprint(draftFingerprint(initial));
      savedSourceSnapshotRef.current = publicationSnapshot(sourceQuery.data);
    }
  }, [sourceQuery.data, draft]);
  // Reconcile with server writes made elsewhere. A pristine editor follows the
  // server; an edited one gets an explicit conflict instead of a Save that can
  // only fail. Our own in-flight writes are skipped until they record their baseline.
  useEffect(() => {
    const fresh = sourceQuery.data;
    const baseline = savedSourceSnapshotRef.current;
    if (!fresh || !draft || !baseline || (busy && MUTATIONS.has(busy)) || mutatingRef.current || !newerThanSnapshot(baseline, fresh)) return;
    const recorded = queryClient.getQueryData<PipelineDraftRecovery>(pipelineDraftRecoveryKey(scope, sourceId));
    if (recorded && samePublicationSnapshot(recorded.sourceSnapshot, publicationSnapshot(fresh))) {
      savedSourceSnapshotRef.current = recorded.sourceSnapshot; savedFingerprintRef.current = recorded.savedFingerprint;
      setSavedFingerprint(recorded.savedFingerprint);
      return;
    }
    if (draftFingerprint(draft) === savedFingerprint) adoptSource(fresh);
    else setConflict((previous) => previous ?? { operation: 'remote', message: CONFLICT_MESSAGE });
  }, [sourceQuery.data, draft, savedFingerprint, busy, adoptSource, queryClient, scope, sourceId]);
  useEffect(() => {
    alive.current = true;
    const sequence = requestSeq;
    const previewController = previewAbortRef;
    const tapController = tapAbortRef;
    return () => {
      alive.current = false;
      sequence.current++;
      previewController.current?.abort();
      tapController.current?.abort();
    };
  }, [sourceId]);

  const perform = useCallback(async <T,>(action: PipelineOperation, operation: () => Promise<T>): Promise<T | undefined> => {
    setBusy(action); setOperationError(action, null);
    if (MUTATIONS.has(action)) mutatingRef.current = true;
    try { return await operation(); }
    catch (cause) {
      if (alive.current) {
        if (pipeConflict(cause) && (action === 'save' || action === 'publish' || action === 'discard')) {
          setConflict({ operation: action === 'discard' ? 'remote' : action, message: CONFLICT_MESSAGE });
          // Learn the newer server draft so the banner's choices act on what is really there.
          void queryClient.invalidateQueries({ queryKey: sourceKey, exact: true });
        }
        setOperationError(action, errorMessage(cause));
      }
      return undefined;
    } finally { if (MUTATIONS.has(action)) mutatingRef.current = false; if (alive.current) setBusy(null); }
  }, [setOperationError, queryClient, sourceKey]);

  const source = sourceQuery.data;
  const runtime = runtimeQuery.data;
  const runtimeNotAvailable = pipeEndpointMissing(runtimeQuery.error);
  const capabilitiesError = runtimeQuery.error && !runtimeNotAvailable ? `Pipeline capabilities could not be loaded: ${runtimeQuery.error.message}` : null;
  const previewOff = runtime?.preview_enabled === false || previewDisabledByServer;
  const previewOnly: PreviewOnlyKind[] = useMemo(() => (runtime?.preview_only_kinds ?? [])
    .filter((entry): entry is { kind: PipelineStepKind; reason: string } => supportedStepKinds([entry.kind]).includes(entry.kind as PipelineStepKind))
    .map((entry) => ({ kind: entry.kind, reason: entry.reason })), [runtime]);
  const capabilities: PipelineCapabilities = {
    supportedSteps: runtime ? supportedStepKinds(runtime.step_kinds) : [],
    previewOnly,
    preview: !!runtime && !previewOff,
    previewDegraded: !!runtime?.preview_degraded_isolation,
    previewReason: previewOff ? 'Draft preview is not enabled on this deployment (NANO_PIPE_PREVIEW_ENABLED). You can still edit, save, and publish.'
      : runtimeNotAvailable ? 'This API does not serve pipeline preview yet. You can still edit, save, and publish.'
        : capabilitiesError ? 'Preview is unavailable because pipeline capabilities could not be loaded.'
          : runtime ? undefined : 'Loading pipeline capabilities.',
    tap: {
      available: !!runtime?.live_tap_enabled,
      reason: runtime && !runtime.live_tap_enabled ? 'Live tap is not configured on this deployment. Load recent events or paste a sample instead.'
        : runtimeNotAvailable ? 'This API does not serve live tap yet.' : undefined,
      maxEvents: TAP_MAX_EVENTS, maxSeconds: TAP_MAX_SECONDS,
    },
    runtime: runtime ? 'ready' : runtimeNotAvailable ? 'not_available' : capabilitiesError ? 'error' : 'loading',
    maxSteps: runtime?.bounds.max_steps ?? MAX_PIPE_STEPS,
    ai: false,
  };
  const releases = useMemo(() => releasesFromVersions(versionsQuery.data), [versionsQuery.data]);
  const activeVersion = (versionsQuery.data ?? []).find((version) => version.is_active);
  const activeRevision = source?.active_version_number ?? activeVersion?.version_number ?? null;
  const pipeline = source ? summaryFromSource(source, activeRevision, source.has_draft_changes) : null;

  const changeDraft = (next: PipelineDraft) => {
    if (!permissions.edit) return;
    const updated = { ...next, revision: (draftRef.current?.revision ?? next.revision) + 1 };
    draftRef.current = updated;
    setDraft(updated); setValidation(null); setPlan(null); setOperationError('validate', null); setOperationError('review', null);
    setPreview((previous) => previous ? { ...previous, stale: true } : null);
    requestSeq.current++; setPreviewPending(false);
    if (savedSourceSnapshotRef.current) rememberDraft(updated, savedFingerprintRef.current, savedSourceSnapshotRef.current);
  };

  const save = async () => perform('save', async () => {
    const current = draftRef.current;
    if (!permissions.edit || !current || !sourceRef.current) throw new Error('Pipeline editing is not permitted.');
    const fingerprint = draftFingerprint(current);
    const baseline = savedSourceSnapshotRef.current;
    if (!baseline) throw new Error('Load the source before saving.');
    const saved = await api.updateLogSource(sourceId, { parser_vrl: serializePipeline(current), expected_updated_at: baseline.expectedUpdatedAt });
    const savedBaseline = publicationSnapshot(saved);
    // Record before the unmount check: the server has already advanced updated_at.
    savedSourceSnapshotRef.current = savedBaseline; savedFingerprintRef.current = fingerprint;
    const key = pipelineDraftRecoveryKey(scope, sourceId);
    const latest = queryClient.getQueryData<PipelineDraftRecovery>(key)?.draft ?? draftRef.current ?? current;
    rememberDraft(latest, fingerprint, savedBaseline);
    void queryClient.invalidateQueries({ queryKey: ['pipe-sources'] });
    if (!alive.current) { void queryClient.invalidateQueries({ queryKey: sourceKey, exact: true }); return; }
    setSavedFingerprint(fingerprint); setConflict(null);
    await sourceQuery.refetch();
    toast({ title: 'Draft saved', description: 'Production keeps running the active version until you publish.' });
  });

  const validateSource = async (parserVrl: string, extension: string | null): Promise<PipelineValidation> => {
    const [parserResult, extensionResult] = await Promise.all([
      api.validateLogSourceVrl(parserVrl),
      extension ? api.validateLogSourceVrl(extension) : Promise.resolve(null),
    ]);
    return {
      valid: parserResult.valid && (!extensionResult || extensionResult.valid),
      errors: [...parserResult.errors, ...(extensionResult?.errors.map((finding) => `Source extension: ${finding}`) ?? [])],
      warnings: extension ? ['The source extension runs after your steps as a separate program.'] : [],
    };
  };
  const validate = async (): Promise<PipelineValidation | undefined> => perform('validate', async () => {
    const current = draftRef.current;
    if (!current) throw new Error('Load a pipeline first.');
    const fingerprint = draftFingerprint(current);
    const extension = sourceRef.current?.extension_enabled !== false ? sourceRef.current?.extension_vrl?.trim() || null : null;
    const checked = await validateSource(serializePipeline(current), extension);
    const inUse = previewOnlyInUse(current.steps, previewOnly);
    if (inUse.length) checked.warnings.unshift(...inUse.map((entry) => `${entry.kind} previews but cannot be published on this deployment: ${entry.reason}`));
    if (alive.current && draftRef.current && fingerprint === draftFingerprint(draftRef.current)) setValidation(checked);
    return checked;
  });

  const runPreview = useCallback(async () => {
    const current = draftRef.current;
    if (!current || !sample || !permissions.edit || previewOff || runtimeNotAvailable) return;
    previewAbortRef.current?.abort();
    const controller = new AbortController();
    previewAbortRef.current = controller;
    const seq = ++requestSeq.current;
    const fingerprint = draftFingerprint(current);
    setPreviewPending(true);
    try {
      const bounded = boundedPreviewRequest(serializePipeline(current), sample, previewInput);
      const result = await api.pipelines.preview(sourceId, bounded.request, controller.signal);
      if (!alive.current || seq !== requestSeq.current || !draftRef.current || draftFingerprint(draftRef.current) !== fingerprint) return;
      setPreview({
        warnings: [...bounded.warnings, ...withoutPreviewBoilerplate(result.warnings)], revision: current.revision, fingerprint, stale: false,
        engine: result.engine, degraded: result.degraded_isolation,
        summary: {
          inputEvents: result.summary.input_events, outputEvents: result.summary.output_events, droppedEvents: result.summary.dropped_events,
          errorEvents: result.summary.error_events, inputBytes: result.summary.input_bytes, outputBytes: result.summary.output_bytes,
        },
        events: result.results.map((row) => ({
          inputId: bounded.selected[row.index]?.id ?? String(row.index), input: bounded.selected[row.index]?.input,
          outputs: row.outputs ?? [], outcome: row.disposition, error: row.error ?? undefined,
          trace: (row.traces ?? []).map((step) => ({ stepId: step.step_id, outputs: step.outputs ?? [], error: step.error ?? undefined, bypassed: step.bypassed })),
        })),
      });
      setPreviewError(null); setPreviewRetryAt(null);
    } catch (cause) {
      if (!alive.current || pipeAborted(cause)) return;
      if (pipeUnavailable(cause) && /not enabled|disabled/i.test(errorMessage(cause))) { setPreviewDisabledByServer(true); setPreviewError(null); setPreview(null); return; }
      if (seq === requestSeq.current) {
        if (pipeBusy(cause)) {
          const retryAfter = pipeRetryAfter(cause);
          setPreviewRetryAt(Date.now() + (retryAfter ?? 5) * 1000);
          setPreviewError(busyMessage('Preview', retryAfter));
        } else setPreviewError(errorMessage(cause));
        setPreview((previous) => previous ? { ...previous, stale: true } : null);
      }
    } finally { if (alive.current && seq === requestSeq.current) setPreviewPending(false); }
  }, [api, sourceId, sample, permissions.edit, previewOff, runtimeNotAvailable, previewInput]);
  // Re-run on draft/sample edits, except while a 429 asked us to back off.
  useEffect(() => {
    if (!draft || !sample || !capabilities.preview) return;
    if (previewRetryAt !== null && Date.now() < previewRetryAt) return;
    const timer = setTimeout(() => { void runPreview(); }, PREVIEW_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [draft, sample, runPreview, capabilities.preview, previewRetryAt]);

  const selectSample = (next: PipelineSample) => {
    requestSeq.current++;
    setPlan(null); setPreview(null); setSampleNotice(null); setOperationError('load', null); setPreviewRetryAt(null);
    setSample(next);
  };

  /** Live tap: one blocking call for the capture window. Cancel aborts it. */
  const startTap = async (options: PipelineTapOptions) => {
    if (!permissions.events || eventAccessRevokedRef.current) { setTap({ state: 'forbidden', events: [] }); return; }
    if (!capabilities.tap.available) { setTap({ state: 'unavailable', events: [], reason: capabilities.tap.reason }); return; }
    let request: ReturnType<typeof boundedTapRequest>;
    try { request = boundedTapRequest(options.seconds, options.maxEvents); }
    catch (cause) { setTap({ state: 'failed', events: [], reason: errorMessage(cause) }); return; }
    tapAbortRef.current?.abort();
    const controller = new AbortController();
    tapAbortRef.current = controller;
    setOperationError('tap', null);
    setTap({ state: 'capturing', events: [], seconds: request.seconds, startedAt: Date.now() });
    try {
      const result = await api.pipelines.tap(sourceId, request, controller.signal);
      if (!alive.current || controller.signal.aborted) return;
      const events = tapEvents(result.events);
      setTap({ state: events.length ? 'completed' : 'no_traffic', events, seconds: result.seconds, ended: result.ended, droppedOversize: result.dropped_oversize, component: result.component });
    } catch (cause) {
      if (!alive.current) return;
      if (controller.signal.aborted || pipeAborted(cause)) { setTap((previous) => previous.state === 'forbidden' ? previous : { state: 'cancelled', events: [] }); return; }
      if (pipeEventAccessDenied(cause)) { revokeEventAccess(); return; }
      if (pipeBusy(cause)) { const retryAfter = pipeRetryAfter(cause); setTap({ state: 'busy', events: [], retryAfter, reason: busyMessage('Live tap', retryAfter) }); return; }
      if (pipeUnavailable(cause)) { setTap({ state: 'unavailable', events: [], reason: errorMessage(cause) }); return; }
      setTap({ state: 'failed', events: [], reason: errorMessage(cause) });
    } finally { if (tapAbortRef.current === controller) tapAbortRef.current = null; }
  };
  const cancelTap = () => { tapAbortRef.current?.abort(); };
  /** Use the tapped events as the preview input (browser memory only). */
  const previewTapEvents = () => {
    if (!tap.events.length) return;
    selectSample({ id: `tap-${Date.now()}`, name: `Live tap · ${tap.events.length}`, origin: 'tap', events: structuredClone(tap.events) });
  };

  /** Recent stored events of this source, through the audited pipe-samples read. */
  const loadRecentEvents = async (limit: number = DEFAULT_RECENT_EVENTS) => perform('load', async () => {
    if (!permissions.events || eventAccessRevokedRef.current) throw new Error('Reading source events requires search:execute.');
    if (!Number.isInteger(limit) || limit < 1 || limit > MAX_RECENT_EVENTS) throw new Error(`Load 1–${MAX_RECENT_EVENTS} recent events.`);
    setSampleNotice(null);
    // A sample chosen or pasted while this read runs wins over its result.
    const seq = requestSeq.current;
    let response;
    try { response = await api.pipelines.samples(sourceId, limit); }
    catch (cause) {
      if (pipeEventAccessDenied(cause)) { revokeEventAccess(); throw cause; }
      if (pipeErrorStatus(cause) === 404) { if (alive.current) setSampleNotice('No recent stored events for this source. Paste a sample or capture a live tap.'); return; }
      throw cause;
    }
    if (!alive.current || eventAccessRevokedRef.current || seq !== requestSeq.current) return;
    const events = recentSampleEvents(response.events, limit);
    if (!events.length) { setSampleNotice('No recent stored events for this source. Paste a sample or capture a live tap.'); return; }
    selectSample({ id: `recent-${Date.now()}`, name: `Recent events · ${events.length}`, origin: 'recent', events });
  });
  /** Pasted raw events; browser memory only. Throws on unusable text. */
  const pasteSample = (text: string) => {
    const events = pastedSampleEvents(text);
    selectSample({ id: `pasted-${Date.now()}`, name: `Pasted sample · ${events.length}`, origin: 'pasted', events });
  };

  /**
   * Freeze exactly what Publish will send: the saved row (parser + extension +
   * updated_at) as it is on the server now, matched against this editor's save
   * baseline, then validated. Nothing typed after this point can reach publish.
   */
  const review = async () => {
    const current = draftRef.current;
    setOperationError('review', null);
    const fail = (cause: unknown) => {
      if (!alive.current) return;
      if (pipeConflict(cause)) setConflict({ operation: 'review', message: CONFLICT_MESSAGE });
      setOperationError('review', errorMessage(cause));
    };
    if (!current || draftFingerprint(current) !== savedFingerprintRef.current) { fail('Save this draft before reviewing a release.'); return; }
    const baseline = savedSourceSnapshotRef.current;
    if (!baseline) return;
    setBusy('review');
    try {
      const fresh = await api.getLogSourceDraftStatus(sourceId);
      assertPublicationSnapshot(baseline, fresh);
      const snapshot = publicationSnapshot(fresh);
      const extension = snapshot.extensionEnabled ? snapshot.extensionVrl?.trim() || null : null;
      const checked = await validateSource(snapshot.parserVrl, extension);
      if (!alive.current || !draftRef.current || draftFingerprint(current) !== draftFingerprint(draftRef.current)) return;
      const steps = parsePipelinePlan(snapshot.parserVrl)?.steps ?? [];
      const inUse = previewOnlyInUse(steps, previewOnly);
      setPlan(Object.freeze({
        snapshot, fingerprint: draftFingerprint(current), revision: current.revision, validation: checked, steps,
        activeVrl: activeParserVrl(fresh), activeVersion: fresh.active_version_number ?? null, previewOnly: inUse,
      }));
    } catch (cause) { fail(cause); }
    finally { if (alive.current) setBusy(null); }
  };
  const activeParserVrl = (fresh: LogSourceWithDraftStatus) => {
    const active = (versionsQuery.data ?? []).find((version) => version.is_active);
    const parser = fresh.active_parser_vrl ?? active?.parser_vrl ?? '';
    const ext = active?.extension_vrl && active.extension_enabled !== false ? active.extension_vrl : null;
    return [parser, ...(ext ? ['# Source extension (separate program)', ext] : [])].join('\n\n');
  };
  const planStale = !!plan && (!source || !samePublicationSnapshot(plan.snapshot, publicationSnapshot(source)));

  /**
   * Publish the reviewed snapshot. The publish endpoint publishes the saved
   * working copy, so first re-read it: if anything moved since review
   * (updated_at, parser, extension), refuse and ask for a new review.
   */
  const publish = async () => perform('publish', async () => {
    const current = draftRef.current;
    if (!permissions.release || !plan || !plan.validation.valid || planStale) throw new Error('Review and validate the saved draft before publishing.');
    if (current && draftFingerprint(current) !== plan.fingerprint) throw new PipeSnapshotConflictError(REVIEW_STALE_MESSAGE);
    const fresh = await api.getLogSourceDraftStatus(sourceId);
    try { assertPublicationSnapshot(plan.snapshot, fresh); }
    catch { throw new PipeSnapshotConflictError(REVIEW_STALE_MESSAGE); }
    // Server-side CAS: publishes exactly the reviewed revision or 409s.
    const result = await api.publishLogSource(sourceId, plan.snapshot.expectedUpdatedAt);
    if (!result.success) throw new Error(result.message || 'Publication was refused.');
    if (!alive.current) { void queryClient.invalidateQueries({ queryKey: sourceKey, exact: true }); return; }
    setPlan(null);
    const [refreshed] = await Promise.all([sourceQuery.refetch(), versionsQuery.refetch()]);
    if (alive.current && refreshed.data && draftRef.current && draftFingerprint(draftRef.current) === plan.fingerprint) adoptSource(refreshed.data);
    void queryClient.invalidateQueries({ queryKey: ['pipe-sources'] });
    toast({ title: 'Published', description: result.message || 'The reviewed pipeline is the active version.' });
  });

  /**
   * Rollback (revert) rewrites the source to the selected version, replacing
   * any saved-but-unpublished draft and this editor's unsaved edits. Refused
   * unless the caller confirmed exactly the local state it replaces.
   */
  const rollback = async (versionId: number, confirmed: { unsavedEdits: boolean }) => perform('rollback', async () => {
    if (!permissions.release) throw new Error('Rollback requires log_sources:deploy.');
    const current = draftRef.current;
    const unsaved = !!current && draftFingerprint(current) !== savedFingerprintRef.current;
    if (unsaved && !confirmed.unsavedEdits) throw new Error('This editor has unsaved edits that rollback would replace. Review the rollback warning and confirm again.');
    const reverted = await api.revertLogSourceVersion(sourceId, versionId);
    // Revert records the version and resets the working copy but does not
    // deploy; deploy so Vector actually runs the restored version.
    let deployed: Awaited<ReturnType<PipelineTransport['deployLogSource']>> | null = null;
    let deployError: string | null = null;
    try { deployed = await api.deployLogSource(sourceId); } catch (cause) { deployError = errorMessage(cause); }
    forgetDraft();
    void queryClient.invalidateQueries({ queryKey: ['pipe-sources'] });
    if (!alive.current) { void queryClient.invalidateQueries({ queryKey: sourceKey, exact: true }); return; }
    setPlan(null); setValidation(null); setPreview(null);
    const [refreshed] = await Promise.all([sourceQuery.refetch(), versionsQuery.refetch()]);
    if (alive.current && refreshed.data) adoptSource(refreshed.data);
    void versionsQuery.refetch();
    if (deployError || (deployed && !deployed.success)) {
      const message = `Version ${reverted.version_number} is active, but deploying it failed: ${deployError ?? deployed?.message ?? 'unknown error'}. Vector still runs the previous configuration.`;
      setOperationError('rollback', message);
      toast({ title: 'Rollback not deployed', description: message, variant: 'destructive' });
      return;
    }
    toast({ title: 'Rolled back and deployed', description: deployed?.message || 'Configuration rollback does not reverse events already processed.' });
  });
  const fetchLatest = () => queryClient.fetchQuery({ queryKey: sourceKey, queryFn: () => api.getLogSourceDraftStatus(sourceId), staleTime: 0 });
  /** Conflict recovery: drop local edits and continue from the server's latest saved copy. */
  const reloadLatest = async () => perform('reload', async () => {
    const latest = await fetchLatest();
    if (!alive.current) { forgetDraft(); return; }
    adoptSource(latest);
    toast({ title: 'Loaded the latest saved draft', description: 'Your unsaved edits were discarded.' });
  });
  /** Conflict recovery: keep local edits but move the save baseline to the latest copy; the next Save replaces it. */
  const keepLocalEdits = async () => perform('reload', async () => {
    const latest = await fetchLatest();
    const current = draftRef.current;
    if (!alive.current || !current) return;
    const baseline = publicationSnapshot(latest);
    const saved = draftFingerprint(draftFromSource(latest));
    savedSourceSnapshotRef.current = baseline; savedFingerprintRef.current = saved;
    setSavedFingerprint(saved); setConflict(null); setPlan(null); setValidation(null);
    setErrors((previous) => { const rest = { ...previous }; delete rest.save; delete rest.review; delete rest.publish; return rest; });
    rememberDraft(current, saved, baseline);
    toast({ title: 'Kept your edits', description: 'Saving will replace the latest server draft with your version.' });
  });
  /**
   * Reset the saved draft to the active version (POST /discard-draft) and drop
   * local edits. Re-read first and refuse when a draft newer than the one this
   * editor has seen was saved; the server re-checks the same revision (CAS).
   */
  const discardDraft = async () => perform('discard', async () => {
    if (!permissions.edit) throw new Error('Pipeline editing is not permitted.');
    const baseline = savedSourceSnapshotRef.current;
    if (!baseline) throw new Error('Load the source before discarding.');
    const observed = sourceRef.current;
    const seen = observed && newerThanSnapshot(baseline, observed) ? publicationSnapshot(observed) : baseline;
    const latest = await api.getLogSourceDraftStatus(sourceId);
    if (newerThanSnapshot(seen, latest)) throw new PipeSnapshotConflictError('Another draft was saved after the one you are discarding. Reload it before discarding.');
    await api.discardLogSourceDraft(sourceId, latest.updated_at);
    forgetDraft();
    void queryClient.invalidateQueries({ queryKey: ['pipe-sources'] });
    const reset = await fetchLatest();
    if (!alive.current) return;
    adoptSource(reset);
    toast({ title: 'Draft discarded', description: 'The pipeline matches the active published version again.' });
  });

  const routedInputs = draft ? routeInputsOfDraft(draft) : [];
  const laneInputs = useMemo(() => {
    const seen = new Map<string, { id: string; kind: 'push' | 'pull'; label: string }>();
    for (const event of [...tap.events, ...(sample?.events ?? [])]) {
      if (event.nanoInput && !seen.has(event.nanoInput)) seen.set(event.nanoInput, { id: event.nanoInput, kind: event.nanoInput.startsWith('pull:') ? 'pull' : 'push', label: 'Seen in captured events' });
    }
    return [...seen.values()];
  }, [tap.events, sample]);

  return {
    pipeline, source, draft, capabilities, permissions, tap, preview, validation, plan, planStale, sample, releases, sampleNotice,
    previewInput, setPreviewInput, routedInputs, laneInputs,
    busy, previewPending, errors, conflict, previewError, capabilitiesError,
    loadError: sourceQuery.error?.message ?? null, historyError: versionsQuery.error?.message ?? null,
    loading: sourceQuery.isLoading, dirty: !!draft && draftFingerprint(draft) !== savedFingerprint,
    imported: !!source && !parsePipelinePlan(source.parser_vrl),
    changeDraft, save, validate, review, publish, rollback, reloadLatest, keepLocalEdits, discardDraft,
    startTap, cancelTap, previewTapEvents, runPreview, loadRecentEvents, pasteSample,
    closeReview: () => setPlan(null),
    retry: () => { void sourceQuery.refetch(); void runtimeQuery.refetch(); },
    retryCapabilities: () => { void runtimeQuery.refetch(); },
  };
}
