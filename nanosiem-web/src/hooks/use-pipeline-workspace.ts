// SPDX-License-Identifier: AGPL-3.0-or-later

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { usePipeLaneInputs } from '@/hooks/use-pipe-inputs';
import { compilePipeline, draftFingerprint, draftFromSource, executableSteps, releaseFromRollout, serializePipeline, summaryFromSource, rawMessageSamples, recentEventSamples, pastedSampleEvents, ephemeralSample, pipelineDraftRecoveryKey, pipelineDraftRecovery, withoutPreviewBoilerplate, supportedStepKinds, routeInputsOfDraft, type PipelineDraftRecovery } from '@/lib/pipeline-model';
import type { CapturedEvent, PipelineConflict, PipelineOperation, PipelineOperationErrors, PipelineCapture, PipelineCaptureOptions, PipelineDraft, PipelinePreview, PipelinePublishOptions, PipelineReleasePlan, PipelineLaneInput, PipelineSample, PipelineValidation } from '@/lib/pipeline-types';
import { parserServingState } from '@/lib/parser-rollout';
import { DEFAULT_MAX_SAMPLES } from '@/lib/parser-samples';
import { publicationSnapshot, assertPublicationSnapshot, samePublicationSnapshot, newerThanSnapshot, pipeEventAccessDenied, pipeConflict, pipeEndpointMissing, pipeErrorStatus, pipePreviewDisabled, pipeBusy, pipeCaptureBounds, boundedPipeCaptureRequest, laneInputsFrom, DEFAULT_RECENT_EVENTS, MAX_RECENT_EVENTS, type PipeCaptureSession, type PipeCaptureSnapshot, type PipePublicationSnapshot, type PipeReleaseSamples, type PipePreviewRequest } from '@/lib/api/pipelines';
import type { LogSource } from '@/lib/api/types';

const previewOutputs = (output: unknown): unknown[] => output === undefined || output === null ? [] : Array.isArray(output) ? output : [output];

type ReviewedReleasePlan = PipelineReleasePlan & { sourceSnapshot: PipePublicationSnapshot; samples?: string[]; samplesFromCapture: boolean; sampleIdentity: string | null };
const MUTATIONS = new Set<string>(['save', 'publish', 'rollback', 'discard', 'reload']);
const CONFLICT_MESSAGE = 'This pipeline was changed on the server after you loaded it (another editor, the CLI, or Log Sources). Saving and publishing are blocked until you choose how to continue.';
const errorMessage = (cause: unknown) => cause instanceof Error ? cause.message : String(cause);

/** Server stop reasons; undefined keeps the state's own explanation. */
const STOP_REASONS: Record<string, string | undefined> = {
  capturing: undefined, duration_reached: undefined, cancelled: undefined, stopped: undefined, no_traffic: undefined, release_changed: undefined,
  event_limit: 'Capture stopped at its event limit. The sample may cover only part of the incoming traffic.',
  byte_limit: 'Capture stopped at its observation byte limit. The sample may cover only part of the incoming traffic.',
  assignment_changed: 'The source assignment changed during capture. Start a new capture to observe the current assignment.',
  authority_changed: 'Source event access changed during capture, so observed events were cleared.',
  runtime_error: 'The runtime reported an error during capture. Retained events are marked incomplete.',
  expired: 'The capture session expired before the runtime completed it.',
};
export const CAPTURE_EXPIRED_REASON = 'Capture snapshots are kept for 10 minutes and then purged. Start a new capture to observe current traffic.';
/** `events` are the observations read from the edge snapshot; the session itself carries progress only. */
export function captureView(session: PipeCaptureSession, snapshotEvents: PipeCaptureSnapshot['events'] | CapturedEvent[] = []): PipelineCapture {
  const stateMap: Record<string, PipelineCapture['state']> = {
    pending: 'connecting', queued: 'connecting', connecting: 'connecting', running: 'capturing', capturing: 'capturing',
    complete: 'completed', completed: 'completed', stopped: 'stopped', no_traffic: 'no_traffic', unavailable: 'unavailable', failed: 'failed',
    interrupted: 'interrupted', limit_reached: 'limit', expired: 'interrupted', cancelled: 'stopped',
  };
  const events: CapturedEvent[] = snapshotEvents.map((event, index) => 'sequence' in event
    ? { id: `${session.id}-${event.sequence ?? index}`, input: event.event, capturedAt: event.observed_at } : event);
  const observed = Number.isFinite(session.observed_events) ? session.observed_events : events.length;
  const mapped = stateMap[session.state] ?? 'failed';
  const state = session.stop_reason === 'release_changed' && mapped !== 'failed' ? 'release_changed'
    : mapped === 'completed' ? session.truncated ? 'limit' : observed === 0 ? 'no_traffic' : mapped : mapped;
  const stopReason = session.stop_reason ? session.stop_reason in STOP_REASONS ? STOP_REASONS[session.stop_reason] : session.stop_reason : undefined;
  return {
    sessionId: session.id, activeBundleSha256: session.active_bundle_sha256, truncated: session.truncated,
    state, events, sourceId: session.log_source_id, point: 'input', startedAt: session.created_at,
    observedEvents: observed, retainUntil: session.retain_until, snapshotAvailable: session.snapshot_available,
    reason: session.error ?? stopReason ?? (stateMap[session.state] ? undefined : `Unknown capture state: ${session.state}`),
  };
}
const captureActive = (capture: PipelineCapture) => capture.state === 'connecting' || capture.state === 'capturing';
const SNAPSHOT_POLL_MS = 2000;
/**
 * Combine a session document with its edge snapshot. Terminal sessions always
 * read the final snapshot; running ones re-read at most every 2 s when the
 * observed count moved. 404 = purged (expired), 409 = not readable yet.
 */
async function observeCapture(sourceId: string, session: PipeCaptureSession, previous: PipelineCapture, signal: AbortSignal | undefined, lastRead: { at: number }): Promise<PipelineCapture> {
  const kept = previous.sessionId === session.id ? previous.events : [];
  const terminal = session.state !== 'queued' && session.state !== 'running';
  const due = terminal || Date.now() - lastRead.at >= SNAPSHOT_POLL_MS && session.observed_events !== kept.length;
  if (!session.snapshot_available || !due) return captureView(session, kept);
  try {
    lastRead.at = Date.now();
    const snapshot = await api.pipelines.captureSnapshot(sourceId, session.id, signal);
    return captureView({ ...session, truncated: session.truncated || snapshot.truncated, retain_until: snapshot.retain_until ?? session.retain_until }, snapshot.events);
  } catch (cause) {
    if (pipeEventAccessDenied(cause) || signal?.aborted) throw cause;
    const status = pipeErrorStatus(cause);
    if (status === 404) return { ...captureView(session), state: 'expired', events: [], reason: CAPTURE_EXPIRED_REASON };
    if (status === 409) return captureView(session, kept);
    const view = captureView(session, kept);
    return terminal ? { ...view, state: 'interrupted', reason: `The runtime observed ${session.observed_events} events, but they could not be read from edge storage: ${errorMessage(cause)}` } : view;
  }
}

// Native preview bounds are independent of the larger live capture bounds.
const PREVIEW_MAX_EVENTS = 100;
const PREVIEW_MAX_STEPS = 32;
const PREVIEW_MAX_EVENT_BYTES = 64 * 1024;
const PREVIEW_MAX_REQUEST_BYTES = 1024 * 1024;
const PREVIEW_MAX_PROGRAM_BYTES = 256 * 1024;

/**
 * NAN-3625: per-event inputs for the preview. An explicit "preview as input"
 * choice applies to every event; otherwise each event keeps the input its
 * stored row recorded. Omitted when no event has one (older backends).
 */
export function previewEventInputs(events: readonly Pick<CapturedEvent, 'nanoInput'>[], override: string | null): Array<string | null> | undefined {
  const inputs = events.map((event) => override ?? event.nanoInput ?? null);
  return inputs.some((input) => input !== null) ? inputs : undefined;
}

function boundedPreviewRequest(current: PipelineDraft, sample: PipelineSample, extension: string | undefined, previewInput: string | null = null) {
  const encoder = new TextEncoder();
  const byteLength = (value: string) => encoder.encode(value).byteLength;
  const warnings: string[] = [];
  let steps = executableSteps(current);
  const repeatedPlanBytes = byteLength(JSON.stringify({ draft_revision: String(current.revision), steps, extension_vrl: extension ?? null, events: [] }));
  if (steps.length > PREVIEW_MAX_STEPS || repeatedPlanBytes >= PREVIEW_MAX_REQUEST_BYTES - PREVIEW_MAX_EVENT_BYTES) {
    const parser = serializePipeline(current);
    if (byteLength(parser) > PREVIEW_MAX_PROGRAM_BYTES) throw new Error('The complete draft parser exceeds the 256 KiB preview program limit. Reduce its size before previewing; no steps were omitted.');
    steps = [{ id: 'combined-draft-parser', name: 'Complete draft parser', enabled: true, vrl: parser }];
    warnings.push(`Preview executes all ${current.steps.length} processing steps as one complete plan to stay within request limits. Per-step traces are unavailable; no processing steps were omitted.`);
  }
  const request: PipePreviewRequest = {
    draft_revision: String(current.revision), steps,
    ...(extension !== undefined ? { extension_vrl: extension } : {}), events: [],
  };
  // Rust serializes an omitted Option as null when checking the total bound.
  let requestBytes = byteLength(JSON.stringify({ ...request, extension_vrl: extension ?? null }));
  if (requestBytes >= PREVIEW_MAX_REQUEST_BYTES) throw new Error('Draft processing and its extension exceed the 1 MiB preview request limit before any input can fit. Reduce the code size before previewing.');
  const selected: PipelineSample['events'] = [];
  // NAN-3625: room for `event_inputs` (≤ 45 bytes per canonical input plus separators).
  if (previewInput !== null || sample.events.some((event) => event.nanoInput)) requestBytes += 20 + 48 * Math.min(sample.events.length, PREVIEW_MAX_EVENTS);
  for (const event of sample.events.slice(0, PREVIEW_MAX_EVENTS)) {
    if (!event.input || typeof event.input !== 'object' || Array.isArray(event.input)) throw new Error(`Sample event ${selected.length + 1} is not a JSON object. Select a valid input sample before previewing.`);
    const eventBytes = byteLength(JSON.stringify(event.input));
    if (eventBytes > PREVIEW_MAX_EVENT_BYTES) throw new Error(`Sample event ${selected.length + 1} exceeds the 64 KiB preview event limit. The frozen capture is preserved; select a smaller input sample before previewing.`);
    const additional = eventBytes + (selected.length > 0 ? 1 : 0);
    if (requestBytes + additional > PREVIEW_MAX_REQUEST_BYTES) break;
    request.events.push(event.input);
    selected.push(event);
    requestBytes += additional;
  }
  const eventInputs = previewEventInputs(selected, previewInput);
  if (eventInputs) request.event_inputs = eventInputs;
  if (selected.length === 0) throw new Error('The first input event cannot fit within the 1 MiB preview request limit with this draft. The frozen capture is preserved; reduce the code or select a smaller sample.');
  if (selected.length < sample.events.length) warnings.unshift(`Preview evaluates the first ${selected.length} of ${sample.events.length} input events to stay within the 100-event and 1 MiB request limits. The full frozen capture is preserved. Remaining inputs were not previewed; they are not dropped events.`);
  return { request, selected, warnings };
}

export function usePipelineWorkspace(sourceId: string) {
  const { hasPermission, tenantRuntime } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [eventAccessRevoked, setEventAccessRevoked] = useState(false);
  const eventAccessRevokedRef = useRef(false);
  const broadEventAccess = hasPermission('search:execute');
  const permissions = { view: hasPermission('log_sources:view'), edit: hasPermission('log_sources:edit'), capture: broadEventAccess && !eventAccessRevoked, release: hasPermission('log_sources:deploy') };
  const scope = tenantRuntime.key;
  const sourceQuery = useQuery({ queryKey: ['pipe-source', scope, sourceId], queryFn: () => api.getLogSourceDraftStatus(sourceId), enabled: !!sourceId && permissions.view });
  const sourceKey = ['pipe-source', scope, sourceId];
  // A 404 means this backend predates the pipe endpoints; retrying cannot change that.
  const runtimeQuery = useQuery({ queryKey: ['pipe-capabilities', scope, sourceId], queryFn: ({ signal }) => api.pipelines.capabilities(sourceId, signal), enabled: !!sourceId && permissions.view,
    retry: (failures, cause) => !pipeEndpointMissing(cause) && !pipeEventAccessDenied(cause) && failures < 2 });
  const releasesQuery = useQuery({ queryKey: ['pipe-rollouts', scope, sourceId], queryFn: () => api.listLogSourceRollouts(sourceId, 30), enabled: !!sourceId && permissions.view, refetchInterval: (query) => query.state.data?.some((release) => !release.terminal) ? 2000 : false });
  const latestLiveQuery = useQuery({ queryKey: ['pipe-latest-live', scope, releasesQuery.data?.[0]?.id, releasesQuery.data?.[0]?.state], queryFn: async () => (await api.listParserRollouts({ states: ['live'], limit: 1 }))[0] ?? null, enabled: !!sourceId && permissions.view });
  const versionsQuery = useQuery({ queryKey: ['pipe-versions', scope, sourceId], queryFn: () => api.getLogSourceVersions(sourceId), enabled: !!sourceId && permissions.view });
  const samplesQuery = useQuery({ queryKey: ['pipe-samples', scope, sourceId], queryFn: () => api.getLogSourceSamples(sourceId), enabled: !!sourceId && permissions.capture });
  const recovered = useRef(queryClient.getQueryData<PipelineDraftRecovery>(pipelineDraftRecoveryKey(scope, sourceId))).current;
  const [draft, setDraft] = useState<PipelineDraft | null>(recovered?.draft ?? null);
  const [savedFingerprint, setSavedFingerprint] = useState(recovered?.savedFingerprint ?? '');
  const [capture, setCapture] = useState<PipelineCapture>({ state: 'ready', sourceId, point: 'input', events: [] });
  const [frozen, setFrozen] = useState<PipelineSample | null>(null);
  const [previewPending, setPreviewPending] = useState(false);
  const [preview, setPreview] = useState<PipelinePreview | null>(null);
  const [validation, setValidation] = useState<PipelineValidation | null>(null);
  const [plan, setPlan] = useState<ReviewedReleasePlan | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  /** Outcome of the last load-recent-events read that produced no sample (e.g. nothing stored recently). */
  const [sampleNotice, setSampleNotice] = useState<string | null>(null);
  // The server answered 503 "not enabled": the deployment turned preview off after capabilities loaded.
  const [previewDisabledByServer, setPreviewDisabledByServer] = useState(false);
  /** NAN-3625: preview every sample event as arriving on this input (null = as recorded). */
  const [previewInput, setPreviewInput] = useState<string | null>(null);
  const [errors, setErrors] = useState<PipelineOperationErrors>({});
  const [conflict, setConflict] = useState<PipelineConflict | null>(null);
  const mutatingRef = useRef(false);
  const requestSeq = useRef(0);
  const previewAbortRef = useRef<AbortController | null>(null);
  const alive = useRef(true);
  const captureRef = useRef(capture);
  const draftRef = useRef(draft);
  const sourceRef = useRef(sourceQuery.data);
  const savedSourceSnapshotRef = useRef<PipePublicationSnapshot | null>(recovered?.sourceSnapshot ?? null);
  const sampleRef = useRef(frozen);
  const savedFingerprintRef = useRef(savedFingerprint);
  captureRef.current = capture;
  draftRef.current = draft;
  sourceRef.current = sourceQuery.data;
  sampleRef.current = frozen;
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
    // The tenant runtime owns this query client and clears it on auth/tenant change.
    // Infinity protects Back/programmatic route unmounts; nothing reaches disk.
    queryClient.setQueryDefaults(key, { gcTime: Infinity });
    queryClient.setQueryData(key, pipelineDraftRecovery(current, saved, baseline));
  }, [queryClient, scope, sourceId]);
  /**
   * Record a server write's new CAS baseline in the tenant-scoped cache. This
   * runs even after the editor unmounted mid-request, so returning to the
   * page never saves against the pre-write timestamp (a self-inflicted 409).
   * The newest draft in the cache wins over the draft this request started with.
   */
  const recordBaseline = useCallback((fallback: PipelineDraft, saved: string, baseline: PipePublicationSnapshot) => {
    const key = pipelineDraftRecoveryKey(scope, sourceId);
    const latest = queryClient.getQueryData<PipelineDraftRecovery>(key)?.draft ?? fallback;
    queryClient.setQueryDefaults(key, { gcTime: Infinity });
    queryClient.setQueryData(key, pipelineDraftRecovery(latest, saved, baseline));
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
    setErrors((previous) => { const rest = { ...previous }; for (const key of ['save', 'validate', 'review', 'publish'] as const) delete rest[key]; return rest; });
    rememberDraft(next, fingerprint, baseline);
  }, [rememberDraft]);
  const revokeEventAccess = useCallback((reason = 'Source event access is no longer permitted. Reload after access is restored.') => {
    eventAccessRevokedRef.current = true;
    previewAbortRef.current?.abort();
    requestSeq.current++;
    setEventAccessRevoked(true);
    const denied: PipelineCapture = { state: 'forbidden', sourceId, point: 'input', events: [], reason };
    captureRef.current = denied;
    sampleRef.current = null;
    setCapture(denied); setFrozen(null); setPreview(null); setPreviewPending(false); setPlan(null); setSampleNotice(null);
    const key = ['pipe-samples', scope, sourceId];
    void queryClient.cancelQueries({ queryKey: key, exact: true }).then(() => queryClient.removeQueries({ queryKey: key, exact: true }));
  }, [queryClient, scope, sourceId]);
  useEffect(() => {
    if (!broadEventAccess || pipeEventAccessDenied(samplesQuery.error) || pipeEventAccessDenied(sourceQuery.error)) revokeEventAccess();
  }, [broadEventAccess, samplesQuery.error, sourceQuery.error, revokeEventAccess]);

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
  // only fail. Older (cached) reads are ignored, and our own in-flight writes
  // are skipped until they have recorded their new baseline.
  useEffect(() => {
    const fresh = sourceQuery.data;
    const baseline = savedSourceSnapshotRef.current;
    if (!fresh || !draft || !baseline || busy && MUTATIONS.has(busy) || mutatingRef.current || !newerThanSnapshot(baseline, fresh)) return;
    const recorded = queryClient.getQueryData<PipelineDraftRecovery>(pipelineDraftRecoveryKey(scope, sourceId));
    if (recorded && samePublicationSnapshot(recorded.sourceSnapshot, publicationSnapshot(fresh))) {
      // A save from an earlier mount of this editor landed after we restored its draft.
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
    return () => {
    alive.current = false;
    sequence.current++;
    previewController.current?.abort();
    const current = captureRef.current;
    if (current.sessionId && captureActive(current)) void api.pipelines.stopCapture(sourceId, current.sessionId).catch(() => undefined);
    };
  }, [sourceId]);

  const perform = useCallback(async <T,>(action: PipelineOperation, operation: () => Promise<T>): Promise<T | undefined> => {
    setBusy(action); setOperationError(action, null);
    if (MUTATIONS.has(action)) mutatingRef.current = true;
    try { return await operation(); }
    catch (cause) {
      if (alive.current) {
        if (pipeEventAccessDenied(cause)) revokeEventAccess();
        if (pipeConflict(cause) && (action === 'save' || action === 'publish' || action === 'discard')) {
          setConflict({ operation: action === 'discard' ? 'remote' : action, message: CONFLICT_MESSAGE });
          // Learn the newer server draft so the banner's choices act on what is really there.
          void queryClient.invalidateQueries({ queryKey: ['pipe-source', scope, sourceId], exact: true });
        }
        setOperationError(action, errorMessage(cause));
      }
      return undefined;
    } finally { if (MUTATIONS.has(action)) mutatingRef.current = false; if (alive.current) setBusy(null); }
  }, [revokeEventAccess, setOperationError, queryClient, scope, sourceId]);
  const releases = (releasesQuery.data ?? []).map((rollout) => {
    const release = releaseFromRollout(rollout);
    return { ...release, versionId: release.state === 'live' ? versionsQuery.data?.find((version) => version.version_number === release.revision)?.id : undefined };
  });
  const serving = parserServingState(releasesQuery.data, latestLiveQuery.data, sourceQuery.data?.active_version_number);
  const pipeline = sourceQuery.data ? { ...summaryFromSource(sourceQuery.data, releases), activeRevision: serving.tracked ? serving.servingVersion : sourceQuery.data.active_version_number ?? null, hasDraft: sourceQuery.data.has_draft_changes } : null;
  const supportedSteps = supportedStepKinds(runtimeQuery.data?.supported_step_kinds);
  const captureBounds = pipeCaptureBounds(runtimeQuery.data?.capture);
  // Not served by this backend yet: a quiet product state, not an error.
  const runtimeNotAvailable = pipeEndpointMissing(runtimeQuery.error);
  const capabilitiesError = runtimeQuery.error && !runtimeNotAvailable ? `Runtime capabilities could not be loaded: ${runtimeQuery.error.message}` : null;
  const NOT_AVAILABLE = 'Pipeline preview and live capture are not available for this workspace yet. You can still edit, save, and publish pipelines.';
  const PREVIEW_OFF = 'Draft preview is not enabled for this workspace yet. Captures and saved samples remain inspectable, and you can still edit, save, and publish.';
  const previewOff = runtimeQuery.data?.preview_enabled === false || previewDisabledByServer;
  const capabilities = {
    supportedSteps, preview: !!runtimeQuery.data && !previewOff, runtime: runtimeQuery.data ? 'ready' as const : runtimeNotAvailable ? 'not_available' as const : capabilitiesError ? 'error' as const : 'loading' as const,
    previewReason: previewOff ? PREVIEW_OFF : runtimeQuery.data ? withoutPreviewBoilerplate(runtimeQuery.data.warnings).join(' ') || undefined
      : runtimeNotAvailable ? NOT_AVAILABLE : capabilitiesError ? 'Preview is unavailable because runtime capabilities could not be loaded.' : 'Loading runtime capabilities.',
    ai: false,
    capture: { available: !!runtimeQuery.data && runtimeQuery.data.capture.enabled === true,
      reason: runtimeQuery.data?.capture.reason ?? (runtimeQuery.data && !runtimeQuery.data.capture.enabled ? 'Live capture requires the runtime capture runner to be enabled for this deployment.' : runtimeNotAvailable ? NOT_AVAILABLE : capabilitiesError ? 'Capture is unavailable because runtime capabilities could not be loaded.' : undefined),
      maxBytes: captureBounds.max_bytes, maxEvents: captureBounds.max_events, maxDurationSeconds: captureBounds.max_duration_seconds },
  };
  // NAN-3621: one lane inputs read serves the Inputs panel and, normalized,
  // the NAN-3625 route-by-input picker (a backend without it lists none).
  const laneInputsQuery = usePipeLaneInputs(sourceId, { enabled: permissions.view });
  const laneInputs: PipelineLaneInput[] = useMemo(() => laneInputsQuery.data ? laneInputsFrom(laneInputsQuery.data) : [], [laneInputsQuery.data]);
  const inputs = { inputs: laneInputsQuery.data, loading: laneInputsQuery.isLoading, error: laneInputsQuery.error?.message ?? null };
  const samples: PipelineSample[] = permissions.capture && samplesQuery.data?.samples.length ? [{ id: 'saved-source-samples', name: 'Saved source samples', events: samplesQuery.data.samples.map((input, index) => {
    return { id: `saved-${index}`, input: { message: input, source_type: sourceQuery.data?.ingest?.source_slugs[0] ?? sourceQuery.data?.source_type } };
  }) }] : [];

  const changeDraft = (next: PipelineDraft) => {
    if (!permissions.edit) return;
    const updated = { ...next, revision: (draftRef.current?.revision ?? next.revision) + 1 };
    setDraft(updated); setValidation(null); setPlan(null); setOperationError('validate', null); setOperationError('review', null);
    setPreview((previous) => previous ? { ...previous, stale: true } : null);
    requestSeq.current++; setPreviewPending(false);
    if (savedSourceSnapshotRef.current) rememberDraft(updated, savedFingerprint, savedSourceSnapshotRef.current);
  };
  const save = async () => perform('save', async () => {
    const current = draftRef.current;
    if (!permissions.edit || !current || !sourceQuery.data) throw new Error('Pipeline editing is not permitted.');
    const snapshot = draftFingerprint(current);
    const baseline = savedSourceSnapshotRef.current;
    if (!baseline) throw new Error('Load the source snapshot before saving.');
    const saved = await api.updateLogSource(sourceId, { name: current.name, description: current.description, parser_vrl: serializePipeline(current), expected_updated_at: baseline.expectedUpdatedAt });
    const savedBaseline = publicationSnapshot(saved);
    // Record before the unmount check: the server has already advanced updated_at.
    savedSourceSnapshotRef.current = savedBaseline; savedFingerprintRef.current = snapshot;
    recordBaseline(draftRef.current ?? current, snapshot, savedBaseline);
    void queryClient.invalidateQueries({ queryKey: ['pipe-sources'] });
    if (!alive.current) { void queryClient.invalidateQueries({ queryKey: sourceKey, exact: true }); return; }
    setSavedFingerprint(snapshot); setConflict(null);
    if (draftRef.current) rememberDraft(draftRef.current, snapshot, savedBaseline);
    await sourceQuery.refetch();
    toast({ title: 'Draft saved', description: 'Production keeps using the active release.' });
  });
  const validate = async (): Promise<PipelineValidation | undefined> => perform('validate', async () => {
    if (!draftRef.current) throw new Error('Load a pipeline first.');
    const current = draftRef.current;
    const fingerprint = draftFingerprint(current);
    const code = compilePipeline(current);
    const extension = sourceQuery.data?.extension_enabled !== false ? sourceQuery.data?.extension_vrl?.trim() : undefined;
    // Production executes parser and extension as separate remap programs.
    const [parserResult, extensionResult] = await Promise.all([
      api.validateLogSourceVrl(serializePipeline(current)),
      extension ? api.validateLogSourceVrl(extension) : Promise.resolve(null),
    ]);
    const checked = {
      valid: parserResult.valid && (!extensionResult || extensionResult.valid),
      errors: [...parserResult.errors, ...(extensionResult?.errors.map((finding) => `Existing source extension: ${finding}`) ?? [])],
      warnings: ['Native VRL validation checks processing code. Publication still requires shared-bundle structural guards, Vector validation and sample tests, and runtime promotion; a queued release can fail those later checks.', ...withoutPreviewBoilerplate(runtimeQuery.data?.warnings), ...(extension ? ['The existing source extension runs after your processing steps as a separate runtime program.'] : []), ...(frozen && !ephemeralSample(frozen) && frozen.events.length > (samplesQuery.data?.max_samples ?? DEFAULT_MAX_SAMPLES) ? [frozen.origin === 'capture' ? `Only the first ${samplesQuery.data?.max_samples ?? DEFAULT_MAX_SAMPLES} captured raw messages can be saved as release samples, and only if you choose to when publishing.` : `Release verification uses the first ${samplesQuery.data?.max_samples ?? DEFAULT_MAX_SAMPLES} raw messages.`] : [])],
      compiledVrl: code,
    };
    if (alive.current && fingerprint === draftFingerprint(draftRef.current!)) setValidation(checked);
    return checked;
  });
  const runPreview = useCallback(async () => {
    const current = draftRef.current;
    if (!current || !frozen || !permissions.capture || eventAccessRevokedRef.current || previewOff || runtimeNotAvailable) return;
    previewAbortRef.current?.abort();
    const controller = new AbortController();
    previewAbortRef.current = controller;
    const seq = ++requestSeq.current;
    const fingerprint = draftFingerprint(current);
    setPreviewPending(true);
    try {
      const bounded = boundedPreviewRequest(current, frozen,
        sourceQuery.data?.extension_vrl && sourceQuery.data.extension_enabled !== false ? sourceQuery.data.extension_vrl : undefined, previewInput);
      const result = await api.pipelines.preview(sourceId, bounded.request, controller.signal);
      if (!alive.current || eventAccessRevokedRef.current || seq !== requestSeq.current || draftFingerprint(draftRef.current!) !== fingerprint) return;
      setPreview({ warnings: [...bounded.warnings, ...withoutPreviewBoilerplate(result.warnings)], revision: current.revision, fingerprint, stale: false, inputCount: result.results.length,
        outputCount: result.results.reduce((count, row) => count + previewOutputs(row.output).length, 0),
        events: result.results.map((row) => ({ inputId: bounded.selected[row.index]?.id ?? String(row.index), input: row.input,
          outputs: previewOutputs(row.output), outcome: row.disposition,
          error: row.error, trace: row.steps.map((step) => ({ stepId: step.step_id, outputs: previewOutputs(step.output), error: step.error })) })) });
      setPreviewError(null);
    } catch (cause) {
      if (alive.current && pipeEventAccessDenied(cause)) { revokeEventAccess(); return; }
      if (alive.current && pipePreviewDisabled(cause)) { setPreviewDisabledByServer(true); setPreviewError(null); setPreview(null); return; }
      if (alive.current && seq === requestSeq.current) {
        setPreviewError(pipeBusy(cause) ? 'Preview capacity is busy. Run preview again in a few seconds.' : errorMessage(cause));
        setPreview((previous) => previous ? { ...previous, stale: true } : null);
      }
    } finally { if (alive.current && seq === requestSeq.current) setPreviewPending(false); }
  }, [sourceId, frozen, permissions.capture, previewOff, runtimeNotAvailable, sourceQuery.data?.extension_vrl, sourceQuery.data?.extension_enabled, revokeEventAccess, previewInput]);
  useEffect(() => {
    if (!draft || !frozen) return;
    const timer = setTimeout(() => { void runPreview(); }, 450);
    return () => clearTimeout(timer);
  }, [draft, frozen, runPreview]);
  const captureId = capture.sessionId;
  const captureRunning = captureActive(capture);
  useEffect(() => {
    if (!captureId || !captureRunning) return;
    const controller = new AbortController();
    let polling = false;
    const lastRead = { at: 0 };
    const timer = setInterval(() => {
      if (polling) return;
      polling = true;
      void api.pipelines.capture(sourceId, captureId, controller.signal).then((session) => observeCapture(sourceId, session, captureRef.current, controller.signal, lastRead)).then((view) => {
        if (!controller.signal.aborted && alive.current && !eventAccessRevokedRef.current) { captureRef.current = view; setCapture(view); }
      }).catch((cause) => {
        if (!controller.signal.aborted && alive.current && pipeEventAccessDenied(cause)) { revokeEventAccess(); return; }
        if (!controller.signal.aborted && alive.current && !eventAccessRevokedRef.current) setCapture((previous) => ({ ...previous, state: 'interrupted', reason: cause instanceof Error ? cause.message : String(cause) }));
      }).finally(() => { polling = false; });
    }, 1000);
    return () => { clearInterval(timer); controller.abort(); };
  }, [sourceId, captureId, captureRunning, revokeEventAccess]);
  // The server purges capture snapshots at retain_until; the live view expires with them.
  // A frozen copy the user explicitly selected for preview stays until the editor closes.
  const retainUntil = capture.retainUntil;
  useEffect(() => {
    if (!captureId || !retainUntil || captureRunning) return;
    const remaining = Date.parse(retainUntil) - Date.now();
    if (Number.isNaN(remaining)) return;
    const expire = () => setCapture((previous) => previous.sessionId === captureId && previous.state !== 'forbidden' ? { ...previous, state: 'expired', events: [], reason: CAPTURE_EXPIRED_REASON } : previous);
    if (remaining <= 0) { expire(); return; }
    const timer = setTimeout(expire, Math.min(remaining, 2_147_000_000));
    return () => clearTimeout(timer);
  }, [captureId, retainUntil, captureRunning]);
  const startCapture = async (options: PipelineCaptureOptions) => perform('capture', async () => {
    if (!permissions.capture) throw new Error('Source event access is required for capture.');
    if (!capabilities.capture.available) throw new Error('Capture is unavailable on this runtime.');
    if (options.filter?.trim()) throw new Error('Capture filters are not supported by this runtime yet.');
    const request = boundedPipeCaptureRequest(options.durationSeconds, options.eventLimit, runtimeQuery.data?.capture);
    setCapture({ state: 'connecting', sourceId, point: 'input', events: [] });
    try {
      const session = await api.pipelines.startCapture(sourceId, request);
      if (alive.current && !eventAccessRevokedRef.current) setCapture(captureView(session));
    } catch (cause) {
      if (alive.current && pipeEventAccessDenied(cause)) revokeEventAccess();
      else if (alive.current && !eventAccessRevokedRef.current) setCapture({ state: 'failed', sourceId, point: 'input', events: [], reason: cause instanceof Error ? cause.message : String(cause) });
      throw cause;
    }
  });
  const stopCapture = async () => perform('stop', async () => {
    const current = captureRef.current;
    if (current.sessionId) {
      const stopped = await api.pipelines.stopCapture(sourceId, current.sessionId);
      const view = await observeCapture(sourceId, stopped, captureRef.current, undefined, { at: 0 });
      if (alive.current && !eventAccessRevokedRef.current) { captureRef.current = view; setCapture(view); }
    }
  });
  const freeze = async () => {
    const current = captureRef.current;
    if (!permissions.capture || !current.events.length) return;
    requestSeq.current++; setPlan(null);
    setFrozen({ id: current.sessionId ?? 'captured-input', name: 'Captured input', origin: 'capture', events: structuredClone(current.events) });
    if (captureActive(current)) await stopCapture();
  };
  const selectSample = (sample: PipelineSample) => { if (permissions.capture) { requestSeq.current++; setPlan(null); setSampleNotice(null); setOperationError('load', null); setFrozen(structuredClone(sample)); setPreview(null); } };
  /**
   * NAN-3447: preview input from the source's newest stored events. The API
   * authorizes and audits the read and returns the bounded Search request;
   * the raw events are read through Search and kept in browser memory only.
   */
  const loadRecentEvents = async (limit: number = DEFAULT_RECENT_EVENTS) => perform('load', async () => {
    if (!permissions.capture || eventAccessRevokedRef.current) throw new Error('Source event access is required to load recent events.');
    if (!Number.isInteger(limit) || limit < 1 || limit > MAX_RECENT_EVENTS) throw new Error(`Load 1–${MAX_RECENT_EVENTS} recent events.`);
    setSampleNotice(null);
    // A sample chosen or pasted while this read runs wins over its result.
    const seq = requestSeq.current;
    const plan = await api.pipelines.recentEvents(sourceId, limit);
    const bounded = Math.min(limit, plan.limit, MAX_RECENT_EVENTS);
    const response = await api.search({ query: plan.query, time_range: plan.time_range, limit: bounded, skip_histogram: true, skip_field_stats: true, use_cache: false });
    if (!alive.current || eventAccessRevokedRef.current || seq !== requestSeq.current) return;
    const events = recentEventSamples(response.results ?? [], { ...plan, limit: bounded });
    if (!events.length) {
      setSampleNotice('No stored events with raw text for this source in the last 24 hours. Paste a sample, or send events and try again.');
      return;
    }
    requestSeq.current++; setPlan(null); setPreview(null);
    setFrozen({ id: `recent-events-${Date.now()}`, name: `Recent events · ${events.length}`, origin: 'recent', events });
  });
  /** NAN-3447: preview input pasted by the user; browser memory only. Throws on unusable text. */
  const pasteSample = (text: string) => {
    if (!permissions.capture || eventAccessRevokedRef.current) throw new Error('Source event access is required to preview events.');
    const events = pastedSampleEvents(text, sourceQuery.data?.ingest?.source_slugs[0] ?? sourceQuery.data?.source_type);
    requestSeq.current++; setPlan(null); setPreview(null); setSampleNotice(null); setOperationError('load', null);
    setFrozen({ id: `pasted-sample-${Date.now()}`, name: `Pasted sample · ${events.length}`, origin: 'pasted', events });
  };
  const saveSample = async () => perform('sample', async () => {
    if (!permissions.capture || !permissions.edit || !frozen) throw new Error('A frozen sample and editing permission are required.');
    const selected = rawMessageSamples(frozen.events).slice(0, samplesQuery.data?.max_samples ?? DEFAULT_MAX_SAMPLES);
    await api.putLogSourceSamples(sourceId, selected);
    await samplesQuery.refetch();
    toast({ title: 'Sample saved', description: `Stored ${selected.length} raw message samples with this source for release testing.` });
  });
  const review = async () => {
    const current = draftRef.current;
    const source = sourceRef.current;
    setOperationError('review', null);
    const fail = (cause: unknown) => {
      if (!alive.current) return;
      if (pipeConflict(cause)) setConflict({ operation: 'review', message: CONFLICT_MESSAGE });
      setOperationError('review', errorMessage(cause));
    };
    if (!current || !source || draftFingerprint(current) !== savedFingerprint) { fail('Save this draft before reviewing a release.'); return; }
    // Hold the exact parser/extension source and sample set across async validation.
    const snapshot = savedSourceSnapshotRef.current;
    if (!snapshot) return;
    try { assertPublicationSnapshot(snapshot, source); }
    catch (cause) { fail(cause); return; }
    const sampleIdentity = sampleRef.current ? JSON.stringify(sampleRef.current) : null;
    let releaseSamples: string[] | undefined;
    try {
      // Loaded/pasted samples are preview-only; the version keeps the source's saved samples.
      if (sampleRef.current && !ephemeralSample(sampleRef.current)) releaseSamples = rawMessageSamples(sampleRef.current.events).slice(0, samplesQuery.data?.max_samples ?? DEFAULT_MAX_SAMPLES);
    } catch (cause) { fail(cause); return; }
    const checked = await validate();
    if (!checked || !checked.valid || !alive.current || draftFingerprint(current) !== draftFingerprint(draftRef.current!)) return;
    if (sampleIdentity !== (sampleRef.current ? JSON.stringify(sampleRef.current) : null)) { fail('The release sample changed during validation. Review the current sample again.'); return; }
    try { if (!sourceRef.current) return; assertPublicationSnapshot(snapshot, sourceRef.current); }
    catch (cause) { fail(cause); return; }
    const samplesFromCapture = sampleRef.current?.origin === 'capture';
    setPlan({ sourceSnapshot: snapshot, samples: releaseSamples, samplesFromCapture, sampleIdentity,
      ...(samplesFromCapture && releaseSamples?.length ? { capturedSampleCount: releaseSamples.length } : {}),
      fingerprint: draftFingerprint(current), revision: current.revision,
      compiledVrl: [checked.compiledVrl!, ...(snapshot.extensionVrl && snapshot.extensionEnabled ? ['# Existing source extension (separate runtime program)', snapshot.extensionVrl] : [])].join('\n\n'), validation: checked,
      activeVrl: (() => {
        const active = versionsQuery.data?.find((version) => version.version_number === pipeline?.activeRevision);
        if (!active) return '';
        return [active.parser_vrl, ...(active.extension_vrl && active.extension_enabled !== false ? ['# Existing source extension (separate runtime program)', active.extension_vrl] : [])].join('\n\n');
      })() });
  };
  const planStale = !!plan && (!sourceQuery.data || plan.sourceSnapshot.expectedUpdatedAt !== sourceQuery.data.updated_at || plan.sourceSnapshot.parserVrl !== sourceQuery.data.parser_vrl || plan.sourceSnapshot.extensionVrl !== (sourceQuery.data.extension_vrl ?? null) || plan.sourceSnapshot.extensionEnabled !== (sourceQuery.data.extension_enabled !== false));
  /**
   * Captured events reach PostgreSQL only when the reviewer opted in on this
   * publication; otherwise the version keeps the source's saved samples.
   */
  const publish = async (options: PipelinePublishOptions = { persistCapturedSamples: false }) => perform('publish', async () => {
    const current = draftRef.current;
    if (!permissions.release || !current || !plan || !plan.validation.valid || planStale || plan.fingerprint !== draftFingerprint(current) || plan.fingerprint !== savedFingerprint) throw new Error('Review and validate the saved draft before publishing.');
    if (plan.sampleIdentity !== (sampleRef.current ? JSON.stringify(sampleRef.current) : null)) throw new Error('The reviewed release sample changed. Review it again before publishing.');
    const source = await api.getLogSource(sourceId);
    assertPublicationSnapshot(plan.sourceSnapshot, source);
    // The reviewed timestamp also reaches the server row lock. Never substitute
    // a fresher query/read timestamp after review (that would publish unseen changes).
    const release: PipeReleaseSamples | undefined = !plan.samples ? undefined
      : !plan.samplesFromCapture ? { origin: 'supplied', samples: plan.samples }
      : options.persistCapturedSamples ? { origin: 'capture', samples: plan.samples, persistCaptured: true } : undefined;
    const result = await api.pipelines.publishReviewed(plan.sourceSnapshot, release);
    // If the editor unmounted, the restored draft reconciles against the newer server copy on return.
    if (!alive.current) { void queryClient.invalidateQueries({ queryKey: sourceKey, exact: true }); return; }
    setPlan(null);
    const [refreshed] = await Promise.all([sourceQuery.refetch(), releasesQuery.refetch(), versionsQuery.refetch()]);
    // Our publication changes updated_at. Adopt the visible, pristine source
    // together with its CAS baseline; never advance a baseline behind edited data.
    if (alive.current && refreshed.data && draftRef.current && draftFingerprint(draftRef.current) === plan.fingerprint) adoptSource(refreshed.data);
    toast({ title: result.rollout ? 'Release queued' : 'Publication accepted', description: result.rollout ? 'Follow the rollout until the runtime reports it live.' : 'No runtime rollout was returned. Check source status before assuming it is serving.' });
  });
  /**
   * Rollback rewrites the server draft to the selected version, replacing any
   * saved-but-unpublished draft and this editor's unsaved edits. Like publish,
   * it refuses unless the caller confirmed exactly the local state it replaces.
   */
  const rollback = async (versionId: number, confirmed: { unsavedEdits: boolean }) => perform('rollback', async () => {
    if (!permissions.release) throw new Error('Release permission is required.');
    const current = draftRef.current;
    const unsaved = !!current && draftFingerprint(current) !== savedFingerprintRef.current;
    if (unsaved && !confirmed.unsavedEdits) throw new Error('This editor has unsaved edits that rollback would replace. Review the rollback warning and confirm again.');
    await api.revertLogSourceVersion(sourceId, versionId);
    forgetDraft();
    void queryClient.invalidateQueries({ queryKey: ['pipe-sources'] });
    if (!alive.current) { void queryClient.invalidateQueries({ queryKey: sourceKey, exact: true }); return; }
    setPlan(null); setValidation(null); setPreview(null);
    const [refreshed] = await Promise.all([sourceQuery.refetch(), releasesQuery.refetch(), versionsQuery.refetch()]);
    if (alive.current && refreshed.data) adoptSource(refreshed.data);
    toast({ title: 'Rollback requested', description: 'Configuration rollback does not reverse events already processed.' });
  });
  const fetchLatest = () => queryClient.fetchQuery({ queryKey: sourceKey, queryFn: () => api.getLogSourceDraftStatus(sourceId), staleTime: 0 });
  /** Conflict recovery: drop local edits and continue from the server's latest saved copy. */
  const reloadLatest = async () => perform('reload', async () => {
    const latest = await fetchLatest();
    if (!alive.current) { forgetDraft(); return; }
    adoptSource(latest);
    toast({ title: 'Loaded the latest saved draft', description: 'Your unsaved edits were discarded.' });
  });
  /**
   * Conflict recovery: keep local edits but move the save baseline to the
   * server's latest copy. The editor stays dirty; the next Save knowingly
   * replaces that copy.
   */
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
  /** Reset the saved server draft to the active published version (POST /discard-draft) and drop local edits. */
  const discardDraft = async () => perform('discard', async () => {
    if (!permissions.edit) throw new Error('Pipeline editing is not permitted.');
    const baseline = savedSourceSnapshotRef.current;
    if (!baseline) throw new Error('Load the source snapshot before discarding.');
    // CAS on the newest server draft this editor has SEEN (the one the conflict
    // banner warned about): a draft saved after that is never wiped (409).
    const observed = sourceQuery.data;
    const expected = observed && newerThanSnapshot(baseline, observed) ? observed.updated_at : baseline.expectedUpdatedAt;
    await api.discardLogSourceDraft(sourceId, expected);
    forgetDraft();
    void queryClient.invalidateQueries({ queryKey: ['pipe-sources'] });
    const latest = await fetchLatest();
    if (!alive.current) return;
    adoptSource(latest);
    toast({ title: 'Draft discarded', description: 'The pipeline matches the active published version again.' });
  });
  const canSaveCaptureSample = permissions.edit && permissions.capture && !!frozen?.events.length && frozen.id === capture.sessionId && !captureActive(capture);
  const routedInputs = draft ? routeInputsOfDraft(draft) : [];
  return { pipeline, draft, capabilities, permissions, capture, preview, validation, plan, planStale, canSaveCaptureSample, samples, frozen, releases, sampleNotice,
    laneInputs, inputs, routedInputs, previewInput, setPreviewInput,
    versions: versionsQuery.data ?? [], busy, previewPending,
    errors, conflict, previewError, capabilitiesError, loadError: sourceQuery.error?.message ?? null, historyError: releasesQuery.error?.message ?? null,
    loading: sourceQuery.isLoading, dirty: !!draft && draftFingerprint(draft) !== savedFingerprint,
    changeDraft, save, validate, review, publish, rollback, reloadLatest, keepLocalEdits, discardDraft, startCapture, stopCapture, freeze, runPreview, selectSample, saveSample, loadRecentEvents, pasteSample,
    closeReview: () => setPlan(null), retry: () => { void sourceQuery.refetch(); void runtimeQuery.refetch(); }, retryCapabilities: () => { void runtimeQuery.refetch(); } };
}
