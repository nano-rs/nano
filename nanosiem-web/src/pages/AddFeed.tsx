// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * AddFeed (NAN-522) — the Add data wizard, connect-first (NAN-4912 phase 2,
 * main's NAN-4847 flow re-backed by the single-tenant APIs).
 *
 * One linear flow, connect before parse:
 *   1. Source   — source key (`source_type`) + name + namespace + metadata, and
 *                 how data arrives: pushed with an ingest token (HTTP / HEC /
 *                 OTLP; the token decides the source) or pulled / listened for
 *                 by a source configuration (Kafka, S3, syslog, …).
 *   2. Connect  — the draft source is created, an ingest token is issued (shown
 *                 once), sender snippets, and a live "first events" check.
 *                 Events land in `logs` unparsed (searchable as
 *                 `source_type=<key>`) before any parser is published.
 *   3. Parse    — samples (pulled from the received events, or pasted) → AI
 *                 or hand-written VRL → diagnostics + per-sample tests.
 *   4. Review   — gate computed from real state (NAN-4754) → publish
 *                 (`deployLogSource` renders the Vector config).
 *
 * Resumable: `?source_id=<id>&stage=connect|parse|review` reopens a draft
 * (NAN-4800 / NAN-2946 deep links from Log sources and the detail page).
 *
 * Single page, vertical step rail on the left, content on the right. No
 * "next/back" hunting — every step is visible and editable; advancing just
 * scrolls and updates the rail's "current" indicator. Steps 1 and 3 collapse
 * to dense summaries when not active.
 *
 * Source of truth: design-ref/shadcn/add-feed-view.jsx
 */
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
  type ReactNode,
} from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  ArrowRight,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  Clock,
  Cloud,
  Code,
  Database,
  FileText,
  Globe,
  Info,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  Route as RouteIcon,
  Rss,
  Search as SearchIcon,
  Sparkles,
  X,
  Zap,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { IssueCredentialPanel } from '@/components/add-data/IssueCredentialPanel';
import { CopyButton } from '@/components/add-data/CopyButton';
import { Badge } from '@/components/ui/badge';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from '@/components/ui/command';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { useSchemaFieldMap } from '@/hooks/useSchemaFieldMap';
import {
  ADD_DATA_SOURCE_PARAM,
  DIRECT_PROTOCOLS,
  INGEST_CREDENTIALS_PATH,
  INGEST_ENDPOINT_QUERY_KEY,
  PROTOCOL_LABEL,
  addDataSources,
  preselectedAddDataSource,
  type AddDataSource,
  type DirectProtocol,
} from '@/lib/add-data-sources';
import { CONNECT_STATUS_QUERY_KEY } from '@/lib/api/log-source-connect';
import { CONNECT_SUMMARY, type ConnectStage } from '@/lib/connect-stage';
import { parserSlug, systemSource, useSourceCatalog } from '@/lib/source-catalog';
import { Link } from 'react-router-dom';
import { DeployGatePanel } from '@/components/add-data/DeployGatePanel';
import { computeDeployGate, type GateAction } from '@/components/add-data/deploy-gate';
import { connectDetailQueryKey } from '@/lib/api/log-source-connect';
import { describeSampleSplit, detectWrappedLines, joinWrappedLines } from '@/lib/sample-wrap';
import { isIncompleteDraftStatus, parserDraftIncomplete } from '@/lib/parser-draft-verdict';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useCapabilities } from '@/hooks/use-capabilities';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import {
  PARSER_JOB_MAX_WAIT_MS,
  formatElapsed,
  pollMelodJob,
  useElapsedWhile,
  useMelodJob,
} from '@/enterprise/hooks/use-melod-job';
import { api, ApiClientError } from '@/lib/api';
import type {
  IngestEndpoint,
  LogSource,
  MelodEditParserResponse,
  ParserDraftResponse,
  RoutingRule,
  SourceConfiguration,
  VrlDiagnostic,
} from '@/lib/api';
import { cn } from '@/lib/utils';
import { VrlEditor } from '@/components/editor/VrlEditor';

// ------------------------------------------------------------------
// Constants — lifted verbatim from design-ref/shadcn/add-feed-view.jsx
// ------------------------------------------------------------------
const NAMESPACE_PREFIXES = [
  { id: 'default', label: 'default', desc: 'no isolation', needsSuffix: false, suffixHint: '' },
  { id: 'aws', label: 'aws:', desc: 'AWS account / VPC', needsSuffix: true, suffixHint: '123456789012:vpc-abc' },
  { id: 'gcp', label: 'gcp:', desc: 'GCP project', needsSuffix: true, suffixHint: 'my-project:default' },
  { id: 'azure', label: 'azure:', desc: 'Azure subscription', needsSuffix: true, suffixHint: 'sub-id:rg-name' },
  { id: 'onprem', label: 'onprem:', desc: 'on-premise environment', needsSuffix: true, suffixHint: 'site-nyc:dc-1' },
] as const;

type NamespacePrefixId = typeof NAMESPACE_PREFIXES[number]['id'];

const TIMEZONES: Array<{ region: string; items: Array<{ id: string; label: string; hint: string }> }> = [
  {
    region: 'UTC',
    items: [{ id: 'UTC', label: 'UTC', hint: '±00:00' }],
  },
  {
    region: 'Americas',
    items: [
      { id: 'America/New_York', label: 'New York', hint: 'EST · −05:00' },
      { id: 'America/Chicago', label: 'Chicago', hint: 'CST · −06:00' },
      { id: 'America/Denver', label: 'Denver', hint: 'MST · −07:00' },
      { id: 'America/Los_Angeles', label: 'Los Angeles', hint: 'PST · −08:00' },
      { id: 'America/Anchorage', label: 'Anchorage', hint: 'AKST · −09:00' },
      { id: 'Pacific/Honolulu', label: 'Honolulu', hint: 'HST · −10:00' },
      { id: 'America/Phoenix', label: 'Phoenix', hint: 'MST · −07:00' },
      { id: 'America/Toronto', label: 'Toronto', hint: 'EST · −05:00' },
      { id: 'America/Sao_Paulo', label: 'São Paulo', hint: 'BRT · −03:00' },
    ],
  },
  {
    region: 'Europe',
    items: [
      { id: 'Europe/London', label: 'London', hint: 'GMT · ±00:00' },
      { id: 'Europe/Berlin', label: 'Berlin', hint: 'CET · +01:00' },
      { id: 'Europe/Paris', label: 'Paris', hint: 'CET · +01:00' },
      { id: 'Europe/Moscow', label: 'Moscow', hint: 'MSK · +03:00' },
    ],
  },
  {
    region: 'Asia',
    items: [
      { id: 'Asia/Dubai', label: 'Dubai', hint: 'GST · +04:00' },
      { id: 'Asia/Kolkata', label: 'Kolkata', hint: 'IST · +05:30' },
      { id: 'Asia/Singapore', label: 'Singapore', hint: 'SGT · +08:00' },
      { id: 'Asia/Shanghai', label: 'Shanghai', hint: 'CST · +08:00' },
      { id: 'Asia/Tokyo', label: 'Tokyo', hint: 'JST · +09:00' },
      { id: 'Asia/Seoul', label: 'Seoul', hint: 'KST · +09:00' },
    ],
  },
  {
    region: 'Oceania',
    items: [
      { id: 'Australia/Sydney', label: 'Sydney', hint: 'AEST · +10:00' },
      { id: 'Australia/Perth', label: 'Perth', hint: 'AWT · +08:00' },
      { id: 'Pacific/Auckland', label: 'Auckland', hint: 'NZST · +12:00' },
    ],
  },
];

const CATEGORIES = ['network', 'endpoint', 'cloud', 'application', 'security', 'system'] as const;


// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------
function sanitizeFeedId(value: string): string {
  // NAN-522: REPLACE invalid chars with `_` (preserves position; matches old
  // wizard behavior the user asked for instead of stripping).
  return value.toLowerCase().replace(/[^a-z0-9_-]/g, '_');
}

function countSamples(text: string): number {
  const trimmed = text.trim();
  if (!trimmed) return 0;
  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed)) return parsed.length;
    return 1;
  } catch {
    return trimmed.split(/\r?\n/).filter((l) => l.trim()).length;
  }
}

function splitSamples(text: string): string[] {
  const trimmed = text.trim();
  if (!trimmed) return [];
  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed)) return parsed.map((p) => (typeof p === 'string' ? p : JSON.stringify(p)));
    return [typeof parsed === 'string' ? parsed : JSON.stringify(parsed)];
  } catch {
    return trimmed.split(/\r?\n/).filter((l) => l.trim());
  }
}

/**
 * Format a 24-hour event count like the mock: "107.4M", "4.2M", "2.1B",
 * "12.7K", "184". Returns `null` for null/undefined; "0" for 0 (rare).
 */
/** The raw text of a received event, as the parser will see it. */
function rawParserSample(event: Record<string, unknown>): string {
  for (const key of ['message', 'raw_content', 'raw_log']) {
    const v = event[key];
    if (typeof v === 'string' && v.trim()) return v;
  }
  return JSON.stringify(event);
}

/** The readable column every step but an open Sample & parse keeps (NAN-4945). */
const READABLE_COLUMN = 'w-full max-w-3xl mx-auto';

/** `?stage=` values, mapped to wizard steps. */
// NAN-4922 (main's linear "Add source" flow): internal step ids are stable
// (they key the engine's effects); the display order is LINEAR_ORDER.
// 1 Source → 6 Details → 5 Transport → 2 Connect → 3 Parse → 4 Review.
const STAGE_STEP: Record<string, number> = { source: 1, details: 6, transport: 5, connect: 2, parse: 3, review: 4 };
const STEP_STAGE: Record<number, string> = { 1: 'source', 6: 'details', 5: 'transport', 2: 'connect', 3: 'parse', 4: 'review' };
const LINEAR_ORDER = [1, 6, 5, 2, 3, 4];
/** Gate rows name the step that fixes them; renumber them for the linear flow. */
function linearGateLabel(label: string): string {
  return label.replace(/step (\d)/g, (_m, d: string) => `step ${({ '1': '2', '2': '4', '3': '5', '4': '6' } as Record<string, string>)[d] ?? d}`);
}

function formatEventsCount(n: number | null | undefined): string | null {
  if (n === null || n === undefined) return null;
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)}K`;
  if (n < 1_000_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  return `${(n / 1_000_000_000).toFixed(1)}B`;
}

const SOURCE_ICON_FOR_TYPE = (type: string) => {
  if (type === 'http' || type === 'vector') return Globe;
  if (type === 'aws_s3' || type === 'aws_sqs' || type === 'crowdstrike_fdr' || type === 'gcp_pubsub' || type === 'azure_event_hubs') return Cloud;
  if (type === 'kafka') return Database;
  return Rss;
};

const SOURCE_TYPE_LABEL: Record<string, string> = {
  http: 'HTTP · ingest',
  kafka: 'Kafka',
  aws_s3: 'AWS S3',
  gcp_pubsub: 'GCP Pub/Sub',
  splunk_hec: 'Splunk HEC',
  vector: 'Vector',
  aws_sqs: 'AWS SQS',
  crowdstrike_fdr: 'CrowdStrike FDR',
  azure_event_hubs: 'Azure Event Hubs',
};

// ------------------------------------------------------------------
// Top-level page
// ------------------------------------------------------------------
type SourceConfigWithEvents = SourceConfiguration & { events_24h?: number | null };

export function AddFeed() {
  useDocumentTitle('Add source');
  const navigate = useNavigate();
  const { toast } = useToast();
  const { hasPermission } = useAuth();
  const { capabilities } = useCapabilities();
  const canUseParserAi = capabilities.melod && hasPermission('melod:parser');
  const [searchParams, setSearchParams] = useSearchParams();
  // How data arrives: pushed with an ingest token (the token decides the
  // source) or routed by a source configuration (pull / listener transports).
  const [transport, setTransport] = useState<'push' | 'pull'>('push');
  // NAN-4922: which push protocol the Connect step shows (any token takes all three).
  const [protocol, setProtocol] = useState<DirectProtocol>(() => {
    const requested = searchParams.get('transport');
    return requested === 'hec' || requested === 'otlp_http' ? requested : 'nano_https';
  });
  const [otlpSignal, setOtlpSignal] = useState('log');
  const queryClient = useQueryClient();
  const fieldMap = useSchemaFieldMap();
  const searchSourceField = fieldMap.field('logSource');
  const identifierTouched = useRef(false);
  // ------------ Step 1: the source catalog (main's NAN-4847 picker) ------------
  const catalog = useSourceCatalog();
  const [catalogType, setCatalogType] = useState('custom');
  const repositorySource = catalogType !== 'custom';
  const endpointQuery = useQuery({
    queryKey: INGEST_ENDPOINT_QUERY_KEY,
    queryFn: () => api.getIngestEndpoint(),
    staleTime: 60 * 1000,
    retry: 1,
  });
  const registryQuery = useQuery({ queryKey: ['add-data', 'log-sources'], queryFn: () => api.listLogSources(), staleTime: 30 * 1000 });
  const statusesQuery = useQuery({ queryKey: CONNECT_STATUS_QUERY_KEY, queryFn: () => api.logSourceConnect.listStatus(), staleTime: 30 * 1000, retry: 1 });
  const addSources = useMemo(() => addDataSources(registryQuery.data, statusesQuery.data), [registryQuery.data, statusesQuery.data]);
  const [tokenSaved, setTokenSaved] = useState(false);
  const [credentialIssued, setCredentialIssued] = useState(false);
  const [credentialBusy, setCredentialBusy] = useState(false);
  const connectionLocked = credentialIssued || credentialBusy;

  // ------------ Step 1 state ------------
  const [feedId, setFeedId] = useState('');
  const [sourceConfigId, setSourceConfigId] = useState('');
  const [nsPrefix, setNsPrefix] = useState<NamespacePrefixId>('default');
  const [nsSuffix, setNsSuffix] = useState('');
  const [name, setName] = useState('');
  // Once the user types in `name` directly, stop auto-populating from feedId.
  const nameTouched = useRef(false);
  // A resumed source may route on several match values; the wizard edits the
  // first (the source key) and must carry the rest through every save, or a
  // Save draft / Publish would silently drop those claims.
  const extraMatchValues = useRef<string[]>([]);
  const matchValuesFor = useCallback(
    (key: string) => [key, ...extraMatchValues.current.filter((v) => v !== key)],
    [],
  );
  const [category, setCategory] = useState('');
  const [vendor, setVendor] = useState('');
  const [product, setProduct] = useState('');
  const [description, setDescription] = useState('');

  // ------------ Step 2 state ------------
  const [entryPath, setEntryPath] = useState<'paste' | 'existing' | 'manual'>('paste');
  const [sampleText, setSampleText] = useState('');
  const [vrl, setVrl] = useState('');
  const [genState, setGenState] = useState<'idle' | 'streaming' | 'done' | 'error'>('idle');
  const [genStatus, setGenStatus] = useState<string>('');
  // NAN-4912 P3: the draft runs as a server job (up to 25 min); this aborts
  // polling, and `genJobIdRef` lets Cancel stop the job on the server.
  const genControllerRef = useRef<AbortController | null>(null);
  const genJobIdRef = useRef<string | null>(null);
  const genElapsedMs = useElapsedWhile(genState === 'streaming');
  const [timezone, setTimezone] = useState('UTC');
  const [sidePane, setSidePane] = useState<'diag' | 'tests' | 'ai'>('diag');

  // Validation results — populated on demand.
  const [validation, setValidation] = useState<{
    diagnostics: VrlDiagnostic[];
    syntaxValid: boolean | null;
    errorMessages: string[];
  }>({ diagnostics: [], syntaxValid: null, errorMessages: [] });
  const [isValidating, setIsValidating] = useState(false);

  // Per-sample test results (one entry per non-empty sample line).
  const [tests, setTests] = useState<Array<{ name: string; status: 'pass' | 'fail'; extracted: number; error?: string }>>([]);
  const [isTesting, setIsTesting] = useState(false);

  // PIVT (AI tab) state — stable session id per page load.
  const sessionIdRef = useRef<string>(`add-feed-${Date.now()}`);
  const [pivtMessage, setPivtMessage] = useState('');
  const [pivtPending, setPivtPending] = useState(false);
  const [pivtSuggestion, setPivtSuggestion] = useState<MelodEditParserResponse | null>(null);
  const editParserJob = useMelodJob<MelodEditParserResponse>();

  // ------------ Step 3 state ------------
  const [acceptWarnings, setAcceptWarnings] = useState(false);
  const [draftId, setDraftId] = useState<string | null>(null);
  // Connect state of the draft (shared cache with the Connect panel's poll).
  const connectDetail = useQuery({
    queryKey: connectDetailQueryKey(draftId ?? ''),
    queryFn: () => api.logSourceConnect.getStatus(draftId as string),
    enabled: !!draftId,
    staleTime: 2000,
  });
  // NAN-1920: guards the debounced auto-persist effect against firing two
  // overlapping CREATE calls before `draftId` state settles (create is async).
  const autoPersistInFlight = useRef(false);
  // NAN-1920: `draftId` state lags a create by a render; these refs give the
  // handlers a synchronous view so an explicit Save/Deploy that lands mid
  // auto-persist reuses the same row instead of racing a second create.
  const draftIdRef = useRef<string | null>(null);
  const autoPersistPromiseRef = useRef<Promise<void> | null>(null);
  // NAN-1920: the pending (not-yet-fired) debounce timer. Held in a ref so an
  // explicit Save/Deploy can cancel it before it races a second create.
  const debounceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [savingDraft, setSavingDraft] = useState(false);
  const [deploying, setDeploying] = useState(false);
  // For new-feed creation, "reachability" really means "is the transport
  // ready to accept events?" — i.e. is the source config enabled + deployed.
  // The backend's `reachable` flag also requires the target log source to
  // exist, but in the new-feed flow we're CREATING that log source, so it's
  // expected to be missing until the user clicks Deploy. We therefore
  // ignore `reachable` and `target_log_source_exists` and derive readiness
  // from the transport flags alone.
  const [reachability, setReachability] = useState<{
    transportReady: boolean;
    sourceConfigEnabled: boolean;
    sourceConfigDeployed: boolean;
    checked: boolean;
  } | null>(null);
  const [namespaceCheck, setNamespaceCheck] = useState<{ valid: boolean; error?: string; checked: boolean } | null>(null);

  // ------------ Cross-cutting state ------------
  const [activeStep, setActiveStep] = useState(1);
  // Steps appear one at a time, in LINEAR_ORDER, and stay once reached.
  const [revealedStep, setRevealedStep] = useState(0);
  const activeRank = LINEAR_ORDER.indexOf(activeStep);
  useEffect(() => { setRevealedStep((prev) => Math.max(prev, activeRank)); }, [activeRank]);

  // ------------ Source configurations (real API) ------------
  const [sourceConfigs, setSourceConfigs] = useState<SourceConfigWithEvents[]>([]);
  const [loadingConfigs, setLoadingConfigs] = useState(true);
  const [existingRules, setExistingRules] = useState<RoutingRule[]>([]);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const configs = await api.listSourceConfigs({ enabled: true });
        if (cancelled) return;
        setSourceConfigs(configs as SourceConfigWithEvents[]);
      } catch (err) {
        if (cancelled) return;
        toast({
          title: 'Failed to load source configurations',
          description: err instanceof Error ? err.message : 'Unknown error',
          variant: 'destructive',
        });
      } finally {
        if (!cancelled) setLoadingConfigs(false);
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, [toast]);

  // Fetch routing rules whenever the selected source config changes — used
  // for the "Existing routing targets" picker (NAN-522 step 4 behavior).
  useEffect(() => {
    if (!sourceConfigId) {
      setExistingRules([]);
      return;
    }
    let cancelled = false;
    api
      .listRoutingRules(sourceConfigId)
      .then((rules) => {
        if (!cancelled) setExistingRules(rules);
      })
      .catch(() => {
        if (!cancelled) setExistingRules([]);
      });
    return () => {
      cancelled = true;
    };
  }, [sourceConfigId]);

  // ------------ Auto-populate name from feedId ------------
  // Mirror feedId into name on every keystroke until the user manually edits
  // the Name field. Tracked via nameTouched (set by the wrapped setName below).
  useEffect(() => {
    if (!nameTouched.current && feedId) {
      setName(feedId);
    }
    // intentionally only on feedId change
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [feedId]);

  // ------------ Derived state ------------
  const sampleCount = useMemo(() => countSamples(sampleText), [sampleText]);
  const errors = validation.diagnostics.filter((d) => d.severity === 'error').length;
  const passingTests = tests.filter((t) => t.status === 'pass').length;
  const failingTests = tests.length - passingTests;
  const testsRun = tests.length > 0;

  const sourceConfig = sourceConfigs.find((c) => c.id === sourceConfigId);
  const namespaceFull =
    nsPrefix === 'default'
      ? 'default'
      : `${NAMESPACE_PREFIXES.find((p) => p.id === nsPrefix)?.label ?? ''}${nsSuffix}`;

  // Existing rules whose target differs from this feedId — show as picker.
  const otherTargets = useMemo(
    () => existingRules.filter((r) => r.target_source_type && r.target_source_type !== feedId),
    [existingRules, feedId],
  );

  // NAN-4754: the gate is computed from real state (see deploy-gate.ts): a
  // parser is required, samples are the tests, no samples is an acknowledged
  // warning, and a push source with no token / no events is a warning.
  const rawDeployGate = computeDeployGate({
    transport,
    strictOcsf: false,
    feedId,
    name,
    sourceConfigId,
    vrl,
    syntaxValid: validation.syntaxValid,
    isValidating,
    errors,
    warningMessages: validation.diagnostics.filter((d) => d.severity === 'warn').map((d) => d.message),
    // Expert mode hides the samples box (and its deploy sends none), so
    // leftover text must not gate it as invisible tests.
    sampleCount: entryPath === 'manual' ? 0 : sampleCount,
    testsRun,
    isTesting,
    passingTests,
    failingTests,
    transportReady: reachability?.checked ? reachability.transportReady : null,
    transportLabel:
      reachability?.checked && !reachability.transportReady
        ? !reachability.sourceConfigEnabled
          ? 'Transport · source config disabled'
          : !reachability.sourceConfigDeployed
            ? 'Transport · source config not deployed'
            : 'Transport · not ready'
        : undefined,
    connection: connectDetail.data
      ? {
          activeTokens: connectDetail.data.active_tokens,
          eventsReceived: connectDetail.data.events_24h,
        }
      : draftId
        ? null
        : { activeTokens: 0, eventsReceived: 0 },
    namespaceValid: namespaceCheck?.checked ? namespaceCheck.valid : null,
    namespaceError: namespaceCheck?.error,
    acknowledged: acceptWarnings,
  });
  const deployGate = { ...rawDeployGate, checks: rawDeployGate.checks.map((check) => ({ ...check, label: linearGateLabel(check.label) })) };
  const canDeploy = deployGate.canDeploy;

  // ------------ Validation runner ------------
  const runValidate = useCallback(
    async (showToast = false): Promise<boolean> => {
      if (!vrl.trim()) {
        setValidation({ diagnostics: [], syntaxValid: null, errorMessages: ['VRL is empty'] });
        return false;
      }
      setIsValidating(true);
      try {
        const result = await api.validateLogSourceVrl(vrl);
        const diagnostics: VrlDiagnostic[] =
          result.diagnostics ??
          // Fallback: synthesize "error" diagnostics from `errors` strings if
          // backend hasn't shipped /diagnostics yet (NAN-522 backend change).
          result.errors.map((message) => ({ severity: 'error' as const, message }));
        setValidation({
          diagnostics,
          syntaxValid: result.valid,
          errorMessages: result.errors,
        });
        if (showToast) {
          if (result.valid) {
            toast({ title: 'VRL valid', description: 'Parser syntax is correct' });
          } else {
            toast({
              title: 'VRL invalid',
              description: result.errors.join(', ') || 'See diagnostics for details',
              variant: 'destructive',
            });
          }
        }
        return result.valid;
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Validation failed';
        setValidation({
          diagnostics: [{ severity: 'error', message }],
          syntaxValid: false,
          errorMessages: [message],
        });
        if (showToast) {
          toast({ title: 'Validation failed', description: message, variant: 'destructive' });
        }
        return false;
      } finally {
        setIsValidating(false);
      }
    },
    [toast, vrl],
  );

  // ------------ Per-sample tests runner ------------
  const runTests = useCallback(async () => {
    const samples = splitSamples(sampleText);
    if (!vrl.trim() || samples.length === 0) {
      setTests([]);
      return;
    }
    setIsTesting(true);
    try {
      const results = await Promise.all(
        samples.map(async (sample, i) => {
          try {
            const r = await api.testLogSourceVrl(vrl, sample);
            const extracted =
              r.extracted_field_count ??
              (r.output ? Object.keys(r.output).length : 0);
            return {
              name: `sample ${i + 1}`,
              status: r.success ? ('pass' as const) : ('fail' as const),
              extracted,
              error: r.error,
            };
          } catch (err) {
            return {
              name: `sample ${i + 1}`,
              status: 'fail' as const,
              extracted: 0,
              error: err instanceof Error ? err.message : 'Test failed',
            };
          }
        }),
      );
      setTests(results);
    } finally {
      setIsTesting(false);
    }
  }, [sampleText, vrl]);

  // Run validate + tests automatically when VRL settles (small debounce).
  useEffect(() => {
    if (!vrl || genState === 'streaming') return;
    const t = setTimeout(() => {
      void runValidate();
      void runTests();
    }, 600);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vrl, sampleText, genState]);

  // ------------ Streaming parser generation ------------
  const handleRegenerate = useCallback(async () => {
    if (!canUseParserAi) return;
    const samples = splitSamples(sampleText);
    if (samples.length === 0 && entryPath !== 'manual') {
      toast({
        title: 'No samples',
        description: 'Paste at least one sample log to generate a parser.',
        variant: 'destructive',
      });
      return;
    }
    if (!feedId) {
      toast({ title: 'Feed identifier required', description: 'Set a feed identifier first.', variant: 'destructive' });
      return;
    }
    genControllerRef.current?.abort();
    const controller = new AbortController();
    genControllerRef.current = controller;
    genJobIdRef.current = null;
    setGenState('streaming');
    setGenStatus('Starting the draft job…');

    // NAN-4753 / NAN-4778: parser drafting runs as a background job (a
    // reasoning model can take 5–10 minutes); poll it instead of holding a
    // stream open through proxies. The samples are what the source received
    // (seeded by the Sample step) or what the analyst pasted. Don't send
    // `feed_id` — the log source may not exist yet; inline samples suffice.
    try {
      const draft = await pollMelodJob<ParserDraftResponse>(
        () =>
          api.melodCreateParserJob({
            log_source_type: feedId,
            sample_logs: samples,
            message: `Generate a VRL parser for "${feedId}" logs from these ${samples.length} sample event(s). The .source_type field is ALREADY SET — do NOT modify it. Extract all useful fields into the UDM schema.`,
          }),
        {
          maxWaitMs: PARSER_JOB_MAX_WAIT_MS,
          signal: controller.signal,
          onJobId: (jobId) => {
            if (genControllerRef.current === controller) genJobIdRef.current = jobId;
          },
          onProgress: (message) => {
            if (genControllerRef.current === controller && message) setGenStatus(message);
          },
        },
      );
      if (genControllerRef.current !== controller) return;
      setVrl(draft.parser.vrl_code);
      setGenState('done');
      setGenStatus(draft.message);
      if (parserDraftIncomplete(draft)) {
        toast({ title: 'Draft incomplete', description: draft.message, variant: 'destructive' });
      }
    } catch (err) {
      if (genControllerRef.current !== controller) return;
      const message = err instanceof Error ? err.message : 'Generation failed';
      if (controller.signal.aborted) {
        setGenState('idle');
        setGenStatus('');
        return;
      }
      setGenState('error');
      setGenStatus(message);
      toast({ title: 'Generation failed', description: message, variant: 'destructive' });
    } finally {
      if (genControllerRef.current === controller) {
        genControllerRef.current = null;
        genJobIdRef.current = null;
      }
    }
  }, [canUseParserAi, entryPath, feedId, sampleText, toast]);

  // Cancel the draft: stop polling and stop the server job (NAN-4912 P3).
  const handleCancelGenerate = useCallback(() => {
    if (!canUseParserAi) return;
    const jobId = genJobIdRef.current;
    genJobIdRef.current = null;
    genControllerRef.current?.abort();
    if (jobId) void api.cancelMelodJob(jobId).catch(() => undefined);
  }, [canUseParserAi]);

  // Stop polling on unmount. The server job keeps running to completion;
  // only an explicit Cancel stops it.
  useEffect(() => {
    return () => {
      genControllerRef.current?.abort();
    };
  }, []);

  // ------------ PIVT edit-parser submit ------------
  const sendPivtMessage = useCallback(
    async (message: string) => {
      if (!canUseParserAi) return;
      if (!message.trim() || !vrl.trim()) {
        toast({
          title: 'Need a parser',
          description: 'Generate or paste VRL before chatting with pivt.',
          variant: 'destructive',
        });
        return;
      }
      setPivtPending(true);
      setPivtSuggestion(null);
      try {
        const samples = splitSamples(sampleText);
        const result = await editParserJob.start(() =>
          api.melodEditParser({
            // Drafts have no id — pass empty string; backend treats as unsaved.
            parser_id: draftId ?? '',
            current_vrl: vrl,
            message,
            sample_logs: samples,
            session_id: sessionIdRef.current,
          }),
          { maxWaitMs: PARSER_JOB_MAX_WAIT_MS },
        );
        setPivtSuggestion(result);
        setPivtMessage('');
      } catch (err) {
        toast({
          title: 'pivt edit failed',
          description: err instanceof Error ? err.message : 'Unknown error',
          variant: 'destructive',
        });
      } finally {
        setPivtPending(false);
      }
    },
    [canUseParserAi, draftId, editParserJob, sampleText, toast, vrl],
  );

  // ------------ Step 3 helpers — namespace + reachability ------------
  // Re-check namespace + reachability when entering / state changes.
  useEffect(() => {
    if (activeStep !== 4) return;
    let cancelled = false;
    (async () => {
      try {
        const result = await api.validateNamespace(namespaceFull);
        if (!cancelled) setNamespaceCheck({ valid: result.valid, error: result.error, checked: true });
      } catch {
        // Endpoint may not be live yet (backend in parallel) — treat as valid
        // and surface a soft note in the UI rather than blocking deploy.
        if (!cancelled) setNamespaceCheck({ valid: true, checked: true });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [activeStep, namespaceFull]);

  useEffect(() => {
    if (activeStep !== 4 || transport !== 'pull' || !sourceConfigId || !feedId) return;
    let cancelled = false;
    (async () => {
      try {
        const result = await api.checkRoutingRuleReachability(sourceConfigId, {
          target_source_type: feedId,
          match_field: 'source_type',
          match_type: 'exact',
          match_value: feedId,
        });
        if (!cancelled) {
          setReachability({
            transportReady: result.source_config_enabled && result.source_config_deployed,
            sourceConfigEnabled: result.source_config_enabled,
            sourceConfigDeployed: result.source_config_deployed,
            checked: true,
          });
        }
      } catch {
        // Endpoint may not be live yet — soft-allow.
        if (!cancelled) {
          setReachability({
            transportReady: true,
            sourceConfigEnabled: true,
            sourceConfigDeployed: true,
            checked: true,
          });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [activeStep, transport, sourceConfigId, feedId]);

  // NAN-1920: await any in-flight auto-persist create and return the resulting
  // draft id (synchronously via ref). Callers use this to reuse the auto-saved
  // row instead of issuing a second, duplicate `createLogSource`.
  const settleAutoPersist = useCallback(async (): Promise<string | null> => {
    // Cancel a pending (not-yet-fired) debounce timer first — otherwise it could
    // fire a SECOND createLogSource after this explicit Save/Deploy already
    // created the row.
    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current);
      debounceTimerRef.current = null;
    }
    if (autoPersistPromiseRef.current) {
      try {
        await autoPersistPromiseRef.current;
      } catch {
        /* auto-persist handles its own errors; fall through to the ref value */
      }
    }
    return draftIdRef.current;
  }, []);

  // ------------ Save draft ------------
  const handleSaveDraft = useCallback(async () => {
    if (!feedId || !name) {
      toast({
        title: 'Missing fields',
        description: 'Feed identifier and display name are required.',
        variant: 'destructive',
      });
      return;
    }
    setSavingDraft(true);
    try {
      // NAN-1920: reuse the auto-persisted row if a create is in flight/done.
      const existingId = await settleAutoPersist();
      const payload = {
        name,
        description: description || undefined,
        namespace: namespaceFull,
        timezone,
        source_type: 'routed',
        // NAN-1906: carry the picked transport into the draft too, so a feed
        // later deployed from this draft still shows its real transport. May be
        // unset while the source config hasn't been chosen yet.
        dispatch_source_config_id: transport === 'pull' ? sourceConfigId || undefined : undefined,
        parser_vrl: vrl,
        category: category || undefined,
        vendor: vendor || undefined,
        product: product || undefined,
        match_values: matchValuesFor(feedId),
      };
      if (existingId) {
        // NAN-1920: lifecycle_status is server-controlled — an update never
        // touches it, so an existing draft stays a draft here.
        await api.updateLogSource(existingId, payload);
      } else {
        // Fresh row from an explicit "Save draft" is created in the draft
        // lifecycle; the server flips it to 'active' only on deploy.
        const created = await api.createLogSource({ ...payload, lifecycle_status: 'draft' as const });
        draftIdRef.current = created.id;
        setDraftId(created.id);
      }
      toast({ title: 'Draft saved', description: `Feed "${name}" saved as draft.` });
    } catch (err) {
      toast({
        title: 'Save failed',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setSavingDraft(false);
    }
  }, [matchValuesFor, category, description, feedId, name, namespaceFull, product, settleAutoPersist, sourceConfigId, timezone, toast, transport, vendor, vrl]);

  // ------------ Auto-persist draft (NAN-1920) ------------
  // Persist the in-progress feed as a `lifecycle_status='draft'` log source as
  // soon as Step 1 is minimally valid (feedId + display name). This is the core
  // of NAN-1920: navigating away no longer silently loses the feed — it lands
  // in Log Sources as a resumable Draft. We only CREATE here (guarded by
  // `!draftId`); later field edits are flushed by explicit Save draft / Deploy,
  // which keeps this unobtrusive (no continuous PUT-on-keystroke churn).
  const autoPersistDraft = useCallback(async () => {
    if (draftId || draftIdRef.current || autoPersistInFlight.current) return;
    if (!feedId || !name) return;
    autoPersistInFlight.current = true;
    try {
      const created = await api.createLogSource({
        name,
        description: description || undefined,
        namespace: namespaceFull,
        timezone,
        source_type: 'routed',
        dispatch_source_config_id: transport === 'pull' ? sourceConfigId || undefined : undefined,
        parser_vrl: vrl,
        category: category || undefined,
        vendor: vendor || undefined,
        product: product || undefined,
        match_values: matchValuesFor(feedId),
        lifecycle_status: 'draft' as const,
      });
      draftIdRef.current = created.id;
      setDraftId(created.id);
    } catch {
      // Best-effort: no toast storm while the user is still typing. The explicit
      // "Save draft" button surfaces errors (e.g. a duplicate feed name).
    } finally {
      autoPersistInFlight.current = false;
    }
  }, [matchValuesFor, category, description, draftId, feedId, name, namespaceFull, product, sourceConfigId, timezone, transport, vendor, vrl]);

  // Debounced trigger: create the draft ~1.2s after the user pauses once Step 1
  // is valid, rather than on every keystroke. Re-arms while `!draftId`; once the
  // draft exists this becomes inert.
  useEffect(() => {
    // NAN-4922 (main's linear flow): the draft is created at Transport →
    // Continue, never from a half-typed Step 1 name; after that it exists.
    if (draftId || !feedId || !name || revealedStep < LINEAR_ORDER.indexOf(2)) return;
    // Store the timer in a ref so settleAutoPersist can cancel a still-pending
    // debounce before it races a second create.
    debounceTimerRef.current = setTimeout(() => {
      debounceTimerRef.current = null;
      // Capture the in-flight promise so an explicit Save/Deploy can await it
      // (via settleAutoPersist) and reuse the row instead of racing a create.
      autoPersistPromiseRef.current = autoPersistDraft();
    }, 1200);
    return () => {
      if (debounceTimerRef.current) {
        clearTimeout(debounceTimerRef.current);
        debounceTimerRef.current = null;
      }
    };
  }, [feedId, name, draftId, autoPersistDraft, revealedStep]);

  // ------------ Navigation guard (NAN-1920) ------------
  // Browser close / refresh guard, mirroring the RuleEditor/Dashboard pattern
  // (the app uses BrowserRouter, so React Router's `useBlocker` isn't available).
  // Only meaningful BEFORE the first auto-save — once `draftId` is set the feed
  // is safely persisted as a Draft, so we don't nag on the way out.
  useEffect(() => {
    const hasUnsavedWork =
      !draftId && (Boolean(feedId) || Boolean(name) || Boolean(vrl.trim()) || Boolean(sampleText.trim()));
    const handler = (e: BeforeUnloadEvent) => {
      if (!hasUnsavedWork) return;
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, [draftId, feedId, name, vrl, sampleText]);

  // ------------ Deploy ------------
  const handleDeploy = useCallback(async () => {
    if (!canDeploy || (transport === 'pull' && !sourceConfigId)) return;
    setDeploying(true);
    try {
      // 1. Pull / listener transports only: create the routing rule on the
      //    source config (matches old wizard's two-call submit). Non-fatal: a
      //    duplicate or inactive transport shouldn't block the log-source
      //    create. A pushed source needs no rule: its ingest token decides it.
      let routingRuleCreated = false;
      if (transport === 'pull') try {
        await api.createRoutingRule(sourceConfigId, {
          match_field: 'source_type',
          match_type: 'exact',
          match_value: feedId,
          target_source_type: feedId,
        });
        routingRuleCreated = true;
      } catch (err) {
        toast({
          title: 'Routing rule warning',
          description: err instanceof Error ? err.message : 'Failed to create routing rule',
          variant: 'destructive',
        });
      }

      // 2. Create (or update) the log source. `source_type: 'routed'` is the
      //    sentinel value that tells the backend this parser receives traffic
      //    via the central source_router; `match_values` drives that router.
      //    NAN-1906: also record the picked source config as the dispatch link
      //    so Log Sources renders the real transport (GCP Pub/Sub, Kafka, …) via
      //    the NAN-1084 JOIN instead of falling back to `source_type` → "HTTP".
      //    Inert for routing: source/router codegen keys on `source_type`
      //    ('routed'), never the dispatch id, for a routed parser.
      const payload = {
        name,
        description: description || undefined,
        namespace: namespaceFull,
        timezone,
        source_type: 'routed',
        dispatch_source_config_id: transport === 'pull' ? sourceConfigId : undefined,
        parser_vrl: vrl,
        category: category || undefined,
        vendor: vendor || undefined,
        product: product || undefined,
        match_values: matchValuesFor(feedId),
        // NAN-1920: lifecycle_status is server-controlled and intentionally
        // omitted here. The api.deployLogSource call below flips draft → active
        // server-side (which enforces the tier cap at that transition); a fresh
        // create in the else-branch defaults to 'active' server-side.
      };
      // NAN-1920: reuse the auto-persisted row if a create is in flight/done,
      // so deploying mid auto-persist doesn't race a duplicate create.
      const existingId = await settleAutoPersist();
      let createdId = existingId;
      if (existingId) {
        await api.updateLogSource(existingId, payload);
      } else {
        const created = await api.createLogSource(payload);
        createdId = created.id;
        draftIdRef.current = created.id;
        setDraftId(created.id);
      }

      // 3. Auto-deploy both layers. The new design's "Deploy feed" CTA
      //    promises a live feed; this matches the meloD concierge flow that
      //    redeploys the source config after creating its routing rule, and
      //    deploys the log source so the central router picks up match_values.
      if (routingRuleCreated) {
        try {
          await api.deploySourceConfig(sourceConfigId);
        } catch (err) {
          toast({
            title: 'Source config redeploy failed',
            description: err instanceof Error ? err.message : 'Routing rule saved but transport not yet redeployed.',
            variant: 'destructive',
          });
        }
      }
      let parserDeployFailed = false;
      if (createdId) {
        try {
          const deployed = await api.deployLogSource(createdId);
          // NAN-5133: a 200 with success:false did not go live; say so.
          if (deployed && deployed.success === false) throw new Error(deployed.message || 'Log source created but parser not yet deployed.');
        } catch (err) {
          parserDeployFailed = true;
          toast({
            title: 'Log source deploy failed',
            description: err instanceof Error ? err.message : 'Log source created but parser not yet deployed.',
            variant: 'destructive',
          });
        }
      }

      if (!parserDeployFailed) toast({ title: 'Source published', description: `${name} is now parsed.` });
      if (createdId) {
        navigate(`/ingestion/log-sources/${createdId}`);
      } else {
        navigate('/ingestion/log-sources');
      }
    } catch (err) {
      const isApiError = err instanceof ApiClientError;
      toast({
        title: 'Deploy failed',
        description: isApiError ? err.message : err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setDeploying(false);
    }
  }, [matchValuesFor, canDeploy, category, description, feedId, name, namespaceFull, navigate, product, settleAutoPersist, sourceConfigId, timezone, toast, transport, vendor, vrl]);

  // ------------ Connect (NAN-4912): the draft exists before any parser ------------
  // Creates the draft now if auto-persist has not, and flushes the current
  // identity into it so the token's route key is the key on screen.
  const [ensuringDraft, setEnsuringDraft] = useState(false);
  const ensureDraft = useCallback(async (): Promise<string | null> => {
    if (!feedId || !name) return null;
    setEnsuringDraft(true);
    const payload = {
      name,
      description: description || undefined,
      namespace: namespaceFull,
      timezone,
      source_type: 'routed',
      dispatch_source_config_id: transport === 'pull' ? sourceConfigId || undefined : undefined,
      parser_vrl: vrl,
      category: category || undefined,
      vendor: vendor || undefined,
      product: product || undefined,
      match_values: matchValuesFor(feedId),
    };
    try {
      const existingId = await settleAutoPersist();
      if (existingId) {
        await api.updateLogSource(existingId, payload);
        return existingId;
      }
      const created = await api.createLogSource({ ...payload, lifecycle_status: 'draft' as const });
      draftIdRef.current = created.id;
      setDraftId(created.id);
      return created.id;
    } catch (err) {
      toast({
        title: 'Could not create the source',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
      return null;
    } finally {
      setEnsuringDraft(false);
    }
  }, [matchValuesFor, category, description, feedId, name, namespaceFull, product, settleAutoPersist, sourceConfigId, timezone, toast, transport, vendor, vrl]);

  // ------------ Step 1: catalog choice (main's chooseCatalog) ------------
  const chooseCatalog = useCallback((id: string) => {
    setCatalogType(id);
    identifierTouched.current = false;
    if (id === 'custom') {
      nameTouched.current = false;
      setFeedId(''); setName(''); setVrl(''); setVendor(''); setProduct(''); setCategory(''); setDescription('');
      return;
    }
    const parser = catalog.data?.find((p) => p.id === id);
    if (!parser) return;
    nameTouched.current = true;
    // NAN-5264: the parser's own match value, not its name (windows_sysmon, not windows_sysmon_ocsf).
    setFeedId(parser.match_value); setName(parser.display_name ?? parser.name ?? parser.match_value);
    setVendor(parser.vendor ?? ''); setProduct(parser.product ?? ''); setCategory(parser.category ?? ''); setDescription(parser.description ?? '');
    setVrl(parser.parser_vrl ?? '');
  }, [catalog.data]);
  const catalogDeepLinkApplied = useRef(false);
  useEffect(() => {
    const type = searchParams.get('type');
    if (!type || catalogDeepLinkApplied.current || !catalog.data) return;
    const parser = catalog.data.find((p) => p.id === type || p.match_value === type || parserSlug(p) === type);
    if (parser) { catalogDeepLinkApplied.current = true; chooseCatalog(parser.id); }
  }, [searchParams, catalog.data, chooseCatalog]);

  // ------------ Transport → Continue: create (or import) the source ------------
  // A custom source becomes a draft that receives events before its parser
  // exists. A repository source is imported linked and deployed at once, so
  // its Connect step can finish without the parse step (main's NAN-4847).
  const [preparing, setPreparing] = useState(false);
  const [repositoryDeployed, setRepositoryDeployed] = useState(false);
  const prepareConnection = useCallback(async () => {
    setPreparing(true);
    try {
      let id: string | null = draftIdRef.current;
      if (repositorySource && !id) {
        const parser = catalog.data?.find((p) => p.id === catalogType);
        if (!parser) throw new Error('Choose an available repository source.');
        const imported = await api.parserRepositories.importParser(parser.repository_id, parser.file_path, {
          import_type: 'linked',
          source_type: feedId,
          ingestion_method: 'routed',
          dispatch_source_config_id: transport === 'pull' ? sourceConfigId || undefined : undefined,
        });
        id = imported.log_source_id;
        draftIdRef.current = id;
        setDraftId(id);
      } else {
        id = await ensureDraft();
        if (!id) return;
      }
      if (repositorySource && id && !repositoryDeployed) {
        const result = await api.deployLogSource(id);
        if (result.success === false) throw new Error(result.message || 'The repository source could not be deployed.');
        setRepositoryDeployed(true);
      }
      void queryClient.invalidateQueries({ queryKey: CONNECT_STATUS_QUERY_KEY });
      setActiveStep(transport === 'push' ? 2 : repositorySource ? 4 : 3);
    } catch (err) {
      toast({ title: 'Could not prepare the ingest path', description: err instanceof Error ? err.message : 'Try again.', variant: 'destructive' });
    } finally {
      setPreparing(false);
    }
  }, [catalog.data, catalogType, ensureDraft, feedId, queryClient, repositoryDeployed, repositorySource, sourceConfigId, toast, transport]);

  // ------------ `?source=<slug>` (NAN-2946): an existing source opens on Connect ------------
  const requestedSource = searchParams.get(ADD_DATA_SOURCE_PARAM);
  const sourceDeepLinkApplied = useRef(false);
  useEffect(() => {
    if (sourceDeepLinkApplied.current || !requestedSource || registryQuery.isLoading || statusesQuery.isLoading) return;
    sourceDeepLinkApplied.current = true;
    const target = preselectedAddDataSource(addSources, requestedSource);
    if (!target?.logSource) return;
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete(ADD_DATA_SOURCE_PARAM);
      next.set('source_id', target.logSource!.id);
      next.set('stage', 'connect');
      return next;
    }, { replace: true });
  }, [addSources, registryQuery.isLoading, requestedSource, setSearchParams, statusesQuery.isLoading]);

  // Received events are the best samples: pull the 10 most recent for this key.
  const [loadingReceived, setLoadingReceived] = useState(false);
  const loadReceivedSamples = useCallback(async (): Promise<number> => {
    if (!feedId) return 0;
    setLoadingReceived(true);
    try {
      const end = new Date();
      const result = await api.search({
        query: `${searchSourceField}=${JSON.stringify(feedId)}`,
        time_range: { start: new Date(end.getTime() - 24 * 60 * 60 * 1000).toISOString(), end: end.toISOString() },
        limit: 10,
        skip_field_stats: true,
        skip_histogram: true,
      });
      const samples = (result.results ?? []).map((e) => rawParserSample(e as Record<string, unknown>)).filter(Boolean);
      if (samples.length > 0) {
        setSampleText(samples.join('\n'));
        setEntryPath('paste');
      }
      return samples.length;
    } catch (err) {
      toast({
        title: 'Could not load received events',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
      return 0;
    } finally {
      setLoadingReceived(false);
    }
  }, [feedId, searchSourceField, toast]);

  const goParse = useCallback(() => setActiveStep(3), []);

  // Entering Parse with no samples while the source already receives (also on
  // a `?stage=parse` resume): seed the samples from what arrived, once.
  const receivedAutoLoaded = useRef(false);
  const receivedEvents = connectDetail.data?.events_24h ?? 0;
  useEffect(() => {
    if (activeStep !== 3 || receivedAutoLoaded.current || sampleText.trim() || receivedEvents === 0 || !feedId) return;
    receivedAutoLoaded.current = true;
    void loadReceivedSamples();
  }, [activeStep, feedId, loadReceivedSamples, receivedEvents, sampleText]);

  // ------------ Resume (NAN-4800 / NAN-2946): ?source_id=&stage= ------------
  const resumeSourceId = searchParams.get('source_id');
  const resumedRef = useRef<string | null>(null);
  useEffect(() => {
    if (!resumeSourceId || resumedRef.current === resumeSourceId) return;
    resumedRef.current = resumeSourceId;
    let cancelled = false;
    void (async () => {
      try {
        const source = await api.getLogSource(resumeSourceId);
        if (cancelled) return;
        draftIdRef.current = source.id;
        setDraftId(source.id);
        nameTouched.current = true;
        identifierTouched.current = true;
        setFeedId(source.match_values?.[0] ?? sanitizeFeedId(source.name));
        extraMatchValues.current = (source.match_values ?? []).slice(1);
        setName(source.name);
        setVendor(source.vendor ?? '');
        setProduct(source.product ?? '');
        setCategory(source.category ?? '');
        setDescription(source.description ?? '');
        setVrl(source.parser_vrl ?? '');
        setTimezone(source.timezone ?? 'UTC');
        const prefix = NAMESPACE_PREFIXES.find((item) => item.id !== 'default' && source.namespace?.startsWith(item.label));
        setNsPrefix(prefix?.id ?? 'default');
        setNsSuffix(prefix ? source.namespace.slice(prefix.label.length) : '');
        if (source.dispatch_source_config_id) {
          setTransport('pull');
          setSourceConfigId(source.dispatch_source_config_id);
        } else {
          setTransport('push');
        }
        // A resumed source exists already: Source, Details and Transport are behind it.
        setRevealedStep(LINEAR_ORDER.indexOf(5));
        setActiveStep(STAGE_STEP[searchParams.get('stage') ?? ''] ?? 2);
      } catch (err) {
        if (!cancelled) {
          toast({
            title: 'Could not open the source',
            description: err instanceof Error ? err.message : 'Unknown error',
            variant: 'destructive',
          });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [resumeSourceId, searchParams, toast]);

  // Keep the address resumable once the draft exists (replace, no history entry).
  useEffect(() => {
    if (!draftId || activeRank < LINEAR_ORDER.indexOf(2)) return;
    if (resumeSourceId && resumedRef.current !== resumeSourceId) return; // a pending resume owns the URL
    const stage = STEP_STAGE[activeStep];
    if (searchParams.get('source_id') === draftId && searchParams.get('stage') === stage) return;
    resumedRef.current = draftId;
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.set('source_id', draftId);
        next.set('stage', stage);
        return next;
      },
      { replace: true },
    );
  }, [activeRank, activeStep, draftId, resumeSourceId, searchParams, setSearchParams]);

  const onGateAction = useCallback(
    (action: GateAction) => {
      if (action === 'step1') setActiveStep(6);
      else if (action === 'connect') setActiveStep(transport === 'push' ? 2 : 5);
      else if (action === 'step2') setActiveStep(3);
      else void runTests();
    },
    [runTests, transport],
  );

  // ------------ Render (main's linear "Add source" flow, NAN-4922) ------------
  const issueSource: AddDataSource | null = draftId && feedId
    ? { slug: feedId, protocols: [...DIRECT_PROTOCOLS], enrolled: true, events24h: connectDetail.data?.events_24h, lastEventAt: connectDetail.data?.last_seen ?? null }
    : null;
  const needsParserWork = !repositorySource;
  const finishHref = `/ingestion/log-sources${draftId ? `?highlight=${encodeURIComponent(draftId)}` : ''}`;
  const parseWide = activeStep === 3 && needsParserWork;
  return (
    <div className="col-start-2 row-start-2 min-h-0 relative flex flex-col bg-background">
      <AddFeedHero feedId={feedId} transport={transport} protocol={protocol} sourceConfig={sourceConfig} hostname={endpointQuery.data?.hostname} />

      <div className="flex-1 min-h-0 overflow-auto scrollbar-thin">
        {/* NAN-4945: the column is full width. Steps keep a readable width; Sample & parse
            uses the whole page while it is open (three panes: samples | VRL | diagnostics). */}
        <div className="w-full px-6 py-5 space-y-4" data-testid="add-feed-linear" data-parse-wide={parseWide || undefined}>
          <div className={READABLE_COLUMN}>
          <SourceStep
            locked={connectionLocked}
            expanded={activeStep === 1}
            onActivate={() => setActiveStep(1)}
            onContinue={() => setActiveStep(6)}
            catalogType={catalogType}
            chooseCatalog={chooseCatalog}
            tenantSources={registryQuery.data ?? []}
            name={name}
            setName={(v) => {
              nameTouched.current = true;
              setName(v);
              if (!identifierTouched.current) {
                const slug = sanitizeFeedId(v);
                setFeedId(systemSource(slug) ? `custom_${slug}` : slug);
              }
            }}
            feedId={feedId}
          />
          </div>
          {revealedStep >= 1 && (
            <div className={READABLE_COLUMN}>
            <DetailsStep
              locked={connectionLocked}
              expanded={activeStep === 6}
              onActivate={() => setActiveStep(6)}
              onContinue={() => setActiveStep(5)}
              searchSourceField={searchSourceField}
              feedId={feedId}
              setFeedId={(v) => {
                identifierTouched.current = true;
                const slug = sanitizeFeedId(v);
                setFeedId(systemSource(slug) ? `custom_${slug}` : slug);
              }}
              name={name}
              vendor={vendor}
              setVendor={setVendor}
              product={product}
              setProduct={setProduct}
              category={category}
              setCategory={setCategory}
              description={description}
              setDescription={setDescription}
              nsPrefix={nsPrefix}
              setNsPrefix={setNsPrefix}
              nsSuffix={nsSuffix}
              setNsSuffix={setNsSuffix}
              existingDraft={!!draftId}
            />
            </div>
          )}
          {revealedStep >= 2 && (
            <div className={READABLE_COLUMN}>
            <TransportStep
              locked={connectionLocked}
              expanded={activeStep === 5}
              onActivate={() => setActiveStep(5)}
              onContinue={() => void prepareConnection()}
              preparing={preparing || ensuringDraft}
              transport={transport}
              setTransport={setTransport}
              protocol={protocol}
              setProtocol={setProtocol}
              otlpSignal={otlpSignal}
              setOtlpSignal={setOtlpSignal}
              sourceConfigs={sourceConfigs}
              loadingConfigs={loadingConfigs}
              sourceConfigId={sourceConfigId}
              setSourceConfigId={setSourceConfigId}
              otherTargets={otherTargets}
              onUseTarget={(target) => { identifierTouched.current = true; setFeedId(target); }}
              feedId={feedId}
            />
            </div>
          )}
          {revealedStep >= 3 && transport === 'push' && (
            <div className={READABLE_COLUMN}>
            <Step4Connect
              expanded={activeStep === 2}
              onActivate={() => setActiveStep(2)}
              endpoint={endpointQuery.data}
              endpointError={endpointQuery.error}
              source={issueSource}
              logSourceId={draftId ?? undefined}
              protocol={protocol}
              otlpSignal={otlpSignal}
              searchField={searchSourceField}
              receivingNow={(connectDetail.data?.events_24h ?? 0) > 0}
              onBusyChange={setCredentialBusy}
              onTokenSaved={() => setTokenSaved(true)}
              onIssued={() => {
                setCredentialIssued(true);
                void queryClient.invalidateQueries({ queryKey: ['add-data', 'log-sources'] });
              }}
              onContinue={needsParserWork ? goParse : undefined}
              onFinish={() => {
                void queryClient.invalidateQueries({ queryKey: CONNECT_STATUS_QUERY_KEY });
                navigate(finishHref);
              }}
              // Main waited for the parser here because a hosted token was only issued once the
              // source was enrolled. A draft receives as soon as it exists, so Finish only needs
              // the token saved; the list then offers "Build parser" for the unparsed source.
              canFinish={tokenSaved}
            />
            </div>
          )}
          {revealedStep >= 4 && needsParserWork && (
            <div className={parseWide ? 'w-full' : READABLE_COLUMN} data-testid="parse-step-column">
            <Step2Parse
              canUseParserAi={canUseParserAi}
              expanded={activeStep === 3}
              onActivate={goParse}
              onContinue={() => setActiveStep(4)}
              receivedEvents={connectDetail.data?.events_24h ?? 0}
              loadingReceived={loadingReceived}
              onLoadReceived={() => void loadReceivedSamples()}
              entryPath={entryPath}
              setEntryPath={setEntryPath}
              sampleText={sampleText}
              setSampleText={setSampleText}
              sampleCount={sampleCount}
              vrl={vrl}
              setVrl={setVrl}
              genState={genState}
              genElapsedMs={genElapsedMs}
              genStatus={genStatus}
              onRegenerate={handleRegenerate}
              onCancelGenerate={handleCancelGenerate}
              onValidate={() => runValidate(true)}
              isValidating={isValidating}
              isTesting={isTesting}
              timezone={timezone}
              setTimezone={setTimezone}
              sidePane={sidePane}
              setSidePane={setSidePane}
              feedId={feedId}
              validation={validation}
              tests={tests}
              pivtMessage={pivtMessage}
              setPivtMessage={setPivtMessage}
              onSendPivt={sendPivtMessage}
              pivtPending={pivtPending}
              pivtSuggestion={pivtSuggestion}
              applyPivtSuggestion={() => {
                if (canUseParserAi && pivtSuggestion?.updated_vrl) {
                  setVrl(pivtSuggestion.updated_vrl);
                  setPivtSuggestion(null);
                }
              }}
              draftSaved={!!draftId}
            />
            </div>
          )}
          {revealedStep >= 5 && (needsParserWork || transport === 'pull') && (
            <div className={READABLE_COLUMN}>
            <Step3Deploy
              expanded={activeStep === 4}
              onActivate={() => setActiveStep(4)}
              transport={transport}
              gate={deployGate}
              onGateAction={onGateAction}
              feedId={feedId}
              name={name}
              sourceConfig={sourceConfig}
              namespaceFull={namespaceFull}
              timezone={timezone}
              category={category}
              vendor={vendor}
              product={product}
              description={description}
              vrl={vrl}
              acceptWarnings={acceptWarnings}
              setAcceptWarnings={setAcceptWarnings}
              canDeploy={canDeploy}
              onSaveDraft={handleSaveDraft}
              onDeploy={handleDeploy}
              savingDraft={savingDraft}
              deploying={deploying}
            />
            </div>
          )}
          <div className={parseWide ? 'w-full' : READABLE_COLUMN}>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              if (!credentialIssued || tokenSaved || window.confirm('The token is shown once. Leave without copying it?')) navigate('/ingestion/log-sources');
            }}
          >
            Cancel
          </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default AddFeed;

// ==================================================================
// Hero
// ==================================================================
function AddFeedHero({
  feedId,
  transport,
  protocol,
  sourceConfig,
  hostname,
}: {
  feedId: string;
  transport: 'push' | 'pull';
  protocol: DirectProtocol;
  sourceConfig?: SourceConfigWithEvents;
  /** This deployment's ingest host (`GET /api/log-sources/ingest-endpoint`). */
  hostname?: string;
}) {
  return (
    <div className="shrink-0 border-b border-border bg-card/40 px-5 py-4 flex items-start gap-4">
      <div className="w-[38px] h-[38px] rounded-lg border border-primary/30 bg-primary/[0.08] flex items-center justify-center shrink-0">
        <Plus className="w-[18px] h-[18px] text-primary" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2.5 flex-wrap">
          <h1 className="text-[16.5px] font-semibold tracking-[-0.01em] text-foreground">Add source</h1>
          <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground border border-border rounded px-1.5 py-px whitespace-nowrap">
            Wizard
          </span>
        </div>
        <div className="text-[11.5px] text-muted-foreground mt-0.5 leading-relaxed max-w-[740px]">
          Choose a source, choose how to send it, then connect. Events arrive before any parser exists; keep your samples,
          parser validation and publish together.
        </div>
      </div>
      <div className="hidden md:flex items-center gap-3 shrink-0">
        <div className="flex flex-col items-end">
          <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground/60">SOURCE</span>
          <span className="text-[12.5px] font-mono text-foreground">{feedId || '—'}</span>
        </div>
        <div className="w-px h-8 bg-border" />
        <div className="flex flex-col items-end">
          <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground/60">VIA</span>
          <span className="text-[12.5px] font-mono text-foreground">
            {transport === 'push' ? `${PROTOCOL_LABEL[protocol]} · ${hostname ?? '—'}` : sourceConfig ? sourceConfig.name : '—'}
          </span>
        </div>
      </div>
    </div>
  );
}

// ==================================================================
// StepCard — collapsible card
// ==================================================================
function StepCard({
  n,
  title,
  eyebrow,
  expanded,
  ok,
  locked = false,
  onActivate,
  summary,
  footer,
  children,
}: {
  n: number;
  /** A token was issued (or is being issued) for this source: earlier steps are read-only. */
  locked?: boolean;
  title: string;
  eyebrow: string;
  expanded: boolean;
  ok: boolean;
  onActivate: () => void;
  summary?: ReactNode;
  footer?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div
      className={cn(
        'rounded-lg border bg-card transition-colors',
        expanded ? 'border-input' : 'border-border',
      )}
    >
      <button
        onClick={onActivate}
        disabled={expanded || locked}
        title={locked ? 'Locked: a token was issued for this source' : undefined}
        className={cn(
          'w-full flex items-center gap-3 px-4 py-3 text-left',
          !expanded && 'hover:bg-foreground/[0.03] cursor-pointer',
        )}
      >
        <div
          className={cn(
            'shrink-0 w-6 h-6 rounded-full flex items-center justify-center text-[11px] font-mono',
            ok
              ? 'bg-emerald-500/15 text-emerald-500 border border-emerald-500/40'
              : expanded
                ? 'bg-primary/15 text-primary border border-primary/50'
                : 'bg-muted text-muted-foreground border border-border',
          )}
        >
          {ok ? <Check className="w-3 h-3" /> : n}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/60">{eyebrow}</span>
            {expanded && <span className="w-1 h-1 rounded-full bg-primary" />}
          </div>
          <div className="text-[14px] font-semibold tracking-[-0.005em] text-foreground mt-0.5">{title}</div>
        </div>
        {!expanded && summary}
      </button>
      {expanded && (
        <>
          <div className="border-t border-border px-4 py-4">{children}</div>
          {footer && (
            <div className="border-t border-border px-4 py-2.5 bg-card/40 flex items-center gap-2 rounded-b-lg">{footer}</div>
          )}
        </>
      )}
    </div>
  );
}

// ==================================================================
// Field primitives — Label / FieldHint / UsageRow
// ==================================================================
function FieldLabel({ children, required }: { children: ReactNode; required?: boolean }) {
  return (
    <div className="text-[10.5px] font-medium text-foreground/80 mb-1.5">
      {children}
      {required && <span className="text-[var(--color-danger,theme(colors.red.400))] ml-1">*</span>}
    </div>
  );
}

function FieldHint({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn('text-[10.5px] text-muted-foreground leading-relaxed mt-1.5', className)}>{children}</div>;
}


// ==================================================================
// Namespace combobox — single typeable control with prefix popover
// ==================================================================
function NamespaceCombobox({
  prefix,
  setPrefix,
  suffix,
  setSuffix,
}: {
  prefix: NamespacePrefixId;
  setPrefix: (v: NamespacePrefixId) => void;
  suffix: string;
  setSuffix: (v: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const cur = NAMESPACE_PREFIXES.find((p) => p.id === prefix)!;

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  return (
    <div ref={ref} className="relative">
      <div className="h-10 flex items-center rounded-md border border-input bg-background focus-within:border-primary transition-colors">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          className="h-full pl-3 pr-2 flex items-center gap-1.5 text-[12.5px] font-mono text-foreground hover:bg-foreground/[0.04] rounded-l-md border-r border-border"
        >
          {cur.label}
          <ChevronDown className={cn('w-3 h-3 text-muted-foreground transition-transform', open && 'rotate-180')} />
        </button>
        {prefix === 'default' ? (
          <span className="flex-1 px-3 text-[12px] text-muted-foreground/60 italic select-none">no isolation</span>
        ) : (
          <input
            value={suffix}
            onChange={(e) => setSuffix(e.target.value)}
            placeholder={cur.suffixHint}
            className="flex-1 h-full bg-transparent px-3 font-mono text-[12.5px] text-foreground placeholder:text-muted-foreground/60 focus:outline-none"
          />
        )}
      </div>
      {open && (
        <div className="absolute top-full left-0 mt-1 w-[300px] rounded-md border border-border bg-popover shadow-[0_8px_30px_rgba(0,0,0,0.45)] py-1 z-20">
          {NAMESPACE_PREFIXES.map((p) => (
            <button
              key={p.id}
              type="button"
              onClick={() => {
                setPrefix(p.id);
                setOpen(false);
              }}
              className={cn(
                'w-full flex items-center gap-3 px-3 py-1.5 text-left hover:bg-foreground/[0.04]',
                prefix === p.id && 'bg-primary/[0.08]',
              )}
            >
              <span className="font-mono text-[12px] text-foreground w-[60px]">{p.label}</span>
              <span className="text-[11px] text-muted-foreground flex-1">{p.desc}</span>
              {prefix === p.id && <Check className="w-3 h-3 text-primary" />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ==================================================================
// SourceConfigCard
// ==================================================================
function SourceConfigCard({
  config,
  selected,
  onSelect,
}: {
  config: SourceConfigWithEvents;
  selected: boolean;
  onSelect: () => void;
}) {
  const Icon = SOURCE_ICON_FOR_TYPE(config.config_type);
  const events = formatEventsCount(config.events_24h);
  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        'flex items-start gap-2.5 p-2.5 rounded-md border text-left transition-colors',
        selected ? 'border-primary bg-primary/[0.08]' : 'border-border bg-card hover:border-input hover:bg-foreground/[0.03]',
      )}
    >
      <div
        className={cn(
          'shrink-0 w-7 h-7 rounded flex items-center justify-center mt-0.5',
          selected ? 'bg-primary/15 text-primary' : 'bg-muted text-muted-foreground',
        )}
      >
        <Icon className="w-3.5 h-3.5" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-1.5">
          <span className="text-[12px] font-medium text-foreground truncate">{config.name}</span>
          {selected && <Check className="w-3 h-3 text-primary shrink-0" />}
        </div>
        <div className="text-[9.5px] font-mono uppercase tracking-wider text-muted-foreground/60 mt-0.5">
          {SOURCE_TYPE_LABEL[config.config_type] ?? config.config_type}
        </div>
        <div className="text-[10.5px] font-mono text-muted-foreground mt-0.5">
          {events ? `${events} · 24h` : 'no traffic yet'}
        </div>
      </div>
    </button>
  );
}

// ==================================================================
// Existing routing targets panel — preserves old wizard's "Available
// Routing Targets" Step 4C behavior. Click a chip to retarget the wizard.
// ==================================================================
function ExistingTargetsPanel({
  targets,
  onUseTarget,
}: {
  targets: RoutingRule[];
  onUseTarget: (target: string) => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="mt-3 rounded-md border border-border bg-card/40">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full px-3 py-2 flex items-center gap-2 text-left"
      >
        <RouteIcon className="w-3 h-3 text-muted-foreground" />
        <span className="text-[11px] text-foreground/80">
          This transport already routes to <span className="font-mono">{targets.length}</span> existing target
          {targets.length === 1 ? '' : 's'}
        </span>
        <span className="flex-1" />
        <ChevronDown className={cn('w-3 h-3 text-muted-foreground transition-transform', open && 'rotate-180')} />
      </button>
      {open && (
        <div className="px-3 pb-3 flex flex-wrap gap-1.5 border-t border-border pt-2">
          {targets.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => onUseTarget(t.target_source_type)}
              className="font-mono text-[10.5px] px-2 h-6 rounded border border-border bg-card hover:border-primary/40 hover:bg-primary/[0.08]"
              title="Reuse this routing target instead of creating a new one"
            >
              {t.target_source_type}
            </button>
          ))}
          <span className="text-[10.5px] text-muted-foreground/60 self-center">
            click a target to register the parser under it
          </span>
        </div>
      )}
    </div>
  );
}

// ==================================================================
// Step 1 — Source (main's NAN-4847 catalog picker)
// ==================================================================
function SourceStep({
  locked,
  expanded,
  onActivate,
  onContinue,
  catalogType,
  chooseCatalog,
  tenantSources,
  name,
  setName,
  feedId,
}: {
  locked: boolean;
  expanded: boolean;
  onActivate: () => void;
  onContinue: () => void;
  catalogType: string;
  chooseCatalog: (id: string) => void;
  tenantSources: LogSource[];
  name: string;
  setName: (v: string) => void;
  feedId: string;
}) {
  const catalog = useSourceCatalog();
  const navigate = useNavigate();
  const ok = !!name && !!feedId;
  // Your sources: an existing source takes another credential on its detail page.
  const yourSources = tenantSources.filter((source) => source.lifecycle_status !== 'draft' &&
    (source.match_values ?? [source.source_type]).some((slug) => !systemSource(slug)));
  const repositories = new Map((catalog.data ?? []).map((parser) => [parser.repository_id, parser.repository_name]));
  const picked = catalogType === 'custom' ? null : catalog.data?.find((p) => p.id === catalogType);
  return (
    <StepCard n={1} title="Source" eyebrow="STEP 1 · Source" locked={locked} expanded={expanded} ok={ok && !expanded}
      onActivate={onActivate}
      summary={<span className="font-mono text-[11px] text-muted-foreground">Source: {name || '—'}{catalogType === 'custom' ? ' (custom)' : picked ? ` (${picked.repository_name})` : ''}</span>}
      footer={<><div className="flex-1" /><Button size="sm" className="h-8 gap-1.5" onClick={onContinue} disabled={!ok} data-testid="source-continue">Continue · details <ArrowRight className="w-3.5 h-3.5" /></Button></>}>
      <Command className="rounded-md border border-border" data-testid="source-catalog">
        <CommandInput aria-label="Search supported sources" placeholder="Search sources and repositories…" />
        <CommandList>
          <CommandItem className="text-[11.5px]" forceMount value="Custom source" onSelect={() => chooseCatalog('custom')}>
            <Plus className="w-3.5 h-3.5 mr-2" />Custom source{catalogType === 'custom' && <Check className="w-3 h-3 ml-auto" />}
          </CommandItem>
          {yourSources.length > 0 && <CommandGroup heading="Your sources">
            {yourSources.map((source) => <CommandItem key={source.id} className="text-[11.5px]" value={`Your sources ${source.name} ${(source.match_values ?? []).join(' ')}`}
              onSelect={() => navigate(`/ingestion/log-sources/${source.id}?action=add-credential#source-credentials`)}>
              {source.name}<span className="ml-auto font-mono text-muted-foreground">Add credential</span>
            </CommandItem>)}
          </CommandGroup>}
          {catalog.isLoading && <CommandItem disabled>Loading supported sources…</CommandItem>}
          {catalog.isError && <CommandItem onSelect={() => void catalog.refetch()}>Could not load supported sources. Retry</CommandItem>}
          {repositories.size > 0 && <CommandGroup heading="From repositories" forceMount>
            {Array.from(repositories, ([id, repoName]) => <CommandGroup heading={repoName} key={id}>
              {(catalog.data ?? []).filter((parser) => parser.repository_id === id).map((parser) => {
                // Sources imported before NAN-5264 were keyed on the parser name.
                const keys = [parser.match_value, parserSlug(parser)];
                const existing = tenantSources.find((source) => (source.match_values ?? []).some((value) => keys.includes(value)));
                return <CommandItem className="text-[11.5px]" key={parser.id}
                  value={`${repoName} ${parser.display_name ?? parser.name} ${parser.vendor ?? ''}`} onSelect={() => {
                    if (existing) navigate(`/ingestion/log-sources/${existing.id}?action=add-credential#source-credentials`);
                    else chooseCatalog(parser.id);
                  }}>
                  {parser.display_name ?? parser.name}
                  <span className="ml-auto" />{existing?.deployed && <Badge variant="secondary">Installed</Badge>}
                  {catalogType === parser.id && <Check className="w-3 h-3 ml-2" />}
                </CommandItem>;
              })}
            </CommandGroup>)}
          </CommandGroup>}
          <CommandEmpty>No matching sources. Choose Custom source.</CommandEmpty>
        </CommandList>
      </Command>
      <div className="mt-3">
        <label className="block text-[11px] text-foreground/80 mb-1.5" htmlFor="add-source-name">Source name</label>
        <input id="add-source-name" value={name} onChange={(event) => setName(event.target.value)} placeholder="e.g. Vercel"
          className="h-9 w-full rounded-md border border-input bg-background px-3 text-[13px] text-foreground focus:border-primary focus:outline-none" />
      </div>
    </StepCard>
  );
}

// ==================================================================
// Step 2 — Details
// ==================================================================
function DetailsStep({
  locked,
  expanded,
  onActivate,
  onContinue,
  searchSourceField,
  feedId,
  setFeedId,
  name,
  vendor,
  setVendor,
  product,
  setProduct,
  category,
  setCategory,
  description,
  setDescription,
  nsPrefix,
  setNsPrefix,
  nsSuffix,
  setNsSuffix,
  existingDraft,
}: {
  locked: boolean;
  expanded: boolean;
  onActivate: () => void;
  onContinue: () => void;
  searchSourceField: string;
  feedId: string;
  setFeedId: (v: string) => void;
  name: string;
  vendor: string;
  setVendor: (v: string) => void;
  product: string;
  setProduct: (v: string) => void;
  category: string;
  setCategory: (v: string) => void;
  description: string;
  setDescription: (v: string) => void;
  nsPrefix: NamespacePrefixId;
  setNsPrefix: (v: NamespacePrefixId) => void;
  nsSuffix: string;
  setNsSuffix: (v: string) => void;
  /** The source exists already: its key is its route key and no longer changes here. */
  existingDraft: boolean;
}) {
  const ok = !!feedId && !!name && !systemSource(feedId);
  return (
    <StepCard n={2} title="Details" eyebrow="STEP 2 · Details" locked={locked}
      expanded={expanded} onActivate={onActivate} ok={ok && !expanded}
      summary={<span className="text-[11px] text-muted-foreground">Details: <span className="font-mono">{feedId}</span> · {[vendor, product, category].map((value) => value || '—').join(' · ')}</span>}
      footer={<><div className="flex-1" /><Button size="sm" className="h-8 gap-1.5" disabled={!ok} onClick={onContinue} data-testid="details-continue">Continue · transport <ArrowRight className="w-3.5 h-3.5" /></Button></>}>
      <div className="space-y-4" data-testid="source-details">
        <div>
          <FieldLabel required>Feed identifier</FieldLabel>
          <div className="flex items-center rounded-md border border-input bg-background focus-within:border-primary">
            <span className="shrink-0 pl-3 text-[12px] font-mono text-muted-foreground/60 select-none">{searchSourceField} =</span>
            <input
              id="feed-identifier"
              aria-label="Feed identifier"
              data-testid="feed-identifier"
              value={feedId}
              disabled={existingDraft}
              onChange={(event) => setFeedId(event.target.value)}
              placeholder="aws_cloudtrail"
              className="h-10 min-w-0 w-full bg-transparent pl-2 pr-3 font-mono text-[13px] text-foreground placeholder:text-muted-foreground/60 focus:outline-none disabled:opacity-70"
            />
          </div>
          <FieldHint>
            Lowercase letters, numbers, <span className="font-mono">_</span> and <span className="font-mono">-</span>. The route key
            every event of this source's tokens carries, and its parser name.
          </FieldHint>
          {feedId && <div className="mt-3 flex items-center gap-2 text-[11px] text-muted-foreground">
            <span>Find these events with <span className="font-mono text-foreground/80">{searchSourceField}={feedId}</span></span>
            <CopyButton text={`${searchSourceField}=${feedId}`} aria-label="Copy search query" />
          </div>}
        </div>
        <div className="grid grid-cols-12 gap-3">
          <div className="col-span-12 md:col-span-4">
            <FieldLabel>Vendor</FieldLabel>
            <input aria-label="Vendor" value={vendor} onChange={(e) => setVendor(e.target.value)} placeholder="Amazon"
              className="h-9 w-full rounded-md border border-input bg-background px-3 text-[13px] text-foreground focus:border-primary focus:outline-none" />
          </div>
          <div className="col-span-12 md:col-span-4">
            <FieldLabel>Product</FieldLabel>
            <input aria-label="Product" value={product} onChange={(e) => setProduct(e.target.value)} placeholder="CloudTrail"
              className="h-9 w-full rounded-md border border-input bg-background px-3 text-[13px] text-foreground focus:border-primary focus:outline-none" />
          </div>
          <div className="col-span-12 md:col-span-4">
            <FieldLabel>Category</FieldLabel>
            <select aria-label="Category" value={category} onChange={(e) => setCategory(e.target.value)}
              className="h-9 w-full rounded-md border border-input bg-background px-2.5 text-[13px] text-foreground focus:border-primary focus:outline-none appearance-none cursor-pointer">
              <option value="">—</option>
              {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>
        </div>
        <Collapsible>
          <CollapsibleTrigger asChild><Button variant="ghost" size="sm" className="h-7 gap-1 text-[11.5px]">Advanced configuration <ChevronDown className="w-3 h-3" /></Button></CollapsibleTrigger>
          <CollapsibleContent className="space-y-4 mt-3">
            <div>
              <FieldLabel>Network namespace</FieldLabel>
              <NamespaceCombobox prefix={nsPrefix} setPrefix={setNsPrefix} suffix={nsSuffix} setSuffix={setNsSuffix} />
              <FieldHint>Isolates identity resolution for overlapping private IPs (10.x, 192.168.x).</FieldHint>
            </div>
            <div>
              <FieldLabel>Description</FieldLabel>
              <textarea aria-label="Description" value={description} onChange={(event) => setDescription(event.target.value)} rows={2}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-[12.5px] text-foreground focus:border-primary focus:outline-none resize-none" />
            </div>
          </CollapsibleContent>
        </Collapsible>
      </div>
    </StepCard>
  );
}

// ==================================================================
// Step 3 — Transport
// ==================================================================
const TRANSPORT_OPTIONS: Array<{ id: DirectProtocol | 'pull'; label: string; description: string }> = [
  { id: 'hec', label: 'HEC', description: 'For HEC forwarders and security tools that speak HEC.' },
  { id: 'nano_https', label: 'HTTP JSON', description: 'For apps and scripts sending JSON over HTTP(S).' },
  { id: 'otlp_http', label: 'OTLP', description: 'For OpenTelemetry logs, metrics and traces.' },
  { id: 'pull', label: 'Source configuration', description: 'Kafka, S3/SQS, Pub/Sub or a listener reads it; routed by a rule at publish.' },
];

function TransportStep({
  locked,
  expanded,
  onActivate,
  onContinue,
  preparing,
  transport,
  setTransport,
  protocol,
  setProtocol,
  otlpSignal,
  setOtlpSignal,
  sourceConfigs,
  loadingConfigs,
  sourceConfigId,
  setSourceConfigId,
  otherTargets,
  onUseTarget,
  feedId,
}: {
  locked: boolean;
  expanded: boolean;
  onActivate: () => void;
  onContinue: () => void;
  preparing: boolean;
  transport: 'push' | 'pull';
  setTransport: (v: 'push' | 'pull') => void;
  protocol: DirectProtocol;
  setProtocol: (v: DirectProtocol) => void;
  otlpSignal: string;
  setOtlpSignal: (v: string) => void;
  sourceConfigs: SourceConfigWithEvents[];
  loadingConfigs: boolean;
  sourceConfigId: string;
  setSourceConfigId: (v: string) => void;
  otherTargets: RoutingRule[];
  onUseTarget: (target: string) => void;
  feedId: string;
}) {
  const value = transport === 'pull' ? 'pull' : protocol;
  const ok = transport === 'push' || !!sourceConfigId;
  return (
    <StepCard locked={locked} n={3} title="How will you send it?" eyebrow="STEP 3 · Transport" expanded={expanded} ok={!expanded && ok} onActivate={onActivate}
      summary={<span className="font-mono text-[11px] text-muted-foreground">Transport: {transport === 'pull' ? 'Source configuration' : PROTOCOL_LABEL[protocol]}</span>}
      footer={<><div className="flex-1" /><Button size="sm" className="h-8 gap-1.5" disabled={preparing || !ok || !feedId} onClick={onContinue} data-testid="transport-continue">
        {preparing ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : null}
        {transport === 'push' ? 'Continue · connect' : 'Continue · sample & parse'} <ArrowRight className="w-3.5 h-3.5" />
      </Button></>}>
      <RadioGroup value={value} onValueChange={(next) => {
        if (next === 'pull') setTransport('pull');
        else { setTransport('push'); setProtocol(next as DirectProtocol); }
      }} aria-label="Transport">
        {TRANSPORT_OPTIONS.map((option) => (
          <label key={option.id} className="flex items-center gap-3 rounded-md border border-border px-3 py-2 text-[12px] cursor-pointer" data-testid={`transport-${option.id}`}>
            <RadioGroupItem value={option.id} aria-label={option.label} />
            <span><span className="block text-foreground">{option.label}</span><FieldHint className="mt-0.5">{option.description}</FieldHint></span>
          </label>
        ))}
      </RadioGroup>
      {transport === 'push' && protocol === 'otlp_http' && (
        <RadioGroup value={otlpSignal} onValueChange={setOtlpSignal} aria-label="OTLP signal" className="mt-3 flex gap-4">
          {['log', 'metric', 'trace'].map((signal) => (
            <label key={signal} className="flex items-center gap-2 text-[12px]"><RadioGroupItem value={signal} />{signal === 'log' ? 'Logs' : signal === 'metric' ? 'Metrics' : 'Traces'}</label>
          ))}
        </RadioGroup>
      )}
      {transport === 'push' && (
        <FieldHint>
          Continue creates the source (a draft until its parser is published). The token you issue next decides the source:
          events sent with it land here whatever source type the sender declares, and are searchable before the parser exists.
        </FieldHint>
      )}
      {transport === 'pull' && (
        <div className="mt-3 space-y-2">
          {loadingConfigs ? (
            <div className="rounded-md border border-border bg-card/40 p-4 text-[11.5px] text-muted-foreground">Loading source configurations…</div>
          ) : sourceConfigs.length === 0 ? (
            <div className="rounded-md border border-dashed border-border bg-card/40 p-4 text-[11.5px] text-muted-foreground">
              No pull sources yet.{' '}
              <Link to="/ingestion/log-sources/cloud-pull" className="text-primary hover:underline">Add one under Cloud pull</Link>, then come back.
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {sourceConfigs.map((c) => (
                <SourceConfigCard key={c.id} config={c} selected={sourceConfigId === c.id} onSelect={() => setSourceConfigId(c.id)} />
              ))}
            </div>
          )}
          {sourceConfigId && otherTargets.length > 0 && <ExistingTargetsPanel targets={otherTargets} onUseTarget={onUseTarget} />}
        </div>
      )}
    </StepCard>
  );
}

// ==================================================================
// Step 4 — Connect (main's Step4Issue): credential → send → first events
// ==================================================================
function Step4Connect({
  expanded,
  onActivate,
  endpoint,
  endpointError,
  source,
  logSourceId,
  protocol,
  otlpSignal,
  searchField,
  receivingNow,
  onIssued,
  onBusyChange,
  onTokenSaved,
  onContinue,
  onFinish,
  canFinish,
}: {
  expanded: boolean;
  onActivate: () => void;
  endpoint?: IngestEndpoint;
  endpointError: Error | null;
  source: AddDataSource | null;
  logSourceId?: string;
  protocol: DirectProtocol;
  otlpSignal: string;
  searchField: string;
  /** The source already receives (any token): a resumed source. */
  receivingNow: boolean;
  onIssued: () => void;
  onBusyChange?: (busy: boolean) => void;
  onTokenSaved?: () => void;
  onContinue?: () => void;
  onFinish: () => void;
  canFinish: boolean;
}) {
  // Credential first, then data: the summary names the credential's own state
  // until one is ready, never "waiting for first event" before it exists.
  const [stage, setStage] = useState<ConnectStage>('none');
  const receiving = stage === 'receiving' || (stage === 'none' && receivingNow);
  return (
    <StepCard
      n={4}
      title="Connect"
      eyebrow="STEP 4 · Connect"
      expanded={expanded}
      ok={!expanded && receiving}
      onActivate={onActivate}
      summary={<span className="font-mono text-[11px] text-muted-foreground">Connect: {PROTOCOL_LABEL[protocol]} · {receiving ? 'receiving' : CONNECT_SUMMARY[stage]}</span>}
      footer={<>
        <Link to={INGEST_CREDENTIALS_PATH} target="_blank" rel="noopener noreferrer" className="text-[10.5px] text-primary hover:underline">Log Sources → Credentials</Link>
        <div className="flex-1" />
        {onContinue && <Button size="sm" className="h-8 gap-1.5" onClick={onContinue} data-testid="connect-continue">Continue · sample & parse <ArrowRight className="w-3.5 h-3.5" /></Button>}
        <Button size="sm" variant={onContinue ? 'outline' : 'default'} className="h-8 gap-1.5" onClick={onFinish} disabled={!canFinish} data-testid="connect-finish">Finish</Button>
      </>}
    >
      <div className="space-y-3">
        {endpointError ? (
          <div className="text-[11.5px] text-red-500" role="alert">Could not load your ingest endpoint: {endpointError.message}</div>
        ) : !endpoint ? (
          <div className="text-[11.5px] text-muted-foreground">Loading your ingest endpoint…</div>
        ) : !source || !logSourceId ? (
          <div className="text-[11.5px] text-muted-foreground">Finish the transport step to create the source first.</div>
        ) : (
          <IssueCredentialPanel
            endpoint={endpoint}
            source={source}
            logSourceId={logSourceId}
            initialProtocol={protocol}
            linear
            signal={otlpSignal}
            searchField={searchField}
            onStageChange={setStage}
            onTokenSaved={onTokenSaved}
            onIssued={onIssued}
            onBusyChange={onBusyChange}
          />
        )}
      </div>
    </StepCard>
  );
}

type Step2Props = {
  canUseParserAi: boolean;
  expanded: boolean;
  onActivate: () => void;
  onContinue: () => void;
  entryPath: 'paste' | 'existing' | 'manual';
  setEntryPath: (v: 'paste' | 'existing' | 'manual') => void;
  sampleText: string;
  setSampleText: (v: string) => void;
  sampleCount: number;
  vrl: string;
  setVrl: (v: string) => void;
  genState: 'idle' | 'streaming' | 'done' | 'error';
  /** Wall-clock time the draft job has been running. */
  genElapsedMs: number;
  genStatus: string;
  onRegenerate: () => void;
  onCancelGenerate: () => void;
  onValidate: () => Promise<boolean>;
  isValidating: boolean;
  isTesting: boolean;
  timezone: string;
  setTimezone: (v: string) => void;
  sidePane: 'diag' | 'tests' | 'ai';
  setSidePane: (v: 'diag' | 'tests' | 'ai') => void;
  feedId: string;
  validation: { diagnostics: VrlDiagnostic[]; syntaxValid: boolean | null; errorMessages: string[] };
  tests: Array<{ name: string; status: 'pass' | 'fail'; extracted: number; error?: string }>;
  pivtMessage: string;
  setPivtMessage: (v: string) => void;
  onSendPivt: (msg: string) => void;
  pivtPending: boolean;
  pivtSuggestion: MelodEditParserResponse | null;
  applyPivtSuggestion: () => void;
  draftSaved: boolean;
  /** Events the source received (24h): offered as samples. */
  receivedEvents: number;
  loadingReceived: boolean;
  onLoadReceived: () => void;
};

function Step2Parse(props: Step2Props) {
  const {
    canUseParserAi,
    expanded,
    onActivate,
    onContinue,
    entryPath,
    setEntryPath,
    sampleText,
    setSampleText,
    sampleCount,
    vrl,
    setVrl,
    genState,
    genElapsedMs,
    genStatus,
    onRegenerate,
    onCancelGenerate,
    onValidate,
    isValidating,
    timezone,
    setTimezone,
    sidePane,
    setSidePane,
    feedId,
    validation,
    tests,
    pivtMessage,
    setPivtMessage,
    onSendPivt,
    pivtPending,
    pivtSuggestion,
    applyPivtSuggestion,
    draftSaved,
    receivedEvents,
    loadingReceived,
    onLoadReceived,
  } = props;

  const errors = validation.diagnostics.filter((d) => d.severity === 'error').length;
  const warnings = validation.diagnostics.filter((d) => d.severity === 'warn').length;
  const passingTests = tests.filter((t) => t.status === 'pass').length;
  const totalTests = tests.length;
  const ok = errors === 0 && totalTests > 0 && passingTests === totalTests && sampleCount > 0;
  const vrlLineCount = vrl.split('\n').length;

  const summary = (
    <div className="hidden md:flex items-center gap-3 text-[11px] shrink-0">
      <span className="font-mono text-foreground">
        {vrlLineCount}{' '}
        <span className="text-muted-foreground/60">
          {vrlLineCount === 1 ? 'line' : 'lines'}
        </span>
      </span>
      <span className="w-px h-4 bg-border" />
      <span className={passingTests === totalTests && totalTests > 0 ? 'text-emerald-500' : 'text-amber-500'}>
        {passingTests}/{totalTests} pass
      </span>
      <span className="w-px h-4 bg-border" />
      <span className={warnings > 0 ? 'text-amber-500' : 'text-muted-foreground'}>{warnings} warn</span>
    </div>
  );

  return (
    <StepCard
      n={5}
      title="Sample & parse"
      eyebrow="STEP 5 · Parse"
      expanded={expanded}
      ok={ok}
      onActivate={onActivate}
      summary={summary}
      footer={
        <>
          <div className="flex items-center gap-3 text-[10.5px] font-mono">
            <span className={passingTests === totalTests && totalTests > 0 ? 'text-emerald-500' : 'text-amber-500'}>
              <span className="tabular-nums">
                {passingTests}/{totalTests}
              </span>{' '}
              pass
            </span>
            <span className="text-muted-foreground/60">·</span>
            <span className={errors > 0 ? 'text-destructive' : 'text-muted-foreground'}>{errors} err</span>
            <span className="text-muted-foreground/60">·</span>
            <span className={warnings > 0 ? 'text-amber-500' : 'text-muted-foreground'}>{warnings} warn</span>
          </div>
          <div className="flex-1" />
          <TimezonePicker value={timezone} onChange={setTimezone} />
          <Button
            variant="default"
            size="sm"
            className="h-8 gap-1.5"
            onClick={onContinue}
            disabled={errors > 0 && entryPath !== 'manual'}
          >
            Continue · review
            <ArrowRight className="w-3.5 h-3.5" />
          </Button>
        </>
      }
    >
      {receivedEvents > 0 && (
        <div className="mb-2 flex items-center gap-2 rounded-md border border-border bg-card/40 px-3 py-1.5 text-[11px]" data-testid="parse-received">
          <Database className="w-3 h-3 text-muted-foreground" />
          <span className="text-muted-foreground">
            <span className="font-mono text-foreground tabular-nums">{receivedEvents.toLocaleString()}</span> events received as{' '}
            <span className="font-mono text-foreground/80">source_type={feedId}</span>
          </span>
          <div className="flex-1" />
          <Button variant="outline" size="sm" className="h-6 px-2 text-[11px]" disabled={loadingReceived} onClick={onLoadReceived}>
            {loadingReceived ? 'Loading…' : 'Use the 10 most recent as samples'}
          </Button>
        </div>
      )}
      <SegmentedPath value={entryPath} onChange={setEntryPath} canUseParserAi={canUseParserAi} />
      {/* NAN-4945: samples take a bounded share (300-560px); the VRL editor and its
          collapsible diagnostics / tests / pivt pane take the rest of the page. */}
      <div className="grid grid-cols-1 lg:grid-cols-[clamp(300px,28%,560px)_32px_minmax(0,1fr)] gap-y-4 mt-3" data-testid="parse-panes">
        <div className="flex flex-col min-w-0">
          {entryPath === 'paste' && (
            <SamplesPaste sampleText={sampleText} setSampleText={setSampleText} sampleCount={sampleCount} />
          )}
          {entryPath === 'existing' && (
            <SamplesExisting feedId={feedId} setSampleText={setSampleText} setFeedId={undefined} />
          )}
          {entryPath === 'manual' && <SamplesManual feedId={feedId} />}
        </div>

        {/* "samples → parser" arrow indicator. Pulses primary while generating. */}
        <div className="hidden lg:flex items-center justify-center pointer-events-none" aria-hidden="true">
          <div
            className={cn(
              'w-8 h-8 rounded-full border bg-card flex items-center justify-center shadow-sm transition-colors duration-200',
              canUseParserAi && genState === 'streaming'
                ? 'border-primary/60 bg-primary/15 animate-pulse'
                : 'border-border',
            )}
          >
            <ArrowRight
              className={cn(
                'w-3.5 h-3.5 transition-colors',
                canUseParserAi && genState === 'streaming' ? 'text-primary' : 'text-muted-foreground/70',
              )}
            />
          </div>
        </div>

        <div className="flex flex-col min-w-0">
          <VrlPanel
            canUseParserAi={canUseParserAi}
            vrl={vrl}
            setVrl={setVrl}
            genState={genState}
            genElapsedMs={genElapsedMs}
            genStatus={genStatus}
            onRegenerate={onRegenerate}
            onCancelGenerate={onCancelGenerate}
            onValidate={onValidate}
            isValidating={isValidating}
            sidePane={sidePane}
            setSidePane={setSidePane}
            validation={validation}
            tests={tests}
            feedId={feedId}
            pivtMessage={pivtMessage}
            setPivtMessage={setPivtMessage}
            onSendPivt={onSendPivt}
            pivtPending={pivtPending}
            pivtSuggestion={pivtSuggestion}
            applyPivtSuggestion={applyPivtSuggestion}
            draftSaved={draftSaved}
          />
        </div>
      </div>
    </StepCard>
  );
}

// ==================================================================
// SegmentedPath
// ==================================================================
function SegmentedPath({
  value,
  onChange,
  canUseParserAi,
}: {
  value: 'paste' | 'existing' | 'manual';
  onChange: (v: 'paste' | 'existing' | 'manual') => void;
  canUseParserAi: boolean;
}) {
  const opts = [
    {
      id: 'paste' as const,
      label: 'Paste samples',
      icon: FileText,
      hint: canUseParserAi ? 'Recommended · pivt drafts the parser' : 'Recommended · validate against samples',
    },
    { id: 'existing' as const, label: 'From data', icon: Database, hint: 'Use logs already arriving' },
    { id: 'manual' as const, label: 'Write VRL', icon: Code, hint: 'Skip samples · expert mode' },
  ];
  return (
    <div className="rounded-md border border-border bg-card p-1 flex gap-1">
      {opts.map((o) => (
        <button
          key={o.id}
          type="button"
          onClick={() => onChange(o.id)}
          className={cn(
            'flex-1 px-2 py-1.5 rounded text-left transition-colors min-w-0',
            value === o.id ? 'bg-primary/15 text-foreground' : 'hover:bg-foreground/[0.04] text-foreground/80',
          )}
        >
          <div className="flex items-center gap-1.5">
            <o.icon className={cn('w-3 h-3 shrink-0', value === o.id ? 'text-primary' : 'text-muted-foreground')} />
            <span className="text-[11.5px] font-medium truncate">{o.label}</span>
          </div>
          <div className="text-[10px] text-muted-foreground mt-0.5 truncate">{o.hint}</div>
        </button>
      ))}
    </div>
  );
}

// ==================================================================
// SamplesPaste
// ==================================================================
function SamplesPaste({
  sampleText,
  setSampleText,
  sampleCount,
}: {
  sampleText: string;
  setSampleText: (v: string) => void;
  sampleCount: number;
}) {
  const { toast } = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const handleUpload = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const raw = String(reader.result ?? '');
      // Cap at first 50 non-empty lines so a multi-thousand-row CSV/log
      // doesn't blow up the meloD generation request. Users can paste more
      // manually if they really need it; the AI only needs ~5–20 samples
      // to draft a parser.
      const MAX_LINES = 50;
      const lines = raw.split(/\r?\n/);
      const nonEmpty = lines.filter((l) => l.trim()).length;
      const truncated = nonEmpty > MAX_LINES;
      const text = truncated
        ? lines.filter((l) => l.trim()).slice(0, MAX_LINES).join('\n')
        : raw;
      setSampleText(text);
      if (truncated) {
        toast({
          title: 'Trimmed to first 50 lines',
          description: `${file.name} had ${nonEmpty} lines. Using the first ${MAX_LINES} as samples — pivt only needs a handful to draft a parser.`,
        });
      }
    };
    reader.readAsText(file);
    // reset so re-uploading the same file re-fires onchange
    e.target.value = '';
  };

  // NAN-4792: show how the box splits into events, and flag lines a terminal
  // soft-wrapped (it only suggests the join; never rewrites by itself).
  const wrap = useMemo(() => detectWrappedLines(sampleText), [sampleText]);

  return (
    <div className="rounded-md border border-border bg-background flex flex-col h-[calc(100vh-320px)]">
      <div className="shrink-0 flex items-center gap-2 px-3 py-1.5 border-b border-border bg-card/40">
        <FileText className="w-3 h-3 text-muted-foreground" />
        <span className="text-[10.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/60">
          Raw samples · any format
        </span>
        <div className="flex-1" />
        <span className="text-[10.5px] font-mono text-muted-foreground tabular-nums">
          {sampleCount} sample{sampleCount === 1 ? '' : 's'}
        </span>
      </div>
      <textarea
        value={sampleText}
        onChange={(e) => setSampleText(e.target.value)}
        spellCheck={false}
        placeholder={'{"timestamp":"2026-04-26T14:21:08Z","event_type":"login",...}\n<134>Apr 26 14:21:08 host sshd[1234]: Accepted password for ...'}
        className="flex-1 bg-transparent px-3 py-2 font-mono text-[11px] leading-[1.55] text-foreground placeholder:text-muted-foreground/60 focus:outline-none resize-none scrollbar-thin"
      />
      <div className="shrink-0 px-3 py-1 border-t border-border text-[10.5px] font-mono text-muted-foreground tabular-nums" data-testid="sample-split">
        {describeSampleSplit(sampleText, sampleCount)}
      </div>
      {wrap.continuations.length > 0 && (
        <div className="shrink-0 flex items-center gap-2 px-3 py-1.5 border-t border-amber-500/30 bg-amber-500/[0.04] text-[10.5px]" data-testid="sample-wrapped">
          <AlertTriangle className="w-3 h-3 text-amber-500 shrink-0" />
          <span className="text-foreground/80">
            {wrap.continuations.length} line{wrap.continuations.length === 1 ? '' : 's'} look like terminal-wrapped tails of the
            line above; each would be sent as its own event.
          </span>
          <div className="flex-1" />
          <Button variant="outline" size="sm" className="h-6 px-2 text-[11px]" onClick={() => setSampleText(joinWrappedLines(sampleText, wrap))}>
            Join wrapped lines
          </Button>
        </div>
      )}
      <div className="shrink-0 flex items-center gap-2 px-3 py-1.5 border-t border-border text-[10px] font-mono text-muted-foreground/60">
        <Info className="w-2.5 h-2.5" />
        <span>Paste 5–10 representative events. JSON arrays auto-split.</span>
        <div className="flex-1" />
        <input
          ref={fileInputRef}
          type="file"
          accept=".txt,.json,.ndjson,.csv,.log,text/*"
          onChange={handleUpload}
          className="hidden"
        />
        <button type="button" onClick={() => fileInputRef.current?.click()} className="text-muted-foreground hover:text-primary">
          Upload file
        </button>
      </div>
    </div>
  );
}

// ==================================================================
// SamplesExisting — pulls real source_type counts from search backend
// ==================================================================
function SamplesExisting({
  feedId,
  setSampleText,
}: {
  feedId: string;
  setSampleText: (v: string) => void;
  setFeedId?: (v: string) => void;
}) {
  const { toast } = useToast();
  const [rows, setRows] = useState<Array<{ st: string; events: number }>>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const [fetchingSamples, setFetchingSamples] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.getSourceTypes();
      setRows(result.map(([st, events]) => ({ st, events })));
    } catch (err) {
      toast({
        title: 'Failed to load source types',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const filtered = rows.filter((r) => r.st.toLowerCase().includes(filter.toLowerCase()));
  const showEmpty = !loading && rows.length === 0;

  const handlePick = useCallback(
    async (st: string) => {
      setSelected(st);
      setFetchingSamples(true);
      try {
        const now = new Date();
        const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        const response = await api.search({
          query: `source_type="${st}"`,
          time_range: { start: yesterday.toISOString(), end: now.toISOString() },
          limit: 10,
          skip_field_stats: true,
        });
        const samples = (response.results ?? [])
          .map((event) => {
            if (typeof (event as Record<string, unknown>).message === 'string' && (event as Record<string, string>).message.trim()) {
              return (event as Record<string, string>).message;
            }
            return JSON.stringify(event);
          })
          .filter(Boolean);
        if (samples.length === 0) {
          toast({
            title: 'No samples',
            description: `No events found for source_type="${st}".`,
            variant: 'destructive',
          });
          return;
        }
        setSampleText(samples.join('\n'));
        toast({ title: 'Samples loaded', description: `${samples.length} event${samples.length === 1 ? '' : 's'} from source_type=${st}` });
      } catch (err) {
        toast({
          title: 'Failed to fetch samples',
          description: err instanceof Error ? err.message : 'Unknown error',
          variant: 'destructive',
        });
      } finally {
        setFetchingSamples(false);
      }
    },
    [setSampleText, toast],
  );

  return (
    <div className="rounded-md border border-border bg-background flex flex-col h-[calc(100vh-320px)]">
      <div className="shrink-0 flex items-center gap-2 px-3 py-1.5 border-b border-border bg-card/40">
        <Database className="w-3 h-3 text-muted-foreground" />
        <span className="text-[10.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/60">
          From recent ingest · last 24h
        </span>
        <div className="flex-1" />
        <button
          type="button"
          onClick={() => void refresh()}
          className="text-[10.5px] font-mono text-muted-foreground hover:text-primary inline-flex items-center gap-1"
        >
          <RefreshCw className={cn('w-3 h-3', loading && 'animate-spin')} />
          Refresh
        </button>
      </div>
      <div className="px-3 py-2 border-b border-border">
        <div className="relative">
          <SearchIcon className="w-3.5 h-3.5 text-muted-foreground absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Search source types…"
            className="h-8 w-full rounded-md border border-input bg-card pl-8 pr-2 text-[12px] text-foreground focus:border-primary focus:outline-none"
          />
        </div>
      </div>
      <div className="flex-1 overflow-auto scrollbar-thin">
        {loading && <div className="px-3 py-6 text-center text-[11px] text-muted-foreground">Loading…</div>}
        {showEmpty && (
          <div className="px-4 py-6 text-center">
            <div className="text-[12px] text-foreground/80 mb-1">No source types found</div>
            <div className="text-[10.5px] text-muted-foreground leading-relaxed">
              Start ingesting logs first, or switch to <span className="font-mono">Paste samples</span>.
            </div>
          </div>
        )}
        {!loading &&
          !showEmpty &&
          filtered.map((row) => (
            <button
              key={row.st}
              type="button"
              onClick={() => void handlePick(row.st)}
              className={cn(
                'w-full flex items-center gap-2 px-3 py-1.5 border-b border-border last:border-b-0 text-left',
                selected === row.st ? 'bg-primary/[0.08]' : 'hover:bg-foreground/[0.04]',
              )}
            >
              <span className={cn('w-1.5 h-1.5 rounded-full', selected === row.st ? 'bg-primary' : 'bg-muted-foreground/60')} />
              <span className="font-mono text-[11.5px] text-foreground flex-1 truncate">{row.st}</span>
              <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums">
                {formatEventsCount(row.events) ?? row.events}
              </span>
            </button>
          ))}
        {!loading && !showEmpty && filtered.length === 0 && (
          <div className="px-3 py-4 text-center text-[11px] text-muted-foreground/60">No matches</div>
        )}
      </div>
      <div className="shrink-0 px-3 py-1.5 border-t border-border text-[10px] font-mono text-muted-foreground/60">
        {fetchingSamples
          ? 'Fetching 10 most-recent events…'
          : selected
            ? `Picks 10 most-recent events · source_type=${selected}`
            : `Click a source_type to pull 10 sample events${feedId ? ` for ${feedId}` : ''}`}
      </div>
    </div>
  );
}

// ==================================================================
// SamplesManual — expert mode (no samples)
// ==================================================================
function SamplesManual({ feedId }: { feedId: string }) {
  return (
    <div className="rounded-md border border-border bg-background flex flex-col h-[calc(100vh-320px)] p-4">
      <div className="flex items-start gap-2.5">
        <div className="w-7 h-7 rounded bg-amber-500/15 border border-amber-500/30 flex items-center justify-center shrink-0">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
        </div>
        <div>
          <div className="text-[12.5px] font-medium text-foreground">Expert mode</div>
          <div className="text-[11px] text-muted-foreground leading-relaxed mt-0.5">
            Skip samples and write VRL by hand. We can't validate against real events, so deploy will warn but not block.{' '}
            <a
              href="https://vector.dev/docs/reference/vrl/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary hover:underline"
            >
              VRL reference →
            </a>
          </div>
        </div>
      </div>
      <div className="mt-4 rounded border border-border bg-muted p-2.5">
        <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground/60 mb-1">Starter snippet</div>
        <pre className="font-mono text-[11px] leading-[1.55] text-foreground/80 whitespace-pre">
{`# Minimum: set source_type and timestamp
.source_type = "${feedId || '<feed_id>'}"
.timestamp = parse_timestamp!(.message, format: "%+")`}
        </pre>
      </div>
    </div>
  );
}

// ==================================================================
// VrlPanel — toolbar + (optional) progress + editor + side tabs
// ==================================================================
type VrlPanelProps = {
  canUseParserAi: boolean;
  vrl: string;
  setVrl: (v: string) => void;
  genState: 'idle' | 'streaming' | 'done' | 'error';
  /** Wall-clock time the draft job has been running. */
  genElapsedMs: number;
  genStatus: string;
  onRegenerate: () => void;
  onCancelGenerate: () => void;
  onValidate: () => Promise<boolean>;
  isValidating: boolean;
  sidePane: 'diag' | 'tests' | 'ai';
  setSidePane: (v: 'diag' | 'tests' | 'ai') => void;
  validation: { diagnostics: VrlDiagnostic[]; syntaxValid: boolean | null; errorMessages: string[] };
  tests: Array<{ name: string; status: 'pass' | 'fail'; extracted: number; error?: string }>;
  feedId: string;
  pivtMessage: string;
  setPivtMessage: (v: string) => void;
  onSendPivt: (msg: string) => void;
  pivtPending: boolean;
  pivtSuggestion: MelodEditParserResponse | null;
  applyPivtSuggestion: () => void;
  draftSaved: boolean;
};

function VrlPanel(props: VrlPanelProps) {
  const {
    canUseParserAi,
    vrl,
    setVrl,
    genState,
    genElapsedMs,
    genStatus,
    onRegenerate,
    onCancelGenerate,
    onValidate,
    isValidating,
    sidePane,
    setSidePane,
    validation,
    tests,
    feedId,
    pivtMessage,
    setPivtMessage,
    onSendPivt,
    pivtPending,
    pivtSuggestion,
    applyPivtSuggestion,
    draftSaved,
  } = props;
  const [sidePaneCollapsed, setSidePaneCollapsedState] = useState<boolean>(
    () => typeof window !== 'undefined' && localStorage.getItem('add-feed-side-pane-collapsed') === '1',
  );
  const setSidePaneCollapsed = (v: boolean) => {
    setSidePaneCollapsedState(v);
    try {
      localStorage.setItem('add-feed-side-pane-collapsed', v ? '1' : '0');
    } catch {
      /* storage unavailable */
    }
  };
  useEffect(() => {
    if (!canUseParserAi && sidePane === 'ai') setSidePane('tests');
  }, [canUseParserAi, setSidePane, sidePane]);

  const tabs: Array<{
    id: 'diag' | 'tests' | 'ai';
    label: string;
    icon: typeof AlertTriangle;
    count: number | null;
    tone: 'good' | 'warn' | 'danger' | null;
  }> = [
    {
      id: 'diag',
      label: 'Diagnostics',
      icon: AlertTriangle,
      count: validation.diagnostics.length,
      tone: validation.diagnostics.some((d) => d.severity === 'error')
        ? 'danger'
        : validation.diagnostics.some((d) => d.severity === 'warn')
          ? 'warn'
          : 'good',
    },
    {
      id: 'tests',
      label: 'Tests',
      icon: Play,
      count: tests.length,
      tone: tests.length > 0 && tests.every((t) => t.status === 'pass') ? 'good' : tests.length > 0 ? 'danger' : null,
    },
    ...(canUseParserAi
      ? [{ id: 'ai' as const, label: 'pivt', icon: Sparkles, count: null, tone: null }]
      : []),
  ];

  return (
    <div className="rounded-md border border-border overflow-hidden flex flex-col h-[calc(100vh-320px)]">
      {/* Toolbar */}
      <div className="shrink-0 flex items-center gap-2 px-3 py-1.5 border-b border-border bg-card/40">
        <Code className="w-3 h-3 text-muted-foreground" />
        <span className="text-[11px] font-mono text-foreground">{feedId || 'parser'}.vrl</span>
        <span className="text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/60">
          {vrl.trim() ? 'VRL · pivt-drafted' : 'VRL · empty'}
        </span>
        <div className="flex-1" />
        {canUseParserAi && (
          <Button
            variant={vrl.trim() ? 'outline' : 'default'}
            size="sm"
            className="h-6 gap-1 text-[10.5px]"
            onClick={onRegenerate}
            disabled={genState === 'streaming'}
          >
            <Sparkles className="w-3 h-3" />
            {genState === 'streaming' ? 'Generating…' : vrl.trim() ? 'Regenerate' : 'Generate with pivt'}
          </Button>
        )}
        <Button variant="outline" size="sm" className="h-6 gap-1 text-[10.5px]" onClick={() => void onValidate()} disabled={isValidating || !vrl.trim()}>
          <Check className="w-3 h-3" />
          {isValidating ? 'Validating…' : 'Validate'}
        </Button>
      </div>

      {/* Generation progress */}
      {canUseParserAi && genState === 'streaming' && (
        <div className="shrink-0 border-b border-border bg-primary/[0.04] px-3 py-2">
          <div className="flex items-center gap-2">
            <Sparkles className="w-3 h-3 text-primary animate-pulse" />
            <span className="text-[11px] text-foreground">pivt is drafting VRL from your samples</span>
            <span className="text-[10.5px] font-mono text-muted-foreground tabular-nums">{formatElapsed(genElapsedMs)}</span>
            <div className="flex-1" />
            <Button variant="ghost" size="sm" className="h-5 px-1.5 text-[10.5px]" onClick={onCancelGenerate}>
              Cancel
            </Button>
          </div>
          <div className="text-[10.5px] font-mono text-muted-foreground/70 mt-1">{genStatus}</div>
          <div className="text-[10px] text-muted-foreground/60 mt-0.5">
            Drafts can take several minutes. You can keep this page open; the job runs on the server.
          </div>
        </div>
      )}

      {/* NAN-5079: an incomplete draft stays visible, with what is left. */}
      {canUseParserAi && genState === 'done' && isIncompleteDraftStatus(genStatus) && (
        <div
          data-testid="parser-draft-incomplete"
          className="shrink-0 border-b border-border bg-destructive/[0.06] px-3 py-2 flex items-start gap-2"
        >
          <AlertTriangle className="w-3 h-3 mt-0.5 text-destructive shrink-0" />
          <div className="min-w-0">
            <div className="text-[11px] text-foreground">Draft incomplete: review the failing samples before publishing</div>
            <div className="text-[10.5px] font-mono text-muted-foreground mt-0.5 break-words">{genStatus}</div>
          </div>
        </div>
      )}

      {/* Body */}
      <div
        className={cn(
          'flex-1 min-h-0 grid divide-x divide-border transition-[grid-template-columns] duration-150 ease-out',
          sidePaneCollapsed ? 'grid-cols-[minmax(0,1fr)_36px]' : 'grid-cols-[minmax(0,1fr)_280px]',
        )}
      >
        <div className="min-h-0 min-w-0 bg-background">
          <VrlEditor value={vrl} onChange={setVrl} placeholder="# Generated VRL will appear here" />
        </div>
        <div className="flex flex-col min-h-0 bg-card/40 overflow-hidden">
          {sidePaneCollapsed ? (
            <div className="flex flex-col items-center py-2 gap-1">
              <button
                type="button"
                onClick={() => setSidePaneCollapsed(false)}
                title="Expand panel"
                className="w-7 h-7 rounded-md hover:bg-muted flex items-center justify-center text-muted-foreground hover:text-foreground"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
              <div className="w-5 h-px bg-border my-1" />
              {tabs.map((t) => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => {
                    setSidePane(t.id);
                    setSidePaneCollapsed(false);
                  }}
                  title={t.label}
                  className={cn(
                    'w-7 h-7 rounded-md flex items-center justify-center transition-colors',
                    sidePane === t.id ? 'bg-muted' : 'hover:bg-muted/60',
                  )}
                >
                  <t.icon
                    className={cn(
                      'w-3.5 h-3.5',
                      t.tone === 'good' && 'text-emerald-500',
                      t.tone === 'warn' && 'text-amber-500',
                      t.tone === 'danger' && 'text-destructive',
                      !t.tone && 'text-muted-foreground',
                    )}
                  />
                </button>
              ))}
            </div>
          ) : (
            <>
              <div className="shrink-0 flex items-center gap-px px-2 py-1.5 border-b border-border">
                {tabs.map((t) => (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setSidePane(t.id)}
                    className={cn(
                      'h-7 px-2 rounded text-[10.5px] flex items-center gap-1.5 transition-colors whitespace-nowrap',
                      sidePane === t.id ? 'text-foreground bg-muted' : 'text-muted-foreground hover:text-foreground/80',
                    )}
                  >
                    <t.icon
                      className={cn(
                        'w-3 h-3 shrink-0',
                        sidePane === t.id && t.tone === 'good' && 'text-emerald-500',
                        sidePane === t.id && t.tone === 'warn' && 'text-amber-500',
                        sidePane === t.id && t.tone === 'danger' && 'text-destructive',
                      )}
                    />
                    <span>{t.label}</span>
                    {t.count !== null && (
                      <span
                        className={cn(
                          'inline-flex items-center justify-center min-w-[14px] h-3.5 px-1 rounded-[3px] font-mono text-[9.5px] tabular-nums',
                          t.tone === 'good' && 'bg-emerald-500/15 text-emerald-500',
                          t.tone === 'warn' && 'bg-amber-500/15 text-amber-500',
                          t.tone === 'danger' && 'bg-destructive/15 text-destructive',
                          !t.tone && 'bg-muted text-muted-foreground',
                        )}
                      >
                        {t.count}
                      </span>
                    )}
                  </button>
                ))}
                <div className="flex-1" />
                <button
                  type="button"
                  onClick={() => setSidePaneCollapsed(true)}
                  title="Collapse panel"
                  className="w-6 h-6 rounded hover:bg-muted flex items-center justify-center text-muted-foreground hover:text-foreground"
                >
                  <ChevronRight className="w-3 h-3" />
                </button>
              </div>
              {sidePane === 'diag' && <DiagPane diagnostics={validation.diagnostics} valid={validation.syntaxValid} />}
              {sidePane === 'tests' && <TestsPane tests={tests} />}
              {canUseParserAi && sidePane === 'ai' && (
                <AiPane
                  message={pivtMessage}
                  setMessage={setPivtMessage}
                  onSend={onSendPivt}
                  pending={pivtPending}
                  suggestion={pivtSuggestion}
                  applySuggestion={applyPivtSuggestion}
                  draftSaved={draftSaved}
                />
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ==================================================================
// Diag / Tests / AI panes
// ==================================================================
function DiagPane({ diagnostics, valid }: { diagnostics: VrlDiagnostic[]; valid: boolean | null }) {
  if (diagnostics.length === 0) {
    return (
      <div className="flex-1 min-h-0 overflow-auto scrollbar-thin">
        <div className="px-3 py-3 flex items-start gap-2">
          <span className="w-4 h-4 rounded bg-emerald-500/15 flex items-center justify-center shrink-0 mt-0.5">
            <Check className="w-2.5 h-2.5 text-emerald-500" />
          </span>
          <div>
            <div className="text-[11.5px] text-foreground">{valid === false ? 'Not yet validated' : 'All checks passed'}</div>
            <div className="text-[10.5px] text-muted-foreground mt-0.5">
              {valid === false
                ? 'Click Validate to check VRL syntax.'
                : 'VRL syntax is valid · 0 errors · 0 warnings.'}
            </div>
          </div>
        </div>
      </div>
    );
  }
  return (
    <div className="flex-1 min-h-0 overflow-auto scrollbar-thin">
      {diagnostics.map((d, i) => (
        <DiagItem key={i} d={d} />
      ))}
    </div>
  );
}

function DiagItem({ d }: { d: VrlDiagnostic }) {
  const palette =
    d.severity === 'error'
      ? { text: 'text-destructive', bg: 'bg-destructive/15', Icon: X }
      : d.severity === 'warn'
        ? { text: 'text-amber-500', bg: 'bg-amber-500/15', Icon: AlertTriangle }
        : { text: 'text-emerald-500', bg: 'bg-emerald-500/15', Icon: Check };
  const { Icon } = palette;
  return (
    <div className="px-3 py-2 border-b border-border last:border-b-0">
      <div className="flex items-start gap-2">
        <span className={cn('w-4 h-4 rounded flex items-center justify-center shrink-0 mt-0.5', palette.bg)}>
          <Icon className={cn('w-2.5 h-2.5', palette.text)} />
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5 flex-wrap">
            {d.code && <span className={cn('text-[10px] font-mono font-medium', palette.text)}>{d.code}</span>}
            {d.line != null && (
              <span className="text-[10px] font-mono text-muted-foreground/60">
                ln {d.line}
                {d.col != null ? `:${d.col}` : ''}
              </span>
            )}
          </div>
          <div className="text-[11px] text-foreground mt-0.5 leading-relaxed">{d.message}</div>
          {d.hint && <div className="text-[10.5px] text-muted-foreground mt-1 leading-relaxed">{d.hint}</div>}
        </div>
      </div>
    </div>
  );
}

function TestsPane({
  tests,
}: {
  tests: Array<{ name: string; status: 'pass' | 'fail'; extracted: number; error?: string }>;
}) {
  if (tests.length === 0) {
    return (
      <div className="flex-1 min-h-0 overflow-auto scrollbar-thin">
        <div className="px-3 py-3 text-[11px] text-muted-foreground">
          Add samples and write/generate VRL to see per-sample test results.
        </div>
      </div>
    );
  }
  return (
    <div className="flex-1 min-h-0 overflow-auto scrollbar-thin">
      {tests.map((t, i) => (
        <div key={i} className="px-3 py-2 border-b border-border last:border-b-0">
          <div className="flex items-center gap-2">
            <span
              className={cn('w-1.5 h-1.5 rounded-full shrink-0', t.status === 'pass' ? 'bg-emerald-500' : 'bg-destructive')}
            />
            <span className="text-[11px] text-foreground flex-1 truncate">{t.name}</span>
            <span className="text-[10px] font-mono text-muted-foreground tabular-nums">{t.extracted} fields</span>
          </div>
          {t.status === 'fail' && t.error && (
            <div className="text-[10.5px] text-destructive mt-1 ml-3.5 truncate" title={t.error}>
              {t.error}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function AiPane({
  message,
  setMessage,
  onSend,
  pending,
  suggestion,
  applySuggestion,
  draftSaved,
}: {
  message: string;
  setMessage: (v: string) => void;
  onSend: (msg: string) => void;
  pending: boolean;
  suggestion: MelodEditParserResponse | null;
  applySuggestion: () => void;
  draftSaved: boolean;
}) {
  const STARTERS = [
    'Explain this parser',
    'Add geo enrichment',
    'Redact sensitive fields',
    'Find redundant logic',
  ];
  const disabled = pending || !draftSaved;
  return (
    <div className="flex flex-col flex-1 min-h-0">
      <div className="px-3 py-3 space-y-3 flex-1 overflow-auto scrollbar-thin">
        {!draftSaved ? (
          <div className="rounded-md bg-amber-500/[0.08] border border-amber-500/30 p-2.5 flex items-start gap-2">
            <Info className="w-3 h-3 text-amber-500 shrink-0 mt-0.5" />
            <div className="text-[10.5px] text-foreground/80 leading-relaxed">
              <span className="text-foreground font-medium">Save a draft first.</span> pivt edits an existing parser, so we
              need to persist this feed before chatting. Use <span className="font-medium">Save draft</span> on Step 3.
            </div>
          </div>
        ) : (
          <div className="rounded-md bg-primary/[0.08] border border-primary/20 p-2.5 flex items-start gap-2">
            <Sparkles className="w-3 h-3 text-primary shrink-0 mt-0.5" />
            <div className="text-[10.5px] text-foreground/80 leading-relaxed">
              <span className="text-foreground font-medium">Ask pivt</span> to tweak the parser — add fields, rename,
              redact, or explain.
            </div>
          </div>
        )}
        <div className="space-y-1.5">
          {STARTERS.map((q) => (
            <button
              key={q}
              type="button"
              disabled={disabled}
              onClick={() => onSend(q)}
              className="w-full text-left h-7 px-2 rounded border border-border bg-card text-[10.5px] text-foreground/80 hover:text-foreground hover:border-primary/40 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {q}
            </button>
          ))}
        </div>
        {suggestion && (
          <div className="rounded-md border border-border bg-card p-2.5 space-y-2">
            <div className="text-[10.5px] text-muted-foreground leading-relaxed">{suggestion.message}</div>
            {suggestion.updated_vrl && (
              <Button size="sm" variant="default" className="h-6 gap-1 text-[10.5px] w-full" onClick={applySuggestion}>
                <Check className="w-3 h-3" />
                Apply to editor
              </Button>
            )}
          </div>
        )}
      </div>
      <div className="shrink-0 p-2 border-t border-border">
        <div className="flex items-end gap-1.5">
          <textarea
            rows={2}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            disabled={!draftSaved}
            placeholder={draftSaved ? 'Ask pivt to edit, explain, or add fields…' : 'Save draft to enable pivt chat…'}
            className="flex-1 resize-none px-2 py-1.5 rounded border border-border bg-card text-[11px] text-foreground placeholder:text-muted-foreground/60 focus:border-primary focus:outline-none disabled:opacity-50"
          />
          <Button
            variant="default"
            size="sm"
            className="h-[34px] gap-1"
            disabled={disabled || !message.trim()}
            onClick={() => onSend(message)}
          >
            {pending ? <Zap className="w-3 h-3 animate-pulse" /> : <ArrowRight className="w-3 h-3" />}
          </Button>
        </div>
      </div>
    </div>
  );
}

// ==================================================================
// TimezonePicker
// ==================================================================
function TimezonePicker({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const groups = useMemo(() => {
    if (!q) return TIMEZONES;
    const lower = q.toLowerCase();
    return TIMEZONES.map((g) => ({
      region: g.region,
      items: g.items.filter(
        (it) =>
          it.id.toLowerCase().includes(lower) ||
          it.label.toLowerCase().includes(lower) ||
          it.hint.toLowerCase().includes(lower),
      ),
    })).filter((g) => g.items.length > 0);
  }, [q]);

  const selected = TIMEZONES.flatMap((g) => g.items).find((it) => it.id === value);

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="h-8 px-2.5 rounded-md border border-border bg-card hover:bg-foreground/[0.04] inline-flex items-center gap-1.5 text-[11px] text-foreground/80"
      >
        <Clock className="w-3 h-3 text-muted-foreground" />
        <span className="font-mono">{value}</span>
        <span className="text-muted-foreground/60">·</span>
        <span className="text-muted-foreground/60">{selected?.hint || ''}</span>
        <ChevronDown className={cn('w-3 h-3 text-muted-foreground ml-0.5 transition-transform', open && 'rotate-180')} />
      </button>
      {open && (
        <div className="absolute right-0 bottom-full mb-1.5 w-[320px] rounded-md border border-border bg-popover shadow-[0_8px_30px_rgba(0,0,0,0.45)] z-30 flex flex-col max-h-[360px]">
          <div className="shrink-0 px-2 py-1.5 border-b border-border">
            <div className="relative">
              <SearchIcon className="w-3 h-3 text-muted-foreground absolute left-2 top-1/2 -translate-y-1/2" />
              <input
                autoFocus
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Search timezones…"
                className="h-7 w-full rounded border border-input bg-background pl-7 pr-2 text-[11.5px] text-foreground focus:border-primary focus:outline-none"
              />
            </div>
          </div>
          <div className="flex-1 overflow-auto scrollbar-thin py-1">
            {groups.map((g) => (
              <div key={g.region}>
                <div className="px-2.5 py-1 text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/60">
                  {g.region}
                </div>
                {g.items.map((it) => (
                  <button
                    key={it.id}
                    type="button"
                    onClick={() => {
                      onChange(it.id);
                      setOpen(false);
                    }}
                    className={cn(
                      'w-full flex items-center gap-2 px-2.5 py-1 text-left',
                      value === it.id ? 'bg-primary/10' : 'hover:bg-foreground/[0.04]',
                    )}
                  >
                    <span className="text-[11.5px] text-foreground flex-1 truncate">{it.label}</span>
                    <span className="text-[10px] font-mono text-muted-foreground">{it.hint}</span>
                    {value === it.id && <Check className="w-3 h-3 text-primary" />}
                  </button>
                ))}
              </div>
            ))}
            {groups.length === 0 && <div className="px-3 py-4 text-center text-[11px] text-muted-foreground/60">No matches</div>}
          </div>
          {value !== 'UTC' && (
            <div className="shrink-0 border-t border-border px-2.5 py-1.5 bg-card/40">
              <div className="text-[10px] text-muted-foreground leading-relaxed">
                Events without offset info will be treated as <span className="font-mono text-foreground/80">{value}</span> and
                converted to UTC.
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ==================================================================
// Step 3 — Review & deploy
// ==================================================================
type Step3Props = {
  expanded: boolean;
  onActivate: () => void;
  transport: 'push' | 'pull';
  gate: ReturnType<typeof computeDeployGate>;
  onGateAction: (action: GateAction) => void;
  feedId: string;
  name: string;
  sourceConfig?: SourceConfigWithEvents;
  namespaceFull: string;
  timezone: string;
  category: string;
  vendor: string;
  product: string;
  description: string;
  vrl: string;
  acceptWarnings: boolean;
  setAcceptWarnings: (v: boolean) => void;
  canDeploy: boolean;
  onSaveDraft: () => void;
  onDeploy: () => void;
  savingDraft: boolean;
  deploying: boolean;
};

function Step3Deploy(props: Step3Props) {
  const {
    expanded,
    onActivate,
    transport,
    gate,
    onGateAction,
    feedId,
    name,
    sourceConfig,
    namespaceFull,
    timezone,
    category,
    vendor,
    product,
    description,
    vrl,
    acceptWarnings,
    setAcceptWarnings,
    canDeploy,
    onSaveDraft,
    onDeploy,
    savingDraft,
    deploying,
  } = props;

  const ok = canDeploy;
  const vrlLineCount = vrl.split('\n').length;

  const summary = (
    <div className="hidden md:flex items-center gap-3 text-[11px] shrink-0">
      <span className={canDeploy ? 'text-emerald-500' : 'text-amber-500'}>
        {canDeploy ? '● ready' : '● review'}
      </span>
    </div>
  );

  return (
    <StepCard
      n={6}
      title="Review & publish"
      eyebrow="STEP 6 · Publish"
      expanded={expanded}
      ok={ok}
      onActivate={onActivate}
      summary={summary}
      footer={
        <>
          <span className="text-[10.5px] text-muted-foreground/70">
            {transport === 'push'
              ? 'Publishes the parser; the source keeps receiving through its tokens.'
              : 'Creates the parser + routing rule, then deploys both.'}
          </span>
          <div className="flex-1" />
          <Button variant="outline" size="sm" className="h-8" onClick={onSaveDraft} disabled={savingDraft}>
            {savingDraft ? 'Saving…' : 'Save draft'}
          </Button>
          <Button variant="default" size="sm" className="h-8 gap-1.5" disabled={!canDeploy || deploying} onClick={onDeploy}>
            <Zap className="w-3.5 h-3.5" />
            {deploying ? 'Publishing…' : 'Publish source'}
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-12 lg:col-span-7 space-y-3">
          <ArtifactCard
            kind="Log source"
            icon={Rss}
            primary={feedId || '—'}
            secondary={name || '—'}
            rows={[
              ['name', name || '—'],
              ['source_type', feedId || '—'],
              ['namespace', namespaceFull],
              ['timezone', timezone],
              ['category', category || '—'],
              ['vendor', vendor || '—'],
              ['product', product || '—'],
            ]}
            description={description}
          />
          {transport === 'pull' && <ArtifactCard
            kind="Routing rule"
            icon={RouteIcon}
            primary={`source_type = "${feedId || '—'}"`}
            secondary={`on ${sourceConfig?.name || '—'}`}
            rows={[
              ['transport', sourceConfig?.name || '—'],
              ['match_field', 'source_type'],
              ['match_type', 'exact'],
              ['match_value', feedId || '—'],
              ['target', feedId || '—'],
            ]}
          />}
          <ArtifactCard
            kind="VRL parser"
            icon={Code}
            primary={`${feedId || 'parser'}.vrl`}
            secondary={`${vrlLineCount} ${vrlLineCount === 1 ? 'line' : 'lines'}`}
            code={vrl}
          />
        </div>

        <div className="col-span-12 lg:col-span-5">
          <DeployGatePanel
            gate={gate}
            acknowledged={acceptWarnings}
            setAcknowledged={setAcceptWarnings}
            onAction={onGateAction}
          />

          <div className="mt-3 rounded-lg border border-border bg-muted p-3">
            <div className="text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground/60 mb-1.5">After publish</div>
            <ul className="space-y-1 text-[10.5px] text-muted-foreground">
              <li className="flex gap-1.5">
                <ArrowRight className="w-3 h-3 mt-0.5 shrink-0 text-muted-foreground/60" />
                {transport === 'push' ? 'New events are parsed within seconds (Vector reload)' : 'Routing rule activates within 2s'}
              </li>
              <li className="flex gap-1.5">
                <ArrowRight className="w-3 h-3 mt-0.5 shrink-0 text-muted-foreground/60" />
                First event appears in <span className="font-mono text-foreground/80">source_type={feedId || '—'}</span>
              </li>
              <li className="flex gap-1.5">
                <ArrowRight className="w-3 h-3 mt-0.5 shrink-0 text-muted-foreground/60" />
                Iterate the parser anytime — versions are tracked
              </li>
            </ul>
          </div>
        </div>
      </div>
    </StepCard>
  );
}

function ArtifactCard({
  kind,
  icon: Icon,
  primary,
  secondary,
  rows,
  code,
  description,
}: {
  kind: string;
  icon: typeof Pencil;
  primary: string;
  secondary?: string;
  rows?: Array<[string, string]>;
  code?: string;
  description?: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-background overflow-hidden">
      <div className="px-3 py-2 border-b border-border bg-card/40 flex items-center gap-2">
        <Icon className="w-3.5 h-3.5 text-muted-foreground" />
        <span className="text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/60">
          Will create · {kind}
        </span>
        <div className="flex-1" />
        {secondary && <span className="text-[10.5px] font-mono text-muted-foreground">{secondary}</span>}
      </div>
      <div className="px-3 py-2.5">
        <div className="text-[12.5px] font-mono text-foreground">{primary}</div>
        {description && <div className="text-[10.5px] text-muted-foreground mt-1 leading-relaxed">{description}</div>}
        {rows && (
          <div className="mt-2 grid grid-cols-[100px_1fr] gap-y-1 gap-x-3 text-[10.5px] font-mono">
            {rows.map(([k, v]) => (
              <FragmentRow key={k} k={k} v={v} />
            ))}
          </div>
        )}
        {code && (
          <pre className="mt-2 max-h-[200px] overflow-auto scrollbar-thin font-mono text-[10.5px] leading-[1.55] text-foreground/80 bg-muted border border-border rounded p-2 whitespace-pre">
            {code}
          </pre>
        )}
      </div>
    </div>
  );
}

function FragmentRow({ k, v }: { k: string; v: string }) {
  return (
    <>
      <span className="text-muted-foreground/60">{k}</span>
      <span className="text-foreground/80 truncate">{v}</span>
    </>
  );
}
