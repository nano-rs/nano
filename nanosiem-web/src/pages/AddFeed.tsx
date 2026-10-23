// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * AddFeed (NAN-522) — redesigned log-onboarding wizard.
 *
 * Replaces the legacy 6-step LogSourceWizard with a 3-step flow:
 *   1. Identify       — feed identifier + ingestion source + namespace + metadata
 *   2. Sample & parse — paste / pick / skip → AI VRL → editor + diagnostics + tests
 *   3. Review & deploy — dense summary + soft-block validation gate
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
  BookOpen,
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
  Network,
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
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useToast } from '@/hooks/use-toast';
import { useMelodJob } from '@/enterprise/hooks/use-melod-job';
import { api, ApiClientError } from '@/lib/api';
import type {
  GeneratedParser,
  MelodEditParserResponse,
  ParserProgressEvent,
  RoutingRule,
  SourceConfiguration,
  VrlDiagnostic,
} from '@/lib/api';
import { cn } from '@/lib/utils';
import { VrlEditor } from '@/components/editor/VrlEditor';
import { useSharedTenant } from '@/hooks/use-shared-tenant';
import type { TenantIngestEndpoint, TenantParserRollout } from '@/lib/api/types';
import { RolloutStatus } from '@/components/parser-rollout/RolloutStrip';
import { PARSER_ROLLOUTS_QUERY_KEY, latestRolloutFor, rolloutPollInterval } from '@/lib/parser-rollout';
import {
  INGEST_CREDENTIALS_QUERY_KEY,
  INGEST_ENDPOINT_QUERY_KEY,
  PROTOCOL_LABEL,
  ADD_DATA_SOURCE_PARAM,
  addDataSources,
  preselectedAddDataSource,
  type AddDataSource,
} from '@/lib/add-data-sources';
import { describeIngestCredentialError } from '@/lib/ingest-credential-errors';
import { IngestEndpointCard } from '@/components/add-data/IngestEndpointCard';
import { IssueCredentialPanel } from '@/components/add-data/IssueCredentialPanel';
import { INGEST_CREDENTIALS_PATH } from '@/components/add-data/LogSourcesTabs';
import { Checkbox } from '@/components/ui/checkbox';
import { useCapabilities } from '@/hooks/use-capabilities';

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

const RAIL_COLLAPSED_KEY = 'add-feed-rail-collapsed';

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
function formatEventsCount(n: number | null | undefined): string | null {
  if (n === null || n === undefined) return null;
  if (n < 1000) return String(n);
  if (n < 1_000_000) return `${(n / 1000).toFixed(1)}K`;
  if (n < 1_000_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  return `${(n / 1_000_000_000).toFixed(1)}B`;
}

const SOURCE_ICON_FOR_TYPE = (type: string) => {
  if (type === 'http' || type === 'vector') return Globe;
  if (type === 'aws_s3' || type === 'aws_sqs' || type === 'gcp_pubsub' || type === 'azure_event_hubs') return Cloud;
  if (type === 'kafka') return Database;
  return Rss;
};

const SOURCE_TYPE_LABEL: Record<string, string> = {
  http: 'HTTP · ingest',
  kafka: 'Kafka',
  aws_s3: 'AWS S3',
  gcp_pubsub: 'GCP Pub/Sub',
  splunk_hec: 'HEC',
  vector: 'Vector',
  aws_sqs: 'AWS SQS',
  azure_event_hubs: 'Azure Event Hubs',
};

// ------------------------------------------------------------------
// Top-level page
// ------------------------------------------------------------------
type SourceConfigWithEvents = SourceConfiguration & { events_24h?: number | null };

/** Hosted-shared Step 1: pick an enrolled source, or build a custom one (Step 2). */
type SharedSourceMode = 'existing' | 'custom';
/** Hosted-shared arrival: one token per source, or one collector token for many (NAN-2597). */
type SharedArrivalMode = 'direct' | 'collector';

export function AddFeed() {
  // NAN-2593: hosted-shared tenants get the "Add data" branch of this wizard.
  // Data arrives at the tenant's own ingest endpoint with a per-source
  // credential, so Step 1 picks how data arrives and which source (instead of
  // a source configuration), Step 3 skips routing rules and source configs,
  // and a Step 4 issues the credential. Dedicated deployments are unchanged.
  const shared = useSharedTenant();
  useDocumentTitle(shared ? 'Add data' : 'Add Feed');
  const navigate = useNavigate();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const { data: activeSchema } = useQuery({
    queryKey: ['schema-fields'],
    queryFn: () => api.getSchemaFields(),
    staleTime: Infinity,
    gcTime: Infinity,
  });
  const strictOcsf = activeSchema?.schema === 'ocsf';

  // ------------ Step 1 state ------------
  const [feedId, setFeedId] = useState('');
  const [sourceConfigId, setSourceConfigId] = useState('');
  const [nsPrefix, setNsPrefix] = useState<NamespacePrefixId>('default');
  const [nsSuffix, setNsSuffix] = useState('');
  const [name, setName] = useState('');
  // Once the user types in `name` directly, stop auto-populating from feedId.
  const nameTouched = useRef(false);
  const [category, setCategory] = useState('');
  const [vendor, setVendor] = useState('');
  const [product, setProduct] = useState('');
  const [description, setDescription] = useState('');

  // ------------ Shared (hosted) state — NAN-2593 ------------
  const endpointQuery = useQuery({
    queryKey: INGEST_ENDPOINT_QUERY_KEY,
    queryFn: () => api.getIngestEndpoint(),
    enabled: shared,
    staleTime: 60 * 1000,
  });
  const registryQuery = useQuery({
    queryKey: ['add-data', 'log-sources'],
    queryFn: () => api.listLogSources(),
    enabled: shared,
    staleTime: 30 * 1000,
  });
  const addSources = useMemo(
    () => addDataSources(endpointQuery.data, registryQuery.data),
    [endpointQuery.data, registryQuery.data],
  );
  const [sharedModeChoice, setSharedMode] = useState<SharedSourceMode>('existing');
  const [selectedSlug, setSelectedSlug] = useState('');
  // NAN-2597: a collector token spans existing sources; custom sources are built (and rolled out) first.
  const [arrivalChoice, setArrival] = useState<SharedArrivalMode>('direct');
  // NAN-2617: collectors exist only once the tenant's Worker speaks ingress v2
  // (`ingress_contract.collector_credentials`, derived per tenant by the API).
  const collectorsEnabled = endpointQuery.data?.ingress_contract?.collector_credentials === true;
  const arrival: SharedArrivalMode = collectorsEnabled ? arrivalChoice : 'direct';
  const [selectedSlugs, setSelectedSlugs] = useState<string[]>([]);
  const collectorArrival = shared && arrival === 'collector';
  const sharedMode: SharedSourceMode = collectorArrival ? 'existing' : sharedModeChoice;
  const collectorTargets = useMemo(
    () => selectedSlugs.map((slug) => addSources.find((s) => s.slug === slug)).filter((s): s is AddDataSource => !!s),
    [addSources, selectedSlugs],
  );
  const toggleSlug = useCallback(
    (slug: string) => setSelectedSlugs((prev) => (prev.includes(slug) ? prev.filter((s) => s !== slug) : [...prev, slug])),
    [],
  );
  // The source the Issue step issues for: the picked source, or the custom
  // source once Step 3 activated it.
  const [issueSource, setIssueSource] = useState<AddDataSource | null>(null);
  const [issueLogSourceId, setIssueLogSourceId] = useState<string | undefined>(undefined);
  // NAN-2607: the parser rollout the custom source's activation filed.
  const [sharedRollout, setSharedRollout] = useState<TenantParserRollout | null>(null);
  const issueTarget: AddDataSource | null =
    sharedMode === 'existing' ? addSources.find((s) => s.slug === selectedSlug) ?? null : issueSource;
  const issueTargetLogSourceId = sharedMode === 'existing' ? issueTarget?.logSource?.id : issueLogSourceId;

  // ------------ Step 2 state ------------
  const [entryPath, setEntryPath] = useState<'paste' | 'existing' | 'manual'>('paste');
  const [sampleText, setSampleText] = useState('');
  const [vrl, setVrl] = useState('');
  const [genState, setGenState] = useState<'idle' | 'streaming' | 'done' | 'error'>('idle');
  const [genProgress, setGenProgress] = useState(0);
  const [genStatus, setGenStatus] = useState<string>('');
  const genControllerRef = useRef<AbortController | null>(null);
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
  const [testedInputKey, setTestedInputKey] = useState<string | null>(null);
  const [isTesting, setIsTesting] = useState(false);

  // pivt (AI tab) state — stable session id per page load.
  const sessionIdRef = useRef<string>(`add-feed-${Date.now()}`);
  const [pivtMessage, setPivtMessage] = useState('');
  const [pivtPending, setPivtPending] = useState(false);
  const [pivtSuggestion, setPivtSuggestion] = useState<MelodEditParserResponse | null>(null);
  const editParserJob = useMelodJob<MelodEditParserResponse>();

  // ------------ Step 3 state ------------
  const [acceptWarnings, setAcceptWarnings] = useState(false);
  const [draftId, setDraftId] = useState<string | null>(null);
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

  // NAN-2946: `?source=<slug>` (Log Source detail "Issue credential", Log
  // Sources platform rows) preselects that source as a direct credential and
  // opens the Issue step. Applied once, after the source list has loaded; an
  // unknown slug leaves the wizard on Step 1.
  const [searchParams] = useSearchParams();
  const requestedSource = shared ? searchParams.get(ADD_DATA_SOURCE_PARAM) : null;
  const deepLinkApplied = useRef(false);
  useEffect(() => {
    if (deepLinkApplied.current || !requestedSource) return;
    if (endpointQuery.isLoading || registryQuery.isLoading) return;
    deepLinkApplied.current = true;
    const target = preselectedAddDataSource(addSources, requestedSource);
    if (!target) return;
    setArrival('direct');
    setSharedMode('existing');
    setSelectedSlug(target.slug);
    setActiveStep(4);
  }, [requestedSource, addSources, endpointQuery.isLoading, registryQuery.isLoading]);
  const [railCollapsed, setRailCollapsed] = useState<boolean>(() => {
    try {
      return localStorage.getItem(RAIL_COLLAPSED_KEY) === '1';
    } catch {
      return false;
    }
  });
  const toggleRail = () =>
    setRailCollapsed((v) => {
      const next = !v;
      try {
        localStorage.setItem(RAIL_COLLAPSED_KEY, next ? '1' : '0');
      } catch {
        /* ignore */
      }
      return next;
    });

  // ------------ Source configurations (real API) ------------
  const [sourceConfigs, setSourceConfigs] = useState<SourceConfigWithEvents[]>([]);
  const [loadingConfigs, setLoadingConfigs] = useState(true);
  const [existingRules, setExistingRules] = useState<RoutingRule[]>([]);

  useEffect(() => {
    // Hosted-shared tenants have no source configurations (platform-managed).
    if (shared) {
      setLoadingConfigs(false);
      return;
    }
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
  }, [shared, toast]);

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
  const warnings = validation.diagnostics.filter((d) => d.severity === 'warn').length;
  const passingTests = tests.filter((t) => t.status === 'pass').length;
  const failingTests = tests.length - passingTests;
  const currentTestKey = `${strictOcsf ? 'ocsf' : 'udm'}\0${vrl}\0${sampleText}`;
  const testsRun = tests.length > 0 && testedInputKey === currentTestKey;

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

  const canDeploy =
    !!feedId &&
    (shared || !!sourceConfigId) &&
    !!name &&
    errors === 0 &&
    (warnings === 0 || acceptWarnings) &&
    // OCSF deployment requires at least one sample that passed both stages:
    // VRL first, then the schema contract. Expert mode cannot bypass it.
    (!strictOcsf || (sampleCount > 0 && testsRun)) &&
    (failingTests === 0 || (entryPath === 'manual' && !strictOcsf)) &&
    // Transport readiness can be soft-acknowledged like other warnings.
    // (If user overrides, they can deploy then enable/deploy the source
    // config separately — meloD concierge does the same defensive sequence.)
    (shared || reachability?.transportReady !== false || acceptWarnings) &&
    namespaceCheck?.valid !== false;

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
      setTestedInputKey(null);
      return;
    }
    const inputKey = currentTestKey;
    setIsTesting(true);
    try {
      const results = await Promise.all(
        samples.map(async (sample, i) => {
          try {
            const r = await api.testLogSourceVrl(vrl, sample, undefined, strictOcsf);
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
      setTestedInputKey(inputKey);
    } finally {
      setIsTesting(false);
    }
  }, [currentTestKey, sampleText, strictOcsf, vrl]);

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
    if (genControllerRef.current) {
      genControllerRef.current.abort();
      genControllerRef.current = null;
    }
    setGenState('streaming');
    setGenProgress(5);
    setGenStatus('Parsing samples · detecting structure…');

    // NOTE: don't send `feed_id` — it must be a TypeID like `feed_<base32>` and
    // we don't have one yet (the log source isn't created). When `sample_logs`
    // is provided the backend doesn't need feed_id; it uses the inline samples.
    genControllerRef.current = api.melodCreateParserStreaming(
      {
        ...(sessionIdRef.current ? { session_id: sessionIdRef.current } : {}),
        log_source_type: feedId,
        sample_logs: samples,
        message: strictOcsf
          ? `Generate a complete OCSF 1.9 VRL parser for "${feedId}" from these ${samples.length} sample event(s). Emit canonical OCSF fields at the event root, set metadata.log_source to "${feedId}", and place only source fields that have no OCSF mapping under unmapped.*. Do not emit .udm, .ext, source_type, or Nano serving aliases.`
          : `Generate a VRL parser for "${feedId}" logs from these ${samples.length} sample event(s). The .source_type field is ALREADY SET — do NOT modify it. Extract all useful fields into the UDM schema.`,
      },
      (event: ParserProgressEvent) => {
        switch (event.type) {
          case 'started':
            setGenProgress(10);
            setGenStatus('Drafting parser · attempt 1…');
            break;
          case 'generating_parser':
            setGenProgress(Math.min(35 + event.attempt * 5, 60));
            setGenStatus(`Drafting parser · attempt ${event.attempt}/${event.max_attempts}…`);
            break;
          case 'validating_syntax':
            setGenProgress(65);
            setGenStatus('Validating VRL syntax…');
            break;
          case 'syntax_validation_result':
            setGenProgress(70);
            setGenStatus(event.valid ? 'Syntax valid · testing samples…' : 'Fixing syntax errors…');
            break;
          case 'testing_parser':
            setGenProgress(75 + Math.floor((event.sample_index / Math.max(event.total_samples, 1)) * 10));
            setGenStatus(`Testing against sample ${event.sample_index}/${event.total_samples}…`);
            break;
          case 'udm_validation_result':
            setGenProgress(95);
            setGenStatus(strictOcsf ? 'Finalizing · OCSF 1.9 validation…' : 'Finalizing · UDM validation…');
            break;
          case 'retrying_with_feedback':
            setGenProgress(50);
            setGenStatus(`Retrying · ${event.reason}`);
            break;
          case 'error':
            setGenState('error');
            setGenProgress(0);
            setGenStatus(event.message);
            toast({ title: 'Generation failed', description: event.message, variant: 'destructive' });
            break;
          default:
            break;
        }
      },
      (parser: GeneratedParser | null, error?: string) => {
        genControllerRef.current = null;
        if (error || !parser) {
          setGenState('error');
          setGenProgress(0);
          setGenStatus(error ?? 'Generation failed');
          if (error) {
            toast({ title: 'Generation failed', description: error, variant: 'destructive' });
          }
          return;
        }
        setVrl(parser.vrl_code);
        setGenState('done');
        setGenProgress(100);
        setGenStatus('Done');
      },
    );
  }, [entryPath, feedId, sampleText, strictOcsf, toast]);

  // Cancel any in-flight stream on unmount.
  useEffect(() => {
    return () => {
      if (genControllerRef.current) genControllerRef.current.abort();
    };
  }, []);

  // ------------ pivt edit-parser submit ------------
  const sendPivtMessage = useCallback(
    async (message: string) => {
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
    [draftId, editParserJob, sampleText, toast, vrl],
  );

  // ------------ Step 3 helpers — namespace + reachability ------------
  // Re-check namespace + reachability when entering / state changes.
  useEffect(() => {
    if (activeStep !== 3) return;
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
    if (shared || activeStep !== 3 || !sourceConfigId || !feedId) return;
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
  }, [shared, activeStep, sourceConfigId, feedId]);

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
        dispatch_source_config_id: sourceConfigId || undefined,
        parser_vrl: vrl,
        category: category || undefined,
        vendor: vendor || undefined,
        product: product || undefined,
        match_values: [feedId],
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
  }, [category, description, feedId, name, namespaceFull, product, settleAutoPersist, sourceConfigId, timezone, toast, vendor, vrl]);

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
        dispatch_source_config_id: sourceConfigId || undefined,
        parser_vrl: vrl,
        category: category || undefined,
        vendor: vendor || undefined,
        product: product || undefined,
        match_values: [feedId],
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
  }, [category, description, draftId, feedId, name, namespaceFull, product, sourceConfigId, timezone, vendor, vrl]);

  // Debounced trigger: create the draft ~1.2s after the user pauses once Step 1
  // is valid, rather than on every keystroke. Re-arms while `!draftId`; once the
  // draft exists this becomes inert.
  useEffect(() => {
    if (draftId || !feedId || !name) return;
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
  }, [feedId, name, draftId, autoPersistDraft]);

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

  // ------------ Deploy (hosted-shared, NAN-2593) ------------
  // No routing rule and no source configuration: the registry entry is
  // created and activated, and the parser reaches the tenant's parser cell
  // through the parser-bundle rollout (NAN-2607). The flow then continues to
  // the Issue step; the credential can be requested at once and is issued
  // when the rollout enrolls the slug.
  const handleSharedDeploy = useCallback(async () => {
    if (!canDeploy) return;
    setDeploying(true);
    try {
      const payload = {
        name,
        description: description || undefined,
        namespace: namespaceFull,
        timezone,
        source_type: 'routed',
        parser_vrl: vrl,
        category: category || undefined,
        vendor: vendor || undefined,
        product: product || undefined,
        match_values: [feedId],
      };
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
      let rollout: TenantParserRollout | null = null;
      if (createdId) {
        // The wizard samples are stored with the published version and run
        // through `vector test` in the sandboxed bundle build (NAN-2607).
        const samples = splitSamples(sampleText);
        const result = await api.deployLogSource(createdId, strictOcsf ? samples : undefined, samples);
        rollout = result.rollout ?? null;
      }
      setSharedRollout(rollout);
      if (rollout) void queryClient.invalidateQueries({ queryKey: PARSER_ROLLOUTS_QUERY_KEY });
      void queryClient.invalidateQueries({ queryKey: ['add-data', 'log-sources'] });
      void queryClient.invalidateQueries({ queryKey: INGEST_ENDPOINT_QUERY_KEY });
      const enrolled = addSources.find((s) => s.slug === feedId);
      setIssueSource(enrolled ?? { slug: feedId, protocols: [], enrolled: false });
      setIssueLogSourceId(createdId ?? undefined);
      setActiveStep(4);
      toast({
        title: 'Source activated',
        description: rollout
          ? `${name} is rolling out to your parser cell. Issue its credential now; it is delivered once the source is enrolled.`
          : `${name} is active. Issue its credential now.`,
      });
    } catch (err) {
      toast({
        title: 'Activation failed',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setDeploying(false);
    }
  }, [addSources, canDeploy, category, description, feedId, name, namespaceFull, product, queryClient, sampleText, settleAutoPersist, strictOcsf, timezone, toast, vendor, vrl]);

  // ------------ Deploy ------------
  const handleDeploy = useCallback(async () => {
    if (shared) {
      await handleSharedDeploy();
      return;
    }
    if (!canDeploy || !sourceConfigId) return;
    setDeploying(true);
    try {
      // 1. Create the routing rule on the source config (matches old wizard's
      //    two-call submit). Non-fatal: a duplicate or inactive transport
      //    shouldn't block the log-source create.
      let routingRuleCreated = false;
      try {
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
        dispatch_source_config_id: sourceConfigId,
        parser_vrl: vrl,
        category: category || undefined,
        vendor: vendor || undefined,
        product: product || undefined,
        match_values: [feedId],
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
      if (createdId) {
        try {
          await api.deployLogSource(
            createdId,
            strictOcsf ? splitSamples(sampleText) : undefined,
          );
        } catch (err) {
          toast({
            title: 'Log source deploy failed',
            description: err instanceof Error ? err.message : 'Log source created but parser not yet deployed.',
            variant: 'destructive',
          });
        }
      }

      toast({ title: 'Feed deployed', description: `${name} is now live.` });
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
  }, [canDeploy, category, description, feedId, handleSharedDeploy, name, namespaceFull, navigate, product, sampleText, settleAutoPersist, shared, sourceConfigId, strictOcsf, timezone, toast, vendor, vrl]);

  // ------------ Render ------------
  return (
    <div className="col-start-2 row-start-2 min-h-0 relative flex flex-col bg-background">
      <AddFeedHero
        feedId={collectorArrival ? `${selectedSlugs.length} sources` : shared && sharedMode === 'existing' ? selectedSlug : feedId}
        sourceConfig={sourceConfig}
        shared={shared ? { hostname: endpointQuery.data?.hostname } : undefined}
      />

      <div
        className={cn(
          'flex-1 min-h-0 grid divide-x divide-border transition-[grid-template-columns] duration-200 ease-out',
          railCollapsed ? 'grid-cols-[44px_minmax(0,1fr)]' : 'grid-cols-[220px_minmax(0,1fr)]',
        )}
      >
        <StepRail
          activeStep={activeStep}
          onJump={setActiveStep}
          collapsed={railCollapsed}
          onToggleCollapsed={toggleRail}
          shared={
            shared
              ? {
                  mode: sharedMode,
                  slug: collectorArrival
                    ? selectedSlugs.length > 0 ? `${selectedSlugs.length} sources` : ''
                    : sharedMode === 'existing' ? selectedSlug : feedId,
                  issueReady: collectorArrival ? collectorTargets.length > 0 : !!issueTarget,
                  hostname: endpointQuery.data?.hostname,
                }
              : undefined
          }
          state={{
            feedId,
            sourceConfigId,
            sampleCount,
            errors,
            warnings,
            passingTests,
            failingTests,
            testsRun,
            timezone,
            namespaceFull,
            canDeploy,
          }}
        />
        <div className="overflow-auto scrollbar-thin">
          <div className="px-6 py-5 space-y-4">
            <Step1Identify
              expanded={activeStep === 1}
              onActivate={() => setActiveStep(1)}
              onContinue={() => setActiveStep(shared && sharedMode === 'existing' ? 4 : 2)}
              shared={
                shared
                  ? {
                      endpoint: endpointQuery.data,
                      endpointError: endpointQuery.error,
                      endpointLoading: endpointQuery.isLoading || registryQuery.isLoading,
                      sources: addSources,
                      mode: sharedMode,
                      setMode: setSharedMode,
                      selectedSlug,
                      setSelectedSlug,
                      arrival,
                      setArrival,
                      selectedSlugs,
                      toggleSlug,
                    }
                  : undefined
              }
              feedId={feedId}
              setFeedId={setFeedId}
              sourceConfigId={sourceConfigId}
              setSourceConfigId={setSourceConfigId}
              nsPrefix={nsPrefix}
              setNsPrefix={setNsPrefix}
              nsSuffix={nsSuffix}
              setNsSuffix={setNsSuffix}
              name={name}
              setName={(v) => {
                nameTouched.current = true;
                setName(v);
              }}
              category={category}
              setCategory={setCategory}
              vendor={vendor}
              setVendor={setVendor}
              product={product}
              setProduct={setProduct}
              description={description}
              setDescription={setDescription}
              sourceConfigs={sourceConfigs}
              loadingConfigs={loadingConfigs}
              otherTargets={otherTargets}
            />
            {(!shared || sharedMode === 'custom') && (
            <Step2Parse
              expanded={activeStep === 2}
              onActivate={() => setActiveStep(2)}
              onContinue={() => setActiveStep(3)}
              entryPath={entryPath}
              setEntryPath={setEntryPath}
              strictOcsf={strictOcsf}
              sampleText={sampleText}
              setSampleText={setSampleText}
              sampleCount={sampleCount}
              vrl={vrl}
              setVrl={setVrl}
              genState={genState}
              genProgress={genProgress}
              genStatus={genStatus}
              onRegenerate={handleRegenerate}
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
                if (pivtSuggestion?.updated_vrl) {
                  setVrl(pivtSuggestion.updated_vrl);
                  setPivtSuggestion(null);
                }
              }}
              draftSaved={!!draftId}
            />
            )}
            {(!shared || sharedMode === 'custom') && (
            <Step3Deploy
              shared={shared}
              expanded={activeStep === 3}
              onActivate={() => setActiveStep(3)}
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
              errors={errors}
              warnings={warnings}
              passingTests={passingTests}
              failingTests={failingTests}
              acceptWarnings={acceptWarnings}
              setAcceptWarnings={setAcceptWarnings}
              canDeploy={canDeploy}
              reachability={reachability}
              namespaceCheck={namespaceCheck}
              onSaveDraft={handleSaveDraft}
              onDeploy={handleDeploy}
              savingDraft={savingDraft}
              deploying={deploying}
              rollout={shared ? sharedRollout : undefined}
            />
            )}
            {shared && (
              <Step4Issue
                n={sharedMode === 'custom' ? 4 : 2}
                expanded={activeStep === 4}
                onActivate={() => setActiveStep(4)}
                endpoint={endpointQuery.data}
                source={issueTarget}
                collectorSources={collectorArrival ? collectorTargets : undefined}
                logSourceId={issueTargetLogSourceId}
                rollout={sharedMode === 'custom' ? sharedRollout : undefined}
                onIssued={() => void queryClient.invalidateQueries({ queryKey: INGEST_CREDENTIALS_QUERY_KEY })}
              />
            )}
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
  sourceConfig,
  shared,
}: {
  feedId: string;
  sourceConfig?: SourceConfigWithEvents;
  /** Hosted-shared tenants: "Add data", and the tenant's ingest host in place of the transport. */
  shared?: { hostname?: string };
}) {
  // NAN-4132: pivt copy only where AI exists (open core has none; unknown = none).
  const aiAvailable = useCapabilities().capabilities.melod === true;
  return (
    <div className="shrink-0 border-b border-border bg-card/40 px-5 py-4 flex items-start gap-4">
      <div className="w-[38px] h-[38px] rounded-lg border border-primary/30 bg-primary/[0.08] flex items-center justify-center shrink-0">
        <Plus className="w-[18px] h-[18px] text-primary" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2.5 flex-wrap">
          <div className="text-[16.5px] font-semibold tracking-[-0.01em] text-foreground">{shared ? 'Add data' : 'Add a new feed'}</div>
          <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground border border-border rounded px-1.5 py-px whitespace-nowrap">
            Wizard
          </span>
        </div>
        <div className="text-[11.5px] text-muted-foreground mt-0.5 leading-relaxed max-w-[740px]">
          {shared
            ? `Pick how data arrives and which source it is, then issue a credential for your ingest endpoint. For a source nano does not parse yet, build a custom parser first${aiAvailable ? '; pivt drafts it from your samples.' : '.'}`
            : `Define a feed identifier, parse incoming events with VRL, and route them to a repository. ${aiAvailable ? 'pivt will draft the parser from your samples — review, validate, and deploy in one place.' : 'Write the parser against your samples, then validate and deploy in one place.'}`}
        </div>
      </div>
      <div className="hidden md:flex items-center gap-3 shrink-0">
        <div className="flex flex-col items-end">
          <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground/60">{shared ? 'SOURCE' : 'DRAFT'}</span>
          <span className="text-[12.5px] font-mono text-foreground">{feedId || '—'}</span>
        </div>
        <div className="w-px h-8 bg-border" />
        <div className="flex flex-col items-end">
          <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground/60">VIA</span>
          {shared ? (
            <span className="text-[12.5px] font-mono text-foreground">{shared.hostname ?? '—'}</span>
          ) : (
            <span className="text-[12.5px] text-foreground">{sourceConfig ? sourceConfig.name : '—'}</span>
          )}
        </div>
      </div>
    </div>
  );
}

// ==================================================================
// Step rail
// ==================================================================
type RailState = {
  feedId: string;
  sourceConfigId: string;
  sampleCount: number;
  errors: number;
  warnings: number;
  passingTests: number;
  failingTests: number;
  testsRun: boolean;
  timezone: string;
  namespaceFull: string;
  canDeploy: boolean;
};

function StepRail({
  activeStep,
  onJump,
  collapsed,
  onToggleCollapsed,
  state,
  shared,
}: {
  activeStep: number;
  onJump: (n: number) => void;
  collapsed: boolean;
  onToggleCollapsed: () => void;
  state: RailState;
  /** Hosted-shared tenants (NAN-2593): arrival + source, then parse/deploy for a custom source, then Issue. */
  shared?: { mode: SharedSourceMode; slug: string; issueReady: boolean; hostname?: string };
}) {
  const allSteps: Array<{
    n: number;
    id: number;
    label: string;
    sub: ReactNode;
    ok: boolean;
  }> = [
    {
      n: 1,
      id: 1,
      label: 'Identify',
      sub: state.feedId ? (
        <span className="font-mono text-foreground">{state.feedId}</span>
      ) : (
        <span className="text-muted-foreground/60">unset</span>
      ),
      ok: !!state.feedId && !!state.sourceConfigId,
    },
    {
      n: 2,
      id: 2,
      label: 'Sample & parse',
      sub: state.sampleCount ? (
        <>
          <span className="text-foreground">
            {state.passingTests}/{state.passingTests + state.failingTests}
          </span>{' '}
          tests ·{' '}
          <span className={state.warnings > 0 ? 'text-amber-500' : 'text-muted-foreground'}>{state.warnings}</span> warn
        </>
      ) : (
        <span className="text-muted-foreground/60">no samples</span>
      ),
      ok: state.testsRun && state.failingTests === 0 && state.errors === 0 && state.sampleCount > 0,
    },
    {
      n: 3,
      id: 3,
      label: 'Review & deploy',
      sub: state.canDeploy ? (
        <span className="text-emerald-500">ready</span>
      ) : (
        <span className="text-muted-foreground/60">blocked</span>
      ),
      ok: state.canDeploy,
    },
  ];
  if (shared) {
    allSteps[0] = {
      ...allSteps[0],
      label: 'Arrival & source',
      sub: shared.slug ? (
        <span className="font-mono text-foreground">{shared.slug}</span>
      ) : (
        <span className="text-muted-foreground/60">unset</span>
      ),
      ok: !!shared.slug && (shared.mode === 'existing' || !!state.feedId),
    };
    allSteps[2] = { ...allSteps[2], label: 'Review & activate' };
    allSteps.push({
      n: 4,
      id: 4,
      label: 'Issue credential',
      sub: shared.issueReady ? <span className="text-foreground">ready</span> : <span className="text-muted-foreground/60">after source</span>,
      ok: false,
    });
  }
  // An existing hosted source needs no parser work: Step 1 → Issue.
  const steps = (shared?.mode === 'existing' ? allSteps.filter((s) => s.id === 1 || s.id === 4) : allSteps).map((s, i) => ({
    ...s,
    n: i + 1,
  }));

  if (collapsed) {
    return (
      <div className="overflow-hidden">
        <div className="py-3 flex flex-col items-center gap-1">
          <button
            onClick={onToggleCollapsed}
            title="Expand step list"
            className="w-8 h-8 rounded-md hover:bg-foreground/5 flex items-center justify-center text-muted-foreground hover:text-foreground"
          >
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
          <div className="w-6 h-px bg-border my-1" />
          {steps.map((s) => (
            <button
              key={s.id}
              onClick={() => onJump(s.id)}
              title={`Step ${s.n} · ${s.label}`}
              className={cn(
                'w-8 h-8 rounded-md flex items-center justify-center transition-colors',
                activeStep === s.id ? 'bg-primary/10' : 'hover:bg-foreground/5',
              )}
            >
              <span
                className={cn(
                  'w-5 h-5 rounded-full flex items-center justify-center text-[10.5px] font-mono',
                  s.ok
                    ? 'bg-emerald-500/15 text-emerald-500 border border-emerald-500/40'
                    : activeStep === s.id
                      ? 'bg-primary/15 text-primary border border-primary/50'
                      : 'bg-muted text-muted-foreground border border-border',
                )}
              >
                {s.ok ? <Check className="w-2.5 h-2.5" /> : s.n}
              </span>
            </button>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="overflow-auto scrollbar-thin">
      <div className="px-3 py-4">
        <div className="flex items-center justify-between px-2 mb-2">
          <div className="text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/60">Onboarding · {steps.length} steps</div>
          <button
            onClick={onToggleCollapsed}
            title="Collapse step list"
            className="w-5 h-5 rounded hover:bg-foreground/5 flex items-center justify-center text-muted-foreground hover:text-foreground"
          >
            <ChevronLeft className="w-3 h-3" />
          </button>
        </div>
        <div className="space-y-1">
          {steps.map((s) => (
            <button
              key={s.id}
              onClick={() => onJump(s.id)}
              className={cn(
                'w-full flex items-start gap-2.5 px-2 py-2 rounded-md text-left transition-colors',
                activeStep === s.id ? 'bg-primary/10 text-foreground' : 'hover:bg-foreground/5 text-foreground/80',
              )}
            >
              <div
                className={cn(
                  'shrink-0 w-5 h-5 rounded-full flex items-center justify-center text-[10.5px] font-mono mt-px',
                  s.ok
                    ? 'bg-emerald-500/15 text-emerald-500 border border-emerald-500/40'
                    : activeStep === s.id
                      ? 'bg-primary/15 text-primary border border-primary/50'
                      : 'bg-muted text-muted-foreground border border-border',
                )}
              >
                {s.ok ? <Check className="w-2.5 h-2.5" /> : s.n}
              </div>
              <div className="flex-1 min-w-0">
                <div className={cn('text-[12px] font-medium', activeStep === s.id ? 'text-foreground' : 'text-foreground/80')}>{s.label}</div>
                <div className="text-[10.5px] font-mono text-muted-foreground mt-0.5 truncate">{s.sub}</div>
              </div>
              {activeStep === s.id && <span className="w-1 h-1 rounded-full bg-primary mt-2" />}
            </button>
          ))}
        </div>

        <div className="mt-5 px-2 pt-3 border-t border-border">
          <div className="text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/60 mb-1.5">
            {shared ? 'Credential preview' : 'Routing preview'}
          </div>
          <div className="text-[10.5px] font-mono text-muted-foreground leading-[1.6] space-y-0.5">
            {shared ? (
              <>
                <div className="flex gap-1.5">
                  <span className="text-muted-foreground/60 w-[60px] shrink-0">source</span>
                  <span className="text-primary truncate">{shared.slug || '—'}</span>
                </div>
                <div className="flex gap-1.5">
                  <span className="text-muted-foreground/60 w-[60px] shrink-0">host</span>
                  <span className="text-foreground truncate" title={shared.hostname}>{shared.hostname ?? '—'}</span>
                </div>
              </>
            ) : (
              <>
                <div className="flex gap-1.5">
                  <span className="text-muted-foreground/60 w-[60px] shrink-0">match</span>
                  <span className="text-foreground">source_type</span>
                </div>
                <div className="flex gap-1.5">
                  <span className="text-muted-foreground/60 w-[60px] shrink-0">value</span>
                  <span className="text-primary truncate">{state.feedId || '—'}</span>
                </div>
              </>
            )}
            <div className="flex gap-1.5">
              <span className="text-muted-foreground/60 w-[60px] shrink-0">ns</span>
              <span className="text-foreground/80 truncate">{state.namespaceFull}</span>
            </div>
            <div className="flex gap-1.5">
              <span className="text-muted-foreground/60 w-[60px] shrink-0">tz</span>
              <span className="text-foreground/80 truncate">{state.timezone}</span>
            </div>
          </div>
        </div>

        <div className="mt-4 px-2">
          <a
            href="https://nano.rs/docs/getting-started/first-feed/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-[10.5px] text-muted-foreground hover:text-primary inline-flex items-center gap-1 cursor-pointer"
          >
            <BookOpen className="w-3 h-3" />
            Onboarding guide
          </a>
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
  onActivate,
  summary,
  footer,
  children,
  keepMounted,
}: {
  n: number;
  title: string;
  eyebrow: string;
  expanded: boolean;
  ok: boolean;
  onActivate: () => void;
  summary?: ReactNode;
  footer?: ReactNode;
  children?: ReactNode;
  /** Keep the body mounted while collapsed (it holds state that must survive, e.g. a one-time token). */
  keepMounted?: boolean;
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
        disabled={expanded}
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
      {(expanded || keepMounted) && (
        <div hidden={!expanded}>
          <div className="border-t border-border px-4 py-4">{children}</div>
          {footer && (
            <div className="border-t border-border px-4 py-2.5 bg-card/40 flex items-center gap-2 rounded-b-lg">{footer}</div>
          )}
        </div>
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

function UsageRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline gap-2 text-[10.5px]">
      <span className="text-emerald-500 w-[88px] shrink-0 font-medium">✓ {label}</span>
      <span className="font-mono text-foreground/80 truncate">{value}</span>
    </div>
  );
}

// ==================================================================
// Step 1 — Identify
// ==================================================================
function Step1Identify({
  expanded,
  onActivate,
  onContinue,
  feedId,
  setFeedId,
  sourceConfigId,
  setSourceConfigId,
  nsPrefix,
  setNsPrefix,
  nsSuffix,
  setNsSuffix,
  name,
  setName,
  category,
  setCategory,
  vendor,
  setVendor,
  product,
  setProduct,
  description,
  setDescription,
  sourceConfigs,
  loadingConfigs,
  otherTargets,
  shared,
}: {
  expanded: boolean;
  onActivate: () => void;
  onContinue: () => void;
  feedId: string;
  setFeedId: (v: string) => void;
  sourceConfigId: string;
  setSourceConfigId: (v: string) => void;
  nsPrefix: NamespacePrefixId;
  setNsPrefix: (v: NamespacePrefixId) => void;
  nsSuffix: string;
  setNsSuffix: (v: string) => void;
  name: string;
  setName: (v: string) => void;
  category: string;
  setCategory: (v: string) => void;
  vendor: string;
  setVendor: (v: string) => void;
  product: string;
  setProduct: (v: string) => void;
  description: string;
  setDescription: (v: string) => void;
  sourceConfigs: SourceConfigWithEvents[];
  loadingConfigs: boolean;
  otherTargets: RoutingRule[];
  /** Hosted-shared tenants (NAN-2593): arrival + source picker instead of a source configuration. */
  shared?: SharedStep1Props;
}) {
  const { data: activeSchema } = useQuery({
    queryKey: ['schema-fields'],
    queryFn: () => api.getSchemaFields(),
    staleTime: Infinity,
    gcTime: Infinity,
  });
  const searchSourceField = activeSchema?.schema === 'ocsf'
    ? 'metadata.log_source'
    : 'source_type';
  const sourceConfig = sourceConfigs.find((c) => c.id === sourceConfigId);
  const sharedExisting = shared?.mode === 'existing';
  const sharedCollector = shared?.arrival === 'collector';
  const sharedPick = sharedCollector
    ? shared.selectedSlugs.length > 0 ? `${shared.selectedSlugs.length} sources` : ''
    : shared?.selectedSlug ?? '';
  const ok = shared
    ? sharedCollector
      ? shared.selectedSlugs.length > 0
      : sharedExisting
        ? !!shared.selectedSlug
        : !!feedId && !!name
    : !!feedId && !!sourceConfigId && !!name;

  const summary = shared ? (
    <div className="hidden md:flex items-center gap-3 text-[11px] text-muted-foreground shrink-0">
      <span className="font-mono text-foreground">{(sharedExisting ? sharedPick : feedId) || '—'}</span>
      <span className="w-px h-4 bg-border" />
      <span>{sharedCollector ? 'collector' : sharedExisting ? 'existing source' : 'custom source'}</span>
    </div>
  ) : (
    <div className="hidden md:flex items-center gap-3 text-[11px] text-muted-foreground shrink-0">
      <span className="font-mono text-foreground">{feedId || '—'}</span>
      <span className="w-px h-4 bg-border" />
      <span>{sourceConfig?.name || '—'}</span>
      <span className="w-px h-4 bg-border" />
      <span className="font-mono">
        {nsPrefix === 'default' ? 'default' : `${NAMESPACE_PREFIXES.find((p) => p.id === nsPrefix)?.label ?? ''}${nsSuffix}`}
      </span>
    </div>
  );

  return (
    <StepCard
      n={1}
      title={shared ? 'How will this data arrive?' : 'Identify the feed'}
      eyebrow={shared ? 'STEP 1 · Arrival & source' : 'STEP 1 · Identify'}
      expanded={expanded}
      ok={ok}
      onActivate={onActivate}
      summary={summary}
      footer={
        <>
          <span className="text-[10.5px] font-mono text-muted-foreground/60 ml-1">
            appears as{' '}
            <span className="text-foreground/80">
              {searchSourceField}={(sharedCollector ? 'declared per event' : sharedExisting ? shared?.selectedSlug : feedId) || '—'}
            </span>{' '}
            in queries
          </span>
          <div className="flex-1" />
          <Button variant="default" size="sm" className="h-8 gap-1.5" onClick={onContinue} disabled={!ok}>
            {sharedCollector ? 'Continue · issue collector' : sharedExisting ? 'Continue · issue credential' : 'Continue · sample & parse'}
            <ArrowRight className="w-3.5 h-3.5" />
          </Button>
        </>
      }
    >
      {shared && <SharedArrival {...shared} />}
      {!sharedExisting && (
      <div className={cn('grid grid-cols-12 gap-4', shared && 'mt-4 pt-4 border-t border-border')}>
        {/* Feed identifier */}
        <div className="col-span-12 md:col-span-7">
          <FieldLabel required>Feed identifier</FieldLabel>
          <div className="relative">
            <span className="absolute left-3 top-1/2 -translate-y-1/2 text-[12px] font-mono text-muted-foreground/60 select-none">source_type=</span>
            <input
              autoFocus
              value={feedId}
              onChange={(e) => setFeedId(sanitizeFeedId(e.target.value))}
              placeholder="aws_cloudtrail"
              // NAN-936 F-17: left padding clears the `source_type=` prefix so
              // the placeholder/value reads `source_type=aws_cloudtrail` without
              // overlapping it (the 12px-mono prefix is ~98px wide from left-3).
              className="h-10 w-full rounded-md border border-input bg-background pl-[104px] pr-3 font-mono text-[13px] text-foreground placeholder:text-muted-foreground/60 focus:border-primary focus:outline-none"
            />
          </div>
          <FieldHint>
            Lowercase letters, numbers, <span className="font-mono">_</span> and <span className="font-mono">-</span>. Used as the transport routing key, parser name, and OCSF log source.
          </FieldHint>

          {feedId && (
            <div className="mt-3 rounded-md border border-emerald-500/25 bg-emerald-500/[0.04] p-2.5 space-y-1">
              {shared ? (
                <UsageRow label="Credential" value={`source = ${feedId}`} />
              ) : (
                <>
                  {/* NAN-3806: the ingest token decides the source, never a header. */}
                  <UsageRow label="Ingest token" value="one bound to this source · Ingestion → Credentials" />
                  <UsageRow label="Transport route" value={`source_type = "${feedId}"`} />
                </>
              )}
              <UsageRow label="Search query" value={`${searchSourceField}=${feedId}`} />
            </div>
          )}
        </div>

        {/* Namespace combobox */}
        <div className="col-span-12 md:col-span-5">
          <FieldLabel>Network namespace</FieldLabel>
          <NamespaceCombobox prefix={nsPrefix} setPrefix={setNsPrefix} suffix={nsSuffix} setSuffix={setNsSuffix} />
          <FieldHint>
            Isolates identity resolution for overlapping private IPs (10.x, 192.168.x). Pick the env this feed belongs to.
          </FieldHint>
        </div>

        {/* Ingestion source (dedicated only; hosted-shared transports are platform-managed) */}
        {!shared && (
        <div className="col-span-12">
          <FieldLabel required>Ingestion source</FieldLabel>
          <FieldHint className="mt-0 mb-2">
            Where logs arrive. We'll add a routing rule on this transport so its events land in this feed.
          </FieldHint>
          {loadingConfigs ? (
            <div className="rounded-md border border-border bg-card/40 p-4 text-[11.5px] text-muted-foreground">Loading source configurations…</div>
          ) : sourceConfigs.length === 0 ? (
            <div className="rounded-md border border-dashed border-border bg-card/40 p-4">
              <div className="text-[12.5px] font-medium text-foreground">No source configurations yet</div>
              <div className="text-[11px] text-muted-foreground mt-1 leading-relaxed">
                You need at least one ingestion transport (HTTP, Kafka, S3, …) before you can route logs to a feed.
              </div>
              <a
                href="/ingestion/source-configurations"
                className="inline-flex items-center gap-1 mt-2 text-[11.5px] text-primary hover:underline"
              >
                Create a source configuration <ArrowRight className="w-3 h-3" />
              </a>
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
              {sourceConfigs.map((c) => (
                <SourceConfigCard
                  key={c.id}
                  config={c}
                  selected={sourceConfigId === c.id}
                  onSelect={() => setSourceConfigId(c.id)}
                />
              ))}
            </div>
          )}

          {sourceConfigId && otherTargets.length > 0 && (
            <ExistingTargetsPanel
              targets={otherTargets}
              onUseTarget={(target) => setFeedId(target)}
            />
          )}
        </div>
        )}

        {/* Display details */}
        <div className="col-span-12 mt-1 pt-3 border-t border-border">
          <div className="text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/60 mb-2">
            Display details · for the feed index
          </div>
          <div className="grid grid-cols-12 gap-3">
            <div className="col-span-12 md:col-span-5">
              <FieldLabel required>Name</FieldLabel>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-[13px] text-foreground focus:border-primary focus:outline-none"
                placeholder="AWS CloudTrail · prod"
              />
            </div>
            <div className="col-span-6 md:col-span-3">
              <FieldLabel>Category</FieldLabel>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="h-9 w-full rounded-md border border-input bg-background px-2.5 text-[13px] text-foreground focus:border-primary focus:outline-none appearance-none cursor-pointer"
              >
                <option value="">—</option>
                {CATEGORIES.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>
            </div>
            <div className="col-span-6 md:col-span-2">
              <FieldLabel>Vendor</FieldLabel>
              <input
                value={vendor}
                onChange={(e) => setVendor(e.target.value)}
                placeholder="Amazon"
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-[13px] text-foreground focus:border-primary focus:outline-none"
              />
            </div>
            <div className="col-span-12 md:col-span-2">
              <FieldLabel>Product</FieldLabel>
              <input
                value={product}
                onChange={(e) => setProduct(e.target.value)}
                placeholder="CloudTrail"
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-[13px] text-foreground focus:border-primary focus:outline-none"
              />
            </div>
            <div className="col-span-12">
              <FieldLabel>Description</FieldLabel>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={2}
                placeholder="Brief description of this log source…"
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-[12.5px] text-foreground focus:border-primary focus:outline-none resize-none"
              />
            </div>
          </div>
        </div>
      </div>
      )}
    </StepCard>
  );
}

// ==================================================================
// Hosted-shared Step 1 body — arrival + source (NAN-2593)
// ==================================================================
type SharedStep1Props = {
  endpoint?: TenantIngestEndpoint;
  endpointError: unknown;
  endpointLoading: boolean;
  sources: AddDataSource[];
  mode: SharedSourceMode;
  setMode: (m: SharedSourceMode) => void;
  selectedSlug: string;
  setSelectedSlug: (slug: string) => void;
  /** NAN-2597: direct (one token per source) or collector (one token, many sources). */
  arrival: SharedArrivalMode;
  setArrival: (a: SharedArrivalMode) => void;
  selectedSlugs: string[];
  toggleSlug: (slug: string) => void;
};

/**
 * Collector credentials (one token, many sources, NAN-2597). The option shows
 * only when the tenant's ingest contract accepts them
 * (`ingress_contract.collector_credentials`).
 */
const COLLECTOR_FLOW_AVAILABLE = true;

function SharedArrival({
  endpoint,
  endpointError,
  endpointLoading,
  sources,
  mode,
  setMode,
  selectedSlug,
  setSelectedSlug,
  arrival,
  setArrival,
  selectedSlugs,
  toggleSlug,
}: SharedStep1Props) {
  const collectorOffered = COLLECTOR_FLOW_AVAILABLE && endpoint?.ingress_contract?.collector_credentials === true;
  const collector = collectorOffered && arrival === 'collector';
  // The contract can withdraw collectors (e.g. an endpoint re-read): fall back to Direct.
  useEffect(() => {
    if (!collectorOffered && arrival === 'collector') setArrival('direct');
  }, [arrival, collectorOffered, setArrival]);
  if (endpointLoading) {
    return <div className="text-[11.5px] text-muted-foreground">Loading your ingest endpoint…</div>;
  }
  if (!endpoint) {
    const problem = describeIngestCredentialError(endpointError);
    return (
      <div className="rounded-md border border-red-500/40 bg-red-500/[0.04] px-3 py-2 text-[11.5px]" role="alert">
        <div className="text-foreground font-medium">Your ingest endpoint is unavailable</div>
        <div className="text-muted-foreground">{problem.detail}</div>
      </div>
    );
  }
  return (
    <div className="grid grid-cols-12 gap-4" data-testid="shared-arrival">
      <div className="col-span-12 lg:col-span-5 space-y-2">
        <FieldLabel>Arrival</FieldLabel>
        <div role="radiogroup" aria-label="Arrival" className="space-y-2">
          <button
            type="button"
            role="radio"
            aria-checked={!collector}
            aria-label="Direct"
            onClick={() => setArrival('direct')}
            className={cn(
              'w-full text-left rounded-md border px-3 py-2',
              !collector ? 'border-primary bg-primary/[0.06]' : 'border-border hover:bg-foreground/[0.03]',
            )}
          >
            <div className="flex items-center gap-2">
              <Globe className={cn('w-3.5 h-3.5', !collector ? 'text-primary' : 'text-muted-foreground')} strokeWidth={1.5} />
              <span className="text-[12px] font-medium text-foreground">Direct</span>
              <span className="font-mono text-[10.5px] text-muted-foreground">HEC · HTTPS JSON · OTLP</span>
            </div>
            <div className="text-[11px] text-muted-foreground mt-1 leading-relaxed">
              A device, app or agent sends one source with its own token. The token fixes the source; nothing to declare per event.
            </div>
          </button>
          {collectorOffered && (
            <button
              type="button"
              role="radio"
              aria-checked={collector}
              aria-label="Collector"
              onClick={() => setArrival('collector')}
              className={cn(
                'w-full text-left rounded-md border px-3 py-2',
                collector ? 'border-primary bg-primary/[0.06]' : 'border-border hover:bg-foreground/[0.03]',
              )}
            >
              <div className="flex items-center gap-2">
                <Network className={cn('w-3.5 h-3.5', collector ? 'text-primary' : 'text-muted-foreground')} strokeWidth={1.5} />
                <span className="text-[12px] font-medium text-foreground">Collector</span>
                <span className="font-mono text-[10.5px] text-muted-foreground">Cribl · Vector · Fluent Bit · OTel</span>
              </div>
              <div className="text-[11px] text-muted-foreground mt-1 leading-relaxed">
                One pipeline, one token, many sources. Each event declares its source; undeclared events land as{' '}
                <span className="font-mono">unknown</span>.
              </div>
            </button>
          )}
        </div>
        {collectorOffered ? null : (
          <div className="text-[10.5px] text-muted-foreground/70 leading-relaxed">
            Collector (Cribl, Vector, Fluent Bit, OTel Collector: one token for many sources) is not enabled for this
            tenant yet. Use one direct credential per source meanwhile.
          </div>
        )}
        <IngestEndpointCard endpoint={endpoint} />
      </div>

      <div className="col-span-12 lg:col-span-7">
        <div className="flex items-center gap-2 mb-1.5">
          <FieldLabel>{collector ? 'Sources this pipeline sends' : 'Source'}</FieldLabel>
          {collector && (
            <span className="font-mono text-[10.5px] text-muted-foreground mb-1.5" data-testid="collector-selected-count">
              {selectedSlugs.length} selected
            </span>
          )}
          <span className="flex-1" />
          {!collector && (
          <div className="inline-flex items-center rounded-md border border-border bg-card p-0.5 mb-1.5" role="tablist" aria-label="Source kind">
            {(['existing', 'custom'] as const).map((m) => (
              <button
                key={m}
                type="button"
                role="tab"
                aria-selected={mode === m}
                onClick={() => setMode(m)}
                className={cn(
                  'h-6 px-2.5 rounded text-[11.5px]',
                  mode === m ? 'bg-accent text-foreground' : 'text-muted-foreground hover:text-foreground',
                )}
              >
                {m === 'existing' ? 'Existing source' : 'New custom source'}
              </button>
            ))}
          </div>
          )}
        </div>
        {!collector && mode === 'custom' ? (
          <div className="rounded-md border border-dashed border-border px-3 py-2.5 text-[11.5px] text-muted-foreground leading-relaxed">
            Name the new source below, then build its parser in Step 2 from your samples. Activating it in Step 3 rolls it
            out to your parser cell; you can issue its credential right away and it is delivered once the source is enrolled.
          </div>
        ) : sources.length === 0 ? (
          <div className="rounded-md border border-dashed border-border px-3 py-2.5 text-[11.5px] text-muted-foreground">
            No sources are enrolled for this tenant yet. Build a custom source instead.
          </div>
        ) : (
          <div
            className="rounded-md border border-border overflow-hidden"
            role={collector ? 'group' : 'radiogroup'}
            aria-label={collector ? 'Collector sources' : 'Existing source'}
          >
            <div className="grid grid-cols-[20px_minmax(0,1.1fr)_minmax(0,1fr)_minmax(0,1fr)_64px] gap-2 px-2.5 h-6 items-center border-b border-border bg-card/60 text-[9.5px] font-mono uppercase tracking-[0.1em] text-muted-foreground">
              <span />
              <span>Source</span>
              <span>Name</span>
              <span>Protocols</span>
              <span className="text-right">24h</span>
            </div>
            <div className="max-h-[260px] overflow-auto scrollbar-thin">
              {sources.map((src) => {
                const selected = collector ? selectedSlugs.includes(src.slug) : src.slug === selectedSlug;
                return (
                  <button
                    key={src.slug}
                    type="button"
                    role={collector ? 'checkbox' : 'radio'}
                    aria-checked={selected}
                    aria-label={src.slug}
                    onClick={() => (collector ? toggleSlug(src.slug) : setSelectedSlug(src.slug))}
                    className={cn(
                      'w-full grid grid-cols-[20px_minmax(0,1.1fr)_minmax(0,1fr)_minmax(0,1fr)_64px] gap-2 px-2.5 h-7 items-center text-left border-b border-border/60 last:border-b-0',
                      selected ? 'bg-primary/[0.08]' : 'hover:bg-foreground/[0.03]',
                    )}
                  >
                    <span
                      className={cn(
                        'w-3 h-3 border',
                        collector ? 'rounded-sm' : 'rounded-full',
                        selected ? 'border-primary bg-primary' : 'border-input',
                      )}
                    />
                    <span className="font-mono text-[11.5px] text-foreground truncate">{src.slug}</span>
                    <span className="text-[11.5px] text-foreground/80 truncate">{src.logSource?.name ?? '—'}</span>
                    <span className="font-mono text-[10.5px] text-muted-foreground truncate">
                      {src.enrolled ? src.protocols.map((p) => PROTOCOL_LABEL[p] ?? p).join(' · ') : 'rolling out'}
                    </span>
                    <span className="font-mono text-[10.5px] text-muted-foreground text-right tabular-nums">
                      {formatEventsCount(src.events24h) ?? '—'}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
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
// Step 2 — Sample & parse
// ==================================================================
type Step2Props = {
  expanded: boolean;
  onActivate: () => void;
  onContinue: () => void;
  entryPath: 'paste' | 'existing' | 'manual';
  setEntryPath: (v: 'paste' | 'existing' | 'manual') => void;
  strictOcsf: boolean;
  sampleText: string;
  setSampleText: (v: string) => void;
  sampleCount: number;
  vrl: string;
  setVrl: (v: string) => void;
  genState: 'idle' | 'streaming' | 'done' | 'error';
  genProgress: number;
  genStatus: string;
  onRegenerate: () => void;
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
};

function Step2Parse(props: Step2Props) {
  const {
    expanded,
    onActivate,
    onContinue,
    entryPath,
    setEntryPath,
    strictOcsf,
    sampleText,
    setSampleText,
    sampleCount,
    vrl,
    setVrl,
    genState,
    genProgress,
    genStatus,
    onRegenerate,
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
      n={2}
      title="Sample & parse"
      eyebrow="STEP 2 · Sample & parse"
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
      <SegmentedPath value={entryPath} onChange={setEntryPath} />
      <div className="relative grid grid-cols-12 gap-4 mt-3">
        <div className="col-span-12 lg:col-span-5 flex flex-col min-w-0">
          {entryPath === 'paste' && (
            <SamplesPaste sampleText={sampleText} setSampleText={setSampleText} sampleCount={sampleCount} />
          )}
          {entryPath === 'existing' && (
            <SamplesExisting feedId={feedId} setSampleText={setSampleText} setFeedId={undefined} />
          )}
          {entryPath === 'manual' &&
            (strictOcsf ? (
              <SamplesPaste
                sampleText={sampleText}
                setSampleText={setSampleText}
                sampleCount={sampleCount}
              />
            ) : (
              <SamplesManual feedId={feedId} />
            ))}
        </div>

        {/* "samples → parser" arrow indicator. Pulses primary while generating. */}
        <div
          className="hidden lg:flex absolute left-[41.666%] top-1/2 -translate-x-1/2 -translate-y-1/2 z-10 pointer-events-none"
          aria-hidden="true"
        >
          <div
            className={cn(
              'w-8 h-8 rounded-full border bg-card flex items-center justify-center shadow-sm transition-colors duration-200',
              genState === 'streaming'
                ? 'border-primary/60 bg-primary/15 animate-pulse'
                : 'border-border',
            )}
          >
            <ArrowRight
              className={cn(
                'w-3.5 h-3.5 transition-colors',
                genState === 'streaming' ? 'text-primary' : 'text-muted-foreground/70',
              )}
            />
          </div>
        </div>

        <div className="col-span-12 lg:col-span-7 flex flex-col min-w-0">
          <VrlPanel
            vrl={vrl}
            setVrl={setVrl}
            genState={genState}
            genProgress={genProgress}
            genStatus={genStatus}
            onRegenerate={onRegenerate}
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
}: {
  value: 'paste' | 'existing' | 'manual';
  onChange: (v: 'paste' | 'existing' | 'manual') => void;
}) {
  const opts = [
    { id: 'paste' as const, label: 'Paste samples', icon: FileText, hint: 'Recommended · pivt drafts the parser' },
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
  const { data: activeSchema } = useQuery({
    queryKey: ['schema-fields'],
    queryFn: () => api.getSchemaFields(),
    staleTime: Infinity,
    gcTime: Infinity,
  });
  const searchSourceField = activeSchema?.schema === 'ocsf'
    ? 'metadata.log_source'
    : 'source_type';
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
          query: `${searchSourceField}="${st}"`,
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
            description: `No events found for ${searchSourceField}="${st}".`,
            variant: 'destructive',
          });
          return;
        }
        setSampleText(samples.join('\n'));
        toast({ title: 'Samples loaded', description: `${samples.length} event${samples.length === 1 ? '' : 's'} from ${searchSourceField}=${st}` });
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
    [searchSourceField, setSampleText, toast],
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
            ? `Picks 10 most-recent events · ${searchSourceField}=${selected}`
            : `Click a log source to pull 10 sample events${feedId ? ` for ${feedId}` : ''}`}
      </div>
    </div>
  );
}

// ==================================================================
// SamplesManual — expert mode (no samples)
// ==================================================================
function SamplesManual({ feedId }: { feedId: string }) {
  const { data: activeSchema } = useQuery({
    queryKey: ['schema-fields'],
    queryFn: () => api.getSchemaFields(),
    staleTime: Infinity,
    gcTime: Infinity,
  });
  const starter = activeSchema?.schema === 'ocsf'
    ? `# Minimal canonical OCSF 1.9 Base Event\nraw_log = string(.message) ?? ""\n. = {\n  "class_uid": 0,\n  "category_uid": 0,\n  "activity_id": 0,\n  "type_uid": 0,\n  "time": to_unix_timestamp!(now(), unit: "milliseconds"),\n  "message": raw_log,\n  "metadata": { "version": "1.9.0", "log_source": "${feedId || '<feed_id>'}" }\n}`
    : `# Minimum: set source_type and timestamp\n.source_type = "${feedId || '<feed_id>'}"\n.timestamp = parse_timestamp!(.message, format: "%+")`;
  return (
    <div className="rounded-md border border-border bg-background flex flex-col h-[calc(100vh-320px)] p-4">
      <div className="flex items-start gap-2.5">
        <div className="w-7 h-7 rounded bg-amber-500/15 border border-amber-500/30 flex items-center justify-center shrink-0">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
        </div>
        <div>
          <div className="text-[12.5px] font-medium text-foreground">Expert mode</div>
          <div className="text-[11px] text-muted-foreground leading-relaxed mt-0.5">
            {activeSchema?.schema === 'ocsf'
              ? 'Write VRL by hand, then provide at least one sample before deployment so Nano can run VRL and validate the resulting OCSF 1.9 event. '
              : "Skip samples and write VRL by hand. We can't validate against real events, so deploy will warn but not block. "}
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
        <pre className="font-mono text-[11px] leading-[1.55] text-foreground/80 whitespace-pre">{starter}</pre>
      </div>
    </div>
  );
}

// ==================================================================
// VrlPanel — toolbar + (optional) progress + editor + side tabs
// ==================================================================
type VrlPanelProps = {
  vrl: string;
  setVrl: (v: string) => void;
  genState: 'idle' | 'streaming' | 'done' | 'error';
  genProgress: number;
  genStatus: string;
  onRegenerate: () => void;
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

export function VrlPanel(props: VrlPanelProps) {
  const {
    vrl,
    setVrl,
    genState,
    genProgress,
    genStatus,
    onRegenerate,
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
  // NAN-4132: the pivt tab, chat and "Generate with pivt" exist only when AI
  // does (`capabilities.melod`). Open core has no AI; an unknown capability is
  // treated as none (fail closed) and a stale 'ai' pane falls back to Diagnostics.
  const aiAvailable = useCapabilities().capabilities.melod === true;
  const activePane = !aiAvailable && sidePane === 'ai' ? 'diag' : sidePane;

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

  const allTabs: Array<{
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
    { id: 'ai', label: 'pivt', icon: Sparkles, count: null, tone: null },
  ];
  const tabs = aiAvailable ? allTabs : allTabs.filter((t) => t.id !== 'ai');

  return (
    <div className="rounded-md border border-border overflow-hidden flex flex-col h-[calc(100vh-320px)]">
      {/* Toolbar */}
      <div className="shrink-0 flex items-center gap-2 px-3 py-1.5 border-b border-border bg-card/40">
        <Code className="w-3 h-3 text-muted-foreground" />
        <span className="text-[11px] font-mono text-foreground">{feedId || 'parser'}.vrl</span>
        <span className="text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/60">
          {vrl.trim() ? (aiAvailable ? 'VRL · pivt-drafted' : 'VRL') : 'VRL · empty'}
        </span>
        <div className="flex-1" />
        {aiAvailable && (
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
      {genState === 'streaming' && (
        <div className="shrink-0 border-b border-border bg-primary/[0.04] px-3 py-2">
          <div className="flex items-center gap-2 mb-1.5">
            <Sparkles className="w-3 h-3 text-primary animate-pulse" />
            <span className="text-[11px] text-foreground">pivt is drafting VRL from your samples…</span>
            <div className="flex-1" />
            <span className="text-[10.5px] font-mono text-muted-foreground tabular-nums">{Math.floor(genProgress)}%</span>
          </div>
          <div className="h-1 rounded-full bg-card overflow-hidden">
            <div className="h-full bg-primary transition-all duration-150" style={{ width: `${genProgress}%` }} />
          </div>
          <div className="text-[10px] font-mono text-muted-foreground/60 mt-1.5">{genStatus}</div>
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
          <VrlEditor value={vrl} onChange={setVrl} placeholder={aiAvailable ? '# Generated VRL will appear here' : '# Write VRL here'} />
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
                    activePane === t.id ? 'bg-muted' : 'hover:bg-muted/60',
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
                      activePane === t.id ? 'text-foreground bg-muted' : 'text-muted-foreground hover:text-foreground/80',
                    )}
                  >
                    <t.icon
                      className={cn(
                        'w-3 h-3 shrink-0',
                        activePane === t.id && t.tone === 'good' && 'text-emerald-500',
                        activePane === t.id && t.tone === 'warn' && 'text-amber-500',
                        activePane === t.id && t.tone === 'danger' && 'text-destructive',
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
              {activePane === 'diag' && <DiagPane diagnostics={validation.diagnostics} valid={validation.syntaxValid} />}
              {activePane === 'tests' && <TestsPane tests={tests} />}
              {activePane === 'ai' && (
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
  errors: number;
  warnings: number;
  passingTests: number;
  failingTests: number;
  acceptWarnings: boolean;
  setAcceptWarnings: (v: boolean) => void;
  canDeploy: boolean;
  reachability: {
    transportReady: boolean;
    sourceConfigEnabled: boolean;
    sourceConfigDeployed: boolean;
    checked: boolean;
  } | null;
  namespaceCheck: { valid: boolean; error?: string; checked: boolean } | null;
  onSaveDraft: () => void;
  onDeploy: () => void;
  savingDraft: boolean;
  deploying: boolean;
  /** Hosted-shared tenants (NAN-2593): activate the registry entry; no routing rule or transport. */
  shared?: boolean;
  /** Hosted-shared (NAN-2607): the parser rollout the activation filed. */
  rollout?: TenantParserRollout | null;
};

function Step3Deploy(props: Step3Props) {
  const {
    expanded,
    onActivate,
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
    errors,
    warnings,
    passingTests,
    failingTests,
    acceptWarnings,
    setAcceptWarnings,
    canDeploy,
    reachability,
    namespaceCheck,
    onSaveDraft,
    onDeploy,
    savingDraft,
    deploying,
    shared,
    rollout,
  } = props;
  const { data: activeSchema } = useQuery({
    queryKey: ['schema-fields'],
    queryFn: () => api.getSchemaFields(),
    staleTime: Infinity,
    gcTime: Infinity,
  });
  const searchSourceField = activeSchema?.schema === 'ocsf'
    ? 'metadata.log_source'
    : 'source_type';

  const ok = canDeploy;
  const totalTests = passingTests + failingTests;
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
      n={3}
      title={shared ? 'Review & activate' : 'Review & deploy'}
      eyebrow={shared ? 'STEP 3 · Activate' : 'STEP 3 · Deploy'}
      expanded={expanded}
      ok={ok}
      onActivate={onActivate}
      summary={summary}
      footer={
        <>
          <span className="text-[10.5px] text-muted-foreground/70">
            {shared
              ? 'Creates the log source and activates it; the parser then rolls out to your parser cell.'
              : 'Creates the parser + routing rule, then deploys both.'}
          </span>
          <div className="flex-1" />
          <Button variant="outline" size="sm" className="h-8" onClick={onSaveDraft} disabled={savingDraft}>
            {savingDraft ? 'Saving…' : 'Save draft'}
          </Button>
          <Button variant="default" size="sm" className="h-8 gap-1.5" disabled={!canDeploy || deploying} onClick={onDeploy}>
            <Zap className="w-3.5 h-3.5" />
            {shared ? (deploying ? 'Activating…' : 'Activate source') : deploying ? 'Deploying…' : 'Deploy feed'}
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
          {!shared && (
          <ArtifactCard
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
          />
          )}
          <ArtifactCard
            kind="VRL parser"
            icon={Code}
            primary={`${feedId || 'parser'}.vrl`}
            secondary={`${vrlLineCount} ${vrlLineCount === 1 ? 'line' : 'lines'}`}
            code={vrl}
          />
        </div>

        <div className="col-span-12 lg:col-span-5">
          <div className="rounded-lg border border-border bg-background overflow-hidden">
            <div className="px-3 py-2 border-b border-border bg-card/40">
              <div className="text-[9.5px] font-mono uppercase tracking-[0.14em] text-muted-foreground/60">Validation gate</div>
            </div>
            <div className="px-3 py-3 space-y-2.5">
              <GateRow ok={errors === 0} label={`VRL syntax · ${errors === 0 ? 'valid' : `${errors} error${errors === 1 ? '' : 's'}`}`} />
              <GateRow
                ok={failingTests === 0}
                label={`Tests · ${totalTests > 0 ? `${passingTests}/${totalTests} pass` : 'not run'}`}
              />
              <GateRow
                ok={warnings === 0}
                warn={warnings > 0 && acceptWarnings}
                label={`Diagnostics · ${warnings === 0 ? 'no warnings' : `${warnings} warning${warnings === 1 ? '' : 's'}`}`}
              />
              {!shared && (
              <GateRow
                ok={reachability?.transportReady !== false}
                warn={reachability?.transportReady === false && acceptWarnings}
                label={
                  !reachability?.checked
                    ? 'Transport · checking…'
                    : reachability.transportReady
                      ? 'Transport ready'
                      : !reachability.sourceConfigEnabled
                        ? 'Transport · source config disabled'
                        : !reachability.sourceConfigDeployed
                          ? 'Transport · source config not deployed'
                          : 'Transport · not ready'
                }
              />
              )}
              <GateRow
                ok={namespaceCheck?.valid !== false}
                label={
                  namespaceCheck?.checked
                    ? namespaceCheck.valid
                      ? 'Namespace valid'
                      : `Namespace · ${namespaceCheck.error ?? 'invalid'}`
                    : 'Namespace · checking…'
                }
              />
            </div>
            {shared && (
              <div className="px-3 pb-3 -mt-1 text-[10.5px] text-muted-foreground leading-relaxed">
                After activation the parser is built and validated against your parser cell&apos;s exact Vector
                before it goes live; a failing build never reaches your cell.
              </div>
            )}
            {shared && rollout && (
              <div className="px-3 pb-3" data-testid="step3-rollout">
                <RolloutStatus rolloutId={rollout.id} initial={rollout} />
              </div>
            )}
            {(warnings > 0 || (!shared && reachability?.transportReady === false)) && (
              <div className="px-3 py-3 border-t border-border bg-amber-500/[0.04]">
                <label className="flex items-start gap-2.5 cursor-pointer group">
                  <Checkbox
                    checked={acceptWarnings}
                    onCheckedChange={(checked) => setAcceptWarnings(checked === true)}
                    className="mt-0.5 h-3.5 w-3.5 cursor-pointer"
                  />
                  <div>
                    <div className="text-[11.5px] text-foreground group-hover:text-foreground leading-snug">
                      {warnings > 0 && reachability?.transportReady === false ? (
                        <>
                          Deploy anyway with{' '}
                          <span className="text-amber-500 font-medium">
                            {warnings} warning{warnings === 1 ? '' : 's'}
                          </span>{' '}
                          + transport not ready
                        </>
                      ) : warnings > 0 ? (
                        <>
                          Deploy anyway with{' '}
                          <span className="text-amber-500 font-medium">
                            {warnings} warning{warnings === 1 ? '' : 's'}
                          </span>
                        </>
                      ) : (
                        <>
                          Deploy anyway —{' '}
                          <span className="text-amber-500 font-medium">transport not ready</span>
                        </>
                      )}
                    </div>
                    <div className="text-[10.5px] text-muted-foreground mt-0.5 leading-relaxed">
                      Parser warnings won't reject events but may produce nulls. If the transport
                      isn't deployed, events won't arrive until you deploy it.
                    </div>
                  </div>
                </label>
              </div>
            )}
            <div className="px-3 py-2 border-t border-border bg-card/40 flex items-center gap-2">
              <span
                className={cn(
                  'inline-flex items-center gap-1.5 text-[10.5px] font-mono',
                  canDeploy ? 'text-emerald-500' : 'text-amber-500',
                )}
              >
                <span className={cn('w-1.5 h-1.5 rounded-full', canDeploy ? 'bg-emerald-500' : 'bg-amber-500')} />
                {canDeploy ? 'Cleared to deploy' : 'Acknowledge warnings to deploy'}
              </span>
            </div>
          </div>

          <div className="mt-3 rounded-lg border border-border bg-muted p-3">
            <div className="text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground/60 mb-1.5">After deploy</div>
            <ul className="space-y-1 text-[10.5px] text-muted-foreground">
              <li className="flex gap-1.5">
                <ArrowRight className="w-3 h-3 mt-0.5 shrink-0 text-muted-foreground/60" />
                {shared ? 'The parser rolls out to your parser cell (minutes, not seconds)' : 'Routing rule activates within 2s'}
              </li>
              {shared && (
                <li className="flex gap-1.5">
                  <ArrowRight className="w-3 h-3 mt-0.5 shrink-0 text-muted-foreground/60" />
                  Issue the source&apos;s credential in the next step
                </li>
              )}
              <li className="flex gap-1.5">
                <ArrowRight className="w-3 h-3 mt-0.5 shrink-0 text-muted-foreground/60" />
                First event appears in <span className="font-mono text-foreground/80">{searchSourceField}={feedId || '—'}</span>
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

// ==================================================================
// Step 4 — Issue credential (hosted-shared, NAN-2593)
// ==================================================================
function Step4Issue({
  n,
  expanded,
  onActivate,
  endpoint,
  source,
  collectorSources,
  logSourceId,
  rollout,
  onIssued,
}: {
  n: number;
  expanded: boolean;
  onActivate: () => void;
  endpoint?: TenantIngestEndpoint;
  source: AddDataSource | null;
  /** NAN-2597: set for a collector credential (the allowlist picked in Step 1). */
  collectorSources?: AddDataSource[];
  logSourceId?: string;
  /** NAN-2607: the rollout the custom source's activation filed (else looked up by log source). */
  rollout?: TenantParserRollout | null;
  onIssued: () => void;
}) {
  const collector = collectorSources !== undefined;
  // A slug that is not enrolled yet is still rolling out to the parser cell:
  // show where that rollout is (the credential is delivered once it is live).
  const rolling = !!source && !source.enrolled;
  const rolloutsQuery = useQuery({
    queryKey: PARSER_ROLLOUTS_QUERY_KEY,
    queryFn: () => api.listParserRollouts({ limit: 50 }),
    enabled: rolling && !rollout && !!logSourceId,
    refetchInterval: (q) => {
      const latest = latestRolloutFor(q.state.data, logSourceId);
      return latest ? rolloutPollInterval(latest) : false;
    },
  });
  const liveRollout = rollout ?? latestRolloutFor(rolloutsQuery.data, logSourceId) ?? null;
  return (
    <StepCard
      keepMounted
      n={n}
      title={collector ? 'Issue a collector credential' : 'Issue a credential'}
      eyebrow={`STEP ${n} · Issue`}
      expanded={expanded}
      ok={false}
      onActivate={onActivate}
      summary={
        collector && collectorSources.length > 0 ? (
          <span className="hidden md:inline font-mono text-[11px] text-foreground">{collectorSources.length} sources</span>
        ) : !collector && source ? (
          <span className="hidden md:inline font-mono text-[11px] text-foreground">{source.slug}</span>
        ) : (
          <span className="hidden md:inline text-[11px] text-muted-foreground/60">pick a source first</span>
        )
      }
      footer={
        <>
          <span className="text-[10.5px] text-muted-foreground/70">
            The token is sealed to this browser and shown once. Manage and revoke credentials under{' '}
            <a href={INGEST_CREDENTIALS_PATH} className="text-primary hover:underline">Log Sources → Credentials</a>.
          </span>
        </>
      }
    >
      {!endpoint ? (
        <div className="text-[11.5px] text-muted-foreground">Loading your ingest endpoint…</div>
      ) : collector ? (
        collectorSources.length === 0 ? (
          <div className="text-[11.5px] text-muted-foreground">Pick the sources this pipeline sends in Step 1.</div>
        ) : (
          <IssueCredentialPanel endpoint={endpoint} collectorSources={collectorSources} onIssued={onIssued} />
        )
      ) : !source ? (
        <div className="text-[11.5px] text-muted-foreground">Pick an existing source in Step 1, or activate a custom one in Step 3.</div>
      ) : (
        <div className="space-y-3">
          {rolling && liveRollout && (
            <div data-testid="issue-rollout">
              <RolloutStatus rolloutId={liveRollout.id} initial={liveRollout} compact />
            </div>
          )}
          <IssueCredentialPanel
            endpoint={endpoint}
            source={source}
            logSourceId={logSourceId}
            onIssued={onIssued}
          />
        </div>
      )}
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

function GateRow({ ok, warn, label }: { ok: boolean; warn?: boolean; label: string }) {
  return (
    <div className="flex items-center gap-2">
      <span
        className={cn(
          'w-3.5 h-3.5 rounded-full flex items-center justify-center shrink-0',
          ok ? 'bg-emerald-500/20 text-emerald-500' : warn ? 'bg-amber-500/20 text-amber-500' : 'bg-amber-500/20 text-amber-500',
        )}
      >
        {ok ? <Check className="w-2 h-2" /> : <AlertTriangle className="w-2 h-2" />}
      </span>
      <span className="text-[11px] text-foreground/80">{label}</span>
    </div>
  );
}
