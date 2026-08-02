// SPDX-License-Identifier: AGPL-3.0-or-later

import { BrowserRouter, Routes, Route, useLocation, Navigate, useParams, Link } from 'react-router-dom';
import { useTier, TierProvider } from '@/hooks/use-tier';
import { useState, useEffect, lazy, Suspense, ComponentType } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ThemeProvider } from '@/components/theme-provider';

// Helper to handle chunk load failures after deployments
// When a new version is deployed, old chunk files may no longer exist
// This wrapper auto-refreshes the page to load the new bundle
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function lazyWithRetry<T extends ComponentType<any>>(
  importFn: () => Promise<{ default: T }>
): React.LazyExoticComponent<T> {
  return lazy(() =>
    importFn().catch(() => {
      // Chunk failed to load - likely a new deployment
      // Refresh to get the new bundle
      window.location.reload();
      // Return a never-resolving promise to prevent error flash
      return new Promise(() => {});
    })
  );
}

// Variant for named exports
// NAN-998: throw loudly if the named export is missing (e.g. caller mismatched
// `lazyWithRetryNamed(...'Foo')` against a file with only `export default`).
// Previously this silently resolved to `{ default: undefined }`, which paints
// a blank page with React error #306 at render time — hard to trace.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function lazyWithRetryNamed<T extends ComponentType<any>>(
  importFn: () => Promise<{ [key: string]: T }>,
  namedExport: string
): React.LazyExoticComponent<T> {
  return lazy(() =>
    importFn()
      .then((module) => {
        const exported = module[namedExport];
        if (exported === undefined) {
          throw new Error(
            `lazyWithRetryNamed: module is missing named export '${namedExport}'. ` +
              `Did the file only export default? Use lazyWithRetry instead.`,
          );
        }
        return { default: exported as T };
      })
      .catch((err) => {
        // If it's our own "missing named export" diagnostic, rethrow so the
        // error surfaces in dev + Sentry instead of triggering a refresh loop.
        if (err instanceof Error && err.message.startsWith('lazyWithRetryNamed:')) {
          throw err;
        }
        window.location.reload();
        return new Promise(() => {});
      })
  );
}

// Create a QueryClient instance for React Query
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60, // 1 minute
      retry: 1,
    },
  },
});

// Context providers and core components - keep eager
import { AuthProvider, useAuth } from '@/contexts/AuthContext';
import { UserPreferencesProvider, useUserPreferences } from '@/contexts/UserPreferencesContext';
import { useOnboardingProgress } from '@/hooks/use-api';
import { useRegisterSchemaHighlightFields } from '@/hooks/useRegisterSchemaHighlightFields';
import { NotebookProvider } from '@/enterprise/contexts/NotebookContext';
import { LayoutProvider } from '@/contexts/LayoutContext';
import { CapabilitiesProvider } from '@/contexts/CapabilitiesProvider';
import { ProtectedRoute } from '@/components/auth/ProtectedRoute';
import { AppLayout } from '@/components/layout/AppLayout';
import { PageContextProvider } from '@/contexts/PageContext';
import { Toaster } from '@/components/ui/sonner';
// Loading fallbacks
import {
  PageLoadingFallback,
  EditorLoadingFallback,
  ChartPageLoadingFallback,
  ListPageLoadingFallback,
  SettingsLoadingFallback,
  DetailPageLoadingFallback,
  WizardLoadingFallback,
} from '@/components/lazy/LoadingFallbacks';

// ============================================================================
// EAGER IMPORTS - Essential for initial load (public routes + core pages)
// ============================================================================
import { Login } from '@/pages/Login';
import { MfaSetup } from '@/pages/MfaSetup';
import { Demo } from '@/enterprise/pages/Demo';
import { DemoClaim } from '@/enterprise/pages/DemoClaim';
import { Setup } from '@/pages/Setup';
import { AuthCallback } from '@/enterprise/pages/AuthCallback';
import Denied from '@/pages/Denied';

// Dashboard and Search are lazy-loaded — they pull in heavy visualization deps
// (recharts, @xyflow/react, react-markdown) that would bloat the main bundle
const Dashboard = lazyWithRetryNamed(() => import('@/pages/Dashboard'), 'Dashboard');
const Search = lazyWithRetryNamed(() => import('@/pages/Search'), 'Search');
const TracePage = lazyWithRetryNamed(() => import('@/pages/TracePage'), 'TracePage');
// NAN-1536: the standalone Traces/Metrics explorer pages are subsumed by the
// tabbed Observability console; the log->trace pivot still routes to TracePage.
const ObservabilityConsole = lazyWithRetryNamed(() => import('@/pages/observability/ObservabilityConsole'), 'ObservabilityConsole');

// ============================================================================
// LAZY IMPORTS - Tier 1: CodeMirror pages (highest impact ~500KB)
// ============================================================================
// NAN-484 — `/rules/editor/:id` is the redesigned editor. The pre-redesign
// `RuleEditor` is retired here alongside its docked RuleTesterInline,
// RulesListPanel, etc. Legacy `/rules/editor-legacy/*` routes are gone.
const RuleEditorRedesign = lazyWithRetryNamed(() => import('@/pages/RuleEditorRedesign'), 'RuleEditorRedesign');
const CustomEnrichmentWizard = lazyWithRetryNamed(() => import('@/enterprise/pages/CustomEnrichmentWizard'), 'CustomEnrichmentWizard');
const CustomIntegrationWizard = lazyWithRetryNamed(() => import('@/enterprise/pages/CustomIntegrationWizard'), 'CustomIntegrationWizard');

// ============================================================================
// LAZY IMPORTS - Tier 2: Large pages (1000+ lines)
// ============================================================================
const AddFeed = lazyWithRetryNamed(() => import('@/pages/AddFeed'), 'AddFeed');
const LogSourceDetail = lazyWithRetryNamed(() => import('@/pages/LogSourceDetail'), 'LogSourceDetail');
const CaseDetail = lazyWithRetryNamed(() => import('@/enterprise/pages/CaseDetail'), 'CaseDetail');
// NAN-437: /inbox route renders the workspace shell without a selected case.
const CaseInvestigate = lazyWithRetryNamed(() => import('@/enterprise/pages/CaseInvestigate'), 'CaseInvestigate');
const AlertDetail = lazyWithRetryNamed(() => import('@/pages/AlertDetail'), 'AlertDetail');
// NAN-746: open-core triage list page
const Alerts = lazyWithRetryNamed(() => import('@/pages/Alerts'), 'Alerts');
const NotebookDetail = lazyWithRetryNamed(() => import('@/enterprise/pages/NotebookDetail'), 'NotebookDetail');

// ============================================================================
// LAZY IMPORTS - Tier 3: Chart/visualization pages (Recharts ~400KB)
// ============================================================================
// NAN-482: new Rules dashboard replaces pre-redesign Detections list. The old
// page is kept importable for the sunset PR; /rules renders Rules.
// NAN-483: redesigned per-rule Matches page replaces pre-redesign DetectionMatches.
const Rules = lazyWithRetryNamed(() => import('@/pages/Rules'), 'Rules');
const Matches = lazyWithRetryNamed(() => import('@/pages/Matches'), 'Matches');
// NAN-1791: auto retro-hunt rules (new + config/run-history).
const RetroHunt = lazyWithRetryNamed(() => import('@/pages/RetroHunt'), 'RetroHunt');
const LogSources = lazyWithRetryNamed(() => import('@/pages/LogSources'), 'LogSources');
const Risk = lazyWithRetryNamed(() => import('@/enterprise/pages/Risk'), 'Risk');
const Prevalence = lazyWithRetryNamed(() => import('@/pages/Prevalence'), 'Prevalence');
const Dashboards = lazyWithRetryNamed(() => import('@/pages/Dashboards'), 'Dashboards');
const DashboardView = lazyWithRetryNamed(() => import('@/pages/DashboardView'), 'DashboardView');
// NAN-1793: scheduled reports (saved search / dashboard → CSV/HTML artifacts).
const Reports = lazyWithRetryNamed(() => import('@/pages/Reports'), 'Reports');
const TuningDashboard = lazyWithRetryNamed(() => import('@/enterprise/pages/TuningDashboard'), 'TuningDashboard');
const TuningDetail = lazyWithRetryNamed(() => import('@/enterprise/pages/TuningDetail'), 'TuningDetail');
const MitreCoverage = lazyWithRetryNamed(() => import('@/pages/MitreCoverage'), 'MitreCoverage');
const RuleRepositories = lazyWithRetryNamed(() => import('@/pages/RuleRepositories'), 'RuleRepositories');
const ParserRepositories = lazyWithRetryNamed(() => import('@/pages/ParserRepositories'), 'ParserRepositories');

// ============================================================================
// LAZY IMPORTS - Tier 4: All other pages
// ============================================================================
const OnboardingWizard = lazyWithRetryNamed(() => import('@/pages/OnboardingWizard'), 'OnboardingWizard');
// NAN-1450: the legacy /entities/:type/:value EntityPage was retired — entity
// drilldowns now run `<field>="<value>" | asset` on the Search page.
// NAN-1070: Cases.tsx is no longer routed — /cases redirects to /inbox.
// The module is kept in the tree so we can revive if needed.
// NAN-1071: Case search — cross-cutting query surface under the Cases nav.
// `CaseSearch.tsx` ships only a default export, so use the plain
// `lazyWithRetry` here. (NAN-1071 originally used the named variant.)
const CaseSearch = lazyWithRetry(() => import('@/enterprise/pages/CaseSearch'));
// NAN-443: Playbooks library (read-only surface)
const Playbooks = lazyWithRetryNamed(() => import('@/enterprise/pages/Playbooks'), 'Playbooks');
// NAN-444: Playbook authoring wizard (three-phase: Start / Build / Review)
const PlaybookNew = lazyWithRetryNamed(() => import('@/enterprise/pages/PlaybookNew'), 'PlaybookNew');
// NAN-470: Playbook repositories admin page (Settings → Playbook Repositories)
const PlaybookRepositories = lazyWithRetryNamed(() => import('@/enterprise/pages/PlaybookRepositories'), 'PlaybookRepositories');
const Marketplace = lazyWithRetryNamed(() => import('@/pages/Marketplace'), 'Marketplace');
const EnrichmentDetail = lazyWithRetryNamed(() => import('@/pages/Settings/EnrichmentDetail'), 'EnrichmentDetail');
// NAN-1111: AgentEnrichmentDetail (and the only provider it dispatched,
// VirusTotal) sunset to the marketplace path; the route is now handled by
// LegacyAgentEnrichmentRedirect below. The lazy import is intentionally
// removed alongside the deletion of the file.
const Credentials = lazyWithRetryNamed(() => import('@/pages/Credentials'), 'Credentials');
// NAN-998: Upload.tsx is a default export — must use lazyWithRetry, not the
// Named variant. Previously crashed with React error #306 on /upload because
// module['Upload'] was undefined.
const Upload = lazyWithRetry(() => import('@/pages/Upload'));
const LookupTables = lazyWithRetryNamed(() => import('@/pages/LookupTables'), 'LookupTables');
const LookupTableCreate = lazyWithRetryNamed(() => import('@/pages/LookupTableCreate'), 'LookupTableCreate');
const LookupTableView = lazyWithRetryNamed(() => import('@/pages/LookupTableView'), 'LookupTableView');
const Notebooks = lazyWithRetryNamed(() => import('@/enterprise/pages/Notebooks'), 'Notebooks');
// Placeholder lazy-loader removed with NAN-1008 (/help now redirects to /docs).
const SiemHealth = lazyWithRetryNamed(() => import('@/pages/SiemHealth'), 'SiemHealth');
const SourceConfigurations = lazyWithRetry(() => import('@/pages/SourceConfigurations'));
const SourceConfigurationDetail = lazyWithRetry(() => import('@/pages/SourceConfigurationDetail'));

// ============================================================================
// LAZY IMPORTS - Settings pages
// ============================================================================
const SettingsLandingPage = lazyWithRetryNamed(() => import('@/pages/Settings/SettingsLanding'), 'SettingsLanding');
const MelodSettings = lazyWithRetryNamed(() => import('@/enterprise/pages/Settings/MelodSettings'), 'MelodSettings');
const RetentionSettings = lazyWithRetryNamed(() => import('@/pages/Settings/RetentionSettings'), 'RetentionSettings');
const RiskSettings = lazyWithRetryNamed(() => import('@/enterprise/pages/Settings/RiskSettings'), 'RiskSettings');
const OidcProvidersPage = lazyWithRetryNamed(() => import('@/enterprise/pages/Settings/OidcProviders'), 'OidcProvidersPage');
const AuditLogPage = lazyWithRetryNamed(() => import('@/pages/Settings/AuditLog'), 'AuditLogPage');
const AccessControlPage = lazyWithRetryNamed(() => import('@/pages/Settings/AccessControl'), 'AccessControlPage');
const ApiKeyForm = lazyWithRetryNamed(() => import('@/pages/Settings/ApiKeyForm'), 'ApiKeyForm');
const PrevalenceSettings = lazyWithRetryNamed(() => import('@/pages/Settings/PrevalenceSettings'), 'PrevalenceSettings');
const CaseSettings = lazyWithRetryNamed(() => import('@/enterprise/pages/Settings/CaseSettings'), 'CaseSettings');
const QueueSettings = lazyWithRetryNamed(() => import('@/enterprise/pages/Settings/QueueSettings'), 'QueueSettings');
const UserSettings = lazyWithRetryNamed(() => import('@/pages/Settings/UserSettings'), 'UserSettings');
const NotificationSettings = lazyWithRetryNamed(() => import('@/pages/Settings/NotificationSettings'), 'NotificationSettings');
const SearchSettings = lazyWithRetryNamed(() => import('@/pages/Settings/SearchSettings'), 'SearchSettings');
const SourceScopes = lazyWithRetryNamed(() => import('@/pages/Settings/SourceScopes'), 'SourceScopes');
const GdprAnonymization = lazyWithRetryNamed(() => import('@/pages/Settings/GdprAnonymization'), 'GdprAnonymizationPage');
const AirgapImportPage = lazyWithRetryNamed(() => import('@/enterprise/airgap/AirgapImportPage'), 'AirgapImportPage');

const API_BASE_URL = import.meta.env.VITE_API_URL ?? '';

interface SetupStatus {
  initialized: boolean;
  has_users: boolean;
}

// Component to check setup status and redirect if needed
function SetupRedirect({ children }: { children: React.ReactNode }) {
  const [isChecking, setIsChecking] = useState(true);
  const [needsSetup, setNeedsSetup] = useState(false);
  const location = useLocation();

  useEffect(() => {
    // Skip check if already on setup page
    if (location.pathname === '/setup') {
      setIsChecking(false);
      return;
    }

    const checkSetupStatus = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/setup/status`);
        if (response.ok) {
          const status: SetupStatus = await response.json();
          // Need setup if not initialized AND no users exist
          setNeedsSetup(!status.initialized && !status.has_users);
        }
      } catch {
        // If we can't check, assume setup is done
        setNeedsSetup(false);
      } finally {
        setIsChecking(false);
      }
    };

    checkSetupStatus();
  }, [location.pathname]);

  if (isChecking) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (needsSetup && location.pathname !== '/setup') {
    return <Navigate to="/setup" replace />;
  }

  return <>{children}</>;
}

// Helper component to wrap routes with permission checks
function PermissionRoute({
  element,
  permission,
  anyPermission
}: {
  element: React.ReactNode;
  permission?: string;
  anyPermission?: string[];
}) {
  return (
    <ProtectedRoute permission={permission} anyPermission={anyPermission}>
      {element}
    </ProtectedRoute>
  );
}

function NotFoundPage() {
  const location = useLocation();
  return (
    // NAN-1934: stable hook for the E2E 404 crawler. The SPA returns HTTP 200
    // for dead routes (React decides 404 client-side), so tests/e2e/crawl-404.mjs
    // keys off this marker rather than brittle copy or HTTP status.
    <div data-testid="not-found-404" className="flex flex-col items-center justify-center h-full text-center px-8 select-none">
      <div className="relative mb-8">
        <span className="text-[10rem] font-black leading-none tracking-tighter bg-gradient-to-b from-muted-foreground/40 to-muted-foreground/10 bg-clip-text text-transparent">
          404
        </span>
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="p-4 rounded-2xl bg-primary/10 backdrop-blur-sm">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="w-10 h-10 text-primary">
              <circle cx="11" cy="11" r="8" />
              <path d="m21 21-4.3-4.3" />
              <path d="M8 11h6" />
            </svg>
          </div>
        </div>
      </div>
      <h1 className="text-2xl font-bold text-foreground mb-2">Nothing here, detective</h1>
      <p className="text-muted-foreground mb-1 max-w-md">
        The page you're looking for doesn't exist or has been moved.
      </p>
      <code className="text-xs text-muted-foreground/60 font-mono mb-8">{location.pathname}</code>
      <Link
        to="/"
        className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-primary text-primary-foreground font-medium text-sm hover:bg-primary/90 transition-colors"
      >
        Back to Home
      </Link>
    </div>
  );
}

// Redirect /rules/:id to /rules/editor/:id
function RuleRedirect() {
  const { id } = useParams();
  return <Navigate to={`/rules/editor/${id}`} replace />;
}

// Legacy form route → right-side flyout on the SSO list (NAN-557).
function SsoEditRedirect() {
  const { id } = useParams();
  return <Navigate to={`/settings/access-control?tab=sso&provider=${encodeURIComponent(id ?? '')}`} replace />;
}

// NAN-1111: the legacy /enrichments/:id deep-link used to render
// pre-marketplace per-provider Settings UIs. ThreatFox + Tor moved to
// the marketplace; IPinfo Lite stays native (binary-volume + non-IOC
// schema — see project_ipinfo_lite_stays_native memory). Map the legacy
// IDs to marketplace slugs and redirect; pass the IPinfo path through
// to the still-active EnrichmentDetail component.
const LEGACY_ENRICHMENT_TO_MARKETPLACE: Record<string, string> = {
  threatfox: 'threatfox',
  tor: 'tor-exit-nodes',
  tor_exit_nodes: 'tor-exit-nodes',
};

function LegacyEnrichmentRoute() {
  const { id } = useParams();
  if (id && LEGACY_ENRICHMENT_TO_MARKETPLACE[id]) {
    // Pure redirect: do NOT gate behind enrichments:view. A user with
    // marketplace permission but no legacy enrichments permission still
    // deserves to follow an old bookmark; the marketplace route enforces
    // its own permission downstream.
    return (
      <Navigate
        to={`/marketplace?slug=${encodeURIComponent(LEGACY_ENRICHMENT_TO_MARKETPLACE[id])}`}
        replace
      />
    );
  }
  // IPinfo Lite and any other still-native source render the legacy
  // Settings detail page, gated by enrichments:view. EnrichmentDetail
  // itself shows a "not available" fallback for unknown source types so
  // unknown IDs don't 500.
  return (
    <PermissionRoute
      permission="enrichments:view"
      element={
        <Suspense fallback={<DetailPageLoadingFallback />}>
          <EnrichmentDetail />
        </Suspense>
      }
    />
  );
}

// NAN-1111: the agent-enrichment deep-link only ever dispatched
// VirusTotal, which is now a marketplace agent enrichment. Map and
// redirect; the AgentEnrichmentDetail component itself was deleted.
const LEGACY_AGENT_ENRICHMENT_TO_MARKETPLACE: Record<string, string> = {
  virustotal: 'virustotal',
};

function LegacyAgentEnrichmentRoute() {
  const { id } = useParams();
  const slug = id ? LEGACY_AGENT_ENRICHMENT_TO_MARKETPLACE[id] : undefined;
  // Unknown IDs fall back to the catalog grid rather than 404. This
  // wrapper is pure `<Navigate>` — no stateful child — which is why it
  // doesn't take `key={resetKey}` like LegacyEnrichmentRoute does. The
  // route below intentionally omits PermissionRoute for the same reason
  // as LegacyEnrichmentRoute's redirect branch: don't gate a redirect.
  return (
    <Navigate
      to={slug ? `/marketplace?slug=${encodeURIComponent(slug)}` : '/marketplace'}
      replace
    />
  );
}

// Redirect to user's preferred landing page (or onboarding for first-time users)
function ExternalRedirect({ url }: { url: string }) {
  useEffect(() => { window.location.href = url; }, [url]);
  return null;
}

function LandingPageRedirect() {
  const { landingPage } = useUserPreferences();
  const { isDemoUser } = useAuth();
  const { data: onboardingProgress, loading: onboardingLoading } = useOnboardingProgress();

  // While loading onboarding state, show nothing to avoid flash
  if (onboardingLoading && !isDemoUser) return null;

  // Skip onboarding wizard for demo users — they get demo-specific hints instead.
  // Only redirect on first visit (no progress record yet) and only once per session.
  // sessionStorage flag prevents redirect loops when the user navigates back from
  // getting-started without taking any action (which would leave progress null).
  if (!isDemoUser && !onboardingProgress && !onboardingLoading) {
    const seen = sessionStorage.getItem('onboarding_seen');
    if (!seen) {
      sessionStorage.setItem('onboarding_seen', '1');
      return <Navigate to="/getting-started" replace />;
    }
  }

  switch (landingPage) {
    case 'search':
      return <Navigate to="/search" replace />;
    case 'cases':
      return <Navigate to="/inbox" replace />;
    case 'dashboards':
      return <Navigate to="/dashboards" replace />;
    case 'rules':
      return <Navigate to="/rules" replace />;
    case 'home':
    default:
      return <Suspense fallback={<ChartPageLoadingFallback />}><Dashboard /></Suspense>;
  }
}

// Protected app routes with layout - uses useAuth so must be inside AuthProvider
function ProtectedAppRoutes() {
  const location = useLocation();
  const resetKey = (location.state as { resetKey?: number } | null)?.resetKey;
  const tierResult = useTier();

  // Seed the editor tokenizers with the active schema's field names so OCSF
  // promoted columns get syntax highlighting everywhere (NAN-1241). Runs only
  // when authenticated (this subtree is inside ProtectedRoute); no-op under UDM.
  useRegisterSchemaHighlightFields();

  return (
    <TierProvider value={tierResult}>
    <NotebookProvider>
      <LayoutProvider>
      <PageContextProvider>
      <AppLayout>
        <Routes>
          {/* Landing page - redirects based on user preference (default: home) */}
          <Route path="/" element={
            <PermissionRoute anyPermission={['dashboards:view', 'search:view']} element={<LandingPageRedirect />} />
          } />

          {/* Onboarding Wizard */}
          <Route path="/getting-started" element={
            <Suspense fallback={<WizardLoadingFallback />}>
              <OnboardingWizard />
            </Suspense>
          } />

          {/* Dashboards */}
          <Route path="/dashboards" element={
            <PermissionRoute permission="dashboards:view" element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <Dashboards key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/dashboards/:id" element={
            <PermissionRoute permission="dashboards:view" element={
              <Suspense fallback={<ChartPageLoadingFallback />}>
                <DashboardView key={resetKey} />
              </Suspense>
            } />
          } />

          {/* Scheduled reports (NAN-1793) */}
          <Route path="/reports" element={
            <PermissionRoute permission="search:view" element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <Reports key={resetKey} />
              </Suspense>
            } />
          } />

          {/* Search */}
          <Route path="/search" element={
            <PermissionRoute permission="search:view" element={
              <Suspense fallback={<PageLoadingFallback />}>
                <Search key={resetKey} />
              </Suspense>
            } />
          } />

          {/* OpenTelemetry distributed trace (NAN-1528) */}
          <Route path="/trace/:traceId" element={
            <PermissionRoute permission="search:view" element={
              <Suspense fallback={<PageLoadingFallback />}>
                <TracePage key={resetKey} />
              </Suspense>
            } />
          } />

          {/* Observability console (NAN-1536) — tabbed surface that subsumes the
              standalone NAN-1534 traces/metrics explorers. The optional :tab
              segment (services|traces|metrics|alerts|slos) drives tab + drill-in
              state; bare /observability lands on Services. */}
          <Route path="/observability" element={
            <PermissionRoute permission="search:view" element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <ObservabilityConsole key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/observability/:tab" element={
            <PermissionRoute permission="search:view" element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <ObservabilityConsole key={resetKey} />
              </Suspense>
            } />
          } />

          {/* Rules */}
          <Route path="/rules" element={
            <PermissionRoute permission="detections:view" element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <Rules key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/rules/editor" element={
            <PermissionRoute permission="detections:create" element={
              <Suspense fallback={<EditorLoadingFallback />}>
                <RuleEditorRedesign key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/rules/editor/new" element={
            <PermissionRoute permission="detections:create" element={
              <Suspense fallback={<EditorLoadingFallback />}>
                <RuleEditorRedesign key={`new-${resetKey ?? ''}`} />
              </Suspense>
            } />
          } />
          <Route path="/rules/editor/:id" element={
            <PermissionRoute permission="detections:edit" element={
              <Suspense fallback={<EditorLoadingFallback />}>
                <RuleEditorRedesign key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/rules/:id/matches" element={
            <PermissionRoute permission="detections:view" element={
              <Suspense fallback={<ChartPageLoadingFallback />}>
                <Matches key={resetKey} />
              </Suspense>
            } />
          } />
          {/* NAN-1791: auto retro-hunt rules. Static "retro-hunt" segment outranks
              the `/rules/:id` dynamic route in React Router's specificity order. */}
          <Route path="/rules/retro-hunt/new" element={
            <PermissionRoute permission="detections:create" element={
              <Suspense fallback={<EditorLoadingFallback />}>
                <RetroHunt key={`new-${resetKey ?? ''}`} />
              </Suspense>
            } />
          } />
          <Route path="/rules/retro-hunt/:id" element={
            <PermissionRoute permission="detections:view" element={
              <Suspense fallback={<EditorLoadingFallback />}>
                <RetroHunt key={resetKey} />
              </Suspense>
            } />
          } />
          {/* Redirect /rules/:id to /rules/editor/:id */}
          <Route path="/rules/:id" element={<RuleRedirect />} />

          {/* MITRE ATT&CK Coverage */}
          <Route path="/rules/coverage" element={
            <PermissionRoute permission="detections:view" element={
              <Suspense fallback={<ChartPageLoadingFallback />}>
                <MitreCoverage />
              </Suspense>
            } />
          } />

          {/* Rule Repositories */}
          <Route path="/rules/repositories" element={
            <PermissionRoute permission="detections:view" element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <RuleRepositories />
              </Suspense>
            } />
          } />
          {/* NAN-958: shareable-link alias — `/rules/marketplace` used to
              fall through to the rule-editor "Rule not found" empty state. */}
          <Route path="/rules/marketplace" element={
            <Navigate to="/rules/repositories" replace />
          } />

          {/* Parser Repositories */}
          <Route path="/ingestion/log-sources/repositories" element={
            <PermissionRoute permission="parsers:view" element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <ParserRepositories />
              </Suspense>
            } />
          } />

          {/* AI Detection Tuning */}
          <Route path="/rules/tuning" element={
            <PermissionRoute permission="detections:view" element={
              <Suspense fallback={<ChartPageLoadingFallback />}>
                <TuningDashboard key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/rules/tuning/:id" element={
            <PermissionRoute permission="detections:view" element={
              <Suspense fallback={<DetailPageLoadingFallback />}>
                <TuningDetail key={resetKey} />
              </Suspense>
            } />
          } />

          {/* Risk */}
          <Route path="/risk" element={
            <PermissionRoute permission="risk:view" element={
              <Suspense fallback={<ChartPageLoadingFallback />}>
                <Risk key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/settings/risk" element={
            <PermissionRoute permission="risk:configure" element={
              <Suspense fallback={<SettingsLoadingFallback />}>
                <RiskSettings key={resetKey} />
              </Suspense>
            } />
          } />

          {/* SIEM Health */}
          <Route path="/platform/health" element={
            <PermissionRoute permission="settings:view" element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <SiemHealth key={resetKey} />
              </Suspense>
            } />
          } />

          {/* Prevalence */}
          <Route path="/prevalence" element={
            <PermissionRoute permission="prevalence:view" element={
              <Suspense fallback={<ChartPageLoadingFallback />}>
                <Prevalence key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/settings/prevalence" element={
            <PermissionRoute permission="prevalence:configure" element={
              <Suspense fallback={<SettingsLoadingFallback />}>
                <PrevalenceSettings key={resetKey} />
              </Suspense>
            } />
          } />

          {/* Alerts — NAN-746 Phase 5 Stream B: open-core triage list. */}
          <Route path="/alerts" element={
            <PermissionRoute permission="alerts:view" element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <Alerts key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/alerts/:id" element={
            <Suspense fallback={<DetailPageLoadingFallback />}>
              <AlertDetail key={resetKey} />
            </Suspense>
          } />

          {/* Cases */}
          {/* NAN-437: /inbox lands on the investigation workspace with
              SignalInbox visible + an empty Thread pane. /cases stays as
              the table/kanban surface, reachable via the Browse-all link. */}
          <Route path="/inbox" element={
            <PermissionRoute permission="cases:view" element={
              <Suspense fallback={<DetailPageLoadingFallback />}>
                <CaseInvestigate />
              </Suspense>
            } />
          } />
          {/* NAN-1071: Case search — cross-cutting query surface. Must
              come before the /cases redirect so /cases/search matches first. */}
          <Route path="/cases/search" element={
            <PermissionRoute permission="cases:view" element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <CaseSearch key={resetKey} />
              </Suspense>
            } />
          } />
          {/* NAN-1070: /cases is redundant with the inbox — the All tab on
              SignalInbox covers full case browsing now. Redirect rather
              than route to <Cases /> so deep-linked references migrate
              automatically. Cases.tsx stays in the tree for the moment so
              we can revive if something turns out to need it. */}
          <Route path="/cases" element={<Navigate to="/inbox" replace />} />
          {/* NAN-443: Playbooks library (Phase 2 — read-only) */}
          <Route path="/playbooks" element={
            <PermissionRoute permission="playbooks:view" element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <Playbooks key={resetKey} />
              </Suspense>
            } />
          } />
          {/* NAN-444: Playbook authoring wizard — /playbooks/new (Phase 3). */}
          <Route path="/playbooks/new" element={
            <PermissionRoute permission="playbooks:manage" element={
              <Suspense fallback={<DetailPageLoadingFallback />}>
                <PlaybookNew key={resetKey} />
              </Suspense>
            } />
          } />
          {/* NAN-470: Playbook Repositories admin page. */}
          <Route path="/playbooks/repositories" element={
            <PermissionRoute permission="playbooks:view" element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <PlaybookRepositories />
              </Suspense>
            } />
          } />

          <Route path="/settings/cases" element={
            <PermissionRoute permission="settings:system" element={
              <Suspense fallback={<SettingsLoadingFallback />}>
                <CaseSettings key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/settings/cases/queues" element={
            <PermissionRoute permission="settings:system" element={
              <Suspense fallback={<SettingsLoadingFallback />}>
                <QueueSettings key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/cases/:id" element={
            <PermissionRoute permission="cases:view" element={
              <Suspense fallback={<DetailPageLoadingFallback />}>
                <CaseDetail key={resetKey} />
              </Suspense>
            } />
          } />

          {/* Notebooks */}
          <Route path="/notebooks" element={
            <PermissionRoute permission="notebooks:view" element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <Notebooks key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/notebooks/:id" element={
            <PermissionRoute permission="notebooks:view" element={
              <Suspense fallback={<DetailPageLoadingFallback />}>
                <NotebookDetail key={resetKey} />
              </Suspense>
            } />
          } />


          {/* Marketplace (top-level) */}
          <Route path="/marketplace" element={
            <PermissionRoute permission="enrichments:view" element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <Marketplace key={resetKey} />
              </Suspense>
            } />
          } />
          {/* Legacy /enrichments → /marketplace. Deep-link routes
              (/enrichments/:id, /enrichments/agent/:id, /enrichments/custom/*)
              preserved below; the :id and /agent/:id routes now redirect
              sunset providers to the marketplace drawer and only IPinfo
              Lite continues to render the legacy Settings UI (NAN-1111). */}
          <Route path="/enrichments" element={<Navigate to="/marketplace" replace />} />
          {/* LegacyEnrichmentRoute handles the permission check itself:
              the IPinfo pass-through path is gated by enrichments:view,
              but the redirect branch deliberately is not (see comment
              in the wrapper). */}
          <Route path="/enrichments/:id" element={<LegacyEnrichmentRoute key={resetKey} />} />

          {/* Agent Enrichments — VirusTotal redirects to marketplace (NAN-1111).
              Pure redirect; no permission gate (marketplace enforces its own). */}
          <Route path="/enrichments/agent/:id" element={<LegacyAgentEnrichmentRoute />} />

          {/* Custom Enrichments */}
          <Route path="/enrichments/custom/new" element={
            <PermissionRoute permission="enrichments:custom:create" element={
              <Suspense fallback={<EditorLoadingFallback />}>
                <CustomEnrichmentWizard key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/enrichments/custom/:id" element={
            <PermissionRoute permission="enrichments:view" element={
              <Suspense fallback={<EditorLoadingFallback />}>
                <CustomEnrichmentWizard key={resetKey} />
              </Suspense>
            } />
          } />

          {/* Custom scheduled API integrations */}
          <Route path="/integrations/custom/new" element={
            <PermissionRoute permission="log_sources:create" element={
              <Suspense fallback={<EditorLoadingFallback />}>
                <CustomIntegrationWizard key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/integrations/custom/:id" element={
            <PermissionRoute permission="log_sources:view" element={
              <Suspense fallback={<EditorLoadingFallback />}>
                <CustomIntegrationWizard key={resetKey} />
              </Suspense>
            } />
          } />

          {/* Log Sources */}
          <Route path="/ingestion/log-sources" element={
            <PermissionRoute permission="log_sources:view" element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <LogSources key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/ingestion/log-sources/new" element={
            <PermissionRoute permission="log_sources:create" element={
              <Suspense fallback={<WizardLoadingFallback />}>
                <AddFeed key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/ingestion/log-sources/wizard" element={
            <PermissionRoute permission="log_sources:create" element={
              <Suspense fallback={<WizardLoadingFallback />}>
                <AddFeed key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/ingestion/log-sources/:id" element={
            <PermissionRoute permission="log_sources:view" element={
              <Suspense fallback={<DetailPageLoadingFallback />}>
                <LogSourceDetail key={resetKey} />
              </Suspense>
            } />
          } />

          {/* Cloud Credentials — single consolidated page; legacy /new and /:id
              routes redirect into it via query params. */}
          <Route path="/ingestion/credentials" element={
            <PermissionRoute permission="credentials:view" element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <Credentials key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/ingestion/credentials/new" element={
            <Navigate to="/ingestion/credentials?add=aws_s3" replace />
          } />
          <Route path="/ingestion/credentials/:id" element={
            <PermissionRoute permission="credentials:view" element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <Credentials key={resetKey} />
              </Suspense>
            } />
          } />

          {/* Upload & Lookup */}
          <Route path="/upload" element={
            <PermissionRoute anyPermission={['search:execute', 'lookup:create']} element={
              <Suspense fallback={<PageLoadingFallback />}>
                <Upload key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/rules/lookup-tables" element={
            <PermissionRoute permission="lookup:view" element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <LookupTables key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/rules/lookup-tables/new" element={
            <PermissionRoute permission="lookup:create" element={
              <Suspense fallback={<SettingsLoadingFallback />}>
                <LookupTableCreate key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/rules/lookup-tables/:name" element={
            <PermissionRoute permission="lookup:view" element={
              <Suspense fallback={<DetailPageLoadingFallback />}>
                <LookupTableView key={resetKey} />
              </Suspense>
            } />
          } />

          {/* Settings — landing page for the dedicated /settings shell (NAN-537).
              Visible to anyone with at least one settings:* permission. */}
          <Route path="/settings" element={
            <PermissionRoute anyPermission={['settings:view', 'settings:system', 'settings:ai', 'settings:ai_providers', 'settings:agent_models', 'settings:retention', 'settings:webhooks', 'users:view', 'groups:view', 'roles:view', 'apikeys:view', 'audit:view']} element={
              <Suspense fallback={<SettingsLoadingFallback />}>
                <SettingsLandingPage key={resetKey} />
              </Suspense>
            } />
          } />
          {/* Notification channels — unified Slack/Teams/PagerDuty/generic surface (NAN-1790). */}
          <Route path="/settings/notifications" element={
            <PermissionRoute permission="settings:webhooks" element={
              <Suspense fallback={<SettingsLoadingFallback />}>
                <NotificationSettings key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/settings/search" element={
            <PermissionRoute permission="settings:system" element={
              <Suspense fallback={<SettingsLoadingFallback />}>
                <SearchSettings key={resetKey} />
              </Suspense>
            } />
          } />
          {/* Per-source RBAC scoping — source-visibility registry + grants (NAN-1802). */}
          <Route path="/settings/source-scopes" element={
            <PermissionRoute permission="source_scopes:view" element={
              <Suspense fallback={<SettingsLoadingFallback />}>
                <SourceScopes key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/settings/storage" element={
            <PermissionRoute permission="settings:retention" element={
              <Suspense fallback={<SettingsLoadingFallback />}>
                <RetentionSettings key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/settings/ai" element={
            <PermissionRoute anyPermission={['settings:ai', 'settings:ai_providers', 'settings:agent_models']} element={
              <Suspense fallback={<SettingsLoadingFallback />}>
                <MelodSettings key={resetKey} />
              </Suspense>
            } />
          } />
          {/* Webhooks were absorbed into the unified Notifications surface
              (channels). Keep the old path as a redirect for existing
              deep links / bookmarks so nobody lands on the retired page. */}
          <Route path="/settings/webhooks" element={
            <Navigate to="/settings/notifications" replace />
          } />
          <Route path="/settings/gdpr" element={
            <PermissionRoute permission="gdpr:anonymize" element={
              <Suspense fallback={<SettingsLoadingFallback />}>
                <GdprAnonymization key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/settings/airgap-import" element={
            <PermissionRoute permission="settings:system" element={
              <Suspense fallback={<SettingsLoadingFallback />}>
                <AirgapImportPage key={resetKey} />
              </Suspense>
            } />
          } />

          {/* Access Control - requires user management permissions */}
          <Route path="/settings/access-control" element={
            <PermissionRoute anyPermission={['users:view', 'groups:view', 'roles:view']} element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <AccessControlPage key={resetKey} />
              </Suspense>
            } />
          } />

          {/* NAN-1005: bare list-view aliases — shareable links shaped like
              `/settings/access-control/groups` redirect to the canonical
              `?tab=groups` form. The `/new` and `/:id` sub-paths below are
              real routes (form pages), unchanged. */}
          <Route path="/settings/access-control/groups" element={
            <Navigate to="/settings/access-control?tab=groups" replace />
          } />
          <Route path="/settings/access-control/roles" element={
            <Navigate to="/settings/access-control?tab=roles" replace />
          } />
          <Route path="/settings/access-control/api-keys" element={
            <Navigate to="/settings/access-control?tab=api-keys" replace />
          } />
          <Route path="/settings/access-control/sso" element={
            <Navigate to="/settings/access-control?tab=sso" replace />
          } />
          <Route path="/settings/access-control/sessions" element={
            <Navigate to="/settings/access-control?tab=sessions" replace />
          } />

          {/* NAN-1192: the legacy GroupForm/RoleForm pages were retired — the
              dense GroupsView/RolesView create & edit inline via dialogs. Old
              deep links to the form pages redirect to the matching tab. */}
          <Route path="/settings/access-control/groups/new" element={
            <Navigate to="/settings/access-control?tab=groups" replace />
          } />
          <Route path="/settings/access-control/groups/:id" element={
            <Navigate to="/settings/access-control?tab=groups" replace />
          } />
          <Route path="/settings/access-control/roles/new" element={
            <Navigate to="/settings/access-control?tab=roles" replace />
          } />
          <Route path="/settings/access-control/roles/:id" element={
            <Navigate to="/settings/access-control?tab=roles" replace />
          } />
          {/* Legacy form routes redirect into the right-side flyout (NAN-557). */}
          <Route path="/settings/access-control/sso/new" element={
            <Navigate to="/settings/access-control?tab=sso&provider=new" replace />
          } />
          <Route path="/settings/access-control/sso/:id" element={
            <SsoEditRedirect />
          } />
          <Route path="/settings/access-control/api-keys/new" element={
            <PermissionRoute permission="apikeys:create" element={
              <Suspense fallback={<SettingsLoadingFallback />}>
                <ApiKeyForm key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/settings/access-control/api-keys/:id" element={
            <PermissionRoute permission="apikeys:create" element={
              <Suspense fallback={<SettingsLoadingFallback />}>
                <ApiKeyForm key={resetKey} />
              </Suspense>
            } />
          } />

          {/* NAN-1192: legacy standalone list pages retired in favour of the
              dense Access Control tabbed surface. */}
          <Route path="/settings/users" element={
            <Navigate to="/settings/access-control?tab=users" replace />
          } />
          <Route path="/settings/groups" element={
            <Navigate to="/settings/access-control?tab=groups" replace />
          } />
          <Route path="/settings/roles" element={
            <Navigate to="/settings/access-control?tab=roles" replace />
          } />
          <Route path="/settings/oidc" element={
            <PermissionRoute permission="settings:system" element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <OidcProvidersPage key={resetKey} />
              </Suspense>
            } />
          } />
          {/* NAN-1005: `/settings/sso` is the spec'd path; the canonical
              implementation lives at /settings/oidc. */}
          <Route path="/settings/sso" element={
            <Navigate to="/settings/oidc" replace />
          } />
          <Route path="/settings/api-keys" element={
            <Navigate to="/settings/access-control?tab=api-keys" replace />
          } />
          <Route path="/settings/sessions" element={
            <Navigate to="/settings/access-control?tab=sessions" replace />
          } />
          <Route path="/settings/audit" element={
            <PermissionRoute permission="audit:view" element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <AuditLogPage key={resetKey} />
              </Suspense>
            } />
          } />
          {/* NAN-1005: `/settings/audit-log` was the spec'd path; canonical
              implementation lives at /settings/audit. */}
          <Route path="/settings/audit-log" element={
            <Navigate to="/settings/audit" replace />
          } />

          {/* Source Configurations - infrastructure + routing */}
          <Route path="/ingestion/source-configurations" element={
            <PermissionRoute permission="source_configs:view" element={
              <Suspense fallback={<ListPageLoadingFallback />}>
                <SourceConfigurations key={resetKey} />
              </Suspense>
            } />
          } />
          <Route path="/ingestion/source-configurations/:id" element={
            <PermissionRoute permission="source_configs:view" element={
              <Suspense fallback={<DetailPageLoadingFallback />}>
                <SourceConfigurationDetail key={resetKey} />
              </Suspense>
            } />
          } />

          {/* User Settings - accessible to all authenticated users */}
          <Route path="/settings/user" element={
            <Suspense fallback={<SettingsLoadingFallback />}>
              <UserSettings key={resetKey} />
            </Suspense>
          } />

          {/* Docs - redirect to external docs site */}
          <Route path="/docs" element={
            <ExternalRedirect url="https://nano.rs/docs/" />
          } />
          {/* NAN-1008: `/help` had no inbound links anywhere in the app —
              just a leftover placeholder stub. Route removed entirely so
              the global 404 catch-all handles stale bookmarks. */}

          {/* 404 catch-all */}
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </AppLayout>
      </PageContextProvider>
      </LayoutProvider>
    </NotebookProvider>
    </TierProvider>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <BrowserRouter>
          <CapabilitiesProvider>
          <AuthProvider>
            <UserPreferencesProvider>
              <SetupRedirect>
                <Routes>
                {/* Public routes - outside ProtectedRoute */}
                <Route path="/login" element={<Login />} />
                <Route path="/mfa-setup" element={<MfaSetup />} />
                <Route path="/demo" element={<Demo />} />
                <Route path="/d/:token" element={<DemoClaim />} />
                <Route path="/denied" element={<Denied />} />
                <Route path="/setup" element={<Setup />} />
                <Route path="/auth/callback/:provider" element={<AuthCallback />} />

                {/* Protected routes - require authentication */}
                <Route
                  path="/*"
                  element={
                    <ProtectedRoute>
                      <ProtectedAppRoutes />
                    </ProtectedRoute>
                  }
                />
              </Routes>
              </SetupRedirect>
              <Toaster />
            </UserPreferencesProvider>
          </AuthProvider>
          </CapabilitiesProvider>
        </BrowserRouter>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
