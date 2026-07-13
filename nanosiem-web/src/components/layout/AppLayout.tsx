// SPDX-License-Identifier: AGPL-3.0-or-later

import { ReactNode, useState, useEffect, useCallback, useMemo, useRef, lazy, Suspense } from 'react';
import ReactDOM from 'react-dom';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Shield as LucideShield,
  Rss,
  ChevronDown,
  Bot,
  Book,
  Bell,
  Database,
  Table,
  List,
  FolderInput,
  TrendingUp,
  LogOut,
  User,
  PenTool,
  Activity,
  ExternalLink,
  Code,
  KeyRound,
  Briefcase,
  Inbox,
  Target,
  Network,
  PlusCircle,
  Webhook,
  Gauge,
  ShieldCheck,
  Menu,
  Moon,
  Sun,
} from 'lucide-react';
import {
  NavHome,
  NavPlusCross,
  NavSearch,
  NavGrid,
  NavLayers,
  NavShield,
  NavList,
  NavChart,
  NavActivity,
  NavBars,
  NavInfo,
  NavSquares,
  NavDownload,
  NavGear,
  NavCollapse,
} from '@/components/layout/nav-icons';
import { PivtIcon } from '@/enterprise/icons/PivtIcon';
import { cn } from '@/lib/utils';
import { useAuth } from '@/contexts/AuthContext';
import { useOnboardingProgress, useSiemHealthLatest, useIngestionHistory } from '@/hooks/use-api';
import { VersionBadge } from '@/components/VersionBadge';
import { ScrollContainerProvider } from '@/contexts/ScrollContainerContext';
import { BreadcrumbProvider } from '@/contexts/BreadcrumbContext';
import { DemoBanner } from '@/components/DemoBanner';
import { LicenseBanner } from '@/components/LicenseBanner';
import { AppBreadcrumbs, useCurrentPageTitle } from '@/components/layout/AppBreadcrumbs';
import { useNotebookOptional } from '@/enterprise/contexts/NotebookContext';
import { useLayoutOptional } from '@/contexts/LayoutContext';
import { usePivtState, type PivtState } from '@/enterprise/hooks/use-pivt-state';
import { PivtSummon } from '@/enterprise/components/pivt/PivtSummon';
import { PivtShellOverlay } from '@/enterprise/components/pivt/PivtShellOverlay';
import { useCapabilities, type Capabilities } from '@/hooks/use-capabilities';
import { NotificationBell } from '@/components/NotificationBell';
import { useTheme } from 'next-themes';
import { SettingsLayout } from '@/components/layout/settings/SettingsLayout';
const CommandPalette = lazy(() => import('@/components/shared/CommandPalette').then(m => ({ default: m.CommandPalette })));
import { Button } from '@/components/ui/button';
import { Logo } from '@/components/ui/logo';
import {
  Sheet,
  SheetContent,
  SheetTitle,
} from '@/components/ui/sheet';

/**
 * Flyout menu for collapsed sidebar sections.
 * Shows sub-items on hover when sidebar is collapsed.
 */
function CollapsedSectionFlyout({
  icon: Icon,
  label,
  items,
  isActive,
  location,
  handleNavClick,
  iconSize = 'w-5 h-5',
}: {
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  label: string;
  items: NavItem[];
  isActive: boolean;
  location: { pathname: string };
  handleNavClick: (e: React.MouseEvent<HTMLAnchorElement>, href: string) => void;
  iconSize?: string;
}) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState({ top: 0, left: 0 });
  const triggerRef = useRef<HTMLDivElement>(null);
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleEnter = () => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    if (triggerRef.current) {
      const rect = triggerRef.current.getBoundingClientRect();
      setPos({ top: rect.top, left: rect.right + 4 });
    }
    setOpen(true);
  };
  const handleLeave = () => {
    timeoutRef.current = setTimeout(() => setOpen(false), 150);
  };

  return (
    <>
      <div ref={triggerRef} onMouseEnter={handleEnter} onMouseLeave={handleLeave}>
        <div
          className={cn(
            'relative flex items-center justify-center h-8 w-8 mx-auto rounded-md transition-colors cursor-pointer',
            isActive
              ? 'bg-primary/10 text-primary'
              : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground',
          )}
        >
          <Icon className={iconSize} />
        </div>
      </div>
      {open && ReactDOM.createPortal(
        <div
          style={{ position: 'fixed', top: pos.top, left: pos.left }}
          className="z-[9999] min-w-[180px] rounded-md border bg-popover p-1 shadow-md animate-in fade-in-0 zoom-in-95 slide-in-from-left-2"
          onMouseEnter={handleEnter}
          onMouseLeave={handleLeave}
        >
          <div className="px-2 py-1.5 text-xs font-semibold text-muted-foreground">{label}</div>
          {items.map((item) => {
            const SubIcon = item.icon;
            const matchesPath = location.pathname === item.href ||
              location.pathname.startsWith(item.href + '/');
            const hasMoreSpecificMatch = items.some(
              sibling => sibling.href !== item.href &&
                sibling.href.startsWith(item.href) &&
                (location.pathname === sibling.href || location.pathname.startsWith(sibling.href + '/'))
            );
            const itemActive = matchesPath && !hasMoreSpecificMatch;
            return (
              <Link
                key={item.name}
                to={item.href}
                onClick={(e) => {
                  handleNavClick(e, item.href);
                  setOpen(false);
                }}
                className={cn(
                  'flex items-center gap-2 rounded-sm px-2 py-1.5 text-[12px] transition-colors',
                  itemActive
                    ? 'text-primary bg-primary/10'
                    : 'text-muted-foreground hover:bg-accent hover:text-foreground',
                )}
              >
                <SubIcon className="w-3.5 h-3.5" />
                {item.name}
              </Link>
            );
          })}
        </div>,
        document.body
      )}
    </>
  );
}

/**
 * Navigation item with optional permission requirements
 * Requirements: 5.3 - Hide menu items user cannot access
 */
interface NavItem {
  name: string;
  href: string;
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  /** Permission(s) required to view this item. If array, user needs ANY of them. */
  permissions?: string | string[];
  /** Build-time capability required to view this item. Hidden in open-core
   *  builds when the capability is off, regardless of user permissions. */
  capability?: keyof Capabilities;
  /** Sub-items for expandable navigation */
  subItems?: NavItem[];
  /** If true, renders as external <a> tag instead of React Router Link */
  external?: boolean;
  /**
   * Extra path prefixes (beyond `href`) that should light the item up as
   * active. Lets a nav entry that points at `/inbox` still highlight when
   * the user is deeper in `/cases/*` — same logical surface, different
   * URL. (NAN-437)
   */
  activePrefixes?: string[];
}

/**
 * Main navigation items with permission requirements
 * Requirements: 5.3
 * Order: Home > Search > Dashboards > Alerts
 */
const navigation: NavItem[] = [
  { name: 'Home', href: '/', icon: NavHome }, // Always visible
  { name: 'Getting Started', href: '/getting-started', icon: NavPlusCross }, // Onboarding wizard
  { name: 'Search', href: '/search', icon: NavSearch, permissions: 'search:view' },
  { name: 'Dashboards', href: '/dashboards', icon: NavGrid, permissions: 'dashboards:view' },
  // NAN-1793: scheduled reports — cron a saved search / dashboard into
  // downloadable CSV/HTML artifacts. Gated on search:view (same as Search).
  { name: 'Reports', href: '/reports', icon: NavList, permissions: 'search:view' },
  // NAN-746: Alerts is the open-core triage surface — core, no capability gate.
  // The /alerts/:id detail page is also core; Cases (when on) keeps its own
  // /inbox + /cases entries below.
  { name: 'Alerts', href: '/alerts', icon: Bell, permissions: 'alerts:view' },
  // Observability is a single top-level entry (NAN-1536) routing to the tabbed
  // console at /observability (Services · Traces · Metrics · Alerts · SLOs).
  // Collapsed the NAN-1534 expandable Traces/Metrics group. Gated on search:view
  // (same as Search) — observability rides the search service.
  { name: 'Observability', href: '/observability', icon: NavActivity, permissions: 'search:view' },
];

// Cases is an expandable group (per design-ref/shadcn/playbook-new-app.jsx)
// with Investigate (the SignalInbox workspace) + Case search + Playbooks as
// children. NAN-1070 dropped the legacy `/cases` table route in favor of the
// inbox; NAN-1071 added the search surface for cross-cutting queries.
const casesNavigation: NavItem[] = [
  { name: 'Investigate', href: '/inbox', icon: Inbox, permissions: 'cases:view', capability: 'cases' },
  { name: 'Case search', href: '/cases/search', icon: NavSearch, permissions: 'cases:view', capability: 'cases' },
  { name: 'Playbooks', href: '/playbooks', icon: List, permissions: 'playbooks:view', capability: 'playbooks' },
];

/**
 * Secondary navigation items (after Detections)
 * Order: Notebooks > Prevalence > Risk
 */
const secondaryMainNavigation: NavItem[] = [
  { name: 'Notebooks', href: '/notebooks', icon: NavList, permissions: 'notebooks:view', capability: 'notebooks' },
  { name: 'Prevalence', href: '/prevalence', icon: NavChart, permissions: 'prevalence:view' },
  { name: 'Risk', href: '/risk', icon: NavBars, permissions: 'risk:view', capability: 'risk' },
  { name: 'Health', href: '/platform/health', icon: NavInfo, permissions: 'settings:view', capability: 'siemHealth' },
];

/**
 * Detection navigation items (expandable section)
 */
const detectionNavigation: NavItem[] = [
  { name: 'All Rules', href: '/rules', icon: List, permissions: 'detections:view' },
  { name: 'Rule Editor', href: '/rules/editor', icon: PenTool, permissions: 'detections:create' },
  { name: 'Repositories', href: '/rules/repositories', icon: FolderInput, permissions: 'detections:view' },
  { name: 'Lookup Tables', href: '/rules/lookup-tables', icon: Table, permissions: 'lookup:view' },
  { name: 'MITRE Coverage', href: '/rules/coverage', icon: Target, permissions: 'detections:view' },
  { name: 'AI Tuning', href: '/rules/tuning', icon: PivtIcon, permissions: 'detections:view', capability: 'aiTuning' },
];


/**
 * Ingestion section - data sources and parsing configuration
 */
const ingestionNavigation: NavItem[] = [
  { name: 'Add New Feed', href: '/ingestion/log-sources/wizard', icon: PlusCircle, permissions: 'log_sources:create' },
  { name: 'Log Sources', href: '/ingestion/log-sources', icon: Rss, permissions: 'log_sources:view' },
  { name: 'Repositories', href: '/ingestion/log-sources/repositories', icon: FolderInput, permissions: 'parsers:view' },
  { name: 'Source Configs', href: '/ingestion/source-configurations', icon: Network, permissions: 'source_configs:view' },
  { name: 'Credentials', href: '/ingestion/credentials', icon: KeyRound, permissions: 'credentials:view' },
];

/**
 * Settings section navigation items with permission requirements
 * Requirements: 5.3
 */
const settingsNavigation: NavItem[] = [
  { name: 'Case Management', href: '/settings/cases', icon: Briefcase, permissions: 'settings:system', capability: 'cases' },
  { name: 'Queues & Routing', href: '/settings/cases/queues', icon: Inbox, permissions: 'settings:system', capability: 'cases' },
  { name: 'Playbook Repositories', href: '/playbooks/repositories', icon: FolderInput, permissions: 'playbooks:view', capability: 'playbooks' },
  { name: 'Rarity Thresholds', href: '/settings/prevalence', icon: Activity, permissions: 'prevalence:configure' },
  { name: 'Risk Scoring', href: '/settings/risk', icon: TrendingUp, permissions: 'risk:configure', capability: 'risk' },
  { name: 'Storage', href: '/settings/storage', icon: Database, permissions: 'settings:retention' },
  { name: 'Search', href: '/settings/search', icon: Gauge, permissions: 'settings:system' },
  { name: 'AI', href: '/settings/ai', icon: Bot, permissions: 'settings:ai', capability: 'melod' },
  { name: 'Webhooks', href: '/settings/webhooks', icon: Webhook, permissions: 'settings:webhooks' },
  { name: 'GDPR', href: '/settings/gdpr', icon: ShieldCheck, permissions: 'gdpr:anonymize' },
  { name: 'Access Control', href: '/settings/access-control', icon: LucideShield, permissions: ['users:view', 'groups:view', 'roles:view', 'apikeys:view', 'audit:view'] },
];


/**
 * Top bar — compact 42px-tall strip on --panel bg.
 * Layout: [sidebar toggle] [breadcrumb: title · trail] ··· [notebook] [notifications]
 */
function TopBar({
  sidebarCollapsed,
  onToggleSidebar,
  onMobileMenuOpen,
  pivt,
}: {
  sidebarCollapsed: boolean;
  onToggleSidebar: () => void;
  onMobileMenuOpen: () => void;
  pivt: PivtState;
}) {
  const currentTitle = useCurrentPageTitle();
  const { hasPermission } = useAuth();
  const { capabilities } = useCapabilities();
  const melodEnabled = capabilities.melod;
  void hasPermission; // kept for future per-action gating in the topbar

  return (
    <div
      className="flex items-center gap-3 px-3.5 h-[42px] border-b border-border shrink-0"
      style={{ background: 'var(--panel)' }}
    >
      {/* Mobile hamburger menu */}
      <Button
        variant="ghost"
        size="icon"
        onClick={onMobileMenuOpen}
        className="h-[22px] w-[22px] shrink-0 md:hidden"
        aria-label="Open menu"
        title="Open menu"
      >
        <Menu className="h-[15px] w-[15px]" />
      </Button>

      {/* Desktop sidebar toggle — custom collapse icon (rotates 180° when collapsed).
          Uses a generic "Toggle sidebar" aria-label to avoid colliding with the
          rail's own collapse button (NAN-915 F-7); the rail button carries the
          state-specific Expand/Collapse wording. */}
      <Button
        variant="ghost"
        size="icon"
        onClick={onToggleSidebar}
        className="h-[22px] w-[22px] shrink-0 hidden md:inline-flex"
        aria-label="Toggle sidebar"
        title={sidebarCollapsed ? 'Expand sidebar (⌘B)' : 'Collapse sidebar (⌘B)'}
      >
        <NavCollapse className={cn('h-[15px] w-[15px]', sidebarCollapsed && 'rotate-180')} />
      </Button>

      {/* Breadcrumb: current page title + trail */}
      <div className="text-[13px] flex items-center gap-2 whitespace-nowrap min-w-0 overflow-hidden">
        <span aria-current="page" className="font-medium text-foreground truncate shrink-0">{currentTitle}</span>
        <div className="hidden md:flex items-center gap-2.5 min-w-0 text-muted-foreground">
          <AppBreadcrumbs />
        </div>
      </div>

      <div className="flex-1 min-w-0" />

      {/* Right actions — PIVT is the new home for notebook interaction;
          the legacy `Start a new notebook` icon (which opened the
          deprecated NotebookSidebar via toggleSidebar) is gone. PIVT's
          @-commands cover notebook creation; the floating PIVT panel
          owns the read surface. */}
      <div className="flex items-center gap-1 shrink-0">
        {melodEnabled && <PivtSummon state={pivt} />}
        <NotificationBell />
      </div>
    </div>
  );
}

/**
 * Strip markdown so AI-generated narrative renders cleanly inside the
 * single-line footer cell. The full markdown source still flows to
 * `/platform/health` where `<Markdown>` formats it properly; here we
 * collapse both block-level structures (tables, code fences, lists,
 * blockquotes — which `truncate` would otherwise render as literal `|`,
 * `>`, `-`) and inline markers (`**bold**`, `*italic*`, `` `code` ``)
 * to plain prose, then squash whitespace so the footer reads as one
 * legible sentence (NAN-914 F-2, NAN-936 F-2).
 */
function stripInlineMarkdown(text: string): string {
  // Skip underscore-italic stripping — UDM field names (src_ip,
  // windows_event_log, src_ip_filled_pct, etc.) routinely appear in the
  // narrative and the `_..._` regex would mangle them. The AI prompt
  // produces `**bold**`/`*italic*` style markdown, not underscore italics.
  const blockStripped = text
    // Fenced code blocks: ```...``` (multi-line)
    .replace(/```[\s\S]*?```/g, '')
    // Markdown table rows: any line that starts and ends with a pipe,
    // including the `|---|---|` separator. The footer's `truncate`
    // flattens these to literal `|` glyphs across the visible line.
    .replace(/^\s*\|.*\|\s*$/gm, '')
    // List bullets and numbered list markers at line start
    .replace(/^\s*[-*+]\s+/gm, '')
    .replace(/^\s*\d+\.\s+/gm, '')
    // Blockquote bars
    .replace(/^\s*>\s*/gm, '')
    // Heading hashes
    .replace(/^\s*#{1,6}\s+/gm, '');

  return blockStripped
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/\*([^*]+)\*/g, '$1')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    // Collapse any whitespace run (including newlines left by stripped
    // blocks) to a single space; `truncate` would do the same visually
    // but normalizing here avoids stray gaps where rows used to be.
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Status bar — 22px-tall strip at the bottom. Mono text on --panel bg.
 * Wired to SIEM health + ingestion history. Rendered on every page, so queries
 * should stay cheap (both return single aggregates / small arrays).
 */
function StatusBar() {
  const currentTitle = useCurrentPageTitle();
  // SIEM Health: the endpoint, status classifier (Fresh/Stalled/Live),
  // overall_score, and the stalled-ingestion narrative are all core
  // heuristics (`nanosiem-core/src/siem_health/analyzer.rs`). Only the
  // per-dimension Live-state commentary is AI-driven; the core fallback
  // fills it with the literal string "AI analysis unavailable", which
  // we filter out below so open builds don't render that placeholder.
  const { data: siemHealth } = useSiemHealthLatest();
  const { data: ingestHistory } = useIngestionHistory(1);
  const layout = useLayoutOptional();

  // Platform status: tint the leading dot + label by SIEM overall_status.
  const status = siemHealth?.overall_status ?? 'unknown';
  const statusColor = status === 'healthy'
    ? 'var(--success)'
    : status === 'degraded'
    ? 'var(--warning)'
    : status === 'unhealthy' || status === 'critical'
    ? 'var(--destructive)'
    : 'var(--muted-foreground)';

  // Ingest summary: prefer the backend's human-readable ingestion detail; fall
  // back to "N% ingest" from the score if the string isn't populated. Filter
  // out the AI-unavailable placeholder so open builds drop down to score.
  const rawIngestDetail = siemHealth?.dimension_details?.ingestion?.trim();
  const ingestDetail = rawIngestDetail === 'AI analysis unavailable' ? undefined : rawIngestDetail;
  // The narrative is markdown; strip inline formatting for the single-line
  // footer cell so `**foo**` etc. don't render as literal asterisks (F-2).
  const ingestDetailDisplay = ingestDetail ? stripInlineMarkdown(ingestDetail) : undefined;
  const ingestScore = siemHealth ? `${Math.round(siemHealth.ingestion_score)}% ingest` : null;

  // Events/min: sum the last hour of ingestion-history points across source
  // types, divide by 60. IngestionHistoryPoint[] bucketing varies, but hours=1
  // typically returns ~60 per-minute buckets or a handful of per-hour ones.
  const totalLastHour = (ingestHistory ?? []).reduce((s, p) => s + p.count, 0);
  const eventsPerMin = Math.round(totalLastHour / 60);
  const eventsLabel = ingestHistory && ingestHistory.length > 0
    ? `${eventsPerMin.toLocaleString()} events/min`
    : null;

  // When a page has contributed page-specific status (e.g. Search's query
  // stats), show it in place of the default ingest detail + events-per-min.
  // Platform dot + page name on the right are preserved.
  const pageStatus = layout?.pageStatus;

  return (
    <footer
      className="hidden md:flex items-center px-3.5 h-[22px] border-t border-border font-mono text-[10.5px] text-muted-foreground gap-[18px] tracking-wide shrink-0"
      style={{ background: 'var(--panel)' }}
    >
      <span style={{ color: statusColor }}>● platform {status}</span>
      {pageStatus ? (
        <span className="flex items-center gap-[18px] min-w-0">{pageStatus}</span>
      ) : (
        <>
          {ingestDetailDisplay ? (
            // AI narrative is the meaningful content — wire the cell as a link
            // to the full /platform/health report so the truncated text has a
            // clear expand-on-click affordance (NAN-914 F-6).
            <Link
              to="/platform/health"
              className="hidden lg:inline truncate max-w-[280px] hover:text-foreground transition-colors"
              title={ingestDetailDisplay}
            >
              {ingestDetailDisplay}
            </Link>
          ) : ingestScore ? (
            <span
              className="hidden lg:inline truncate max-w-[280px]"
              title={ingestScore}
            >
              {ingestScore}
            </span>
          ) : null}
          {eventsLabel && <span className="hidden lg:inline">{eventsLabel}</span>}
        </>
      )}
      <span className="flex-1" />
      <span>nano · {currentTitle.toLowerCase()}</span>
    </footer>
  );
}

interface AppLayoutProps {
  children: ReactNode;
}

/**
 * Routes under /settings get their own dedicated shell (NAN-537). This
 * top-level dispatcher swaps `MainAppShell` for `SettingsLayout` on those
 * routes — done before the main shell's hooks fire so we don't violate
 * rules-of-hooks when navigating in/out of settings.
 */
export function AppLayout({ children }: AppLayoutProps) {
  const location = useLocation();
  const isSettingsRoute = location.pathname === '/settings' || location.pathname.startsWith('/settings/');
  if (isSettingsRoute) {
    return <SettingsLayout>{children}</SettingsLayout>;
  }
  return <MainAppShell>{children}</MainAppShell>;
}

// User-avatar dropdown content shared by the desktop sidebar + mobile drawer
// triggers. Density matches the redesign cookbook (11.5px body, 12px icons,
// h-7 rows) — shadcn DropdownMenuItem defaults to text-sm/14px which dwarfed
// everything else in the app.
function UserMenuContent({
  onLogout,
  onUserSettings,
}: {
  onLogout: () => void | Promise<void>;
  onUserSettings: () => void;
}) {
  const { resolvedTheme, setTheme } = useTheme();
  const isDark = resolvedTheme === 'dark';
  const itemCls = 'text-[11.5px] py-1.5 gap-2';
  // Pops up from the avatar trigger with a small lift, then shifts right
  // via `alignOffset` so the menu straddles the sidebar / content edge —
  // the floating-overlay feel the redesign goes for, vs. either flush-left
  // (default `align="end"` with no offset) or fully-detached-right
  // (`side="right"`).
  return (
    <DropdownMenuContent
      side="top"
      align="end"
      sideOffset={8}
      alignOffset={72}
      className="w-52"
    >
      <DropdownMenuItem onClick={onUserSettings} className={itemCls}>
        <User className="w-3.5 h-3.5" />
        User Settings
      </DropdownMenuItem>
      {/* NAN-917 F-25: theme toggle is now reachable from every route via the
          user menu (previously only on /settings/*). */}
      <DropdownMenuItem
        onClick={() => setTheme(isDark ? 'light' : 'dark')}
        className={itemCls}
      >
        {isDark ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
        {isDark ? 'Switch to light theme' : 'Switch to dark theme'}
      </DropdownMenuItem>
      <DropdownMenuSeparator />
      <DropdownMenuItem asChild className={itemCls}>
        <a href="https://nano.rs/docs/" target="_blank" rel="noopener noreferrer">
          <Book className="w-3.5 h-3.5" />
          Docs
          <ExternalLink className="w-3 h-3 ml-auto opacity-50" />
        </a>
      </DropdownMenuItem>
      <DropdownMenuItem asChild className={itemCls}>
        <a href="/swagger-ui/" target="_blank" rel="noopener noreferrer">
          <Code className="w-3.5 h-3.5" />
          API
          <ExternalLink className="w-3 h-3 ml-auto opacity-50" />
        </a>
      </DropdownMenuItem>
      <DropdownMenuSeparator />
      <DropdownMenuItem
        onClick={onLogout}
        className={cn(itemCls, 'text-destructive focus:text-destructive')}
      >
        <LogOut className="w-3.5 h-3.5" />
        Sign out
      </DropdownMenuItem>
      <DropdownMenuSeparator />
      <VersionBadge />
    </DropdownMenuContent>
  );
}

function MainAppShell({ children }: AppLayoutProps) {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout, hasPermission, hasAnyPermission, isDemoUser } = useAuth();
  const { data: onboardingProgress } = useOnboardingProgress();
  const notebook = useNotebookOptional();
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const pivt = usePivtState();

  // ── PIVT keyboard shortcuts ─────────────────────────────────────────────
  // ⌘. / ctrl+.            → toggle open/close
  // ⌘⇧. / ctrl+shift+.     → switch dock ↔ float (and open if closed)
  // Escape hatch: don't fire while the user is typing into an input /
  // textarea / contenteditable — ⌘. is a common page-search shortcut in
  // those contexts, and hijacking it while typing would be surprising.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (!(e.metaKey || e.ctrlKey)) return;
      if (e.key !== '.') return;
      const target = e.target as HTMLElement | null;
      const tag = target?.tagName?.toLowerCase();
      const isEditable =
        tag === 'input' ||
        tag === 'textarea' ||
        tag === 'select' ||
        target?.isContentEditable === true;
      if (isEditable) return;
      e.preventDefault();
      if (e.shiftKey) {
        pivt.switchDockFloat();
      } else {
        pivt.toggle();
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [pivt]);


  /**
   * Filter navigation items based on user permissions
   * Requirements: 5.3 - Hide menu items user cannot access
   */
  const { capabilities } = useCapabilities();
  const filterNavItems = useCallback((items: NavItem[]): NavItem[] => {
    return items.filter(item => {
      // Build-time capability gate — open-core builds drop enterprise items.
      if (item.capability && !capabilities[item.capability]) return false;

      // No permission required - always show
      if (!item.permissions) return true;

      // Check permission(s)
      if (Array.isArray(item.permissions)) {
        return hasAnyPermission(item.permissions);
      }
      return hasPermission(item.permissions);
    });
  }, [hasPermission, hasAnyPermission, capabilities]);

  // Filtered navigation arrays based on user permissions
  const filteredNavigation = useMemo(() => {
    const items = filterNavItems(navigation);
    // Hide "Getting Started" for demo users, or once the user has opted out
    // (Dismiss / Finish Early / Skip for now → dismissed=true) or completed
    // the wizard. The rail entry is for users still working through setup;
    // the recovery path for everyone else is User Settings → Reopen
    // Getting Started.
    if (isDemoUser || onboardingProgress?.dismissed || onboardingProgress?.completed_at) {
      return items.filter(item => item.href !== '/getting-started');
    }
    return items;
  }, [filterNavItems, onboardingProgress, isDemoUser]);
  const filteredSecondaryMainNavigation = useMemo(() => filterNavItems(secondaryMainNavigation), [filterNavItems]);
  const filteredCasesNavigation = useMemo(() => filterNavItems(casesNavigation), [filterNavItems]);
  const filteredDetectionNavigation = useMemo(() => filterNavItems(detectionNavigation), [filterNavItems]);
  const filteredIngestionNavigation = useMemo(() => filterNavItems(ingestionNavigation), [filterNavItems]);
  const filteredSettingsNavigation = useMemo(() => filterNavItems(settingsNavigation), [filterNavItems]);


  const isCasesActive = location.pathname.startsWith('/inbox')
    || location.pathname.startsWith('/cases')
    || location.pathname.startsWith('/playbooks');
  const isDetectionActive = location.pathname.startsWith('/rules');
  const isIngestionActive = filteredIngestionNavigation.some(item => location.pathname.startsWith(item.href));
  const isSettingsActive = filteredSettingsNavigation.some(item => location.pathname.startsWith(item.href));

  // Accordion state - only one section can be open at a time.
  // Settings is no longer part of the accordion (NAN-537) — it's a single
  // top-level link that hands off to the dedicated /settings shell.
  type NavSection = 'cases' | 'detections' | 'ingestion' | null;
  const getInitialOpenSection = (): NavSection => {
    if (isCasesActive) return 'cases';
    if (isDetectionActive) return 'detections';
    if (isIngestionActive) return 'ingestion';
    return null;
  };
  const [openSection, setOpenSection] = useState<NavSection>(getInitialOpenSection);

  // Toggle section - clicking open section closes it, clicking closed section opens it (and closes others)
  const toggleSection = (section: NavSection) => {
    setOpenSection(prev => prev === section ? null : section);
  };

  // Derived state for each section
  const casesOpen = openSection === 'cases';
  const detectionsOpen = openSection === 'detections';
  const ingestionOpen = openSection === 'ingestion';

  // Auto-expand section when navigating to a page within it
  useEffect(() => {
    if (isCasesActive && openSection !== 'cases') {
      setOpenSection('cases');
    } else if (isDetectionActive && openSection !== 'detections') {
      setOpenSection('detections');
    } else if (isIngestionActive && openSection !== 'ingestion') {
      setOpenSection('ingestion');
    }
  }, [isCasesActive, isDetectionActive, isIngestionActive]);

  // Mobile menu state
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Initialize sidebar state from localStorage
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    const saved = localStorage.getItem('nanosiem-sidebar-collapsed');
    return saved ? JSON.parse(saved) : false;
  });

  // Smart sidebar: auto-collapse when notebook opens, restore when it closes
  // Persist the auto-collapsed flag so it survives page refreshes — without this,
  // the ref resets to false on mount while sidebarCollapsed stays true from localStorage,
  // so closing the notebook never restores the left nav.
  const autoCollapsedRef = useRef(
    localStorage.getItem('nanosiem-sidebar-auto-collapsed') === 'true'
  );

  useEffect(() => {
    const enabled = localStorage.getItem('nanosiem-smart-sidebar') !== 'false'; // default: true
    if (!enabled) return;

    const notebookVisible = notebook?.isOpen && !notebook?.isMinimized;

    if (notebookVisible) {
      // Notebook just opened — collapse sidebar if it's expanded
      setSidebarCollapsed((prev: boolean) => {
        if (!prev) {
          autoCollapsedRef.current = true;
          localStorage.setItem('nanosiem-sidebar-auto-collapsed', 'true');
          return true;
        }
        return prev;
      });
    } else if (autoCollapsedRef.current) {
      // Notebook closed — restore sidebar if we auto-collapsed it
      autoCollapsedRef.current = false;
      localStorage.setItem('nanosiem-sidebar-auto-collapsed', 'false');
      setSidebarCollapsed(false);
    }
  }, [notebook?.isOpen, notebook?.isMinimized]);

  // Handle navigation with state reset for same-route clicks
  const handleNavClick = useCallback((e: React.MouseEvent<HTMLAnchorElement>, href: string) => {
    // Close mobile menu on any navigation
    setMobileMenuOpen(false);
    // If clicking on the same route, force a fresh page by using state
    if (location.pathname === href) {
      e.preventDefault();
      navigate(href, { replace: true, state: { resetKey: Date.now() } });
    }
    // Otherwise, let the Link handle it normally
  }, [location.pathname, navigate]);

  // Handle logout
  const handleLogout = useCallback(async () => {
    await logout();
    navigate('/login', { replace: true });
  }, [logout, navigate]);

  // Get user initials for avatar
  const getUserInitials = () => {
    const name = user?.name?.trim();
    if (!name) return 'U';
    const parts = name.split(/\s+/).filter(p => p.length > 0);
    if (parts.length >= 2 && parts[0].length > 0 && parts[1].length > 0) {
      return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
    }
    const initials = name.substring(0, 2).toUpperCase();
    return initials || 'U';
  };

  // Get primary role for display
  const getPrimaryRole = () => {
    if (!user?.roles || user.roles.length === 0) return 'User';
    return user.roles[0];
  };

  // Save sidebar state to localStorage
  useEffect(() => {
    localStorage.setItem('nanosiem-sidebar-collapsed', JSON.stringify(sidebarCollapsed));
  }, [sidebarCollapsed]);

  // Keyboard shortcut to toggle sidebar (Ctrl/Cmd + B)
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key === 'b') {
        event.preventDefault();
        autoCollapsedRef.current = false;
        localStorage.setItem('nanosiem-sidebar-auto-collapsed', 'false');
        setSidebarCollapsed((prev: boolean) => !prev);
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  return (
    <div
      className="h-screen text-foreground flex overflow-hidden"
      style={{ background: 'var(--background)' }}
    >
      {/* Left rail — bg matches main content; 1px border separates. */}
      <aside
        className={cn(
          'hidden md:flex flex-col transition-[width] duration-200 border-r border-border shrink-0',
          sidebarCollapsed ? 'w-11' : 'w-52',
        )}
        style={{ background: 'var(--background)' }}
      >
        {/* Compact 42px header with the real Logo, sized to fit. No underline. */}
        <div
          className={cn(
            'h-[42px] flex items-center shrink-0',
            sidebarCollapsed ? 'justify-center px-0' : 'justify-start pl-3',
          )}
        >
          {sidebarCollapsed ? (
            <Logo className="w-3.5 h-3.5" size="small" />
          ) : (
            <Logo className="h-3.5" size="normal" />
          )}
        </div>

        <nav
          className={cn(
            'flex-1 overflow-y-auto overflow-x-hidden scrollbar-thin flex flex-col gap-0.5',
            sidebarCollapsed ? 'px-0 py-1.5 items-center' : 'px-2.5 py-1',
          )}
        >
          {filteredNavigation.map((item) => {
            const Icon = item.icon;
            // Check for exact match OR if it's a parent route (e.g., /cases matches /cases/123)
            // But exclude /settings paths from parent matching to avoid double-highlighting.
            // NAN-437: `activePrefixes` covers cross-URL surfaces (e.g. Cases
            // nav points at /inbox but should light up on /cases too).
            const isActive =
              location.pathname === item.href ||
              (item.href !== '/' && location.pathname.startsWith(item.href + '/') && !location.pathname.includes('/settings')) ||
              (item.activePrefixes?.some(p => location.pathname === p || location.pathname.startsWith(p + '/')) ?? false);
            return (
              <Link
                key={item.name}
                to={item.href}
                onClick={(e) => handleNavClick(e, item.href)}
                className={cn(
                  'relative flex items-center gap-2.5 h-8 px-2 rounded-md text-[12.5px] font-medium transition-colors',
                  isActive
                    ? 'bg-primary/10 text-primary'
                    : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground',
                  sidebarCollapsed && 'w-8 !px-0 !gap-0 mx-auto justify-center'
                )}
                aria-label={item.name}
                title={sidebarCollapsed ? item.name : undefined}
              >
                <Icon className="w-[15px] h-[15px]" />
                {!sidebarCollapsed && item.name}
              </Link>
            );
          })}

          {/* Cases Section - expandable with Investigate + Playbooks sub-items */}
          {filteredCasesNavigation.length > 0 && (
            <div>
              {sidebarCollapsed ? (
                <CollapsedSectionFlyout
                  icon={NavLayers}
                  label="Cases"
                  items={filteredCasesNavigation}
                  isActive={isCasesActive}
                  location={location}
                  handleNavClick={handleNavClick}
                />
              ) : (
                <button
                  onClick={() => toggleSection('cases')}
                  className={cn(
                    'relative flex items-center w-full h-8 px-2 gap-2.5 rounded-md text-[12.5px] font-medium transition-colors justify-between',
                    isCasesActive
                      ? 'bg-primary/10 text-primary'
                      : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground'
                  )}
                >
                  <div className="flex items-center gap-3">
                    <NavLayers className="w-[15px] h-[15px]" />
                    Cases
                  </div>
                  <ChevronDown
                    className={cn('w-4 h-4 transition-transform', casesOpen && 'rotate-180')}
                  />
                </button>
              )}
              {casesOpen && !sidebarCollapsed && (
                <div className="mt-1 ml-6 space-y-0.5 border-l border-border/40 pl-2">
                  {filteredCasesNavigation.map((item) => {
                    const Icon = item.icon;
                    const isActive = item.href === '/inbox'
                      ? location.pathname === '/inbox' || location.pathname.startsWith('/cases')
                      : location.pathname.startsWith(item.href);
                    return (
                      <Link
                        key={item.name}
                        to={item.href}
                        onClick={(e) => handleNavClick(e, item.href)}
                        className={cn(
                          'flex items-center h-7 gap-2 rounded-md px-2 text-[12px] transition-colors',
                          isActive
                            ? 'bg-primary/10 text-primary'
                            : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground'
                        )}
                      >
                        <Icon className="w-3 h-3" />
                        {item.name}
                      </Link>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* Rules Section - expandable with sub-items */}
          {filteredDetectionNavigation.length > 0 && (
            <div>
              {sidebarCollapsed ? (
                <CollapsedSectionFlyout
                  icon={NavShield}
                  label="Rules"
                  items={filteredDetectionNavigation}
                  isActive={isDetectionActive}
                  location={location}
                  handleNavClick={handleNavClick}
                />
              ) : (
                <button
                  onClick={() => toggleSection('detections')}
                  className={cn(
                  'relative flex items-center w-full h-8 px-2 gap-2.5 rounded-md text-[12.5px] font-medium transition-colors justify-between',
                  isDetectionActive
                    ? 'bg-primary/10 text-primary'
                    : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground'
                  )}
                >
                  <div className="flex items-center gap-3">
                    <NavShield className="w-[15px] h-[15px]" />
                    Rules
                  </div>
                  <ChevronDown
                    className={cn(
                      'w-4 h-4 transition-transform',
                      detectionsOpen && 'rotate-180'
                    )}
                  />
                </button>
              )}
              {detectionsOpen && !sidebarCollapsed && (
                <div className="mt-1 ml-6 space-y-0.5 border-l border-border/40 pl-2">
                  {filteredDetectionNavigation.map((item) => {
                    const Icon = item.icon;
                    // For "All Rules", only highlight on exact match
                    // For others, use startsWith but exclude other sub-routes
                    const isActive = item.href === '/rules'
                      ? location.pathname === '/rules'
                      : location.pathname.startsWith(item.href);
                    return (
                      <Link
                        key={item.name}
                        to={item.href}
                        onClick={(e) => handleNavClick(e, item.href)}
                        className={cn(
                          'flex items-center h-7 gap-2 rounded-md px-2 text-[12px] transition-colors',
                          isActive
                            ? 'bg-primary/10 text-primary'
                            : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground'
                        )}
                      >
                        <Icon className="w-3 h-3" />
                        {item.name}
                      </Link>
                    );
                  })}
                </div>
              )}

            </div>
          )}

          {/* Secondary Main Navigation - Notebooks, Prevalence, Risk */}
          {filteredSecondaryMainNavigation.map((item) => {
            const Icon = item.icon;
            // Exclude /settings paths to avoid double-highlighting with settings nav
            const isActive = location.pathname === item.href ||
              (location.pathname.startsWith(item.href + '/') && !location.pathname.includes('/settings'));
            return (
              <Link
                key={item.name}
                to={item.href}
                onClick={(e) => handleNavClick(e, item.href)}
                className={cn(
                  'relative flex items-center gap-2.5 h-8 px-2 rounded-md text-[12.5px] font-medium transition-colors',
                  isActive
                    ? 'bg-primary/10 text-primary'
                    : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground',
                  sidebarCollapsed && 'w-8 !px-0 !gap-0 mx-auto justify-center'
                )}
                aria-label={item.name}
                title={sidebarCollapsed ? item.name : undefined}
              >
                <Icon className="w-[15px] h-[15px]" />
                {!sidebarCollapsed && item.name}
              </Link>
            );
          })}

          {/* Marketplace - top-level */}
          {hasPermission('enrichments:view') && (
            <Link
              to="/marketplace"
              onClick={(e) => handleNavClick(e, '/marketplace')}
              className={cn(
                'relative flex items-center gap-2.5 h-8 px-2 rounded-md text-[12.5px] font-medium transition-colors',
                location.pathname.startsWith('/marketplace') || location.pathname.startsWith('/enrichments')
                  ? 'bg-primary/10 text-primary'
                  : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground',
                sidebarCollapsed && 'w-8 !px-0 !gap-0 mx-auto justify-center'
              )}
              aria-label="Marketplace"
              title={sidebarCollapsed ? 'Marketplace' : undefined}
            >
              <NavSquares className="w-[15px] h-[15px]" />
              {!sidebarCollapsed && 'Marketplace'}
            </Link>
          )}

          {/* Ingestion Section - feeds, parsers, credentials */}
          {filteredIngestionNavigation.length > 0 && (
            <div className="pt-2">
              {sidebarCollapsed ? (
                <CollapsedSectionFlyout
                  icon={NavDownload}
                  label="Ingestion"
                  items={filteredIngestionNavigation}
                  isActive={isIngestionActive}
                  location={location}
                  handleNavClick={handleNavClick}
                />
              ) : (
                <button
                  onClick={() => toggleSection('ingestion')}
                  className={cn(
                    'relative flex items-center w-full h-8 px-2 gap-2.5 rounded-md text-[12.5px] font-medium transition-colors justify-between',
                    isIngestionActive
                      ? 'bg-primary/10 text-primary'
                      : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground'
                  )}
                >
                  <div className="flex items-center gap-3">
                    <NavDownload className="w-[15px] h-[15px]" />
                    Ingestion
                  </div>
                  <ChevronDown
                    className={cn(
                      'w-4 h-4 transition-transform',
                      ingestionOpen && 'rotate-180'
                    )}
                  />
                </button>
              )}
              {ingestionOpen && !sidebarCollapsed && (
                <div className="mt-1 ml-6 space-y-0.5 border-l border-border/40 pl-2">
                  {filteredIngestionNavigation.map((item) => {
                    const Icon = item.icon;
                    // Check if this item matches the current path
                    const matchesPath = location.pathname === item.href ||
                      location.pathname.startsWith(item.href + '/');
                    // Don't highlight if a more specific sibling item also matches
                    // (e.g., don't highlight /log-sources when on /log-sources/wizard)
                    const hasMoreSpecificMatch = filteredIngestionNavigation.some(
                      sibling => sibling.href !== item.href &&
                        sibling.href.startsWith(item.href) &&
                        (location.pathname === sibling.href || location.pathname.startsWith(sibling.href + '/'))
                    );
                    const isActive = matchesPath && !hasMoreSpecificMatch;
                    return (
                      <Link
                        key={item.name}
                        to={item.href}
                        onClick={(e) => handleNavClick(e, item.href)}
                        className={cn(
                          'flex items-center h-7 gap-2 rounded-md px-2 text-[12px] transition-colors',
                          isActive
                            ? 'bg-primary/10 text-primary'
                            : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground'
                        )}
                      >
                        <Icon className="w-3 h-3" />
                        {item.name}
                      </Link>
                    );
                  })}
                </div>
              )}

            </div>
          )}

          {/* Settings — single top-level link into the dedicated /settings shell (NAN-537).
               NAN-841: now visible to demo users too (SETTINGS_VIEW is in DEMO_PERMISSIONS).
               Sub-page handlers are still blocked by demo_guard until NAN-842 lands. */}
          {filteredSettingsNavigation.length > 0 && (
            <div className="mt-2 border-t border-border/40 pt-3">
              <Link
                to="/settings"
                onClick={(e) => handleNavClick(e, '/settings')}
                className={cn(
                  'relative flex items-center gap-2.5 h-8 px-2 rounded-md text-[12.5px] font-medium transition-colors',
                  isSettingsActive
                    ? 'bg-primary/10 text-primary'
                    : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground',
                  sidebarCollapsed && 'w-8 !px-0 !gap-0 mx-auto justify-center',
                )}
                aria-label="Settings"
                title={sidebarCollapsed ? 'Settings' : undefined}
              >
                <NavGear className="w-[15px] h-[15px]" />
                {!sidebarCollapsed && 'Settings'}
              </Link>
            </div>
          )}
        </nav>

        <div
          className={cn(
            'mt-auto border-t border-border shrink-0',
            sidebarCollapsed ? 'px-0 py-2 flex flex-col items-center gap-1.5' : 'px-2.5 py-2',
          )}
        >
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              {!sidebarCollapsed ? (
                <button className="w-full h-10 px-1.5 rounded-md hover:bg-foreground/5 flex items-center gap-2.5 text-left transition-colors">
                  <div className="w-7 h-7 rounded-full bg-primary/15 text-primary flex items-center justify-center font-mono font-semibold text-[10.5px] shrink-0">
                    {getUserInitials()}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-[12px] font-medium text-foreground truncate leading-tight">{user?.name || 'User'}</p>
                    <p className="text-[10.5px] text-muted-foreground truncate">{getPrimaryRole()}</p>
                  </div>
                  <ChevronDown className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                </button>
              ) : (
                <button
                  className="w-7 h-7 rounded-full bg-primary/15 text-primary flex items-center justify-center font-mono font-semibold text-[10px] hover:bg-primary/25 transition-colors"
                  title={user?.name || 'User'}
                >
                  {getUserInitials()}
                </button>
              )}
            </DropdownMenuTrigger>
            <UserMenuContent onLogout={handleLogout} onUserSettings={() => navigate('/settings/user')} />
          </DropdownMenu>

          {/* Collapse toggle below the user pill (mirrors topbar button). Mockup:
              full-width "Collapse" text+icon when expanded, centered icon rotated
              180° when collapsed. */}
          <button
            onClick={() => { autoCollapsedRef.current = false; localStorage.setItem('nanosiem-sidebar-auto-collapsed', 'false'); setSidebarCollapsed(!sidebarCollapsed); }}
            className={cn(
              'rounded-md flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-foreground/5 transition-colors',
              sidebarCollapsed ? 'w-7 h-7 mt-0.5' : 'w-full h-7 mt-1 gap-1.5 px-2 text-[11px]',
            )}
            aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            title={sidebarCollapsed ? 'Expand sidebar (⌘B)' : 'Collapse sidebar (⌘B)'}
          >
            <NavCollapse className={cn('w-[14px] h-[14px]', sidebarCollapsed && 'rotate-180')} />
            {!sidebarCollapsed && <span>Collapse</span>}
          </button>
        </div>
      </aside>

      {/* Main column — flat flex-col (no card wrapper, no outer padding) */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <BreadcrumbProvider>
          {/* Topbar: 42px, --panel bg */}
          <TopBar
            sidebarCollapsed={sidebarCollapsed}
            onToggleSidebar={() => { autoCollapsedRef.current = false; localStorage.setItem('nanosiem-sidebar-auto-collapsed', 'false'); setSidebarCollapsed(!sidebarCollapsed); }}
            onMobileMenuOpen={() => setMobileMenuOpen(true)}
            pivt={pivt}
          />

          {/* Main area + notebook sidebar + PIVT dock share this 1fr row.
              PivtShellOverlay renders the docked panel as a flex sibling
              after NotebookSidebar (so they can coexist until NAN-405
              consolidates NotebookChat into PIVT). Float + rail are absolute
              positioned and don't affect this layout.
              Open-core builds skip the overlay entirely; the main content is
              rendered as a flex child directly. */}
          <div className="flex-1 flex min-w-0 overflow-hidden">
            {(() => {
              const mainContent = (
                <main className="flex-1 flex flex-col min-w-0 overflow-x-hidden md:[overflow-x:clip]">
                  <LicenseBanner />
                  <DemoBanner />
                  <div
                    ref={scrollContainerRef}
                    style={{ scrollbarGutter: 'stable both-edges' }}
                    className="flex-1 overflow-y-auto overflow-x-hidden md:[overflow-x:clip] p-3 min-w-0"
                  >
                    <ScrollContainerProvider value={scrollContainerRef}>
                      {children}
                    </ScrollContainerProvider>
                  </div>
                </main>
              );
              return capabilities.melod ? (
                <PivtShellOverlay state={pivt}>{mainContent}</PivtShellOverlay>
              ) : (
                mainContent
              );
            })()}
          </div>

          {/* Status strip: 22px, --panel bg */}
          <StatusBar />
        </BreadcrumbProvider>
      </div>

      {/* Mobile navigation drawer */}
      <Sheet open={mobileMenuOpen} onOpenChange={setMobileMenuOpen}>
        <SheetContent side="left" className="w-72 bg-sidebar p-0 flex flex-col">
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <div className="p-4 pb-2">
            <div className="flex items-center justify-center">
              <Logo className="w-20 h-20" size="normal" />
            </div>
          </div>

          <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
            {filteredNavigation.map((item) => {
              const Icon = item.icon;
              // NAN-437: honor `activePrefixes` so the Cases nav item
              // stays lit on /cases paths even though its href is /inbox.
              const isActive =
                location.pathname === item.href ||
                (item.href !== '/' && location.pathname.startsWith(item.href + '/') && !location.pathname.includes('/settings')) ||
                (item.activePrefixes?.some(p => location.pathname === p || location.pathname.startsWith(p + '/')) ?? false);
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  onClick={(e) => handleNavClick(e, item.href)}
                  className={cn(
                    'relative flex items-center gap-2.5 h-8 px-2 rounded-md text-[12.5px] font-medium transition-colors',
                    isActive
                      ? 'bg-primary/10 text-primary'
                      : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground'
                  )}
                >
                  <Icon className="w-[15px] h-[15px]" />
                  {item.name}
                </Link>
              );
            })}

            {/* Cases Section (mobile) */}
            {filteredCasesNavigation.length > 0 && (
              <div>
                <button
                  onClick={() => toggleSection('cases')}
                  className={cn(
                    'relative flex items-center w-full h-8 px-2 gap-2.5 rounded-md text-[12.5px] font-medium transition-colors justify-between',
                    isCasesActive
                      ? 'bg-primary/10 text-primary'
                      : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground'
                  )}
                >
                  <div className="flex items-center gap-3">
                    <NavLayers className="w-[15px] h-[15px]" />
                    Cases
                  </div>
                  <ChevronDown className={cn('w-4 h-4 transition-transform', casesOpen && 'rotate-180')} />
                </button>
                {casesOpen && (
                  <div className="mt-1 ml-4 space-y-1">
                    {filteredCasesNavigation.map((item) => {
                      const Icon = item.icon;
                      const isActive = item.href === '/inbox'
                        ? location.pathname === '/inbox' || location.pathname.startsWith('/cases')
                        : location.pathname.startsWith(item.href);
                      return (
                        <Link
                          key={item.name}
                          to={item.href}
                          onClick={(e) => handleNavClick(e, item.href)}
                          className={cn(
                            'flex items-center gap-3 px-3 py-2 text-sm font-medium transition-all border-l-2',
                            isActive
                              ? 'bg-primary/10 text-primary'
                              : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground'
                          )}
                        >
                          <Icon className="w-3.5 h-3.5" />
                          {item.name}
                        </Link>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* Rules Section */}
            {filteredDetectionNavigation.length > 0 && (
              <div>
                <button
                  onClick={() => toggleSection('detections')}
                  className={cn(
                    'relative flex items-center w-full h-8 px-2 gap-2.5 rounded-md text-[12.5px] font-medium transition-colors justify-between',
                    isDetectionActive
                      ? 'bg-primary/10 text-primary'
                      : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground'
                  )}
                >
                  <div className="flex items-center gap-3">
                    <NavShield className="w-[15px] h-[15px]" />
                    Rules
                  </div>
                  <ChevronDown className={cn('w-4 h-4 transition-transform', detectionsOpen && 'rotate-180')} />
                </button>
                {detectionsOpen && (
                  <div className="mt-1 ml-4 space-y-1">
                    {filteredDetectionNavigation.map((item) => {
                      const Icon = item.icon;
                      const isActive = item.href === '/rules'
                        ? location.pathname === '/rules'
                        : location.pathname.startsWith(item.href);
                      return (
                        <Link
                          key={item.name}
                          to={item.href}
                          onClick={(e) => handleNavClick(e, item.href)}
                          className={cn(
                            'flex items-center gap-3 px-3 py-2 text-sm font-medium transition-all border-l-2',
                            isActive
                              ? 'bg-primary/10 text-primary'
                              : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground'
                          )}
                        >
                          <Icon className="w-3.5 h-3.5" />
                          {item.name}
                        </Link>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* Secondary Nav */}
            {filteredSecondaryMainNavigation.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.href ||
                (location.pathname.startsWith(item.href + '/') && !location.pathname.includes('/settings'));
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  onClick={(e) => handleNavClick(e, item.href)}
                  className={cn(
                    'relative flex items-center gap-2.5 h-8 px-2 rounded-md text-[12.5px] font-medium transition-colors',
                    isActive
                      ? 'bg-primary/10 text-primary'
                      : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground'
                  )}
                >
                  <Icon className="w-[15px] h-[15px]" />
                  {item.name}
                </Link>
              );
            })}

            {/* Marketplace */}
            {hasPermission('enrichments:view') && (
              <Link
                to="/marketplace"
                onClick={(e) => handleNavClick(e, '/marketplace')}
                className={cn(
                  'relative flex items-center gap-2.5 h-8 px-2 rounded-md text-[12.5px] font-medium transition-colors',
                  location.pathname.startsWith('/marketplace') || location.pathname.startsWith('/enrichments')
                    ? 'bg-primary/10 text-primary'
                    : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground'
                )}
              >
                <NavSquares className="w-[15px] h-[15px]" />
                Marketplace
              </Link>
            )}

            {/* Ingestion Section */}
            {filteredIngestionNavigation.length > 0 && (
              <div className="pt-2">
                <button
                  onClick={() => toggleSection('ingestion')}
                  className={cn(
                    'relative flex items-center w-full h-8 px-2 gap-2.5 rounded-md text-[12.5px] font-medium transition-colors justify-between',
                    isIngestionActive
                      ? 'bg-primary/10 text-primary'
                      : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground'
                  )}
                >
                  <div className="flex items-center gap-3">
                    <NavDownload className="w-[15px] h-[15px]" />
                    Ingestion
                  </div>
                  <ChevronDown className={cn('w-4 h-4 transition-transform', ingestionOpen && 'rotate-180')} />
                </button>
                {ingestionOpen && (
                  <div className="mt-1 ml-4 space-y-1">
                    {filteredIngestionNavigation.map((item) => {
                      const Icon = item.icon;
                      const matchesPath = location.pathname === item.href ||
                        location.pathname.startsWith(item.href + '/');
                      const hasMoreSpecificMatch = filteredIngestionNavigation.some(
                        sibling => sibling.href !== item.href &&
                          sibling.href.startsWith(item.href) &&
                          (location.pathname === sibling.href || location.pathname.startsWith(sibling.href + '/'))
                      );
                      const isActive = matchesPath && !hasMoreSpecificMatch;
                      return (
                        <Link
                          key={item.name}
                          to={item.href}
                          onClick={(e) => handleNavClick(e, item.href)}
                          className={cn(
                            'flex items-center gap-3 px-3 py-2 text-sm font-medium transition-all border-l-2',
                            isActive
                              ? 'bg-primary/10 text-primary'
                              : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground'
                          )}
                        >
                          <Icon className="w-3.5 h-3.5" />
                          {item.name}
                        </Link>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* Settings — single top-level link to /settings (NAN-537). NAN-841: demo users see it too. */}
            {filteredSettingsNavigation.length > 0 && (
              <div className="pt-2">
                <Link
                  to="/settings"
                  onClick={(e) => handleNavClick(e, '/settings')}
                  className={cn(
                    'relative flex items-center gap-3 px-3 py-2 text-sm font-medium transition-all',
                    isSettingsActive
                      ? 'bg-primary/10 text-primary'
                      : 'text-muted-foreground hover:bg-foreground/5 hover:text-foreground',
                  )}
                >
                  <NavGear className="w-[15px] h-[15px]" />
                  Settings
                </Link>
              </div>
            )}
          </nav>

          {/* User menu in mobile drawer */}
          <div className="mt-auto p-4">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button className="flex items-center gap-3 w-full hover:bg-accent/50 rounded-xl p-2 -m-2 transition-colors">
                  <div className="w-8 h-8 bg-primary/20 rounded-full flex items-center justify-center">
                    <span className="text-xs font-medium text-primary">{getUserInitials()}</span>
                  </div>
                  <div className="flex-1 min-w-0 text-left">
                    <p className="text-sm font-medium truncate">{user?.name || 'User'}</p>
                    <p className="text-xs text-muted-foreground truncate">{getPrimaryRole()}</p>
                  </div>
                  <ChevronDown className="w-4 h-4 text-muted-foreground" />
                </button>
              </DropdownMenuTrigger>
              <UserMenuContent
                onLogout={handleLogout}
                onUserSettings={() => {
                  setMobileMenuOpen(false);
                  navigate('/settings/user');
                }}
              />
            </DropdownMenu>
          </div>
        </SheetContent>
      </Sheet>

      {/* Command Palette (Cmd+K) */}
      <Suspense fallback={null}>
        <CommandPalette />
      </Suspense>

      {/* The floating "Back to Setup" button was removed: with the sidebar
          entry persisting until completion (NAN-912 F-22), the floating
          chrome was redundant intrusion on every non-getting-started page
          while onboarding was still in progress. Users have the rail link
          for discovery and `/getting-started` as a direct URL. */}

    </div>
  );
}
