// SPDX-License-Identifier: AGPL-3.0-or-later

import { useMemo } from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb';
import { useBreadcrumbContext } from '@/contexts/BreadcrumbContext';
import { useCapabilities, type Capabilities } from '@/hooks/use-capabilities';

interface BreadcrumbSegment {
  label: string;
  href?: string;
}

interface BreadcrumbRoute {
  pattern: RegExp;
  segments: BreadcrumbSegment[];
  specificity: number;
  capability?: keyof Capabilities;
}

/**
 * Static breadcrumb config mapping route patterns to breadcrumb segments.
 * `:dynamic` label means "use pageTitle from BreadcrumbContext".
 * Last segment has no href (current page).
 */
const BREADCRUMB_CONFIG: Array<{ path: string; segments: BreadcrumbSegment[]; capability?: keyof Capabilities }> = [
  // Main nav
  { path: '/search', segments: [{ label: 'Home', href: '/' }, { label: 'Search' }] },
  { path: '/settings/search', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Search' }] },
  { path: '/dashboards', segments: [{ label: 'Home', href: '/' }, { label: 'Dashboards' }] },
  { path: '/dashboards/:id', segments: [{ label: 'Home', href: '/' }, { label: 'Dashboards', href: '/dashboards' }, { label: ':dynamic' }] },
  // NAN-437: the Cases nav item points at /inbox now. Breadcrumb trails
  // use /inbox as the canonical "Cases" parent; /cases is the table view.
  { path: '/inbox', segments: [{ label: 'Home', href: '/' }, { label: 'Cases' }], capability: 'cases' },
  { path: '/cases', segments: [{ label: 'Home', href: '/' }, { label: 'Cases', href: '/inbox' }, { label: 'Browse all' }], capability: 'cases' },
  // NAN-1071/1076: cross-cutting case-search page.
  { path: '/cases/search', segments: [{ label: 'Home', href: '/' }, { label: 'Cases', href: '/inbox' }, { label: 'Case search' }], capability: 'cases' },
  { path: '/settings/cases', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Case Management' }], capability: 'cases' },
  { path: '/cases/:id', segments: [{ label: 'Home', href: '/' }, { label: 'Cases', href: '/inbox' }, { label: ':dynamic' }], capability: 'cases' },

  // Detection / Rules
  { path: '/rules', segments: [{ label: 'Home', href: '/' }, { label: 'Rules' }] },
  { path: '/rules/editor', segments: [{ label: 'Home', href: '/' }, { label: 'Rules', href: '/rules' }, { label: 'New Rule' }] },
  { path: '/rules/editor/new', segments: [{ label: 'Home', href: '/' }, { label: 'Rules', href: '/rules' }, { label: 'New Rule' }] },
  { path: '/rules/editor/:id', segments: [{ label: 'Home', href: '/' }, { label: 'Rules', href: '/rules' }, { label: ':dynamic' }] },
  { path: '/rules/:id/matches', segments: [{ label: 'Home', href: '/' }, { label: 'Rules', href: '/rules' }, { label: ':dynamic' }] },
  { path: '/rules/coverage', segments: [{ label: 'Home', href: '/' }, { label: 'Rules', href: '/rules' }, { label: 'MITRE Coverage' }] },
  { path: '/rules/repositories', segments: [{ label: 'Home', href: '/' }, { label: 'Rules', href: '/rules' }, { label: 'Repositories' }] },
  // Playbooks
  { path: '/playbooks', segments: [{ label: 'Home', href: '/' }, { label: 'Playbooks' }], capability: 'playbooks' },
  { path: '/playbooks/new', segments: [{ label: 'Home', href: '/' }, { label: 'Playbooks', href: '/playbooks' }, { label: 'New playbook' }], capability: 'playbooks' },
  { path: '/playbooks/:id', segments: [{ label: 'Home', href: '/' }, { label: 'Playbooks', href: '/playbooks' }, { label: ':dynamic' }], capability: 'playbooks' },
  { path: '/playbooks/repositories', segments: [{ label: 'Home', href: '/' }, { label: 'Playbooks', href: '/playbooks' }, { label: 'Repositories' }], capability: 'playbooks' },
  { path: '/rules/tuning', segments: [{ label: 'Home', href: '/' }, { label: 'Rules', href: '/rules' }, { label: 'AI Tuning' }], capability: 'aiTuning' },
  { path: '/rules/tuning/:id', segments: [{ label: 'Home', href: '/' }, { label: 'Rules', href: '/rules' }, { label: 'AI Tuning', href: '/rules/tuning' }, { label: ':dynamic' }], capability: 'aiTuning' },

  // Secondary main nav
  { path: '/notebooks', segments: [{ label: 'Home', href: '/' }, { label: 'Notebooks' }], capability: 'notebooks' },
  { path: '/notebooks/:id', segments: [{ label: 'Home', href: '/' }, { label: 'Notebooks', href: '/notebooks' }, { label: ':dynamic' }], capability: 'notebooks' },
  { path: '/prevalence', segments: [{ label: 'Home', href: '/' }, { label: 'Prevalence' }] },
  { path: '/settings/prevalence', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Rarity Thresholds' }] },
  { path: '/risk', segments: [{ label: 'Home', href: '/' }, { label: 'Risk' }], capability: 'risk' },
  { path: '/settings/risk', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Risk Scoring' }], capability: 'risk' },
  { path: '/platform/health', segments: [{ label: 'Home', href: '/' }, { label: 'SIEM Health' }], capability: 'siemHealth' },

  // Alerts — NAN-746: open-core triage surface. /alerts is the list page;
  // /alerts/:id is the detail. No capability tag — both ship in core.
  { path: '/alerts', segments: [{ label: 'Home', href: '/' }, { label: 'Alerts' }] },
  { path: '/alerts/:id', segments: [{ label: 'Home', href: '/' }, { label: 'Alerts', href: '/alerts' }, { label: ':dynamic' }] },

  // Lookup Tables (under Rules)
  { path: '/rules/lookup-tables', segments: [{ label: 'Home', href: '/' }, { label: 'Rules', href: '/rules' }, { label: 'Lookup Tables' }] },
  { path: '/rules/lookup-tables/new', segments: [{ label: 'Home', href: '/' }, { label: 'Rules', href: '/rules' }, { label: 'Lookup Tables', href: '/rules/lookup-tables' }, { label: 'New' }] },
  { path: '/rules/lookup-tables/:name', segments: [{ label: 'Home', href: '/' }, { label: 'Rules', href: '/rules' }, { label: 'Lookup Tables', href: '/rules/lookup-tables' }, { label: ':dynamic' }] },

  // Upload
  { path: '/upload', segments: [{ label: 'Home', href: '/' }, { label: 'Upload' }] },

  // Ingestion
  { path: '/ingestion/log-sources', segments: [{ label: 'Home', href: '/' }, { label: 'Ingestion' }, { label: 'Log Sources' }] },
  { path: '/ingestion/log-sources/new', segments: [{ label: 'Home', href: '/' }, { label: 'Ingestion' }, { label: 'Log Sources', href: '/ingestion/log-sources' }, { label: 'Add Feed' }] },
  { path: '/ingestion/log-sources/wizard', segments: [{ label: 'Home', href: '/' }, { label: 'Ingestion' }, { label: 'Log Sources', href: '/ingestion/log-sources' }, { label: 'Add Feed' }] },
  { path: '/ingestion/log-sources/repositories', segments: [{ label: 'Home', href: '/' }, { label: 'Ingestion' }, { label: 'Log Sources', href: '/ingestion/log-sources' }, { label: 'Repositories' }] },
  { path: '/ingestion/log-sources/:id', segments: [{ label: 'Home', href: '/' }, { label: 'Ingestion' }, { label: 'Log Sources', href: '/ingestion/log-sources' }, { label: ':dynamic' }] },
  { path: '/ingestion/source-configurations', segments: [{ label: 'Home', href: '/' }, { label: 'Ingestion' }, { label: 'Source Configs' }] },
  { path: '/ingestion/source-configurations/:id', segments: [{ label: 'Home', href: '/' }, { label: 'Ingestion' }, { label: 'Source Configs', href: '/ingestion/source-configurations' }, { label: ':dynamic' }] },
  { path: '/ingestion/credentials', segments: [{ label: 'Home', href: '/' }, { label: 'Ingestion' }, { label: 'Credentials' }] },
  { path: '/ingestion/credentials/:id', segments: [{ label: 'Home', href: '/' }, { label: 'Ingestion' }, { label: 'Credentials' }] },

  // Marketplace (top-level)
  { path: '/marketplace', segments: [{ label: 'Home', href: '/' }, { label: 'Marketplace' }] },
  // Deep-link / wizard routes still live under /enrichments (untouched in NAN-571 phase 1).
  { path: '/enrichments/:id', segments: [{ label: 'Home', href: '/' }, { label: 'Marketplace', href: '/marketplace' }, { label: ':dynamic' }] },
  { path: '/enrichments/agent/:id', segments: [{ label: 'Home', href: '/' }, { label: 'Marketplace', href: '/marketplace' }, { label: ':dynamic' }], capability: 'agentEnrichment' },
  { path: '/enrichments/custom/new', segments: [{ label: 'Home', href: '/' }, { label: 'Marketplace', href: '/marketplace' }, { label: 'New Enrichment' }], capability: 'customEnrichment' },
  { path: '/enrichments/custom/:id', segments: [{ label: 'Home', href: '/' }, { label: 'Marketplace', href: '/marketplace' }, { label: ':dynamic' }], capability: 'customEnrichment' },
  { path: '/integrations/custom/new', segments: [{ label: 'Home', href: '/' }, { label: 'Marketplace', href: '/marketplace' }, { label: 'New API Integration' }], capability: 'customEnrichment' },
  { path: '/integrations/custom/:id', segments: [{ label: 'Home', href: '/' }, { label: 'Marketplace', href: '/marketplace' }, { label: ':dynamic' }], capability: 'customEnrichment' },
  { path: '/settings/storage', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Storage' }] },
  { path: '/settings/ai', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'AI' }], capability: 'melod' },
  { path: '/settings/webhooks', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Webhooks' }] },
  { path: '/settings/access-control', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Access Control' }] },
  { path: '/settings/access-control/users/new', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Access Control', href: '/settings/access-control' }, { label: 'New User' }] },
  { path: '/settings/access-control/users/:id', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Access Control', href: '/settings/access-control' }, { label: 'Edit User' }] },
  { path: '/settings/access-control/groups/new', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Access Control', href: '/settings/access-control' }, { label: 'New Group' }] },
  { path: '/settings/access-control/groups/:id', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Access Control', href: '/settings/access-control' }, { label: 'Edit Group' }] },
  { path: '/settings/access-control/roles/new', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Access Control', href: '/settings/access-control' }, { label: 'New Role' }] },
  { path: '/settings/access-control/roles/:id', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Access Control', href: '/settings/access-control' }, { label: 'Edit Role' }] },
  { path: '/settings/access-control/api-keys/new', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Access Control', href: '/settings/access-control' }, { label: 'New API Key' }] },
  { path: '/settings/access-control/api-keys/:id', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Access Control', href: '/settings/access-control' }, { label: 'Edit API Key' }] },

  // Legacy settings sub-pages
  { path: '/settings/users', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Access Control', href: '/settings/access-control' }, { label: 'Users' }] },
  { path: '/settings/groups', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Access Control', href: '/settings/access-control' }, { label: 'Groups' }] },
  { path: '/settings/roles', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Access Control', href: '/settings/access-control' }, { label: 'Roles' }] },
  { path: '/settings/oidc', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Access Control', href: '/settings/access-control' }, { label: 'SSO Providers' }], capability: 'sso' },
  { path: '/settings/api-keys', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Access Control', href: '/settings/access-control' }, { label: 'API Keys' }] },
  { path: '/settings/sessions', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Access Control', href: '/settings/access-control' }, { label: 'Sessions' }] },
  { path: '/settings/audit', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'Access Control', href: '/settings/access-control' }, { label: 'Audit Log' }] },
  { path: '/settings/gdpr', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'GDPR Anonymization' }] },
  { path: '/settings/user', segments: [{ label: 'Home', href: '/' }, { label: 'Settings' }, { label: 'User Settings' }] },

  { path: '/help', segments: [{ label: 'Home', href: '/' }, { label: 'Help' }] },
];

/**
 * Convert a route path pattern like "/rules/editor/:id" to a regex.
 * :param segments become ([^/]+) capture groups.
 */
function pathToRegex(path: string): RegExp {
  const escaped = path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const withParams = escaped.replace(/:([^/]+)/g, '([^/]+)');
  return new RegExp(`^${withParams}$`);
}

/** Compile route configs into sorted regex patterns (most specific first). */
const compiledRoutes: BreadcrumbRoute[] = BREADCRUMB_CONFIG
  .map(({ path, segments, capability }) => ({
    pattern: pathToRegex(path),
    segments,
    capability,
    // More path segments and fewer params = more specific
    specificity: path.split('/').length * 10 - (path.match(/:/g) || []).length,
  }))
  .sort((a, b) => b.specificity - a.specificity);

/** Resolve segments for the current pathname. */
function useResolvedSegments() {
  const location = useLocation();
  const { pageTitle } = useBreadcrumbContext();
  const { capabilities } = useCapabilities();

  return useMemo(() => {
    const pathname = location.pathname;
    if (pathname === '/') return null;

    for (const route of compiledRoutes) {
      if (route.capability && !capabilities[route.capability]) continue;
      if (route.pattern.test(pathname)) {
        return route.segments.map(seg => ({
          ...seg,
          label: seg.label === ':dynamic' ? (pageTitle || '\u2026') : seg.label,
        }));
      }
    }
    return null;
  }, [location.pathname, pageTitle, capabilities]);
}

/** Hook to get the current page title from the breadcrumb config. */
export function useCurrentPageTitle(): string {
  const segments = useResolvedSegments();
  if (!segments || segments.length === 0) return 'Home';
  return segments[segments.length - 1].label;
}

export function AppBreadcrumbs() {
  const segments = useResolvedSegments();

  // The TopBar already renders the current page as a chip via
  // `useCurrentPageTitle()` (the last segment). Dropping it here keeps the
  // trail to ancestors-only and avoids "Add Feed · Home / ... / Add Feed"
  // (NAN-911 F-16/F-32). If only "Home" remains after the drop we still
  // render — that single breadcrumb gives the user a one-click back to the
  // landing surface from any leaf route.
  const trail = segments?.slice(0, -1) ?? [];
  if (trail.length === 0) return null;

  return (
    <>
      <span className="text-muted-foreground/40 select-none" aria-hidden="true">&middot;</span>
      <Breadcrumb>
        <BreadcrumbList>
          {trail.map((segment, index) => (
            <span key={index} className="contents">
              {index > 0 && <BreadcrumbSeparator>/</BreadcrumbSeparator>}
              <BreadcrumbItem>
                {segment.href ? (
                  <BreadcrumbLink asChild>
                    <Link to={segment.href}>{segment.label}</Link>
                  </BreadcrumbLink>
                ) : (
                  <span className="text-muted-foreground">{segment.label}</span>
                )}
              </BreadcrumbItem>
            </span>
          ))}
        </BreadcrumbList>
      </Breadcrumb>
    </>
  );
}
