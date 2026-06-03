// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Settings section registry — single source of truth for the Settings rail,
 * landing grid, breadcrumb, and search.
 *
 * Maps design-ref section IDs (`design-ref/shadcn/settings-data.jsx`) to the
 * actual app routes + permissions. Sections without a real route yet point at
 * a placeholder hash route under /settings — the shell renders a "coming soon"
 * card. As each section is ported, swap its `href` to the live route.
 *
 * The matchPrefixes array lets the rail light up across legacy URLs (e.g.
 * Access Control children at /settings/access-control/users/... still light up
 * the "Users" rail item even before the route is renamed).
 */

import type { ComponentType, SVGProps } from 'react';
import type { Capabilities } from '@/hooks/use-capabilities';
import {
  Briefcase,
  // Bell, — kept on hand for when Notifications ships
  Webhook,
  Bot,
  Activity,
  TrendingUp,
  Gauge,
  Cloud,
  Database,
  Shield,
  ShieldCheck,
  KeyRound,
  Users as UsersIcon,
  UserCog,
  MonitorSmartphone,
  ClipboardList,
  Inbox,
  ToggleLeft,
  Layers,
  Timer,
  Route,
  Boxes,
  Cpu,
  MessageSquare,
  Zap,
  type LucideIcon,
} from 'lucide-react';

export type SectionStatus = 'ok' | 'attention' | 'warn' | 'danger' | null;

export type SettingsGroupId = 'workspace' | 'detection' | 'admin';

export interface SettingsSectionChild {
  id: string;
  label: string;
  href: string;
  matchPrefixes?: string[];
  /** ANY of these permissions grants access. */
  permissions?: string | string[];
  /** Build-time capability gate — hides the entry in open-core builds when off. */
  capability?: keyof Capabilities;
  icon?: LucideIcon | ComponentType<SVGProps<SVGSVGElement>>;
}

export interface SettingsSection {
  id: string;
  label: string;
  group: SettingsGroupId;
  icon: LucideIcon | ComponentType<SVGProps<SVGSVGElement>>;
  desc: string;
  /** Where to navigate when clicked. */
  href: string;
  /** Extra prefixes that should mark this rail item active. */
  matchPrefixes?: string[];
  /** ANY of these permissions grants access. Empty = visible to everyone. */
  permissions?: string | string[];
  /** Build-time capability gate — hides the section in open-core builds when off. */
  capability?: keyof Capabilities;
  status?: SectionStatus;
  attentionMsg?: string;
  /** Set to true if the page hasn't been built yet — rail still shows it; clicking lands on a stub. */
  comingSoon?: boolean;
  /**
   * Hide this section from demo users (`demo_analyst`). Use when a section is
   * gated on a permission demo users hold for an unrelated reason — e.g. the AI
   * section keys on `settings:ai`, which demo users have only as a read-only
   * meloD-availability probe for natural-language search, not to view/manage AI
   * settings (NAN-1198). Backend access stays governed by `demo_guard`.
   */
  demoHidden?: boolean;
  children?: SettingsSectionChild[];
}

export const SETTINGS_GROUPS: Array<{ id: SettingsGroupId; label: string; desc: string }> = [
  { id: 'workspace', label: 'Workspace', desc: 'Product surfaces and how work flows through them.' },
  { id: 'detection', label: 'Detection & Search', desc: 'Tune how rules, scoring, and queries behave.' },
  { id: 'admin', label: 'Administration', desc: 'Who can do what, and what the system records.' },
];

export const SETTINGS_SECTIONS: SettingsSection[] = [
  // ------- Workspace -------
  {
    id: 'case-mgmt',
    label: 'Case Management',
    group: 'workspace',
    icon: Briefcase,
    desc: 'Case statuses, SLA, auto-assign rules, templates.',
    href: '/settings/cases',
    permissions: 'settings:system',
    capability: 'cases',
    status: 'ok',
    children: [
      {
        id: 'case-mgmt-general',
        label: 'General',
        href: '/settings/cases?tab=general',
        icon: ToggleLeft,
        permissions: 'settings:system',
      },
      {
        id: 'case-mgmt-grouping',
        label: 'Grouping Rules',
        href: '/settings/cases?tab=grouping',
        icon: Layers,
        permissions: 'settings:system',
      },
      {
        id: 'case-mgmt-sla',
        label: 'SLA',
        href: '/settings/cases?tab=sla',
        icon: Timer,
        permissions: 'settings:system',
      },
    ],
  },
  {
    id: 'queues',
    label: 'Queues & Routing',
    group: 'workspace',
    icon: Inbox,
    desc: 'Triage queues and auto-routing rules for incoming cases.',
    href: '/settings/cases/queues',
    permissions: 'settings:system',
    capability: 'cases',
    status: 'ok',
    children: [
      {
        id: 'queues-list',
        label: 'Queues',
        href: '/settings/cases/queues?tab=queues',
        icon: Inbox,
        permissions: 'settings:system',
      },
      {
        id: 'queues-routing',
        label: 'Routing Rules',
        href: '/settings/cases/queues?tab=routing',
        icon: Route,
        permissions: 'settings:system',
      },
    ],
  },
  // Notifications hidden until the surface ships — flip back on when there's
  // a real channels/routing config to manage. The /settings/notifications
  // route still exists in App.tsx and renders SettingsComingSoon for any
  // direct deeplink, but the rail no longer surfaces it.
  // {
  //   id: 'notifications',
  //   label: 'Notifications',
  //   group: 'workspace',
  //   icon: Bell,
  //   desc: 'Email, Slack, PagerDuty channels and routing.',
  //   href: '/settings/notifications',
  //   permissions: 'settings:system',
  //   status: 'ok',
  //   comingSoon: true,
  // },
  {
    id: 'webhooks',
    label: 'Webhooks',
    group: 'workspace',
    icon: Webhook,
    desc: 'Outbound webhooks for cases, alerts, rule changes.',
    href: '/settings/webhooks',
    permissions: 'settings:webhooks',
    status: 'ok',
  },

  // ------- Detection & Search -------
  {
    id: 'ai',
    label: 'AI & pivt',
    group: 'detection',
    icon: Bot,
    desc: 'Model selection, guardrails, allowed capabilities, cost caps.',
    href: '/settings/ai',
    permissions: 'settings:ai',
    capability: 'melod',
    // Demo users hold `settings:ai` only for the meloD-availability probe; the
    // section is otherwise demo-restricted by demo_guard, so hide it (NAN-1198).
    demoHidden: true,
    status: 'ok',
    children: [
      {
        id: 'ai-providers',
        label: 'Providers',
        href: '/settings/ai?tab=providers',
        icon: Cloud,
        permissions: 'settings:ai',
      },
      {
        id: 'ai-models',
        label: 'Models',
        href: '/settings/ai?tab=models',
        icon: Boxes,
        permissions: 'settings:ai',
      },
      {
        id: 'ai-agents',
        label: 'Agent Models',
        href: '/settings/ai?tab=agents',
        icon: Cpu,
        permissions: 'settings:ai',
      },
      {
        id: 'ai-guidance',
        label: 'Guidance',
        href: '/settings/ai?tab=guidance',
        icon: MessageSquare,
        permissions: 'settings:ai',
      },
      {
        id: 'ai-usage',
        label: 'Usage',
        href: '/settings/ai?tab=usage',
        icon: Activity,
        permissions: 'settings:ai',
      },
      {
        id: 'ai-monitoring',
        label: 'Monitoring',
        href: '/settings/ai?tab=monitoring',
        icon: Shield,
        permissions: 'settings:ai',
      },
    ],
  },
  {
    id: 'rarity',
    label: 'Rarity Thresholds',
    group: 'detection',
    icon: Activity,
    desc: 'Global thresholds for rarity scoring across entity types.',
    href: '/settings/prevalence',
    permissions: 'prevalence:configure',
    status: 'ok',
  },
  {
    id: 'risk',
    label: 'Risk Scoring',
    group: 'detection',
    icon: TrendingUp,
    desc: 'Risk model weights, decay, tier boundaries.',
    href: '/settings/risk',
    permissions: 'risk:configure',
    capability: 'risk',
    status: 'ok',
  },
  {
    id: 'search',
    label: 'Search',
    group: 'detection',
    icon: Gauge,
    desc: 'Default lookback, concurrency, query timeout.',
    href: '/settings/search',
    permissions: 'settings:system',
    status: 'ok',
  },
  {
    id: 'storage',
    label: 'Storage & Retention',
    group: 'detection',
    icon: Database,
    desc: 'Hot/warm/cold tiers, retention policies, cost caps.',
    href: '/settings/storage',
    permissions: 'settings:retention',
    status: 'ok',
    children: [
      {
        id: 'storage-clickhouse',
        label: 'ClickHouse · Logs',
        href: '/settings/storage?tab=clickhouse',
        icon: Zap,
        permissions: 'settings:retention',
      },
      {
        id: 'storage-postgres',
        label: 'PostgreSQL · Metadata',
        href: '/settings/storage?tab=postgres',
        icon: Database,
        permissions: 'settings:retention',
      },
    ],
  },

  // ------- Administration -------
  {
    id: 'access',
    label: 'Access Control',
    group: 'admin',
    icon: Shield,
    desc: 'Users, groups, roles, API keys, sessions.',
    href: '/settings/access-control',
    matchPrefixes: ['/settings/access-control'],
    permissions: ['users:view', 'groups:view', 'roles:view', 'apikeys:view', 'audit:view'],
    status: 'ok',
    children: [
      {
        id: 'access-users',
        label: 'Users',
        href: '/settings/access-control?tab=users',
        matchPrefixes: ['/settings/access-control/users'],
        permissions: 'users:view',
        icon: UsersIcon,
      },
      {
        id: 'access-groups',
        label: 'Groups',
        href: '/settings/access-control?tab=groups',
        matchPrefixes: ['/settings/access-control/groups'],
        permissions: 'groups:view',
        icon: UserCog,
      },
      {
        id: 'access-roles',
        label: 'Roles',
        href: '/settings/access-control?tab=roles',
        matchPrefixes: ['/settings/access-control/roles'],
        permissions: 'roles:view',
        icon: KeyRound,
      },
      {
        id: 'access-keys',
        label: 'API Keys',
        href: '/settings/access-control?tab=api-keys',
        matchPrefixes: ['/settings/access-control/api-keys'],
        permissions: 'apikeys:view',
        icon: KeyRound,
      },
      {
        id: 'access-sessions',
        label: 'Sessions',
        href: '/settings/access-control?tab=sessions',
        matchPrefixes: ['/settings/access-control/sessions'],
        permissions: 'users:view',
        icon: MonitorSmartphone,
      },
    ],
  },
  {
    id: 'sso',
    label: 'Single Sign-On',
    group: 'admin',
    icon: KeyRound,
    desc: 'SAML / OIDC providers, JIT provisioning, group mapping.',
    href: '/settings/oidc',
    matchPrefixes: ['/settings/oidc'],
    permissions: 'settings:system',
    status: 'ok',
    capability: 'sso',
  },
  {
    id: 'audit',
    label: 'Audit Log',
    group: 'admin',
    icon: ClipboardList,
    desc: 'Immutable audit of every configuration change.',
    href: '/settings/audit',
    permissions: 'audit:view',
    status: 'ok',
  },
  {
    id: 'gdpr',
    label: 'GDPR & Compliance',
    group: 'admin',
    icon: ShieldCheck,
    desc: 'Data subject requests, retention overrides, legal hold.',
    href: '/settings/gdpr',
    permissions: 'gdpr:anonymize',
    status: 'ok',
  },
];

export const GROUP_LABEL: Record<SettingsGroupId, string> = Object.fromEntries(
  SETTINGS_GROUPS.map(g => [g.id, g.label]),
) as Record<SettingsGroupId, string>;

/**
 * Flat lookup: section.id → section. Children appear here too, with parent
 * back-reference so the breadcrumb can render "Settings / Group / Parent / Child".
 */
export interface FlatSection extends SettingsSection {
  parent?: SettingsSection;
}

export const SECTION_BY_ID: Record<string, FlatSection> = (() => {
  const out: Record<string, FlatSection> = {};
  for (const s of SETTINGS_SECTIONS) {
    out[s.id] = s;
    if (s.children) {
      for (const c of s.children) {
        out[c.id] = {
          ...s,
          ...c,
          group: s.group,
          desc: s.desc,
          icon: c.icon || s.icon,
          parent: s,
        };
      }
    }
  }
  return out;
})();

/**
 * Resolve which section a URL belongs to. Returns the most-specific match
 * (children before parents, longer paths before shorter) so the rail
 * highlights e.g. "Users" not just "Access Control" inside
 * /settings/access-control/users/..., and "Queues & Routing" not "Case
 * Management" inside /settings/cases/queues.
 *
 * Specificity = path length. Children always win over parents when both
 * match — keeps the Access Control nesting working.
 */
export function resolveActiveSection(pathname: string, search?: string): { sectionId: string | null; parentId: string | null } {
  type Candidate = {
    sectionId: string;
    parentId: string | null;
    pathLen: number;
    isChild: boolean;
  };
  const matches: Candidate[] = [];

  for (const s of SETTINGS_SECTIONS) {
    // Check children first
    for (const c of (s.children || [])) {
      const prefixes = [c.href, ...(c.matchPrefixes || [])];
      for (const p of prefixes) {
        const [path, qs] = p.split('?');
        if (qs) {
          // Tab-based child: require exact pathname AND matching ?tab= so a
          // sibling subroute (e.g. /settings/cases/queues) doesn't pick up
          // the Case Management tab children via prefix.
          if (pathname !== path) continue;
          if (!search) continue;
          const want = new URLSearchParams(qs);
          const got = new URLSearchParams(search);
          if (want.get('tab') !== got.get('tab')) continue;
          matches.push({ sectionId: c.id, parentId: s.id, pathLen: path.length + qs.length, isChild: true });
        } else {
          // Path-based child: prefix match.
          if (pathname === path || pathname.startsWith(path + '/')) {
            matches.push({ sectionId: c.id, parentId: s.id, pathLen: path.length, isChild: true });
          }
        }
      }
    }
    // Check the section itself
    const prefixes = [s.href, ...(s.matchPrefixes || [])];
    for (const p of prefixes) {
      const [path] = p.split('?');
      if (pathname === path || pathname.startsWith(path + '/')) {
        matches.push({ sectionId: s.id, parentId: null, pathLen: path.length, isChild: false });
      }
    }
  }

  if (matches.length === 0) return { sectionId: null, parentId: null };

  // Sort: children before parents, then longest path wins (most specific).
  matches.sort((a, b) => {
    if (a.isChild !== b.isChild) return a.isChild ? -1 : 1;
    return b.pathLen - a.pathLen;
  });
  const best = matches[0];
  return { sectionId: best.sectionId, parentId: best.parentId };
}
