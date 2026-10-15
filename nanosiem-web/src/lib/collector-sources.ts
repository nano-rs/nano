// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Collector credentials (NAN-2597, design §2 / §2.1): one token for a
 * pipeline (Cribl, Vector, Fluent Bit, OTel Collector) that writes an
 * allowlist of sources. Each event declares its source by slug or by an
 * alias chosen here (a vendor sourcetype such as `pan:traffic`);
 * an event that declares nothing lands as `unknown` (Unattributed).
 *
 * The rules mirror the API (`validate_collector_sources`) and the 9001680
 * insert guard, so the form refuses what the server would.
 */

import type { AddDataSource, DirectProtocol } from '@/lib/add-data-sources';
import { DIRECT_PROTOCOLS } from '@/lib/add-data-sources';

/** `{declared_name: slug}` as the API takes it (`source_aliases`). */
export type SourceAliases = Record<string, string>;

/** The API's serialized `source_aliases` bound (`MAX_SOURCE_ALIASES_BYTES`). */
export const MAX_SOURCE_ALIASES_BYTES = 16 * 1024;

export const UNKNOWN_SOURCE = 'unknown';

const ALIAS_RE = /^[A-Za-z0-9:._/-]{1,128}$/;

/**
 * Sourcetypes senders already stamp for common sources (vendor add-on and
 * Cribl pack conventions). Prefilled as removable alias chips when a source
 * joins the allowlist, so an existing HEC pipeline works without re-tagging.
 */
export const VENDOR_SOURCETYPES: Record<string, string[]> = {
  palo_alto_traffic: ['pan:traffic'],
  palo_alto_threat: ['pan:threat'],
  palo_alto_system: ['pan:system'],
  palo_alto_globalprotect: ['pan:globalprotect'],
  windows_security: ['WinEventLog:Security', 'XmlWinEventLog:Security'],
  windows_system: ['WinEventLog:System', 'XmlWinEventLog:System'],
  windows_application: ['WinEventLog:Application', 'XmlWinEventLog:Application'],
  microsoft_sysmon: ['XmlWinEventLog:Microsoft-Windows-Sysmon/Operational'],
  sysmon: ['XmlWinEventLog:Microsoft-Windows-Sysmon/Operational'],
  okta: ['OktaIM2:log'],
  aws_cloudtrail: ['aws:cloudtrail'],
  aws_vpc_flow: ['aws:cloudwatchlogs:vpcflow'],
  aws_guardduty: ['aws:cloudwatch:guardduty'],
  apache_access: ['access_combined'],
  apache_error: ['apache_error'],
  nginx_access: ['nginx:plus:access'],
  cisco_asa: ['cisco:asa'],
  fortigate: ['fortigate_traffic'],
  linux_audit: ['linux:audit'],
  linux_secure: ['linux_secure'],
  o365: ['o365:management:activity'],
  microsoft_365: ['o365:management:activity'],
  azure_ad: ['azure:aad:signin'],
  crowdstrike_fdr: ['crowdstrike:events:sensor'],
  zscaler_web: ['zscalernss-web'],
};

/** Suggested aliases for a slug, never the slug itself. */
export function suggestedAliases(slug: string): string[] {
  return (VENDOR_SOURCETYPES[slug] ?? []).filter((a) => a !== slug);
}

/**
 * Add each newly allowlisted slug's vendor sourcetypes (unless a name is
 * already taken, is a slug, or is invalid) and drop aliases whose slug left
 * the allowlist. Slugs already in `previousSlugs` keep exactly the aliases
 * the user left them with.
 */
export function syncAliases(aliases: SourceAliases, slugs: string[], previousSlugs: string[] = []): SourceAliases {
  const allowed = new Set(slugs);
  const next: SourceAliases = {};
  for (const [name, slug] of Object.entries(aliases)) {
    if (allowed.has(slug) && !allowed.has(name)) next[name] = slug;
  }
  for (const slug of slugs) {
    if (previousSlugs.includes(slug)) continue;
    for (const name of suggestedAliases(slug)) {
      if (!(name in next) && !allowed.has(name) && aliasNameProblem(name) === null) next[name] = slug;
    }
  }
  return next;
}

/** Why a declared name cannot be an alias, or null. */
export function aliasNameProblem(name: string): string | null {
  if (!ALIAS_RE.test(name)) return 'Use 1-128 of A-Z a-z 0-9 : . _ / -';
  if (name === UNKNOWN_SOURCE || name === 'default') return `${name} is reserved (Unattributed)`;
  return null;
}

/** Why adding `name → slug` would be refused, or null. */
export function aliasProblem(name: string, slug: string, aliases: SourceAliases, slugs: string[]): string | null {
  const shape = aliasNameProblem(name);
  if (shape) return shape;
  if (slugs.includes(name)) return `${name} is already a source in this credential`;
  if (!slugs.includes(slug)) return `${slug} is not in the allowlist`;
  const owner = aliases[name];
  if (owner && owner !== slug) return `${name} already maps to ${owner}`;
  return null;
}

export function aliasesBytes(aliases: SourceAliases): number {
  return new TextEncoder().encode(JSON.stringify(aliases)).length;
}

export interface CollectorSelectionProblem {
  field: 'sources' | 'aliases';
  message: string;
}

/** The whole allowlist + aliases, as the API validates it. */
export function collectorSelectionProblem(slugs: string[], aliases: SourceAliases): CollectorSelectionProblem | null {
  if (slugs.length === 0) return { field: 'sources', message: 'Pick at least one source.' };
  if (slugs.includes(UNKNOWN_SOURCE)) return { field: 'sources', message: 'unknown is implicit; do not list it.' };
  if (new Set(slugs).size !== slugs.length) return { field: 'sources', message: 'Sources must be distinct.' };
  for (const [name, slug] of Object.entries(aliases)) {
    const problem = aliasProblem(name, slug, aliases, slugs);
    if (problem) return { field: 'aliases', message: `${name}: ${problem}` };
  }
  const bytes = aliasesBytes(aliases);
  if (bytes > MAX_SOURCE_ALIASES_BYTES) {
    return { field: 'aliases', message: `Aliases take ${bytes} bytes; the limit is ${MAX_SOURCE_ALIASES_BYTES}.` };
  }
  return null;
}

/** Aliases grouped per slug, in allowlist order. */
export function aliasesBySlug(aliases: SourceAliases, slugs: string[]): Array<{ slug: string; aliases: string[] }> {
  return slugs.map((slug) => ({
    slug,
    aliases: Object.entries(aliases)
      .filter(([, s]) => s === slug)
      .map(([name]) => name)
      .sort(),
  }));
}

/** `{{sources}}` for the sender templates: slugs, then aliases (as the server's `declared_sources`). */
export function declaredSources(slugs: string[], aliases: SourceAliases): string {
  return [...slugs, ...Object.keys(aliases).sort()].join(', ');
}

/**
 * Protocols a collector can carry: each allowlisted slug is issued from its
 * route template for that protocol, so only protocols every selected source
 * offers qualify (sources still rolling out offer HEC and HTTPS JSON).
 */
export function collectorProtocols(sources: AddDataSource[]): DirectProtocol[] {
  if (sources.length === 0) return [];
  const offered = (s: AddDataSource): DirectProtocol[] => (s.protocols.length > 0 ? s.protocols : ['hec', 'nano_https']);
  return DIRECT_PROTOCOLS.filter((p) => sources.every((s) => offered(s).includes(p)));
}

export function defaultCollectorLabel(protocol: string): string {
  return `collector-${protocol.replace(/_/g, '-')}`;
}
