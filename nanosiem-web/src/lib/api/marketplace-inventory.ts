// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Marketplace inventory (NAN-4946): main's unified inventory model, projected
 * client-side from this deployment's dedicated APIs instead of the hosted
 * `/api/marketplace/items` projection.
 *
 * - Catalog entries (`/api/marketplace/catalog`) become one item each, keyed by
 *   their slug so `?slug=` deep links and the curated sections keep working.
 * - Hand-authored custom enrichments (`/api/custom-enrichments`, enterprise)
 *   become `custom:<id>` items. A custom enrichment that a catalog install
 *   created is already represented by its catalog entry and is not repeated.
 *
 * Hosted entitlements (baseline / premium, purchase, checkout) have no
 * single-tenant meaning. What still gates an item is the build and its licence:
 * an entry whose execution backend is unavailable here carries a `requirement`
 * derived from `/api/capabilities`, never from a hosted/shared flag. On an open
 * build the cause is the edition; on an enterprise build a licensed flag is
 * false only because licence admission failed (NAN-5088), so the cause is the
 * licence.
 */
import type { MarketplaceCatalogEntry, EnrichmentMarketplaceRepo } from './marketplace';
import type { BuildEdition, Capabilities } from '@/hooks/use-capabilities';
import type { CustomEnrichmentSummary } from '@/enterprise/api/custom-enrichment';
import type { PlatformFeedsStatus } from './enrichment';

/** `platform`: first-party nano content. `custom`: hand-authored or third-party repository content. */
export type InventoryKind = 'platform' | 'custom';

/**
 * Why an item cannot run here. `edition`: this build does not ship the runtime
 * (open). `licence`: the enterprise build ships it but licence admission is
 * not active, so every licensed capability reads false (NAN-5088).
 */
export type InventoryRequirementCause = 'edition' | 'licence';

/** A capability this deployment lacks that the item needs to run. */
export interface InventoryRequirement {
  capability: keyof Capabilities;
  cause: InventoryRequirementCause;
  /** Short label for card footers: "Enterprise edition" / "Active licence". */
  label: string;
}

/** Sentence form of a requirement: "Requires the Enterprise edition" / "Requires an active licence". */
export function requirementSentence(requirement: InventoryRequirement): string {
  return requirement.cause === 'licence' ? 'Requires an active licence' : `Requires the ${requirement.label}`;
}

function requirementFor(capability: keyof Capabilities, edition: BuildEdition): InventoryRequirement {
  return edition === 'enterprise'
    ? { capability, cause: 'licence', label: 'Active licence' }
    : { capability, cause: 'edition', label: 'Enterprise edition' };
}

export interface InventoryItem {
  id: string;
  kind: InventoryKind;
  source: 'catalog' | 'custom_enrichment';
  name: string;
  description: string | null;
  /** Catalog category (`data` / `agent` / `identity` / `collector`), or the custom enrichment type. */
  category: string;
  installed: boolean;
  enabled: boolean;
  effective_health: string;
  reason: string | null;
  last_sync: string | null;
  execution_stage: string;
  capabilities: string[];
  author: string;
  /** Catalog slug, or the custom enrichment type. */
  connector: string;
  repository_id: string | null;
  repository_name: string | null;
  repo_commit: string | null;
  version: number | null;
  record_count: number | null;
  requires_network: boolean;
  requirement: InventoryRequirement | null;
  can_toggle: boolean;
  can_edit: boolean;
  /** The catalog entry behind a catalog item (install / configure flows). */
  entry: MarketplaceCatalogEntry | null;
  /** NAN-4948: nano's signed platform feed bundle provides this feed. */
  provided_by_bundle?: BundleProvision | null;
}

/** NAN-4948 / NAN-4959: how nano's signed platform feed bundle provides a feed. */
export interface BundleProvision {
  feed_id: string;
  /** Installed revision; null when the bundle does not carry the feed yet. */
  revision: number | null;
  /** `fresh` / `stale` / `expired`, or `not_installed`. */
  state: string;
  active: boolean;
  detail: string | null;
  /** When the installed revision was produced upstream (last update). */
  produced_at?: string | null;
  /** When the bundle carrying it was installed here. */
  installed_at?: string | null;
  /** When the scheduled check for a newer bundle is next due (next refresh). */
  next_check_at?: string | null;
  /** Online updates run (false: air-gap, refreshed by importing a bundle file). */
  auto_update?: boolean;
  channel?: string | null;
}

/** Platform feed bundle feed ids → the catalog slugs they supersede. */
const BUNDLE_FEED_SLUGS: Record<string, string[]> = {
  ipinfo_lite: ['ipinfo_lite', 'ipinfo-lite'],
  threatfox: ['threatfox'],
  tor_exit_nodes: ['tor-exit-nodes', 'tor_exit_nodes', 'tor'],
};

/**
 * NAN-4959: feeds that come ONLY from the bundle (every platform feed: IPinfo
 * Lite, ThreatFox, Tor). Their catalog card reads as bundle-provided even
 * before a bundle (or a bundle carrying them) is installed: there is no direct
 * fetcher to install or configure. Mirrors the server's
 * `marketplace::platform_feed::bundle_feed_for_slug`.
 */
const BUNDLE_ONLY_FEEDS = ['ipinfo_lite', 'threatfox', 'tor_exit_nodes'];

/** NAN-4959: the bundle feed id a catalog slug stands for, if the bundle provides it. */
export function bundleFeedForSlug(slug: string): string | null {
  const s = slug.trim().toLowerCase();
  for (const [feed, slugs] of Object.entries(BUNDLE_FEED_SLUGS)) if (slugs.includes(s)) return feed;
  return null;
}

/** Prefer the API's explicit ownership contract; retain aliases for older APIs. */
export function platformFeedForEntry(entry: Pick<MarketplaceCatalogEntry, 'slug' | 'platform_feed_id'>): string | null {
  return entry.platform_feed_id ?? bundleFeedForSlug(entry.slug);
}

/**
 * NAN-4948 / NAN-4959: catalog slug -> how the bundle provides that feed, from
 * the platform feed status. Bundle-only feeds (IPinfo Lite) are present even
 * when no bundle, or no bundle carrying them, is installed.
 */
export function bundleProvisions(status: PlatformFeedsStatus | null | undefined): Map<string, BundleProvision> {
  const bySlug = new Map<string, BundleProvision>();
  if (!status?.available) return bySlug;
  const common = {
    installed_at: status.installed_at ?? null,
    next_check_at: status.next_check_at ?? null,
    auto_update: status.auto_update !== false,
    channel: status.channel ?? null,
  };
  if (status.installed) {
    for (const feed of status.feeds) {
      const active = feed.active !== false && feed.state !== 'expired';
      const provision: BundleProvision = {
        ...common, feed_id: feed.feed_id, revision: feed.revision, state: feed.state, active,
        detail: feed.detail ?? null, produced_at: feed.produced_at ?? null,
      };
      bySlug.set(feed.feed_id, provision);
      for (const slug of BUNDLE_FEED_SLUGS[feed.feed_id] ?? []) bySlug.set(slug, provision);
    }
  }
  for (const feedId of BUNDLE_ONLY_FEEDS) {
    for (const slug of BUNDLE_FEED_SLUGS[feedId]) {
      if (bySlug.has(slug)) continue;
      bySlug.set(slug, {
        ...common, feed_id: feedId, revision: null, state: 'not_installed', active: false, produced_at: null,
        detail: status.installed ? 'The installed bundle does not carry this feed.' : 'No feed bundle installed yet.',
      });
    }
  }
  return bySlug;
}

/**
 * NAN-4948: mark the catalog cards nano's signed feed bundle covers. The bundle
 * stamps them at ingest whatever the edition, so a covered card carries no
 * edition requirement and needs no install.
 */
export function applyFeedBundle(items: InventoryItem[], status: PlatformFeedsStatus | null | undefined): InventoryItem[] {
  const bySlug = bundleProvisions(status);
  if (bySlug.size === 0) return items;
  let changed = false;
  const next = items.map(item => {
    const feedId = item.entry ? platformFeedForEntry(item.entry) : null;
    const provision = item.source === 'catalog' ? bySlug.get(feedId ?? item.id) : undefined;
    if (!provision) return item;
    changed = true;
    const reason = !provision.active ? 'bundle_inactive' : provision.state === 'stale' ? 'bundle_stale' : null;
    const feed = status?.feeds.find(f => f.feed_id === provision.feed_id);
    return {
      ...item,
      requirement: null,
      reason,
      effective_health: reason === null ? 'healthy' : provision.state,
      execution_stage: 'bronze_ingest',
      // A bundle-only feed the bundle does not carry yet has no sync to show
      // (a pre-NAN-4959 native sync's time and count would mislead).
      last_sync: provision.revision === null ? null : provision.produced_at ?? item.last_sync,
      record_count: provision.revision === null ? null : feed?.loaded ?? feed?.records ?? item.record_count,
      provided_by_bundle: provision,
    };
  });
  return changed ? next : items;
}

const FIRST_PARTY_OWNERS = ['nano-rs', 'nanos-sh'];

/**
 * First-party content repositories: exact parse, mirroring the server's
 * `marketplace::first_party` rule (https, host github.com, owner nano-rs /
 * nanos-sh, one repository segment, no credentials, query or fragment).
 * Missing or unparseable metadata is NOT first-party.
 */
export function isFirstPartyRepo(repo: Pick<EnrichmentMarketplaceRepo, 'url'> | null | undefined): boolean {
  if (!repo?.url) return false;
  let url: URL;
  try { url = new URL(repo.url.trim()); } catch { return false; }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) return false;
  if (url.port && url.port !== '443') return false;
  if (url.hostname.toLowerCase() !== 'github.com') return false;
  const segments = url.pathname.replace(/^\/+|\/+$/g, '').split('/');
  if (segments.length !== 2) return false;
  const [owner, name] = segments;
  return FIRST_PARTY_OWNERS.includes(owner.toLowerCase()) && /^[A-Za-z0-9._-]+$/.test(name.replace(/\.git$/, ''));
}

/** Which capability an entry's execution backend needs, if this deployment lacks it. */
export function entryRequirement(entry: MarketplaceCatalogEntry, caps: Capabilities, edition: BuildEdition): InventoryRequirement | null {
  if (entry.execution_backend === 'deno') {
    const capability: keyof Capabilities = entry.category === 'agent' ? 'agentEnrichment' : 'customEnrichment';
    return caps[capability] ? null : requirementFor(capability, edition);
  }
  if (entry.execution_backend === 'collector') {
    return caps.customEnrichment ? null : requirementFor('customEnrichment', edition);
  }
  // A native agent entry is backed by an agent enrichment provider, which only
  // the enterprise edition ships; the open server refuses its install (403).
  if (entry.execution_backend === 'native' && entry.category === 'agent') {
    return caps.agentEnrichment ? null : requirementFor('agentEnrichment', edition);
  }
  return null;
}

function entryStage(entry: MarketplaceCatalogEntry): string {
  if (entry.execution_backend === 'identity' || entry.category === 'identity') return 'identity_directory_sync';
  if (entry.execution_backend === 'collector' || entry.category === 'collector') return 'scheduled_pull';
  if (entry.category === 'agent' || 'artifact_types' in (entry.config ?? {})) return 'agent_on_demand';
  if (entry.execution_backend === 'native') return 'bronze_ingest';
  return 'tenant_scheduled_publication';
}

function entryReason(entry: MarketplaceCatalogEntry, requirement: InventoryRequirement | null): string | null {
  if (requirement) return 'requires_capability';
  if (!entry.installed) return 'not_installed';
  if (!entry.enabled) return 'disabled';
  if (entry.requires_credential === 'required' && !entry.has_credentials) return 'missing_credentials';
  if (entry.last_sync_status === 'failed' || entry.last_error) return 'sync_failed';
  const syncs = entry.category === 'data' || entry.execution_backend === 'native' || entry.category === 'identity';
  if (syncs && !entry.last_sync_at && !entry.is_syncing) return 'not_synced';
  return null;
}

export function healthFor(reason: string | null, syncing = false): string {
  if (syncing) return 'syncing';
  switch (reason) {
    case null: return 'healthy';
    case 'not_installed': return 'available';
    case 'requires_capability': return 'unavailable';
    case 'disabled': return 'disabled';
    case 'sync_failed': return 'error';
    default: return 'attention';
  }
}

export function catalogItem(entry: MarketplaceCatalogEntry, repos: EnrichmentMarketplaceRepo[], caps: Capabilities, edition: BuildEdition): InventoryItem {
  const repo = entry.repository_id ? repos.find(r => r.id === entry.repository_id) ?? null : null;
  const platformFeedId = platformFeedForEntry(entry);
  const requirement = platformFeedId ? null : entryRequirement(entry, caps, edition);
  const reason = platformFeedId ? 'bundle_inactive' : entryReason(entry, requirement);
  // Unknown provenance (repository metadata missing or failed to load) is untrusted.
  const firstParty = entry.source_type === 'system' || (entry.source_type === 'repository' && isFirstPartyRepo(repo));
  return {
    id: entry.slug,
    kind: firstParty ? 'platform' : 'custom',
    source: 'catalog',
    name: entry.name,
    description: entry.description ?? null,
    category: entry.category,
    installed: entry.installed,
    enabled: entry.installed && entry.enabled,
    effective_health: healthFor(reason, !!entry.is_syncing),
    reason,
    last_sync: platformFeedId ? null : entry.last_sync_at ?? null,
    execution_stage: platformFeedId ? 'bronze_ingest' : entryStage(entry),
    capabilities: entry.tags,
    author: entry.author || (firstParty ? 'nano' : 'unknown'),
    connector: entry.slug,
    repository_id: entry.repository_id ?? null,
    repository_name: repo?.name ?? null,
    repo_commit: repo?.last_sync_commit ?? null,
    version: entry.installed_version ?? entry.manifest_version ?? null,
    record_count: platformFeedId ? null : entry.installed && entry.category !== 'agent' ? entry.record_count : null,
    requires_network: entry.requires_network ?? true,
    requirement,
    can_toggle: !platformFeedId && entry.installed && !requirement,
    can_edit: false,
    entry,
    provided_by_bundle: platformFeedId ? {
      feed_id: platformFeedId,
      revision: null,
      state: 'not_installed',
      active: false,
      detail: 'Platform feed status is unavailable.',
    } : undefined,
  };
}

export function customItem(def: CustomEnrichmentSummary): InventoryItem {
  const reason = !def.enabled ? 'disabled'
    : def.status !== 'active' ? 'not_deployed'
    : def.enrichment_type === 'agent' ? null
    : def.last_run_status === 'success' ? null
    : def.last_run_status === 'failed' ? 'sync_failed' : 'not_synced';
  return {
    id: `custom:${def.id}`,
    kind: 'custom',
    source: 'custom_enrichment',
    name: def.name,
    description: def.description,
    category: def.enrichment_type,
    installed: true,
    enabled: def.enabled,
    effective_health: healthFor(reason),
    reason,
    last_sync: def.last_run_at,
    execution_stage: def.enrichment_type === 'agent' ? 'agent_on_demand' : 'tenant_scheduled_publication',
    capabilities: [def.enrichment_type],
    author: 'this deployment',
    connector: def.enrichment_type,
    repository_id: null,
    repository_name: null,
    repo_commit: null,
    version: null,
    record_count: null,
    requires_network: true,
    requirement: null,
    can_toggle: def.status === 'active' || !def.enabled,
    can_edit: true,
    entry: null,
  };
}

/**
 * Project catalog + custom enrichments into one inventory, catalog-installed
 * customs once. `connectorNames` are the bundled connector specs: a catalog
 * collector entry for the same vendor is represented by its pull-collector
 * card (connector feeds, NAN-4914) and is left out unless it was installed on
 * the older collector runtime.
 */
export function buildInventory(entries: MarketplaceCatalogEntry[], customs: CustomEnrichmentSummary[], repos: EnrichmentMarketplaceRepo[], caps: Capabilities, edition: BuildEdition, connectorNames: ReadonlySet<string> = new Set()): InventoryItem[] {
  const fromCatalog = new Set(entries.map(e => e.custom_enrichment_id).filter((id): id is string => !!id));
  const visible = entries.filter(e => !(e.category === 'collector' && connectorNames.has(e.slug) && !e.installed));
  return [
    ...visible.map(entry => catalogItem(entry, repos, caps, edition)),
    ...customs.filter(def => !fromCatalog.has(def.id)).map(customItem),
  ];
}

export function inventoryAction(item: InventoryItem): string {
  if (item.provided_by_bundle) return 'Feed bundle';
  if (item.requirement) return item.requirement.label;
  if (!item.installed) return 'Install';
  return item.enabled ? 'Disable' : 'Enable';
}

export function inventoryRouteId(slug: string): string {
  return slug;
}

const REASONS: Record<string, string> = {
  not_installed: 'Not installed.',
  requires_capability: 'Needs a capability this edition does not include.',
  disabled: 'Installed and disabled.',
  missing_credentials: 'Installed; credentials are required before it can run.',
  sync_failed: 'The last sync failed.',
  not_synced: 'No successful sync has been recorded.',
  not_deployed: 'Saved but not deployed: no active version runs.',
  bundle_inactive: 'Provided by the nano feed bundle; it is not stamping new events (expired or not loaded).',
  bundle_stale: 'Provided by the nano feed bundle; the installed revision is stale.',
};

export function inventoryReason(item: InventoryItem): string {
  if (!item.reason) return item.provided_by_bundle ? 'Provided by the nano feed bundle; stamped at ingest.' : 'Healthy';
  if (item.reason === 'requires_capability' && item.requirement) return `${requirementSentence(item.requirement)}.`;
  return Object.prototype.hasOwnProperty.call(REASONS, item.reason) ? REASONS[item.reason] : 'Status is unknown.';
}

export const SYNC_POLL_MS = 3_500;
export const SYNC_POLL_MAX_MS = 2 * 60_000;

/**
 * Catalog refetch interval while an entry is mid-sync (NAN-1108): poll every
 * 3.5 s, for at most two minutes per sync episode. `started` remembers when the
 * episode began and resets once nothing is syncing.
 */
export function syncPollInterval(syncing: boolean, started: { current: number | null }, now = Date.now()): number | false {
  if (!syncing) { started.current = null; return false; }
  started.current ??= now;
  return now - started.current < SYNC_POLL_MAX_MS ? SYNC_POLL_MS : false;
}
