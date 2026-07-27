// SPDX-License-Identifier: AGPL-3.0-or-later

import React from 'react';
import { ChevronDown, ChevronRight, Server, Clock, Network, Shield, FileText, Globe, AlertTriangle, Terminal, Eye, Search, X, User, Loader2, Copy, Table, ArrowRight, Building2, Users, ShieldCheck, Database, Plug, Package, Focus, Layers, Zap, Plus, Minus } from 'lucide-react';
import { api } from '@/lib/api';
import type { AssetEventsRequest, AssetEventFilters, AssetPagination, TimeRange, EntityContextResponse, AssetTrueTimeRangeResponse, IdentityUser } from '@/lib/api/types';
import { UDM_COLUMNS } from '@/lib/udm-fields';
import { fieldVal } from '@/lib/ocsf-field-fallbacks';
import { isPrevalenceSentinelField, isPrevalenceSentinelValue } from '@/lib/prevalence-sentinels';
import { useSchemaEntityMap } from '@/hooks/useSchemaEntityMap';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { nplQuotedBody } from '@/lib/npl-quote';

// NAN-1450: module-level so the object identity is stable across renders. Passed
// inline, it gave `useSchemaEntityMap` a fresh `fallback` every render, which
// made `resolveEntityType` a new callback each render, which re-fired the
// entity-context effect → setEntityContext → re-render → an infinite
// `/api/entities/:type/:value/context` request storm. Const fallbacks keep UDM
// byte-identical (NAN-1241).
const ASSET_ENTITY_FALLBACK: Record<string, string> = {
  src_ip: 'ip', dest_ip: 'ip', src_host: 'host', dest_host: 'host', user: 'user',
};

// Types for asset view data
interface AssetIdentity {
  ip?: string | null;
  hostname?: string | null;
  mac?: string | null;
  user?: string | null;
  valid_from?: string;
  valid_until?: string;
  observation_count?: number;
}

interface AssetProfile {
  primary_identifier: {
    field: string;
    value: string;
  } | null;
  identities: AssetIdentity[];
  first_seen: string | null;
  last_seen: string | null;
}

// Raw event from backend
interface AssetEvent {
  id: string;
  timestamp: string;
  source_type: string;
  event_type: string;
  summary: string;
  details: Record<string, unknown>;
}

interface SearchResult {
  id: string;
  timestamp: Date;
  source: string;
  fields: Record<string, unknown>;
}

interface AssetViewProps {
  results: SearchResult[];
  onDrilldown?: (filters: Record<string, unknown>) => void;
  onAddToQuery?: (field: string, value: string, exclude: boolean) => void;
  prevalenceFilter?: {
    artifacts: string[];
    filterType: 'include' | 'rare';
    timestamp?: number;
  } | null;
  timeRange?: TimeRange;
  onFetchLog?: (id: string, timestamp: Date, sourceType?: string) => Promise<Record<string, unknown> | null>;
}

// Check if a string value is meaningful (not empty, not just a dash, not whitespace-only)
function isNonEmptyValue(val: string | null | undefined): val is string {
  if (!val) return false;
  const trimmed = val.trim();
  return trimmed !== '' && trimmed !== '-';
}

// Deduplicate and organize identities by type
function ResolvedIdentities({ identities, onDrilldown }: { identities: AssetIdentity[]; onDrilldown?: (filters: Record<string, unknown>) => void }) {
  // Extract unique values for each field type
  const uniqueIps = new Set<string>();
  const uniqueHostnames = new Set<string>();
  const uniqueUsers = new Set<string>();
  const uniqueMacs = new Set<string>();

  for (const identity of identities) {
    if (isNonEmptyValue(identity.ip)) uniqueIps.add(identity.ip.trim());
    if (isNonEmptyValue(identity.hostname)) uniqueHostnames.add(identity.hostname.trim());
    if (isNonEmptyValue(identity.user)) uniqueUsers.add(identity.user.trim());
    if (isNonEmptyValue(identity.mac)) uniqueMacs.add(identity.mac.trim());
  }

  const hasAny = uniqueIps.size > 0 || uniqueHostnames.size > 0 || uniqueUsers.size > 0 || uniqueMacs.size > 0;

  if (!hasAny) return null;

  const handleClick = (field: string, value: string) => {
    onDrilldown?.({ [field]: value });
  };

  return (
    <div className="mt-3 pt-3 border-t border-border">
      <div className="flex flex-wrap gap-y-1 text-xs font-mono [&>span:not(:first-child)]:before:content-['·'] [&>span:not(:first-child)]:before:mx-2 [&>span:not(:first-child)]:before:text-muted-foreground/40">
        {/* IPs */}
        {Array.from(uniqueIps).slice(0, 4).map(ip => (
          <span key={ip}>
            <span className="text-muted-foreground">ip=</span>
            <span
              className="text-emerald-600 dark:text-emerald-400 cursor-pointer hover:underline"
              onClick={() => handleClick('src_ip', ip)}
            >
              {ip}
            </span>
          </span>
        ))}
        {uniqueIps.size > 4 && (
          <span className="text-muted-foreground">+{uniqueIps.size - 4} IPs</span>
        )}

        {/* Hostnames */}
        {Array.from(uniqueHostnames).slice(0, 3).map(hostname => (
          <span key={hostname}>
            <span className="text-muted-foreground">host=</span>
            <span
              className="text-blue-600 dark:text-blue-400 cursor-pointer hover:underline"
              onClick={() => handleClick('src_host', hostname)}
            >
              {hostname}
            </span>
          </span>
        ))}
        {uniqueHostnames.size > 3 && (
          <span className="text-muted-foreground">+{uniqueHostnames.size - 3} hosts</span>
        )}

        {/* Users */}
        {Array.from(uniqueUsers).slice(0, 4).map(user => (
          <span key={user}>
            <span className="text-muted-foreground">user=</span>
            <span
              className="text-purple-600 dark:text-purple-400 cursor-pointer hover:underline"
              onClick={() => handleClick('user', user)}
            >
              {user}
            </span>
          </span>
        ))}
        {uniqueUsers.size > 4 && (
          <span className="text-muted-foreground">+{uniqueUsers.size - 4} users</span>
        )}

        {/* MACs */}
        {Array.from(uniqueMacs).slice(0, 3).map(mac => (
          <span key={mac}>
            <span className="text-muted-foreground">mac=</span>
            <span
              className="text-amber-600 dark:text-amber-400 cursor-pointer hover:underline"
              onClick={() => handleClick('src_mac', mac)}
            >
              {mac}
            </span>
          </span>
        ))}
        {uniqueMacs.size > 3 && (
          <span className="text-muted-foreground">+{uniqueMacs.size - 3} MACs</span>
        )}
      </div>
    </div>
  );
}

// Format timestamp for display (UTC)
function formatTime(timestamp: string | Date | null): string {
  if (!timestamp) return 'N/A';
  try {
    const date = parseAsUTC(timestamp);
    if (isNaN(date.getTime())) return String(timestamp) || 'N/A';
    const month = date.toLocaleString('en-US', { month: 'short', timeZone: 'UTC' });
    const day = date.getUTCDate();
    const year = date.getUTCFullYear();
    const hours = date.getUTCHours().toString().padStart(2, '0');
    const mins = date.getUTCMinutes().toString().padStart(2, '0');
    const secs = date.getUTCSeconds().toString().padStart(2, '0');
    return `${month} ${day}, ${year}, ${hours}:${mins}:${secs} UTC`;
  } catch {
    return String(timestamp) || 'N/A';
  }
}

/** Risk badge + first/last seen timestamps (shared between user and host profile cards) */
function RiskBadgeAndTimestamps({ entityContext, isLoadingTimeRange, trueTimeRange, assetProfile }: {
  entityContext: EntityContextResponse | null;
  isLoadingTimeRange: boolean;
  trueTimeRange: AssetTrueTimeRangeResponse | null;
  assetProfile: { first_seen: string | null; last_seen: string | null };
}) {
  return (
    <div className="flex items-center gap-3 shrink-0">
      {entityContext?.risk && (() => {
        const score = entityContext.risk.risk_score;
        const level = score > 70 ? 'Critical' : score > 50 ? 'High' : score > 30 ? 'Medium' : 'Low';
        const color = score > 70 ? 'text-red-500 bg-red-500/10 border-red-500/30'
          : score > 50 ? 'text-orange-500 bg-orange-500/10 border-orange-500/30'
          : score > 30 ? 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30'
          : 'text-green-500 bg-green-500/10 border-green-500/30';
        return (
          <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-xs font-medium ${color}`}>
            <Shield className="w-3.5 h-3.5" />
            <span>{score}</span>
            <span className="opacity-75">{level}</span>
          </div>
        );
      })()}
      <div className="text-right text-xs text-muted-foreground">
        <div className="flex items-center gap-1 justify-end">
          <Clock className="w-3 h-3" />
          <span>First: {isLoadingTimeRange ? <Loader2 className="w-3 h-3 animate-spin inline" /> : formatTime(trueTimeRange?.first_seen ?? assetProfile.first_seen)}</span>
        </div>
        <div className="flex items-center gap-1 justify-end mt-0.5">
          <Clock className="w-3 h-3" />
          <span>Last: {isLoadingTimeRange ? <Loader2 className="w-3 h-3 animate-spin inline" /> : formatTime(trueTimeRange?.last_seen ?? assetProfile.last_seen)}</span>
        </div>
      </div>
    </div>
  );
}

/** Recent cases section for the asset profile card */
function CasesSection({ entityContext }: { entityContext: EntityContextResponse }) {
  if (entityContext.case_count === 0) return null;
  return (
    <div className="mt-3 pt-3 border-t border-border">
      <div className="flex items-center gap-1.5 mb-1.5">
        <FileText className="w-3.5 h-3.5 text-blue-500" />
        <span className="text-xs font-medium text-foreground">{entityContext.case_count} case{entityContext.case_count !== 1 ? 's' : ''} (7d)</span>
      </div>
      <div className="space-y-0.5">
        {entityContext.cases.slice(0, 3).map((c) => {
          const severityColor = c.severity === 'critical' ? 'bg-red-500/20 text-red-400'
            : c.severity === 'high' ? 'bg-orange-500/20 text-orange-400'
            : c.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400'
            : 'bg-blue-500/20 text-blue-400';
          return (
            <a
              key={c.id}
              href={`/cases/${c.id}`}
              className="flex items-center gap-2 text-xs px-2 py-1 rounded hover:bg-muted/50 transition-colors group"
            >
              <span className="text-muted-foreground font-mono shrink-0">#{c.case_number}</span>
              <span className="text-foreground truncate flex-1 group-hover:text-primary transition-colors">
                {c.title}
              </span>
              <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium uppercase shrink-0 w-[4.25rem] text-center ${severityColor}`}>
                {c.severity}
              </span>
              <span className="text-muted-foreground shrink-0 capitalize w-[5.5rem] text-right">{c.status.replace(/_/g, ' ')}</span>
              <span className="text-muted-foreground shrink-0 text-[10px] w-[4.5rem] text-right" title={new Date(c.created_at).toLocaleString()}>
                {(() => {
                  const d = new Date(c.created_at);
                  const now = new Date();
                  const diffMs = now.getTime() - d.getTime();
                  const diffH = Math.floor(diffMs / 3600000);
                  if (diffH < 24) return `${diffH}h ago`;
                  const diffD = Math.floor(diffH / 24);
                  if (diffD < 7) return `${diffD}d ago`;
                  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
                })()}
              </span>
            </a>
          );
        })}
        {entityContext.case_count > 3 && (
          <span className="text-[10px] text-muted-foreground px-2">+{entityContext.case_count - 3} more</span>
        )}
      </div>
    </div>
  );
}

// Parse timestamp string as UTC (handles database format without Z suffix)
function parseAsUTC(timestamp: string | Date): Date {
  if (timestamp instanceof Date) return timestamp;
  if (!timestamp) return new Date();

  // If it already has timezone info (Z or +/-), parse directly
  if (timestamp.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(timestamp)) {
    return new Date(timestamp);
  }

  // Database format: "YYYY-MM-DD HH:MM:SS.ffffff" - append Z to treat as UTC
  const isoString = timestamp.replace(' ', 'T') + 'Z';
  return new Date(isoString);
}

// Format just the time portion (UTC 24-hour)
function formatTimeOnly(timestamp: string | Date): string {
  try {
    const date = parseAsUTC(timestamp);
    if (isNaN(date.getTime())) return String(timestamp);
    const hours = date.getUTCHours().toString().padStart(2, '0');
    const mins = date.getUTCMinutes().toString().padStart(2, '0');
    const secs = date.getUTCSeconds().toString().padStart(2, '0');
    return `${hours}:${mins}:${secs}`;
  } catch {
    return String(timestamp);
  }
}

// Format date header (UTC)
function formatDateHeader(timestamp: string | Date): string {
  try {
    const date = parseAsUTC(timestamp);
    if (isNaN(date.getTime())) return String(timestamp);
    const weekday = date.toLocaleString('en-US', { weekday: 'short', timeZone: 'UTC' });
    const month = date.toLocaleString('en-US', { month: 'short', timeZone: 'UTC' });
    const day = date.getUTCDate();
    const year = date.getUTCFullYear();
    return `${weekday}, ${month} ${day}, ${year}`;
  } catch {
    return String(timestamp);
  }
}

// Color/icon constants for event type classification
const DEFAULT_COLOR = 'text-blue-600 dark:text-blue-400';
const NETWORK_COLOR = 'text-emerald-600 dark:text-emerald-400';
const ALERT_COLOR = 'text-red-600 dark:text-red-400';
const AUTH_FAIL_COLOR = 'text-orange-600 dark:text-orange-400';
const MUTED_COLOR = 'text-muted-foreground';

// Pre-built lookup for server-computed event_type → color/icon (avoids per-call allocation)
const EVENT_TYPE_STYLE: Record<string, { color: string; icon: React.ReactNode }> = {
  'ALERT': { color: ALERT_COLOR, icon: <AlertTriangle className="w-3 h-3" /> },
  'AUTH_SUCCESS': { color: DEFAULT_COLOR, icon: <Shield className="w-3 h-3" /> },
  'AUTH_FAILURE': { color: AUTH_FAIL_COLOR, icon: <Shield className="w-3 h-3" /> },
  'NETWORK': { color: NETWORK_COLOR, icon: <Network className="w-3 h-3" /> },
  'DNS': { color: NETWORK_COLOR, icon: <Globe className="w-3 h-3" /> },
  'DHCP': { color: NETWORK_COLOR, icon: <Network className="w-3 h-3" /> },
  'PROCESS': { color: DEFAULT_COLOR, icon: <Terminal className="w-3 h-3" /> },
  'FILE': { color: DEFAULT_COLOR, icon: <FileText className="w-3 h-3" /> },
  'IMAGE_LOAD': { color: MUTED_COLOR, icon: <Package className="w-3 h-3" /> },
  'REGISTRY': { color: DEFAULT_COLOR, icon: <Database className="w-3 h-3" /> },
  'PIPE': { color: MUTED_COLOR, icon: <Plug className="w-3 h-3" /> },
};

// Determine event type from log fields
// Returns type label and simple text color (no badge backgrounds)
// Color scheme: blue for most events, green for network, red for alerts
function getEventType(fields: Record<string, unknown>): { type: string; color: string; icon: React.ReactNode } {
  // Use server-computed event_type when available (matches facet classification)
  const precomputed = fields.event_type as string | undefined;
  if (precomputed) {
    const mapped = EVENT_TYPE_STYLE[precomputed];
    if (mapped) return { type: precomputed, ...mapped };
    return { type: precomputed, color: MUTED_COLOR, icon: <Eye className="w-3 h-3" /> };
  }

  // Fallback: heuristic classification when event_type not pre-computed
  const sourceType = String(fields.source_type || '').toLowerCase();
  const action = String(fields.action || '').toLowerCase();
  const fileAction = fields.file_action as string | undefined;
  const authResult = fields.auth_result as string | undefined;

  // Alert/Signal events - red
  if (sourceType === 'signal' || sourceType.includes('alert')) {
    return { type: 'ALERT', color: ALERT_COLOR, icon: <AlertTriangle className="w-3 h-3" /> };
  }

  // Authentication events - blue (orange for failures)
  if (sourceType.includes('auth') || action.includes('login') || action.includes('logon') || authResult) {
    const isFailed = authResult?.toLowerCase().includes('fail') || action.includes('fail');
    return {
      type: isFailed ? 'AUTH_FAILURE' : 'AUTH_SUCCESS',
      color: isFailed ? AUTH_FAIL_COLOR : DEFAULT_COLOR,
      icon: <Shield className="w-3 h-3" />
    };
  }

  // Network connection events - green
  if (action.includes('connection') || action.includes('network_connection') ||
      sourceType.includes('firewall') || sourceType.includes('proxy') ||
      ((fields.dest_ip || (fields.dest_port && fields.dest_port !== 0 && fields.dest_port !== '0')) && !action.includes('process') && !action.includes('exec'))) {
    return { type: 'NETWORK', color: NETWORK_COLOR, icon: <Network className="w-3 h-3" /> };
  }

  // DNS events - green (network-related)
  const srcPort = Number(fields.src_port) || 0;
  const destPort = Number(fields.dest_port) || 0;
  if ((sourceType.includes('dns') || fields.query || srcPort === 53 || destPort === 53) && !sourceType.includes('dhcp')) {
    return { type: 'DNS', color: NETWORK_COLOR, icon: <Globe className="w-3 h-3" /> };
  }

  // Network info / inventory events (DHCP, adapter info) - green
  if (sourceType.includes('dhcp') || action.includes('dhcp') ||
      action === 'network_info' || action === 'networkinfo' || action.includes('network_adapter')) {
    return { type: 'DHCP', color: NETWORK_COLOR, icon: <Network className="w-3 h-3" /> };
  }

  // Image load events (DLL loads) - muted (noisy, default filtered)
  if (action === 'image_load' || action === 'imageload') {
    return { type: 'IMAGE_LOAD', color: MUTED_COLOR, icon: <Package className="w-3 h-3" /> };
  }

  // Registry events
  if (action.includes('registry') || String(fields.category || '').toLowerCase() === 'registry') {
    return { type: 'REGISTRY', color: DEFAULT_COLOR, icon: <Database className="w-3 h-3" /> };
  }

  // Pipe events (named pipe create/connect)
  if (action.includes('pipe') || String(fields.category || '').toLowerCase() === 'pipe') {
    return { type: 'PIPE', color: MUTED_COLOR, icon: <Plug className="w-3 h-3" /> };
  }

  // Process events - blue
  if (action.includes('process') || action.includes('exec') || action.includes('spawn') || action.includes('start')) {
    return { type: 'PROCESS', color: DEFAULT_COLOR, icon: <Terminal className="w-3 h-3" /> };
  }

  // File events - blue
  if (fileAction || action.includes('file') || action.includes('write') || action.includes('read') || action.includes('create') || action.includes('delete')) {
    return { type: 'FILE', color: DEFAULT_COLOR, icon: <FileText className="w-3 h-3" /> };
  }

  // Fallback: if we have dest_ip/dest_port, it's likely network - green
  if (fields.dest_ip || (fields.dest_port && fields.dest_port !== 0 && fields.dest_port !== '0')) {
    return { type: 'NETWORK', color: NETWORK_COLOR, icon: <Network className="w-3 h-3" /> };
  }

  // Default/unmapped - grey
  return { type: 'EVENT', color: MUTED_COLOR, icon: <Eye className="w-3 h-3" /> };
}

// Get key inline fields to display based on event type
// Returns array of [fieldName, value] pairs to show on the row.
// NAN-1322/1324: `fieldVal` resolves each UDM concept through the shared
// native-OCSF fallback map (UDM key first → byte-identical under UDM, then the
// native OCSF column) so the inline preview populates under OCSF.
function getInlineFields(fields: Record<string, unknown>, eventType: string): Array<[string, string]> {
  const result: Array<[string, string]> = [];
  const fv = (concept: string) => fieldVal(fields, concept);

  const addField = (name: string, value: unknown) => {
    if (value !== null && value !== undefined && value !== '' && value !== 0 && value !== '0'
      && !(typeof value === 'string' && value.trim() === '-')) {
      result.push([name, String(value)]);
    }
  };

  switch (eventType) {
    case 'PROCESS':
      addField('process', fv('process_name'));
      addField('cmd', fv('command_line') || fields.process);
      addField('parent', fv('parent_command_line') || fields.parent_process || fields.parent_process_name);
      addField('user', fv('user'));
      break;

    case 'FILE':
      addField('file', fv('file_name') || fv('file_path'));
      addField('action', fields.file_action || fields.action);
      addField('process', fv('process_name'));
      addField('user', fv('user'));
      addField('hash', fv('file_hash'));
      break;

    case 'NETWORK':
      addField('dest', fv('dest_host') || fv('dest_ip'));
      addField('port', fv('dest_port'));
      addField('url', fv('url'));
      addField('process', fv('process_name'));
      addField('bytes', fv('bytes_out') || fv('bytes_in'));
      break;

    case 'DHCP':
      addField('ip', fv('src_ip') || fields.ip);
      addField('mac', fv('src_mac') || fields.mac);
      addField('host', fv('src_host'));
      break;

    case 'DNS':
      addField('query', fv('query'));
      addField('answer', fv('answer'));
      addField('type', fields.query_type);
      addField('process', fv('process_name'));
      break;

    case 'ALERT':
      addField('rule', fields.rule_name);
      addField('severity', fields.severity);
      addField('tactic', fields.mitre_tactic);
      addField('technique', fields.mitre_technique);
      break;

    case 'AUTH_SUCCESS':
    case 'AUTH_FAILURE':
      addField('user', fv('user'));
      addField('type', fv('auth_type'));
      addField('src', fv('src_ip') || fv('src_host'));
      addField('target', fv('dest_host') || fields.target_host);
      break;

    case 'IMAGE_LOAD':
      addField('process', fv('process_name'));
      addField('hash', fv('process_hash'));
      addField('signature', fields.signature);
      addField('user', fv('user'));
      break;

    case 'REGISTRY':
      addField('path', fields.registry_path);
      addField('value', fields.registry_value_data);
      addField('process', fv('process_name'));
      addField('user', fv('user'));
      break;

    case 'PIPE':
      addField('process', fv('process_name'));
      addField('user', fv('user'));
      break;

    default:
      addField('action', fields.action);
      addField('message', fields.message);
      break;
  }

  return result.slice(0, 5); // Limit to 5 inline fields
}

// Event type label component (simple text, no badge)
function EventTypeLabel({ type, color, icon }: { type: string; color: string; icon: React.ReactNode }) {
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-medium ${color}`}>
      {icon}
      {type}
    </span>
  );
}

// Default table columns by event type for drilldown table views
// Per-event-type `| table` drilldown column lists (UDM names). Under OCSF these
// names don't exist, so resolveTableColumns() (below) intersects the list with
// the active schema's field set before emitting the `| table` command, dropping
// columns that would 500. Under UDM every name resolves, so the output stays
// byte-identical (NAN-1241).
const TABLE_COLUMNS: Record<string, string> = {
  PROCESS: 'timestamp, source_type, action, user, src_host, process_name, process, process_path, parent_process, process_hash',
  FILE: 'timestamp, source_type, action, user, src_host, file_path, file_name, file_hash, file_action, process_name',
  NETWORK: 'timestamp, source_type, action, user, src_ip, dest_ip, dest_port, dest_host, url, protocol, bytes_in, bytes_out',
  DNS: 'timestamp, source_type, action, user, src_ip, query, query_type, answer, dest_ip',
  AUTH_SUCCESS: 'timestamp, source_type, action, user, src_ip, src_host, auth_type, auth_result, session_id',
  AUTH_FAILURE: 'timestamp, source_type, action, user, src_ip, src_host, auth_type, auth_result, status',
  DHCP: 'timestamp, source_type, action, src_ip, src_mac, src_host, user',
  ALERT: 'timestamp, source_type, rule_name, severity, user, src_ip, dest_ip, mitre_tactic, mitre_technique',
  IMAGE_LOAD: 'timestamp, source_type, user, src_host, process_name, process_hash, signature',
  REGISTRY: 'timestamp, source_type, action, user, src_host, process_name, registry_path, registry_value_data',
  PIPE: 'timestamp, source_type, action, user, src_host, process_name',
  EVENT: 'timestamp, source_type, action, user, src_ip, src_host, dest_ip, dest_host, message',
};

// Always-safe columns kept even when intersection with the active schema would
// otherwise empty the list (OCSF with none of the UDM names present).
const ALWAYS_TABLE_COLUMNS = ['timestamp', 'source_type'];

/**
 * Resolve the `| table` column list for an event type against the active schema.
 * `schemaFieldNames === null` (schema not yet loaded, or UDM where the const is
 * already correct) → return the const verbatim (UDM byte-identical). Otherwise
 * keep only columns present in the schema, preserving the always-safe ones.
 */
function resolveTableColumns(type: string, schemaFieldNames: Set<string> | null): string {
  const base = TABLE_COLUMNS[type] || TABLE_COLUMNS.EVENT;
  if (!schemaFieldNames) return base;
  const cols = base.split(',').map(c => c.trim()).filter(Boolean);
  const kept = cols.filter(c => ALWAYS_TABLE_COLUMNS.includes(c) || schemaFieldNames.has(c));
  return (kept.length > 0 ? kept : ALWAYS_TABLE_COLUMNS).join(', ');
}

// Single timeline event row
interface TimelineEventProps {
  event: SearchResult;
  onDrilldown?: (filters: Record<string, unknown>) => void;
  onAddToQuery?: (field: string, value: string, exclude: boolean) => void;
  onFetchLog?: (id: string, timestamp: Date, sourceType?: string) => Promise<Record<string, unknown> | null>;
  isHighlighted?: boolean;
  groupCount?: number;
  groupedEvents?: SearchResult[];
}

function TimelineEvent({ event, onDrilldown, onAddToQuery, onFetchLog, isHighlighted, groupCount = 1, groupedEvents }: TimelineEventProps) {
  const [expanded, setExpanded] = React.useState(false);
  const [fullLogData, setFullLogData] = React.useState<Record<string, unknown> | null>(null);
  const [isLoadingFullLog, setIsLoadingFullLog] = React.useState(false);
  const [expandedValueKeys, setExpandedValueKeys] = React.useState<Set<string>>(new Set());
  const hoverTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  // Schema-aware `| table` columns: under OCSF the UDM column names are dropped
  // if absent from the active schema (would 500); under UDM we pass null so the
  // const passes through byte-identical (NAN-1241).
  const { schemaFields } = useSchemaEntityMap();
  const schemaFieldNames = React.useMemo(
    () =>
      schemaFields && schemaFields.schema !== 'udm'
        ? new Set(schemaFields.fields.map(f => f.name))
        : null,
    [schemaFields],
  );
  // Categorization "known field" oracle (NAN-1241): a field counts as a known
  // core column if the active schema knows it OR it's a UDM column. Under UDM
  // this is byte-identical to the old `UDM_COLUMNS.has()` check (the schema set is
  // empty); under OCSF, promoted columns (`src_endpoint.ip`, `class_uid`, …)
  // become "known" so they land in Core, not the Extended (ext spill) bucket.
  // Mirrors EventInspectorPanel knownSchemaFields∪UDM_COLUMNS.
  const isKnownField = React.useCallback(
    (name: string): boolean =>
      (schemaFieldNames?.has(name) ?? false) || UDM_COLUMNS.has(name),
    [schemaFieldNames],
  );
  const fields = event.fields;
  const { type, color, icon } = getEventType(fields);
  const inlineFields = getInlineFields(fields, type);

  // Get important detail fields, prioritized by event type
  // Uses fullLogData (fetched on expand) when available, otherwise falls back to slim fields
  const detailFields = React.useMemo(() => {
    const source = fullLogData || fields;

    // Fields to always exclude
    const exclude = new Set([
      'id', 'timestamp', '_display_type', '_asset_profile', '_asset_events',
      '_asset_histogram', '_asset_sections', '_asset_pagination', 'details', 'event_type', 'summary'
    ]);

    // Priority fields by event type (shown first in expanded view)
    const priorityFields: Record<string, string[]> = {
      PROCESS: ['command_line', 'process_name', 'process_path', 'process_id', 'parent_command_line', 'parent_process_id', 'process_hash', 'user', 'src_host'],
      FILE: ['file_path', 'file_name', 'file_hash', 'file_action', 'process_name', 'user', 'src_host'],
      NETWORK: ['dest_ip', 'dest_host', 'dest_port', 'src_ip', 'src_port', 'protocol', 'bytes_in', 'bytes_out', 'process_name', 'user'],
      DHCP: ['src_ip', 'src_mac', 'src_host', 'user', 'event_type', 'source_type'],
      DNS: ['query', 'query_type', 'answer', 'dest_ip', 'src_ip', 'process_name'],
      ALERT: ['rule_name', 'severity', 'message', 'mitre_tactic', 'mitre_technique', 'src_ip', 'dest_ip', 'user'],
      AUTH_SUCCESS: ['user', 'auth_type', 'auth_result', 'src_ip', 'src_host', 'session_id'],
      AUTH_FAILURE: ['user', 'auth_type', 'auth_result', 'status', 'src_ip', 'src_host', 'failure_reason'],
      IMAGE_LOAD: ['image_loaded', 'process_name', 'process_path', 'process_hash', 'signed', 'signature', 'user', 'src_host'],
      REGISTRY: ['registry_path', 'registry_value_data', 'event_type', 'process_name', 'user', 'src_host'],
      PIPE: ['pipe_name', 'event_type', 'process_name', 'user', 'src_host'],
      EVENT: ['message', 'event_type', 'source_type', 'user', 'src_ip', 'src_host'],
    };

    // Check if value is meaningful (not empty, not zero, not empty array/object, not a placeholder)
    const isMeaningful = (value: unknown): boolean => {
      if (value === null || value === undefined || value === '') return false;
      if (typeof value === 'number' && value === 0) return false;
      if (value === '0') return false;
      if (Array.isArray(value) && value.length === 0) return false;
      if (typeof value === 'object' && !Array.isArray(value) && Object.keys(value as Record<string, unknown>).length === 0) return false;
      if (typeof value === 'string') {
        const trimmed = value.trim();
        if (trimmed === '-' || trimmed === '[]' || trimmed === '{}' || trimmed === 'null') return false;
      }
      return true;
    };

    const priority = priorityFields[type] || priorityFields.EVENT;

    // Collect all meaningful fields
    const allFields = Object.entries(source)
      .filter(([key, value]) =>
        !exclude.has(key) &&
        !key.startsWith('_') &&
        isMeaningful(value) &&
        // Filter prevalence sentinel values (65535=N/A, 9999=common). See lib/prevalence-sentinels.
        !isPrevalenceSentinelField(key, value)
      );

    // Category sort matching SearchResults: UDM first, then enrichment types
    const getFieldCat = (name: string): number => {
      if (name === 'risk_score' || name === 'risk_entity' || name === 'risk_factors' || name.startsWith('risk_')) return 1;
      if (name.startsWith('ioc_')) return 2;
      if (name.includes('_identity_') || name.startsWith('identity_') || name === 'is_nat_candidate') return 3;
      if (name.startsWith('prevalence_') || name === 'host_count' || name === 'is_rare' ||
          name === 'prevalence_score' || name === 'prevalence_type' || name === 'prevalence_artifact' ||
          name === 'total_occurrences' || name === 'first_seen' || name === 'last_seen') return 4;
      if (name.startsWith('lookup_')) return 5;
      if (name.startsWith('enriched_')) return 6;
      if (name.startsWith('custom_')) return 7;
      if (name.startsWith('metadata_')) return 8;
      if (!isKnownField(name)) return 9; // ext fields
      return 0; // schema core (UDM, or OCSF promoted)
    };

    // Sort: priority fields first (in order), then by category, then alphabetically
    const sorted = allFields.sort(([keyA], [keyB]) => {
      const aIdx = priority.indexOf(keyA);
      const bIdx = priority.indexOf(keyB);
      // Both are priority fields — keep priority order
      if (aIdx !== -1 && bIdx !== -1) return aIdx - bIdx;
      // Only one is priority — it goes first
      if (aIdx !== -1) return -1;
      if (bIdx !== -1) return 1;
      // Neither is priority — sort by category then alpha
      const catA = getFieldCat(keyA);
      const catB = getFieldCat(keyB);
      if (catA !== catB) return catA - catB;
      return keyA.localeCompare(keyB);
    });

    return sorted;
  }, [fields, fullLogData, type, isKnownField]);

  const timestamp = fields.timestamp as string || event.timestamp?.toString() || '';

  // Field name color matching SearchResults: UDM=sky, risk=orange, ioc=red, enrichment=muted
  const fieldNameColor = (k: string) =>
    (k === 'risk_score' || k === 'risk_entity' || k === 'risk_factors' || k.startsWith('risk_')) ? "text-orange-400" :
    k.startsWith('ioc_') ? "text-red-400" :
    isKnownField(k) ? "text-sky-700 dark:text-sky-400/70" :
    "text-muted-foreground";

  // Prefetch full log on hover (400ms debounce to skip scroll drive-bys).
  // NAN-1032: pass source_type so the backend can use the (source_type, timestamp, ...)
  // PK index — without it, S3-backed historical lookups take 12–60s.
  const eventSourceType = fields.source_type as string | undefined;
  const prefetchLog = React.useCallback(() => {
    if (!onFetchLog || fullLogData || isLoadingFullLog) return;
    setIsLoadingFullLog(true);
    const ts = event.timestamp instanceof Date ? event.timestamp : new Date(event.timestamp as unknown as string);
    onFetchLog(event.id, ts, eventSourceType)
      .then((data) => { if (data) setFullLogData(data); })
      .catch(() => {})
      .finally(() => setIsLoadingFullLog(false));
  }, [onFetchLog, event.id, event.timestamp, eventSourceType, fullLogData, isLoadingFullLog]);

  const handleMouseEnter = React.useCallback(() => {
    if (fullLogData || isLoadingFullLog) return;
    hoverTimerRef.current = setTimeout(prefetchLog, 400);
  }, [prefetchLog, fullLogData, isLoadingFullLog]);

  const handleMouseLeave = React.useCallback(() => {
    if (hoverTimerRef.current) {
      clearTimeout(hoverTimerRef.current);
      hoverTimerRef.current = null;
    }
  }, []);

  // Prevalence indicator: show on collapsed row when prevalence_min has a real (non-sentinel) value
  const prevMin = fields.prevalence_min as number | undefined;
  const hasRealPrevalence = prevMin !== undefined && !isPrevalenceSentinelValue(prevMin);
  const prevColor = hasRealPrevalence
    ? prevMin <= 3 ? 'bg-red-500/20 text-red-400 border-red-500/30'
    : prevMin <= 10 ? 'bg-orange-500/20 text-orange-400 border-orange-500/30'
    : prevMin <= 25 ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
    : null // > 25 is common, don't show indicator
    : null;

  // Severity-based left border accent
  const severity = String(fields.severity || '').toLowerCase();
  const severityBorder = severity === 'critical' ? 'border-l-2 border-l-red-500'
    : severity === 'high' ? 'border-l-2 border-l-orange-500'
    : '';

  // Group expansion state (for showing grouped events inline)
  const [groupExpanded, setGroupExpanded] = React.useState(false);

  return (
    <div className={`group transition-all duration-500 ${severityBorder} ${isHighlighted ? 'ring-1 ring-primary/60 bg-primary/5 rounded' : ''}`}>
      <button
        className="w-full flex items-start gap-4 py-2 px-3 hover:bg-muted/50 rounded transition-colors text-left"
        onMouseEnter={handleMouseEnter}
        onMouseLeave={handleMouseLeave}
        onClick={() => {
          if (groupCount > 1 && !groupExpanded) {
            setGroupExpanded(true);
            return;
          }
          if (groupCount > 1 && (groupExpanded || expanded)) {
            if (expanded) {
              setExpanded(false);
              setGroupExpanded(false);
              return;
            }
            setGroupExpanded(false);
            return;
          }
          setExpanded(prev => !prev);
          // Fetch on expand if hover didn't prefetch yet
          if (!expanded) prefetchLog();
        }}
      >
        {/* Expand chevron */}
        <div className="pt-0.5 text-muted-foreground">
          {(groupCount > 1 && !groupExpanded) || !expanded
            ? <ChevronRight className="w-4 h-4" />
            : <ChevronDown className="w-4 h-4" />}
        </div>

        {/* Timestamp */}
        <div className="w-20 flex-shrink-0 text-xs text-muted-foreground font-mono pt-0.5">
          {formatTimeOnly(timestamp)}
        </div>

        {/* Event type + inline fields */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 text-xs">
            <EventTypeLabel type={type} color={color} icon={icon} />
            {groupCount > 1 && (
              <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-muted text-[10px] font-mono text-muted-foreground border border-border"
                title={`${groupCount} similar events collapsed`}>
                <Layers className="w-2.5 h-2.5" />
                &times; {groupCount.toLocaleString()}
              </span>
            )}
            <span className="text-muted-foreground/60">|</span>
            <div className="flex items-center gap-2 min-w-0 overflow-hidden">
              {inlineFields.map(([field, value], i) => {
                const strVal = String(value);
                return (
                  <DropdownMenu key={field}>
                    <DropdownMenuTrigger asChild>
                      <span
                        className="inline-flex items-center gap-0.5 min-w-0 shrink cursor-pointer"
                        onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); e.currentTarget.click(); }}
                        onClick={(e) => e.stopPropagation()}
                      >
                        {i > 0 && <span className="text-muted-foreground/40 mr-1 shrink-0">·</span>}
                        <span className={`${fieldNameColor(field)} shrink-0`}>{field}=</span>
                        <span className="text-foreground font-mono max-w-[120px] sm:max-w-[200px] lg:max-w-[500px] truncate hover:text-primary">{value}</span>
                      </span>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="start" className="min-w-[180px]" onClick={(e) => e.stopPropagation()}>
                      <DropdownMenuItem onClick={() => navigator.clipboard.writeText(strVal)}>
                        <Copy className="w-3.5 h-3.5 mr-2" /> Copy value
                      </DropdownMenuItem>
                      {onAddToQuery && (
                        <>
                          <DropdownMenuItem onClick={() => onAddToQuery(field, strVal, false)}>
                            <Plus className="w-3.5 h-3.5 mr-2" /> Add to search
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => onAddToQuery(field, strVal, true)}>
                            <Minus className="w-3.5 h-3.5 mr-2" /> Exclude from search
                          </DropdownMenuItem>
                        </>
                      )}
                      <DropdownMenuSeparator />
                      <DropdownMenuItem onClick={() => onDrilldown?.({ [field]: value })}>
                        <ArrowRight className="w-3.5 h-3.5 mr-2" /> Search raw
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                );
              })}
            </div>
            {prevColor && (
              <span className={`${prevColor} inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded border shrink-0`}
                title={`Rare artifact — seen on ${prevMin} host${prevMin !== 1 ? 's' : ''}`}>
                <Server className="w-2.5 h-2.5" />
                {prevMin}
              </span>
            )}
          </div>
        </div>
      </button>

      {/* Expanded details */}
      {expanded && (
        <div className="ml-12 pl-4 border-l border-border mb-2">
          <div className="bg-muted/30 rounded-lg p-3 space-y-1">
            {isLoadingFullLog && (
              <div className="flex items-center gap-2 text-xs text-muted-foreground py-1">
                <Loader2 className="w-3 h-3 animate-spin" />
                Loading full event details...
              </div>
            )}
            {detailFields.map(([key, value]) => {
              const stringValue = typeof value === 'object' ? JSON.stringify(value) : String(value);
              const tableColumns = resolveTableColumns(type, schemaFieldNames);
              const truncateAt = 200;
              const isLong = stringValue.length > truncateAt;
              const isValueExpanded = expandedValueKeys.has(key);
              const displayValue = (!isLong || isValueExpanded) ? stringValue : stringValue.substring(0, truncateAt);
              return (
                <div key={key} className="flex gap-2 text-xs">
                  <span className="text-muted-foreground font-medium min-w-[120px]" title={isKnownField(key) ? "Indexed column" : undefined}>{key}:</span>
                  <div className="min-w-0 flex-1">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <span
                          className="text-foreground font-mono break-all cursor-pointer hover:text-primary"
                          onContextMenu={(e) => {
                            e.preventDefault();
                            // Trigger the dropdown via a synthetic pointer event on the element
                            e.currentTarget.click();
                          }}
                        >
                          {displayValue}
                        </span>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="start" className="min-w-[180px]" onClick={(e) => e.stopPropagation()}>
                        <DropdownMenuItem onClick={() => navigator.clipboard.writeText(stringValue)}>
                          <Copy className="w-3.5 h-3.5 mr-2" /> Copy value
                        </DropdownMenuItem>
                        {onAddToQuery && (
                          <>
                            <DropdownMenuItem onClick={() => onAddToQuery(key, stringValue, false)}>
                              <Plus className="w-3.5 h-3.5 mr-2" /> Add to search
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => onAddToQuery(key, stringValue, true)}>
                              <Minus className="w-3.5 h-3.5 mr-2" /> Exclude from search
                            </DropdownMenuItem>
                          </>
                        )}
                        <DropdownMenuSeparator />
                        <DropdownMenuItem onClick={() => onDrilldown?.({ [key]: value })}>
                          <ArrowRight className="w-3.5 h-3.5 mr-2" /> Search raw
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => onDrilldown?.({ [key]: value, _tableCommand: `| table ${tableColumns}` })}>
                          <Table className="w-3.5 h-3.5 mr-2" /> Search as table
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                    {isLong && !isValueExpanded && (
                      <button
                        className="text-primary hover:underline ml-1 inline"
                        onClick={(e) => {
                          e.stopPropagation();
                          e.preventDefault();
                          setExpandedValueKeys(prev => {
                            const next = new Set(prev);
                            next.add(key);
                            return next;
                          });
                        }}
                      >
                        [+{stringValue.length - truncateAt} chars]
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
            {detailFields.length === 0 && !isLoadingFullLog && (
              <div className="text-xs text-muted-foreground">No additional details</div>
            )}
          </div>
        </div>
      )}

      {/* Expanded group: show individual events inline */}
      {groupExpanded && groupCount > 1 && groupedEvents && (
        <div className="ml-8 border-l-2 border-muted">
          <div className="px-3 py-1.5 text-[10px] text-muted-foreground flex items-center justify-between">
            <span>{groupCount.toLocaleString()} similar events</span>
            <button
              onClick={(e) => { e.stopPropagation(); setGroupExpanded(false); }}
              className="text-muted-foreground hover:text-foreground text-[10px] underline"
            >
              Collapse
            </button>
          </div>
          <div className="divide-y divide-border/30">
            {groupedEvents.slice(0, 10).map((ge, i) => (
              <TimelineEvent
                key={ge.id || `group-${i}`}
                event={ge}
                onDrilldown={onDrilldown}
                onAddToQuery={onAddToQuery}
                onFetchLog={onFetchLog}
              />
            ))}
            {groupedEvents.length > 10 && (
              <div className="px-3 py-1.5 text-[10px] text-muted-foreground">
                +{(groupedEvents.length - 10).toLocaleString()} more events not shown
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

const EVENTS_PER_PAGE = 200;
const HIGH_SEVERITY = new Set(['high', 'critical']);
const DEDUP_WINDOW_MS = 60_000; // 60 seconds
const NOISY_EVENT_TYPES = new Set(['DHCP', 'DNS', 'IMAGE_LOAD', 'REGISTRY', 'PIPE']);

interface EventGroup {
  event: SearchResult;
  count: number;
  groupedEvents: SearchResult[];
}

export function AssetView({ results, onDrilldown, onAddToQuery, prevalenceFilter, timeRange, onFetchLog }: AssetViewProps) {
  // Schema-aware entity resolution + identity field set (OCSF dotted columns).
  // `fallback` MUST be a stable reference (ASSET_ENTITY_FALLBACK) — see its
  // definition for the infinite-loop this prevents (NAN-1450).
  const { resolveEntityType, schemaFields } = useSchemaEntityMap({
    fallback: ASSET_ENTITY_FALLBACK,
  });

  // Highlight state for prevalence click → scroll-to-event
  const [highlightedEventId, setHighlightedEventId] = React.useState<string | null>(null);
  const highlightTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastAppliedFilterRef = React.useRef(prevalenceFilter);

  // Server-side pagination state
  const [events, setEvents] = React.useState<SearchResult[]>([]);
  const [pagination, setPagination] = React.useState<AssetPagination | null>(null);
  const [isLoadingMore, setIsLoadingMore] = React.useState(false);
  const [serverFilters, setServerFilters] = React.useState<AssetEventFilters>({});
  const [searchText, setSearchText] = React.useState('');
  const [focusMode, setFocusMode] = React.useState(true);
  const [groupSimilar, setGroupSimilar] = React.useState(true);
  const [interestingOnly, setInterestingOnly] = React.useState(false);

  // Store initial facets so filter buttons don't disappear when filtering
  const [initialFacets, setInitialFacets] = React.useState<{
    source_type: [string, number][];
    event_type: [string, number][];
    user: [string, number][];
  } | null>(null);

  // Asset context for pagination requests
  const [assetContext, setAssetContext] = React.useState<{
    identifier_field: string;
    identifier_value: string;
    identities: Record<string, unknown>[];
  } | null>(null);

  // Lazy-loaded true time range (first/last seen)
  const [trueTimeRange, setTrueTimeRange] = React.useState<AssetTrueTimeRangeResponse | null>(null);
  const [isLoadingTimeRange, setIsLoadingTimeRange] = React.useState(false);

  // Entity context (risk, alerts, cases)
  const [entityContext, setEntityContext] = React.useState<EntityContextResponse | null>(null);

  // User profile from identity registry (for user-type assets)
  const [userProfile, setUserProfile] = React.useState<IdentityUser | null>(null);
  const [isLoadingUserProfile, setIsLoadingUserProfile] = React.useState(false);

  // Infinite scroll sentinel
  const sentinelRef = React.useRef<HTMLDivElement>(null);

  // Extract asset profile and pagination from the first result
  const assetProfile = React.useMemo<AssetProfile | null>(() => {
    if (!results.length) return null;
    const fields = results[0]?.fields;
    if (fields?._display_type === 'asset' && fields?._asset_profile) {
      return fields._asset_profile as AssetProfile;
    }
    return null;
  }, [results]);

  // Fetch entity context (risk, alerts, cases) when asset profile is available
  React.useEffect(() => {
    if (!assetProfile?.primary_identifier) return;
    const field = assetProfile.primary_identifier.field;
    const value = assetProfile.primary_identifier.value;

    // Map the primary-identifier field to an entity type via the active schema
    // (handles OCSF dotted columns); falls back to the UDM map / the raw field.
    const entityType = resolveEntityType(field) || field;

    // Collect resolved identity values for broader matching
    const identityValues: string[] = [];
    for (const id of assetProfile.identities || []) {
      if (id.ip && !identityValues.includes(id.ip)) identityValues.push(id.ip);
      if (id.hostname && !identityValues.includes(id.hostname)) identityValues.push(id.hostname);
      if (id.user && !identityValues.includes(id.user)) identityValues.push(id.user);
    }

    api.getEntityContext(entityType, value, identityValues.length > 0 ? identityValues : undefined)
      .then(setEntityContext)
      .catch(() => { /* Entity context is supplementary — fail silently */ });
  }, [assetProfile, resolveEntityType]);

  // Fetch user profile from identity registry when primary identifier is a user field
  React.useEffect(() => {
    if (!assetProfile?.primary_identifier) return;
    if (assetProfile.primary_identifier.field !== 'user') {
      setUserProfile(null);
      return;
    }

    setIsLoadingUserProfile(true);
    api.lookupIdentityUser(assetProfile.primary_identifier.value)
      .then(setUserProfile)
      .catch(() => setUserProfile(null))
      .finally(() => setIsLoadingUserProfile(false));
  }, [assetProfile]);

  // Lazy-load true time range (first/last seen) once asset context is available
  React.useEffect(() => {
    if (!assetContext) return;

    setIsLoadingTimeRange(true);
    api.getAssetTrueTimeRange({
      identifier_field: assetContext.identifier_field,
      identifier_value: assetContext.identifier_value,
      identities: assetContext.identities,
    })
      .then(setTrueTimeRange)
      .catch(() => { /* Time range is cosmetic — fail silently */ })
      .finally(() => setIsLoadingTimeRange(false));
  }, [assetContext]);

  // Initialize events and pagination from initial results
  React.useEffect(() => {
    if (!results.length) return;
    const fields = results[0]?.fields;

    if (fields?._display_type === 'asset') {
      // Extract pagination metadata and save initial facets
      if (fields._asset_pagination) {
        const pag = fields._asset_pagination as AssetPagination;
        setPagination(pag);
        // Save initial facets so filter buttons persist when filtering
        // Also set default filter to exclude DHCP (noise events)
        if (pag.facets && !initialFacets) {
          const eventTypes = pag.facets.event_type || [];
          setInitialFacets({
            source_type: pag.facets.source_type || [],
            event_type: eventTypes,
            user: pag.facets.user || [],
          });
          // Default focus mode: exclude noisy event types
          const quietTypes = eventTypes
            .map(([type]) => type)
            .filter(type => !NOISY_EVENT_TYPES.has(type));
          if (quietTypes.length < eventTypes.length && quietTypes.length > 0) {
            setServerFilters(prev => prev.event_types ? prev : { ...prev, event_types: quietTypes });
          }
        }
      }

      // Extract events from _asset_events
      if (fields._asset_events) {
        const rawEvents = fields._asset_events as AssetEvent[];
        const converted = rawEvents.map((e, i) => ({
          id: e.id || `event-${i}`,
          timestamp: parseAsUTC(e.timestamp),
          source: e.source_type,
          fields: { ...e.details, timestamp: e.timestamp, source_type: e.source_type, event_type: e.event_type }
        }));
        setEvents(converted);
      }

      // Extract asset context for pagination
      if (fields._asset_profile) {
        const profile = fields._asset_profile as AssetProfile;
        if (profile.primary_identifier) {
          setAssetContext({
            identifier_field: profile.primary_identifier.field,
            identifier_value: profile.primary_identifier.value,
            identities: profile.identities as Record<string, unknown>[],
          });
        }
      }
    }
  }, [results]);

  // Source identity field names stripped from drilldown filters before the
  // resolved-identity OR clause is re-added. Seeded from the UDM set, then
  // unioned with the active schema's ip/host/user fields so OCSF dotted identity
  // columns (src_endpoint.ip, actor.user.name, …) are stripped too (NAN-1241).
  const sourceIdentityFields = React.useMemo(() => {
    const set = new Set(['src_ip', 'src_host', 'user', 'src_mac']);
    // Under UDM the legacy 4-field set IS the existing behavior; the backend's
    // entity-typed field universe is a superset (dest_ip/dest_host/dest_user/…)
    // whose inclusion would change which drilldown filters get stripped. Only
    // union the schema's identity fields under non-UDM schemas so UDM drilldown
    // output stays byte-identical (NAN-1241).
    if (schemaFields && schemaFields.schema !== 'udm') {
      for (const f of schemaFields.fields) {
        if (f.entity_type === 'ip' || f.entity_type === 'host' || f.entity_type === 'user') {
          set.add(f.name);
        }
      }
    }
    return set;
  }, [schemaFields]);

  // Identity-aware drilldown handler
  const handleAssetDrilldown = React.useCallback((filters: Record<string, unknown>) => {
    if (!onDrilldown) return;


    if (!assetProfile?.identities?.length) {
      onDrilldown(filters);
      return;
    }

    const identityClauses: string[] = [];
    const identities = assetProfile.identities;

    const uniqueIps = new Set<string>();
    const uniqueHostnames = new Set<string>();

    for (const identity of identities) {
      if (identity.ip?.trim()) uniqueIps.add(identity.ip.trim());
      if (identity.hostname?.trim()) uniqueHostnames.add(identity.hostname.trim());
    }

    for (const ip of uniqueIps) {
      identityClauses.push(`src_ip="${nplQuotedBody(ip)}"`);
    }
    for (const hostname of uniqueHostnames) {
      identityClauses.push(`src_host="${nplQuotedBody(hostname)}"`);
    }

    const modifiedFilters: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(filters)) {
      if (!sourceIdentityFields.has(key)) {
        modifiedFilters[key] = value;
      }
    }

    if (identityClauses.length > 0) {
      modifiedFilters._identityClause = `(${identityClauses.join(' OR ')})`;
    }

    onDrilldown(modifiedFilters);
  }, [onDrilldown, assetProfile, sourceIdentityFields]);

  // Load more events (infinite scroll)
  const loadMore = React.useCallback(async () => {
    if (!assetContext || !pagination || !pagination.has_more || isLoadingMore || !timeRange) return;

    setIsLoadingMore(true);
    try {
      const request: AssetEventsRequest = {
        identifier_field: assetContext.identifier_field,
        identifier_value: assetContext.identifier_value,
        identities: assetContext.identities,
        time_range: timeRange,
        offset: events.length,
        limit: EVENTS_PER_PAGE,
      };

      const response = await api.getAssetEvents(request);

      // Convert events and append (compute event_type so filters match facets)
      const newEvents = response.events.map((e: Record<string, unknown>, i: number) => {
        const details = (e.details as Record<string, unknown>) || e;
        const fields = { ...details, timestamp: e.timestamp || details.timestamp, source_type: e.source_type || details.source_type };
        // Compute event_type using the same classifier as initial load so TYPE filter stays consistent
        const { type: eventType } = getEventType(fields);
        return {
          id: (e.id as string) || `event-${events.length + i}`,
          timestamp: parseAsUTC((e.timestamp as string) || (details.timestamp as string) || ''),
          source: (e.source_type as string) || (details.source_type as string) || 'unknown',
          fields: { ...fields, event_type: eventType },
        };
      });

      setEvents(prev => [...prev, ...newEvents]);
      setPagination({
        ...response,
        offset: response.offset,
        has_more: response.has_more,
      });
    } catch (err) {
      console.error('Failed to load more asset events:', err);
    } finally {
      setIsLoadingMore(false);
    }
  }, [assetContext, events.length, isLoadingMore, pagination, timeRange]);

  // Infinite scroll observer
  React.useEffect(() => {
    const sentinel = sentinelRef.current;
    if (!sentinel) return;

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting && pagination?.has_more && !isLoadingMore) {
          loadMore();
        }
      },
      { rootMargin: '200px' }
    );

    observer.observe(sentinel);
    return () => observer.disconnect();
  }, [loadMore, isLoadingMore, pagination?.has_more]);

  // Get facet counts - use initialFacets for filter options (so buttons don't disappear)
  // but show current counts from pagination when available
  const sourceCounts = React.useMemo<[string, number][]>(() => {
    // Use initial facets for the list of options
    if (initialFacets?.source_type?.length) {
      // If we have current facet data, update counts but keep all original options
      const currentCounts = new Map(pagination?.facets?.source_type || []);
      return initialFacets.source_type.map(([source, initialCount]) =>
        [source, currentCounts.get(source) ?? initialCount]
      );
    }
    if (pagination?.facets?.source_type?.length) {
      return pagination.facets.source_type;
    }
    // Fallback: compute from loaded events
    const counts = new Map<string, number>();
    for (const event of events) {
      const source = (event.fields?.source_type as string) || 'unknown';
      counts.set(source, (counts.get(source) || 0) + 1);
    }
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  }, [initialFacets?.source_type, pagination?.facets?.source_type, events]);

  const eventTypeCounts = React.useMemo<[string, { count: number; color: string }][]>(() => {
    // Use initial facets for the list of options
    if (initialFacets?.event_type?.length) {
      const currentCounts = new Map(pagination?.facets?.event_type || []);
      return initialFacets.event_type.map(([type, initialCount]) => {
        const { color } = getEventType({ event_type: type });
        return [type, { count: currentCounts.get(type) ?? initialCount, color }];
      });
    }
    if (pagination?.facets?.event_type?.length) {
      return pagination.facets.event_type.map(([type, count]) => {
        const { color } = getEventType({ event_type: type });
        return [type, { count, color }];
      });
    }
    // Fallback: compute from loaded events
    const counts = new Map<string, { count: number; color: string }>();
    for (const event of events) {
      const { type, color } = getEventType(event.fields || {});
      const existing = counts.get(type);
      if (existing) {
        existing.count++;
      } else {
        counts.set(type, { count: 1, color });
      }
    }
    return Array.from(counts.entries()).sort((a, b) => b[1].count - a[1].count);
  }, [initialFacets?.event_type, pagination?.facets?.event_type, events]);

  const userCounts = React.useMemo<[string, number][]>(() => {
    // Use initial facets for the list of options
    if (initialFacets?.user?.length) {
      const currentCounts = new Map(pagination?.facets?.user || []);
      return initialFacets.user.map(([user, initialCount]) =>
        [user, currentCounts.get(user) ?? initialCount]
      );
    }
    if (pagination?.facets?.user?.length) {
      return pagination.facets.user;
    }
    // Fallback: compute from loaded events
    const counts = new Map<string, number>();
    for (const event of events) {
      const user = event.fields?.user as string | undefined;
      if (user && user.trim()) {
        counts.set(user, (counts.get(user) || 0) + 1);
      }
    }
    return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  }, [initialFacets?.user, pagination?.facets?.user, events]);

  // Filter toggle handlers - "exclude on click" logic
  // Default: all lit up (showing all). Click = exclude (dim out). Click again = re-include (light up).
  // Filter array contains items to SHOW. Empty/undefined = show all.
  const toggleSourceFilter = (source: string) => {
    setServerFilters(prev => {
      // Use .length check — empty arrays are truthy and would defeat || fallback
      const allSources = (initialFacets?.source_type?.length ? initialFacets.source_type : sourceCounts).map(([s]) => s);
      const current = prev.source_types;

      let newSources: string[];
      if (!current || current.length === 0) {
        // No filter = showing all. Click = exclude this one (show all except clicked)
        newSources = allSources.filter(s => s !== source);
      } else if (current.includes(source)) {
        // Currently included, click = exclude it
        newSources = current.filter(s => s !== source);
      } else {
        // Currently excluded, click = include it back
        newSources = [...current, source];
      }

      // If all items are now included, clear the filter (show all)
      if (newSources.length >= allSources.length) {
        newSources = [];
      }

      return { ...prev, source_types: newSources.length > 0 ? newSources : undefined };
    });
  };

  const toggleUserFilter = (user: string) => {
    setServerFilters(prev => {
      const allUsers = (initialFacets?.user?.length ? initialFacets.user : userCounts).map(([u]) => u);
      const current = prev.users;

      let newUsers: string[];
      if (!current || current.length === 0) {
        newUsers = allUsers.filter(u => u !== user);
      } else if (current.includes(user)) {
        newUsers = current.filter(u => u !== user);
      } else {
        newUsers = [...current, user];
      }

      if (newUsers.length >= allUsers.length) {
        newUsers = [];
      }

      return { ...prev, users: newUsers.length > 0 ? newUsers : undefined };
    });
  };

  const toggleEventTypeFilter = (eventType: string) => {
    setServerFilters(prev => {
      const allTypes = (initialFacets?.event_type?.length ? initialFacets.event_type : eventTypeCounts).map(([t]) => t);
      const current = prev.event_types;

      let newTypes: string[];
      if (!current || current.length === 0) {
        newTypes = allTypes.filter(t => t !== eventType);
      } else if (current.includes(eventType)) {
        newTypes = current.filter(t => t !== eventType);
      } else {
        newTypes = [...current, eventType];
      }

      if (newTypes.length >= allTypes.length) {
        newTypes = [];
      }

      return { ...prev, event_types: newTypes.length > 0 ? newTypes : undefined };
    });
  };

  // Focus mode toggle: exclude noisy event types or show all
  const toggleFocusMode = () => {
    setFocusMode(prev => {
      const next = !prev;
      if (next) {
        // Re-apply noisy type exclusions
        const allTypes = (initialFacets?.event_type?.length ? initialFacets.event_type : eventTypeCounts).map(([t]) => t);
        const quietTypes = allTypes.filter(t => !NOISY_EVENT_TYPES.has(t));
        if (quietTypes.length < allTypes.length && quietTypes.length > 0) {
          setServerFilters(f => ({ ...f, event_types: quietTypes }));
        }
      } else {
        // Show all — clear event_types filter
        setServerFilters(f => ({ ...f, event_types: undefined }));
      }
      return next;
    });
  };

  // Client-side filtering: filter loaded events by active filters + search text
  const filteredEvents = React.useMemo(() => {
    let filtered = events;

    // Filter by source_type
    if (serverFilters.source_types && serverFilters.source_types.length > 0) {
      const allowed = new Set(serverFilters.source_types.map(s => s.toLowerCase()));
      filtered = filtered.filter(e => {
        const source = String(e.fields?.source_type || '').toLowerCase();
        return allowed.has(source);
      });
    }

    // Filter by event_type (using getEventType for consistency with display)
    if (serverFilters.event_types && serverFilters.event_types.length > 0) {
      const allowed = new Set(serverFilters.event_types);
      filtered = filtered.filter(e => {
        const { type } = getEventType(e.fields || {});
        return allowed.has(type);
      });
    }

    // Filter by user
    if (serverFilters.users && serverFilters.users.length > 0) {
      const allowed = new Set(serverFilters.users.map(u => u.toLowerCase()));
      filtered = filtered.filter(e => {
        const user = String(e.fields?.user || '').toLowerCase();
        return user && allowed.has(user);
      });
    }

    // Filter by search text (match against key analyst fields)
    if (searchText.trim()) {
      const needle = searchText.trim().toLowerCase();
      filtered = filtered.filter(e => {
        const f = e.fields || {};
        return (
          String(f.message || '').toLowerCase().includes(needle) ||
          String(f.action || '').toLowerCase().includes(needle) ||
          String(f.user || '').toLowerCase().includes(needle) ||
          String(f.process_name || '').toLowerCase().includes(needle) ||
          String(f.src_ip || '').toLowerCase().includes(needle) ||
          String(f.dest_ip || '').toLowerCase().includes(needle) ||
          String(f.src_host || '').toLowerCase().includes(needle) ||
          String(f.dest_host || '').toLowerCase().includes(needle)
        );
      });
    }

    // "Interesting only" mode: keep medium+ severity, alerts, auth failures
    if (interestingOnly) {
      const INTERESTING_TYPES = new Set(['ALERT', 'AUTH_FAILURE']);
      const INTERESTING_SEVERITIES = new Set(['medium', 'high', 'critical']);
      filtered = filtered.filter(e => {
        const f = e.fields || {};
        const { type } = getEventType(f);
        if (INTERESTING_TYPES.has(type)) return true;
        const sev = String(f.severity || '').toLowerCase();
        return INTERESTING_SEVERITIES.has(sev);
      });
    }

    return filtered;
  }, [events, serverFilters.source_types, serverFilters.event_types, serverFilters.users, searchText, interestingOnly]);

  // Dedup: collapse consecutive similar events into groups
  const groupedEvents = React.useMemo<EventGroup[]>(() => {
    if (!groupSimilar || filteredEvents.length === 0) {
      return filteredEvents.map(e => ({ event: e, count: 1, groupedEvents: [e] }));
    }

    const groups: EventGroup[] = [];

    const dedupKey = (e: SearchResult) => {
      const f = e.fields || {};
      const { type } = getEventType(f);
      const action = String(f.action || '');
      const processName = String(f.process_name || '');
      return `${type}|${action}|${processName}`;
    };

    const isHighSeverity = (e: SearchResult) => {
      const sev = String(e.fields?.severity || '').toLowerCase();
      const { type } = getEventType(e.fields || {});
      return HIGH_SEVERITY.has(sev) || type === 'ALERT';
    };

    for (const event of filteredEvents) {
      // High/critical severity events are never collapsed
      if (isHighSeverity(event)) {
        groups.push({ event, count: 1, groupedEvents: [event] });
        continue;
      }

      const key = dedupKey(event);
      const lastGroup = groups[groups.length - 1];

      if (
        lastGroup &&
        lastGroup.count > 0 &&
        !isHighSeverity(lastGroup.event) &&
        dedupKey(lastGroup.event) === key &&
        Math.abs(event.timestamp.getTime() - lastGroup.event.timestamp.getTime()) <= DEDUP_WINDOW_MS
      ) {
        lastGroup.count++;
        lastGroup.groupedEvents.push(event);
      } else {
        groups.push({ event, count: 1, groupedEvents: [event] });
      }
    }

    return groups;
  }, [filteredEvents, groupSimilar]);

  // Group visible events by date (using deduped groups)
  const eventsByDate = React.useMemo(() => {
    const dateGroups: Map<string, EventGroup[]> = new Map();

    for (const group of groupedEvents) {
      const timestamp = group.event.fields?.timestamp as string || group.event.timestamp?.toString() || '';
      const dateKey = formatDateHeader(timestamp);

      if (!dateGroups.has(dateKey)) {
        dateGroups.set(dateKey, []);
      }
      dateGroups.get(dateKey)!.push(group);
    }

    return dateGroups;
  }, [groupedEvents]);

  // Prevalence click → find matching event, scroll to it, highlight it.
  // Only triggers when prevalenceFilter changes (not on events changes from pagination).
  React.useEffect(() => {
    if (prevalenceFilter === lastAppliedFilterRef.current) return;
    lastAppliedFilterRef.current = prevalenceFilter;

    if (!prevalenceFilter || prevalenceFilter.artifacts.length === 0 || events.length === 0) {
      return;
    }

    const artifact = prevalenceFilter.artifacts[0].toLowerCase();
    const targetTimestamp = prevalenceFilter.timestamp;

    // Find events that match the artifact
    const matchingEvents = events.filter((event) => {
      const f = event.fields || {};
      // Hash match
      const fileHash = String(f.file_hash || '').toLowerCase();
      const processHash = String(f.process_hash || '').toLowerCase();
      if (fileHash === artifact || processHash === artifact) return true;
      // Domain match
      const destHost = String(f.dest_host || '').toLowerCase();
      const query = String(f.query || '').toLowerCase();
      const urlDomain = String(f.url_domain || '').toLowerCase();
      if (destHost === artifact || query === artifact || urlDomain === artifact) return true;
      return false;
    });

    if (matchingEvents.length === 0) return;

    // Find the event closest to the clicked timestamp
    let bestEvent = matchingEvents[0];
    if (targetTimestamp) {
      let bestDiff = Math.abs(bestEvent.timestamp.getTime() - targetTimestamp);
      for (const event of matchingEvents) {
        const diff = Math.abs(event.timestamp.getTime() - targetTimestamp);
        if (diff < bestDiff) {
          bestDiff = diff;
          bestEvent = event;
        }
      }
    }

    const eventId = bestEvent.id;
    setHighlightedEventId(eventId);

    // Scroll to the event after a tick (allow render to apply id attributes)
    requestAnimationFrame(() => {
      document.getElementById(`asset-event-${eventId}`)?.scrollIntoView({
        behavior: 'smooth',
        block: 'center',
      });
    });

    // Clear highlight after 3 seconds
    if (highlightTimerRef.current) clearTimeout(highlightTimerRef.current);
    highlightTimerRef.current = setTimeout(() => {
      setHighlightedEventId(null);
    }, 3000);

    return () => {
      if (highlightTimerRef.current) clearTimeout(highlightTimerRef.current);
    };
  }, [prevalenceFilter, events]);

  const totalCount = pagination?.total_count ?? events.length;
  const loadedCount = events.length;
  const filteredCount = filteredEvents.length;
  const hasActiveFilters = !!(serverFilters.source_types || serverFilters.event_types || serverFilters.users || searchText.trim() || interestingOnly);

  if (!results.length) {
    return (
      <div className="text-center py-16 text-muted-foreground">
        <Server className="w-12 h-12 mx-auto mb-3 opacity-50" />
        <p className="search-console-section-header justify-center"><Server />Asset Profile</p>
        <p className="mt-3 text-sm text-foreground">No asset context returned</p>
        <p className="text-xs mt-1">Try a broader identifier pivot or widen the time range.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Profile Card */}
      {assetProfile && (
        <div className="bg-card border border-border rounded-lg p-4">
          {/* User Profile Card — shown when identifier is user AND IdP data loaded */}
          {assetProfile.primary_identifier?.field === 'user' && isLoadingUserProfile ? (
            <div className="flex items-center gap-3">
              <div className="w-5 h-5 rounded bg-muted animate-pulse shrink-0" />
              <div className="flex-1 space-y-2">
                <div className="h-5 w-48 bg-muted animate-pulse rounded" />
                <div className="h-3 w-32 bg-muted animate-pulse rounded" />
              </div>
            </div>
          ) : assetProfile.primary_identifier?.field === 'user' && userProfile ? (
            <>
              {/* Header: avatar icon, name, risk badge, first/last seen */}
              <div className="flex items-start justify-between gap-3 flex-wrap">
                <div className="flex items-center gap-3 min-w-0">
                  <User className="w-5 h-5 text-primary shrink-0" />
                  <div className="min-w-0">
                    <h2 className="text-lg font-semibold text-foreground truncate">
                      {userProfile.display_name || userProfile.username || assetProfile.primary_identifier.value}
                    </h2>
                    <p className="text-xs text-muted-foreground font-mono">
                      {userProfile.username}
                      {userProfile.email && userProfile.email !== userProfile.username && (
                        <> &middot; {userProfile.email}</>
                      )}
                    </p>
                  </div>
                </div>
                <RiskBadgeAndTimestamps entityContext={entityContext} isLoadingTimeRange={isLoadingTimeRange} trueTimeRange={trueTimeRange} assetProfile={assetProfile} />
              </div>

              {/* Structured metadata row */}
              <div className="mt-3 pt-3 border-t border-border grid grid-cols-2 sm:grid-cols-4 gap-x-6 gap-y-2 text-xs">
                {userProfile.department && (
                  <div>
                    <span className="text-muted-foreground flex items-center gap-1"><Building2 className="w-3 h-3" />Department</span>
                    <span className="text-foreground font-medium block truncate">{userProfile.department}</span>
                  </div>
                )}
                {userProfile.title && (
                  <div>
                    <span className="text-muted-foreground">Title</span>
                    <span className="text-foreground font-medium block truncate">{userProfile.title}</span>
                  </div>
                )}
                {(userProfile.manager_display_name || userProfile.manager_upn) && (
                  <div>
                    <span className="text-muted-foreground">Manager</span>
                    <span
                      className="text-primary font-medium block truncate cursor-pointer hover:underline"
                      onClick={() => onDrilldown?.({ user: userProfile.manager_upn || userProfile.manager_display_name })}
                    >
                      {userProfile.manager_display_name || userProfile.manager_upn}
                    </span>
                  </div>
                )}
                <div>
                  <span className="text-muted-foreground">Account</span>
                  <span className="text-foreground font-medium block truncate">
                    {userProfile.account_status === 'active' ? (
                      <span className="text-green-500">Active</span>
                    ) : (
                      <span className="text-yellow-500 capitalize">{userProfile.account_status || 'Unknown'}</span>
                    )}
                    {userProfile.mfa_enabled && (
                      <span className="ml-1.5 inline-flex items-center gap-0.5 text-green-500" title="MFA enabled">
                        <ShieldCheck className="w-3 h-3" /> MFA
                      </span>
                    )}
                  </span>
                </div>
              </div>

              {/* Groups */}
              {userProfile.groups && userProfile.groups.length > 0 && (
                <div className="mt-2 flex flex-wrap items-center gap-1">
                  <Users className="w-3 h-3 text-muted-foreground shrink-0 mr-0.5" />
                  {userProfile.groups.slice(0, 5).map(g => (
                    <span key={g} className="px-1.5 py-0.5 rounded bg-muted text-[10px] text-muted-foreground font-medium">{g}</span>
                  ))}
                  {userProfile.groups.length > 5 && (
                    <span className="text-[10px] text-muted-foreground">+{userProfile.groups.length - 5} more</span>
                  )}
                </div>
              )}

              {/* Resolved Identities */}
              <ResolvedIdentities identities={assetProfile.identities} onDrilldown={onDrilldown} />
              {entityContext && <CasesSection entityContext={entityContext} />}
            </>
          ) : (
            <>
              {/* Host / Default Profile Card */}
              <div className="flex items-start justify-between gap-3 flex-wrap">
                <div className="flex items-center gap-3 min-w-0">
                  {assetProfile.primary_identifier?.field === 'user'
                    ? <User className="w-5 h-5 text-primary shrink-0" />
                    : <Server className="w-5 h-5 text-primary shrink-0" />
                  }
                  <div className="min-w-0">
                    <h2 className="text-lg font-semibold text-foreground truncate">
                      {assetProfile.primary_identifier?.value || 'Unknown Asset'}
                    </h2>
                    <p className="text-xs text-muted-foreground">
                      Identifier: <span className="font-mono">{assetProfile.primary_identifier?.field}</span>
                    </p>
                  </div>
                </div>
                <RiskBadgeAndTimestamps entityContext={entityContext} isLoadingTimeRange={isLoadingTimeRange} trueTimeRange={trueTimeRange} assetProfile={assetProfile} />
              </div>

              <ResolvedIdentities identities={assetProfile.identities} onDrilldown={onDrilldown} />
              {entityContext && <CasesSection entityContext={entityContext} />}
            </>
          )}
        </div>
      )}

      {/* Timeline */}
      <div className="bg-card border border-border rounded-lg">
        {/* Header with filters */}
        <div className="px-4 py-3 border-b border-border space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="search-console-section-header"><Server />Asset Stream</span>
              <span className="search-console-section-meta">
                ({hasActiveFilters
                  ? `${filteredCount.toLocaleString()} of ${loadedCount.toLocaleString()} loaded`
                  : loadedCount.toLocaleString()
                }{loadedCount !== totalCount ? ` · ${totalCount.toLocaleString()} total` : ''} events)
              </span>
              {isLoadingMore && <Loader2 className="w-3 h-3 animate-spin text-muted-foreground" />}
            </div>
            {/* Mode toggles */}
            <div className="flex items-center gap-1.5">
              <button
                onClick={toggleFocusMode}
                className={`inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-medium rounded border transition-all ${
                  focusMode
                    ? 'bg-primary/10 text-primary border-primary/40 hover:bg-primary/20'
                    : 'bg-muted/20 text-muted-foreground border-border hover:bg-muted/40'
                }`}
                title={focusMode ? 'Focus mode: noisy event types hidden. Click to show all.' : 'Showing all event types. Click to enable focus mode.'}
              >
                <Focus className="w-3 h-3" />
                Focus
              </button>
              <button
                onClick={() => setGroupSimilar(prev => !prev)}
                className={`inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-medium rounded border transition-all ${
                  groupSimilar
                    ? 'bg-primary/10 text-primary border-primary/40 hover:bg-primary/20'
                    : 'bg-muted/20 text-muted-foreground border-border hover:bg-muted/40'
                }`}
                title={groupSimilar ? 'Grouping similar events. Click to expand all.' : 'Showing all events individually. Click to group similar.'}
              >
                <Layers className="w-3 h-3" />
                Group
              </button>
              <button
                onClick={() => setInterestingOnly(prev => !prev)}
                className={`inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-medium rounded border transition-all ${
                  interestingOnly
                    ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/40 hover:bg-amber-500/20'
                    : 'bg-muted/20 text-muted-foreground border-border hover:bg-muted/40'
                }`}
                title={interestingOnly ? 'Showing interesting events only (medium+ severity, alerts, auth failures). Click to show all.' : 'Click to show only interesting events.'}
              >
                <Zap className="w-3 h-3" />
                Interesting
              </button>
            </div>
          </div>

          {/* Event type toggles */}
          {eventTypeCounts.length > 1 && (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[10px] text-muted-foreground uppercase tracking-wide mr-1">Type</span>
              {eventTypeCounts.map(([eventType, { count, color }]) => {
                const isEnabled = !serverFilters.event_types || serverFilters.event_types.includes(eventType);
                return (
                  <button
                    key={eventType}
                    onClick={() => toggleEventTypeFilter(eventType)}
                    className={`inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-medium rounded border transition-all ${
                      isEnabled
                        ? `${color} bg-current/10 border-current/40 hover:bg-current/20`
                        : 'bg-muted/20 text-muted-foreground/50 border-border/50 line-through opacity-60 hover:opacity-80'
                    }`}
                  >
                    {eventType}
                    <span className={isEnabled ? 'opacity-60' : 'opacity-40'}>({count.toLocaleString()})</span>
                  </button>
                );
              })}
            </div>
          )}

          {/* Source type toggles */}
          {sourceCounts.length > 1 && (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[10px] text-muted-foreground uppercase tracking-wide mr-1">Source</span>
              {sourceCounts.map(([source, count]) => {
                const isEnabled = !serverFilters.source_types || serverFilters.source_types.includes(source);
                return (
                  <button
                    key={source}
                    onClick={() => toggleSourceFilter(source)}
                    className={`inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-medium rounded border transition-all ${
                      isEnabled
                        ? 'bg-primary/10 text-primary border-primary/40 hover:bg-primary/20'
                        : 'bg-muted/20 text-muted-foreground/50 border-border/50 line-through opacity-60 hover:opacity-80'
                    }`}
                  >
                    {source}
                    <span className={isEnabled ? 'opacity-60' : 'opacity-40'}>({count.toLocaleString()})</span>
                  </button>
                );
              })}
            </div>
          )}

          {/* User toggles */}
          {userCounts.length > 1 && (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[10px] text-muted-foreground uppercase tracking-wide mr-1">User</span>
              {userCounts.map(([user, count]) => {
                const isEnabled = !serverFilters.users || serverFilters.users.includes(user);
                return (
                  <button
                    key={user}
                    onClick={() => toggleUserFilter(user)}
                    className={`inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-medium rounded border transition-all ${
                      isEnabled
                        ? 'bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/40 hover:bg-purple-500/20'
                        : 'bg-muted/20 text-muted-foreground/50 border-border/50 line-through opacity-60 hover:opacity-80'
                    }`}
                  >
                    <User className="w-3 h-3" />
                    {user}
                    <span className={isEnabled ? 'opacity-60' : 'opacity-40'}>({count.toLocaleString()})</span>
                  </button>
                );
              })}
            </div>
          )}

          {/* Search box */}
          <div className="flex items-center gap-3 pt-1">
            <div className="relative flex-1 max-w-xs">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
              <input
                type="text"
                placeholder="Filter loaded events..."
                value={searchText}
                onChange={(e) => setSearchText(e.target.value)}
                className="w-full h-7 pl-8 pr-7 text-xs bg-transparent border border-border rounded-md focus:outline-none focus:ring-1 focus:ring-ring placeholder:text-muted-foreground"
              />
              {searchText && (
                <button
                  onClick={() => setSearchText('')}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  <X className="w-3 h-3" />
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Events grouped by date */}
        <div className="divide-y divide-border">
          {filteredEvents.length === 0 ? (
            <div className="p-8 text-center text-muted-foreground">
              {isLoadingMore ? (
                <div className="flex items-center justify-center gap-2">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Loading events...</span>
                </div>
              ) : hasActiveFilters ? (
                <>
                  <p className="text-sm text-foreground">No asset events match the current scope</p>
                  <p className="text-xs mt-1">{loadedCount.toLocaleString()} rows are loaded. Relax one filter or clear the local scope.</p>
                </>
              ) : (
                <>
                  <p className="text-sm text-foreground">0 events returned for this asset</p>
                  <p className="text-xs mt-1">Expand the time range, pivot on a different identity, or verify the asset query.</p>
                </>
              )}
            </div>
          ) : (
            <>
              {Array.from(eventsByDate.entries()).map(([dateKey, dateGroups]) => {
                const eventCount = dateGroups.reduce((sum, g) => sum + g.count, 0);
                return (
                  <div key={dateKey}>
                    {/* Date header */}
                    <div className="px-4 py-2 bg-muted/20 text-xs font-medium text-muted-foreground sticky top-0">
                      {dateKey} <span className="text-muted-foreground/60">({eventCount.toLocaleString()} events{dateGroups.length !== eventCount ? ` · ${dateGroups.length} rows` : ''})</span>
                    </div>

                    {/* Events for this date */}
                    <div className="divide-y divide-border/50">
                      {dateGroups.map((group, i) => (
                        <div key={group.event.id || i} id={`asset-event-${group.event.id}`}>
                          <TimelineEvent
                            event={group.event}
                            onDrilldown={handleAssetDrilldown}
                            onAddToQuery={onAddToQuery}
                            onFetchLog={onFetchLog}
                            isHighlighted={highlightedEventId === group.event.id}
                            groupCount={group.count}
                            groupedEvents={group.groupedEvents}
                          />
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}

              {/* Infinite scroll sentinel */}
              <div ref={sentinelRef} className="h-1" />

              {/* Loading indicator / load more info */}
              {isLoadingMore ? (
                <div className="p-3 text-center text-xs text-muted-foreground flex items-center justify-center gap-2">
                  <Loader2 className="w-3 h-3 animate-spin" />
                  Loading more events...
                </div>
              ) : pagination?.has_more ? (
                <div className="p-3 text-center text-xs text-muted-foreground">
                  Showing {loadedCount.toLocaleString()} of {totalCount.toLocaleString()} events - scroll for more
                </div>
              ) : null}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
