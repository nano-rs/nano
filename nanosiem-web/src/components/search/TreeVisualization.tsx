// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  useState,
  useCallback,
  useMemo,
  useRef,
  useEffect,
} from 'react';
import type { MouseEvent as ReactMouseEvent } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  ChevronRight,
  Copy,
  FileSignature,
  GitBranch,
  Globe,
  Layers,
  Monitor,
  Search as SearchIcon,
  Share2,
  X,
} from 'lucide-react';
import { cn } from '@/lib/utils';

// ─────────────────────────── public types ───────────────────────────

export interface TreeNode {
  id: string;
  label: string;
  detail?: string;
  children: TreeNode[];
  prevalence?: {
    host_count: number;
    first_seen?: string;
    last_seen?: string;
    is_rare: boolean;
  };
  _data?: Record<string, unknown>;
  _ancestors?: TreeNode[];
}

export interface TreeConfig {
  parent_field: string;
  child_field: string;
  label_field: string;
  detail_field?: string;
  prevalence_field?: string;
}

interface TreeVisualizationProps {
  nodes: TreeNode[];
  config: TreeConfig;
  onFilter?: (field: string, value: string) => void;
  fieldsCollapsed?: boolean;
  fieldsCount?: number;
  onExpandFields?: () => void;
}

// ─────────────────────────── helpers ───────────────────────────

const NOTABLE_RED = 'oklch(62% 0.18 28)';
const AMBER = 'oklch(72% 0.14 80)';

type Preset = 'process' | 'web' | 'custom';

function derivePreset(config: TreeConfig): Preset {
  const child = config.child_field?.toLowerCase() ?? '';
  const parent = config.parent_field?.toLowerCase() ?? '';
  if (child.includes('process') || parent.includes('process')) return 'process';
  if (child === 'url' || parent.includes('referrer')) return 'web';
  return 'custom';
}

const LOLBIN_NAMES = new Set([
  'rundll32.exe',
  'regsvr32.exe',
  'mshta.exe',
  'cmd.exe',
  'powershell.exe',
  'powershell_ise.exe',
  'pwsh.exe',
  'wscript.exe',
  'cscript.exe',
  'certutil.exe',
  'bitsadmin.exe',
  'installutil.exe',
  'msbuild.exe',
  'regasm.exe',
  'regsvcs.exe',
  'mshtml.exe',
  'forfiles.exe',
]);

const USER_WRITABLE_PATTERNS = [
  /\\appdata\\roaming\\/i,
  /\\appdata\\local\\temp\\/i,
  /\\users\\[^\\]+\\downloads\\/i,
  /\\programdata\\/i,
  /\\temp\\/i,
];

const ENC_CMDLINE_RE = /-e(?:nc|ncoded)?(?:command)?\s+[A-Za-z0-9+/=]{16,}/i;

function firstString(row: Record<string, unknown> | undefined, keys: string[]): string | undefined {
  if (!row) return undefined;
  for (const k of keys) {
    const v = row[k];
    if (v == null) continue;
    if (typeof v === 'string' && v.length > 0) return v;
    if (typeof v === 'number') return String(v);
  }
  return undefined;
}

function firstBool(row: Record<string, unknown> | undefined, keys: string[]): boolean | undefined {
  if (!row) return undefined;
  for (const k of keys) {
    const v = row[k];
    if (typeof v === 'boolean') return v;
    if (typeof v === 'string') {
      const lc = v.toLowerCase();
      if (lc === 'true' || lc === 'signed' || lc === 'verified' || lc === 'valid') return true;
      if (lc === 'false' || lc === 'unsigned' || lc === 'invalid') return false;
    }
  }
  return undefined;
}

function formatUtcTime(raw: unknown): string | undefined {
  if (raw == null) return undefined;
  const d = raw instanceof Date ? raw : new Date(String(raw));
  if (Number.isNaN(d.getTime())) return undefined;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

function formatUtcDate(raw: unknown): string | undefined {
  if (raw == null) return undefined;
  const d = raw instanceof Date ? raw : new Date(String(raw));
  if (Number.isNaN(d.getTime())) return undefined;
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  return `${months[d.getUTCMonth()]} ${d.getUTCDate()}, ${d.getUTCFullYear()}`;
}

function shortHash(raw?: string): string | undefined {
  if (!raw) return undefined;
  const s = raw.trim();
  if (s.length <= 10) return s;
  return `${s.slice(0, 4)}…${s.slice(-4)}`;
}

interface DisplayNode {
  name: string;
  pid?: string;
  user?: string;
  cmd?: string;
  hashRaw?: string;
  hashDisplay?: string;
  prevHostCount?: number;
  isRare: boolean;
  signed?: boolean;
  signer?: string;
  ts?: string;
  tsDate?: string;
  flags: string[];
  decoded?: string;
}

function derive(node: TreeNode, preset: Preset): DisplayNode {
  const r = node._data;
  const name = typeof node.label === 'string' ? node.label : JSON.stringify(node.label ?? node.id);

  const pid = preset === 'process'
    ? firstString(r, ['pid', 'process_id', 'ProcessId'])
    : undefined;

  const user = firstString(r, ['user', 'user_name', 'username', 'target_user', 'process_user']);

  const cmd = node.detail
    ?? firstString(r, ['command_line', 'CommandLine', 'cmdline', 'url', 'http_url']);

  const hashRaw = firstString(r, [
    'process_hash',
    'file_hash',
    'image_hash',
    'sha256',
    'SHA256',
    'md5',
    'MD5',
    'sha1',
  ]);

  const prevHostCount = node.prevalence?.host_count;
  const isRare = !!(node.prevalence?.is_rare);

  const signed = firstBool(r, [
    'process_signed',
    'file_signed',
    'image_signed',
    'signature_verified',
    'signed',
  ]);
  const signer = firstString(r, [
    'process_signer',
    'file_signer',
    'image_signer',
    'signature_subject',
    'signer',
  ]);

  const ts = formatUtcTime(r?.timestamp ?? r?.event_time ?? r?.utc_time);
  const tsDate = formatUtcDate(r?.timestamp ?? r?.event_time ?? r?.utc_time);

  const flags: string[] = [];
  const nameLc = name.toLowerCase();
  const cmdLc = (cmd ?? '').toLowerCase();

  if (preset === 'process' && cmd && ENC_CMDLINE_RE.test(cmd)) flags.push('encoded-cmdline');
  if (preset === 'process' && LOLBIN_NAMES.has(nameLc)) flags.push('lolbin');
  if (signed === false) flags.push('unsigned');
  if (isRare) flags.push('rare-hash');
  if (cmdLc && USER_WRITABLE_PATTERNS.some((re) => re.test(cmdLc))) flags.push('user-writable-path');

  const decoded = firstString(r, ['decoded_command_line', 'decoded_cmdline']);

  return {
    name,
    pid,
    user,
    cmd,
    hashRaw,
    hashDisplay: shortHash(hashRaw),
    prevHostCount,
    isRare,
    signed,
    signer,
    ts,
    tsDate,
    flags,
    decoded,
  };
}

function suspicionScore(d: DisplayNode): number {
  let s = 0;
  if (d.isRare) s += 3;
  if (d.flags.includes('encoded-cmdline')) s += 2;
  if (d.flags.includes('lolbin')) s += 1;
  if (d.flags.includes('unsigned')) s += 2;
  if (d.flags.includes('user-writable-path')) s += 1;
  return s;
}

function subtreeMaxSus(node: TreeNode, preset: Preset): number {
  let m = suspicionScore(derive(node, preset));
  for (const c of node.children ?? []) {
    m = Math.max(m, subtreeMaxSus(c, preset));
  }
  return m;
}

// Build parent map so we can walk from any id up to the root (for focus mode).
function buildParentMap(roots: TreeNode[]): Map<string, string | null> {
  const m = new Map<string, string | null>();
  const walk = (n: TreeNode, parent: string | null) => {
    m.set(n.id, parent);
    for (const c of n.children ?? []) walk(c, n.id);
  };
  roots.forEach((r) => walk(r, null));
  return m;
}

function collectIds(roots: TreeNode[]): Set<string> {
  const s = new Set<string>();
  const walk = (n: TreeNode) => {
    s.add(n.id);
    for (const c of n.children ?? []) walk(c);
  };
  roots.forEach(walk);
  return s;
}

function computeDepth(roots: TreeNode[]): number {
  let max = 0;
  const walk = (n: TreeNode, d: number) => {
    max = Math.max(max, d);
    for (const c of n.children ?? []) walk(c, d + 1);
  };
  roots.forEach((r) => walk(r, 1));
  return max;
}

function flattenAll(roots: TreeNode[]): TreeNode[] {
  const out: TreeNode[] = [];
  const walk = (n: TreeNode) => {
    out.push(n);
    for (const c of n.children ?? []) walk(c);
  };
  roots.forEach(walk);
  return out;
}

// ─────────────────────────── layout constants ───────────────────────────

const INDENT = 22;

// ─────────────────────────── row ───────────────────────────

interface RowProps {
  node: TreeNode;
  display: DisplayNode;
  depth: number;
  ancestorLines: boolean[];
  lastInGroup: boolean;
  hasChildren: boolean;
  isExpanded: boolean;
  isSelected: boolean;
  onToggle: (e: ReactMouseEvent) => void;
  onSelect: () => void;
}

function TreeRow({
  display,
  depth,
  ancestorLines,
  lastInGroup,
  hasChildren,
  isExpanded,
  isSelected,
  onToggle,
  onSelect,
}: RowProps) {
  const sus = suspicionScore(display);
  const tone: 'critical' | 'warn' | 'normal' = sus >= 5 ? 'critical' : sus >= 3 ? 'warn' : 'normal';
  const isRare = display.isRare;
  const isEncoded = display.flags.includes('encoded-cmdline');
  const isLolbin = display.flags.includes('lolbin');
  const isUnsigned = display.flags.includes('unsigned');

  return (
    <div
      className={cn(
        'relative flex items-center group cursor-pointer transition-colors',
        isSelected ? 'bg-primary/8' : 'hover:bg-foreground/3',
      )}
      style={{ minHeight: 24 }}
      onClick={onSelect}
    >
      {isSelected && (
        <span className="absolute left-0 top-0 bottom-0 w-0.5 bg-primary" aria-hidden />
      )}

      {/* Indent guides + connector + caret */}
      <div className="relative flex shrink-0" style={{ width: depth * INDENT + INDENT }}>
        {ancestorLines.map((hasMore, i) => (
          <span
            key={i}
            className="absolute top-0 bottom-0"
            style={{
              left: i * INDENT + 7,
              borderLeft: hasMore ? '1px solid var(--border)' : 'none',
            }}
            aria-hidden
          />
        ))}
        {depth > 0 && (
          <>
            <span
              className="absolute top-0"
              style={{
                left: (depth - 1) * INDENT + 7,
                width: 1,
                height: lastInGroup ? 12 : '100%',
                background: 'var(--border)',
              }}
              aria-hidden
            />
            <span
              className="absolute"
              style={{
                left: (depth - 1) * INDENT + 7,
                top: 12,
                width: 10,
                height: 1,
                background: 'var(--border)',
              }}
              aria-hidden
            />
          </>
        )}
        {hasChildren ? (
          <button
            type="button"
            onClick={onToggle}
            className="absolute top-1/2 -translate-y-1/2 w-4 h-4 flex items-center justify-center text-muted-foreground hover:text-foreground cursor-pointer"
            style={{ left: depth * INDENT - 1 }}
            aria-label={isExpanded ? 'Collapse' : 'Expand'}
          >
            <ChevronRight
              className={cn('w-[10px] h-[10px] transition-transform', isExpanded && 'rotate-90')}
            />
          </button>
        ) : (
          <span
            className="absolute top-1/2 -translate-y-1/2 w-1 h-1 rounded-full bg-muted-foreground/40"
            style={{ left: depth * INDENT + 5 }}
            aria-hidden
          />
        )}
      </div>

      {/* Content */}
      <span className="flex items-center gap-2 min-w-0 pr-3 flex-1 py-[3px] font-mono">
        <span
          className={cn(
            'text-[12px] whitespace-nowrap shrink-0',
            tone === 'critical' ? 'text-foreground font-semibold'
              : tone === 'warn' ? 'text-foreground font-medium'
                : 'text-foreground',
          )}
        >
          {display.name}
        </span>

        {display.pid && (
          <span className="text-[10.5px] text-muted-foreground/70 tabular-nums shrink-0">· {display.pid}</span>
        )}
        {display.user && (
          <span className="text-[10.5px] text-muted-foreground shrink-0">{display.user}</span>
        )}

        <span className="flex items-center gap-1 shrink-0">
          {isRare && (
            <span
              className="inline-flex items-center gap-0.5 px-1 rounded text-[9.5px] font-semibold uppercase tracking-wide"
              style={{ color: NOTABLE_RED, background: 'oklch(62% 0.18 28 / 0.12)' }}
              title={
                typeof display.prevHostCount === 'number'
                  ? `Seen on ${display.prevHostCount} host${display.prevHostCount === 1 ? '' : 's'}`
                  : 'Rare'
              }
            >
              rare
              {typeof display.prevHostCount === 'number' && (
                <>
                  <span className="opacity-50">·</span>
                  <span className="tabular-nums">{display.prevHostCount}</span>
                  <Monitor className="w-[8.5px] h-[8.5px] opacity-80" aria-hidden />
                </>
              )}
            </span>
          )}
          {isEncoded && (
            <span
              className="inline-flex items-center px-1 rounded text-[9.5px] font-semibold uppercase tracking-wide"
              style={{ color: AMBER, background: 'oklch(72% 0.14 80 / 0.12)' }}
            >
              -enc
            </span>
          )}
          {isLolbin && !isEncoded && (
            <span
              className="inline-flex items-center px-1 rounded text-[9.5px] font-semibold uppercase tracking-wide"
              style={{ color: AMBER, background: 'oklch(72% 0.14 80 / 0.10)' }}
            >
              lolbin
            </span>
          )}
          {isUnsigned && (
            <span
              className="inline-flex items-center px-1 rounded text-[9.5px] font-semibold uppercase tracking-wide"
              style={{ color: NOTABLE_RED, background: 'oklch(62% 0.18 28 / 0.10)' }}
            >
              unsigned
            </span>
          )}
          {display.signed === true && !isUnsigned && (
            <FileSignature
              className="w-[10px] h-[10px] text-muted-foreground/60"
              aria-label={display.signer ? `Signed by ${display.signer}` : 'Signed'}
            />
          )}
        </span>

        {display.cmd && (
          <span
            className={cn(
              'text-[11px] truncate',
              isEncoded ? 'text-amber-400/80' : 'text-muted-foreground',
            )}
          >
            {display.cmd}
          </span>
        )}

        {display.ts && (
          <span className="text-[10px] text-muted-foreground/70 tabular-nums shrink-0 ml-auto pl-2">
            {display.ts}
          </span>
        )}
      </span>
    </div>
  );
}

// ─────────────────────────── detail panel ───────────────────────────

interface DetailProps {
  node: TreeNode;
  display: DisplayNode;
  parentDisplay?: DisplayNode;
  depth: number;
  ancestorLines: boolean[];
  lastInGroup: boolean;
  onFocus: () => void;
  onClearFocus: () => void;
  isFocused: boolean;
  onPivot: () => void;
  hasPivot: boolean;
}

function TreeDetail({
  display,
  parentDisplay,
  depth,
  ancestorLines,
  lastInGroup,
  onFocus,
  onClearFocus,
  isFocused,
  onPivot,
  hasPivot,
}: DetailProps) {
  const [copiedHash, setCopiedHash] = useState(false);
  const [copiedShare, setCopiedShare] = useState(false);
  const [pivoted, setPivoted] = useState(false);
  const isEncoded = display.flags.includes('encoded-cmdline');

  return (
    <div className="relative flex" style={{ background: 'var(--muted)' }}>
      {/* Left indent — continue ancestor lines + vertical stub */}
      <div className="relative shrink-0" style={{ width: depth * INDENT + INDENT }}>
        {ancestorLines.map((hasMore, i) => (
          <span
            key={i}
            className="absolute top-0 bottom-0"
            style={{
              left: i * INDENT + 7,
              borderLeft: hasMore ? '1px solid var(--border)' : 'none',
            }}
            aria-hidden
          />
        ))}
        {!lastInGroup && depth > 0 && (
          <span
            className="absolute top-0 bottom-0"
            style={{ left: (depth - 1) * INDENT + 7, width: 1, background: 'var(--border)' }}
            aria-hidden
          />
        )}
      </div>

      <div className="flex-1 border-l-2 border-primary/40 bg-primary/[0.03] px-3 py-2 my-0.5 mr-3 rounded-r">
        <div className="grid grid-cols-[140px_1fr] gap-x-4 gap-y-1 text-[11px]">
          {display.pid && (
            <DetailRow k="PID · PPID">
              <span className="text-foreground tabular-nums">{display.pid}</span>
              {parentDisplay?.pid && (
                <>
                  {' '}
                  <span className="text-muted-foreground/70">·</span>{' '}
                  <span className="text-muted-foreground tabular-nums">{parentDisplay.pid}</span>
                  {parentDisplay.name && (
                    <span className="text-muted-foreground/70"> ({parentDisplay.name})</span>
                  )}
                </>
              )}
            </DetailRow>
          )}
          {display.user && (
            <DetailRow k="User">
              <span className="text-foreground">{display.user}</span>
            </DetailRow>
          )}
          {(display.ts || display.tsDate) && (
            <DetailRow k="Executed at">
              {display.ts && <span className="text-foreground tabular-nums">{display.ts}</span>}
              {display.tsDate && <span className="text-muted-foreground/70"> · {display.tsDate}</span>}
            </DetailRow>
          )}
          {display.hashDisplay && (
            <DetailRow k="Image hash">
              <span className="text-foreground font-mono">{display.hashDisplay}</span>
              {typeof display.prevHostCount === 'number' && (
                <span
                  className={cn(
                    'ml-2 inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[9.5px] font-semibold uppercase tracking-wide',
                    display.isRare
                      ? ''
                      : 'text-muted-foreground bg-foreground/5',
                  )}
                  style={
                    display.isRare
                      ? { color: NOTABLE_RED, background: 'oklch(62% 0.18 28 / 0.12)' }
                      : undefined
                  }
                >
                  prevalence <span className="tabular-nums">{display.prevHostCount}</span>{' '}
                  {display.prevHostCount === 1 ? 'host' : 'hosts'}
                </span>
              )}
            </DetailRow>
          )}
          <DetailRow k="Signature">
            {display.signed === true ? (
              <span className="inline-flex items-center gap-1.5 text-foreground">
                <FileSignature className="w-[11px] h-[11px] text-muted-foreground" />
                {display.signer ?? 'Signed'}
                {display.signer && <span className="text-muted-foreground/70">(verified)</span>}
              </span>
            ) : display.signed === false ? (
              <span className="inline-flex items-center gap-1.5" style={{ color: NOTABLE_RED }}>
                <AlertTriangle className="w-[11px] h-[11px]" />
                Unsigned
              </span>
            ) : (
              <span className="text-muted-foreground/70">—</span>
            )}
          </DetailRow>
          {display.cmd && (
            <DetailRow k="Command line">
              <div
                className={cn(
                  'font-mono text-[11px] rounded border px-2 py-1.5 break-all w-full',
                  isEncoded
                    ? 'text-foreground'
                    : 'bg-card border-border text-foreground/90',
                )}
                style={
                  isEncoded
                    ? {
                      background: 'oklch(72% 0.14 80 / 0.06)',
                      borderColor: 'oklch(72% 0.14 80 / 0.3)',
                    }
                    : undefined
                }
              >
                {display.cmd}
              </div>
              {display.decoded && (
                <div className="mt-1.5 flex gap-2 items-start w-full">
                  <span className="text-[9.5px] font-semibold uppercase tracking-wide px-1 rounded bg-primary/12 text-primary mt-0.5">
                    decoded
                  </span>
                  <span className="font-mono text-[11px] text-foreground break-all">
                    {display.decoded}
                  </span>
                </div>
              )}
            </DetailRow>
          )}
          {display.flags.length > 0 && (
            <DetailRow k="Flags">
              <div className="flex flex-wrap gap-1">
                {display.flags.map((f) => {
                  const isCrit = ['rare-hash', 'unsigned', 'encoded-cmdline'].includes(f);
                  return (
                    <span
                      key={f}
                      className="px-1.5 py-0.5 rounded text-[9.5px] font-semibold uppercase tracking-wide"
                      style={
                        isCrit
                          ? { color: NOTABLE_RED, background: 'oklch(62% 0.18 28 / 0.12)' }
                          : { color: AMBER, background: 'oklch(72% 0.14 80 / 0.10)' }
                      }
                    >
                      {f.replace(/-/g, ' ')}
                    </span>
                  );
                })}
              </div>
            </DetailRow>
          )}
        </div>

        {/* Action row */}
        <div className="flex items-center gap-1 mt-2 pt-2 border-t border-border/60">
          <ActionButton
            icon={<Layers className="w-[10px] h-[10px]" />}
            label={isFocused ? 'Exit focus mode' : 'Focus ancestry'}
            highlight
            onClick={(e) => {
              e.stopPropagation();
              if (isFocused) onClearFocus();
              else onFocus();
            }}
          />
          {hasPivot && (
            <ActionButton
              icon={<SearchIcon className="w-[10px] h-[10px]" />}
              label={pivoted ? 'Filter added →' : 'Pivot to events'}
              onClick={(e) => {
                e.stopPropagation();
                onPivot();
                setPivoted(true);
                window.setTimeout(() => setPivoted(false), 1400);
              }}
            />
          )}
          {display.hashRaw && (
            <ActionButton
              icon={<Copy className="w-[10px] h-[10px]" />}
              label={copiedHash ? 'Hash copied' : 'Copy hash'}
              onClick={(e) => {
                e.stopPropagation();
                navigator.clipboard?.writeText(display.hashRaw ?? '');
                setCopiedHash(true);
                window.setTimeout(() => setCopiedHash(false), 1200);
              }}
            />
          )}
          <ActionButton
            icon={<Share2 className="w-[10px] h-[10px]" />}
            label={copiedShare ? 'Link copied' : 'Share node'}
            onClick={(e) => {
              e.stopPropagation();
              navigator.clipboard?.writeText(window.location.href);
              setCopiedShare(true);
              window.setTimeout(() => setCopiedShare(false), 1200);
            }}
          />
        </div>
      </div>
    </div>
  );
}

function DetailRow({ k, children }: { k: string; children: React.ReactNode }) {
  return (
    <>
      <span className="text-muted-foreground font-mono text-[10px] uppercase tracking-[0.12em] pt-[3px]">
        {k}
      </span>
      <span className="font-mono text-[11px] text-foreground flex items-center flex-wrap gap-x-1 gap-y-0.5">
        {children}
      </span>
    </>
  );
}

function ActionButton({
  icon,
  label,
  onClick,
  highlight,
}: {
  icon: React.ReactNode;
  label: string;
  onClick: (e: ReactMouseEvent) => void;
  highlight?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'inline-flex items-center gap-1.5 px-2 h-6 rounded-md text-[10.5px] font-mono transition-colors cursor-pointer',
        highlight
          ? 'text-primary hover:bg-primary/10 border border-primary/30'
          : 'text-muted-foreground hover:text-foreground hover:bg-foreground/5',
      )}
    >
      {icon}
      {label}
    </button>
  );
}

// ─────────────────────────── recursive node ───────────────────────────

interface TreeNodeComponentProps {
  node: TreeNode;
  depth: number;
  ancestorLines: boolean[];
  lastInGroup: boolean;
  preset: Preset;
  parentMap: Map<string, string | null>;
  flatById: Map<string, TreeNode>;
  expanded: Set<string>;
  onToggle: (id: string) => void;
  selectedId: string | null;
  onSelect: (id: string) => void;
  visibleSet: Set<string> | null;
  focusSet: Set<string> | null;
  focusedId: string | null;
  onFocus: (id: string | null) => void;
  onPivot: (node: TreeNode, display: DisplayNode) => void;
  hasPivot: boolean;
}

function TreeNodeComponent(props: TreeNodeComponentProps) {
  const {
    node, depth, ancestorLines, lastInGroup, preset,
    parentMap, flatById, expanded, onToggle,
    selectedId, onSelect, visibleSet, focusSet, focusedId, onFocus,
    onPivot, hasPivot,
  } = props;

  const children = node.children ?? [];
  const hasChildren = children.length > 0;
  const isExpanded = expanded.has(node.id);
  const isSelected = selectedId === node.id;

  const visibleFilter = visibleSet === null || visibleSet.has(node.id);
  const focusFilter = focusSet === null || focusSet.has(node.id);
  if (!visibleFilter || !focusFilter) return null;

  const display = derive(node, preset);
  const parentId = parentMap.get(node.id);
  const parentNode = parentId ? flatById.get(parentId) : undefined;
  const parentDisplay = parentNode ? derive(parentNode, preset) : undefined;

  return (
    <>
      <TreeRow
        node={node}
        display={display}
        depth={depth}
        ancestorLines={ancestorLines}
        lastInGroup={lastInGroup}
        hasChildren={hasChildren}
        isExpanded={isExpanded}
        isSelected={isSelected}
        onToggle={(e) => { e.stopPropagation(); onToggle(node.id); }}
        onSelect={() => onSelect(node.id)}
      />
      {isSelected && (
        <TreeDetail
          node={node}
          display={display}
          parentDisplay={parentDisplay}
          depth={depth}
          ancestorLines={ancestorLines}
          lastInGroup={lastInGroup}
          onFocus={() => onFocus(node.id)}
          onClearFocus={() => onFocus(null)}
          isFocused={focusedId === node.id}
          onPivot={() => onPivot(node, display)}
          hasPivot={hasPivot}
        />
      )}
      {isExpanded && hasChildren && children.map((child, i) => {
        const last = i === children.length - 1;
        return (
          <TreeNodeComponent
            key={child.id}
            {...props}
            node={child}
            depth={depth + 1}
            lastInGroup={last}
            ancestorLines={[...ancestorLines, !lastInGroup]}
          />
        );
      })}
    </>
  );
}

// ─────────────────────────── main ───────────────────────────

const ROOTS_PAGE_SIZE = 25;
const SUSPICIOUS_THRESHOLD = 3;

export function TreeVisualization({
  nodes,
  config,
  onFilter,
  fieldsCollapsed,
  fieldsCount,
  onExpandFields,
}: TreeVisualizationProps) {
  const preset = useMemo(() => derivePreset(config), [config]);
  const presetLabel =
    preset === 'process' ? 'process ancestry' :
      preset === 'web' ? 'web referrer' : 'custom';

  // Infinite scroll sentinel for very wide first-level fanout
  const [visibleRoots, setVisibleRoots] = useState(ROOTS_PAGE_SIZE);
  const sentinelRef = useRef<HTMLDivElement>(null);
  const hasMoreRoots = nodes.length > visibleRoots;
  useEffect(() => {
    const sentinel = sentinelRef.current;
    if (!sentinel) return;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting && hasMoreRoots) {
          setVisibleRoots((prev) => prev + ROOTS_PAGE_SIZE);
        }
      },
      { rootMargin: '200px' },
    );
    observer.observe(sentinel);
    return () => observer.disconnect();
  }, [hasMoreRoots]);

  // Index: all nodes + parent map
  const flatById = useMemo(() => {
    const m = new Map<string, TreeNode>();
    for (const n of flattenAll(nodes)) m.set(n.id, n);
    return m;
  }, [nodes]);
  const parentMap = useMemo(() => buildParentMap(nodes), [nodes]);

  // Stats
  const stats = useMemo(() => {
    const all = flattenAll(nodes);
    const total = all.length;
    const hashes = new Set<string>();
    let flagged = 0;
    for (const n of all) {
      const d = derive(n, preset);
      if (d.hashRaw) hashes.add(d.hashRaw);
      if (suspicionScore(d) >= SUSPICIOUS_THRESHOLD) flagged += 1;
    }
    return { total, unique: hashes.size, flagged, depth: computeDepth(nodes) };
  }, [nodes, preset]);

  // Expansion state — default auto-expand LOLBin ancestry if process preset, otherwise first level.
  const allNodeIds = useMemo(() => collectIds(nodes), [nodes]);
  const [expanded, setExpanded] = useState<Set<string>>(() => {
    if (nodes.length === 0) return new Set();
    // Small trees: fully expand. Large trees: expand roots + suspicious paths only.
    if (allNodeIds.size <= 60) return new Set(allNodeIds);
    const s = new Set<string>();
    // Always expand roots
    for (const r of nodes) s.add(r.id);
    // Walk, expanding any subtree that contains a suspicious node
    const walk = (n: TreeNode): boolean => {
      const children = n.children ?? [];
      let childSus = false;
      for (const c of children) if (walk(c)) childSus = true;
      const self = suspicionScore(derive(n, preset)) >= SUSPICIOUS_THRESHOLD;
      if (childSus || self) s.add(n.id);
      return childSus || self;
    };
    nodes.forEach(walk);
    return s;
  });

  const toggleNode = useCallback((id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const expandAll = useCallback(() => setExpanded(new Set(allNodeIds)), [allNodeIds]);
  const collapseAll = useCallback(() => setExpanded(new Set(nodes.map((r) => r.id))), [nodes]);

  // Selection + focus
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [focusedId, setFocusedId] = useState<string | null>(null);

  // Filter + suspicious-only
  const [filter, setFilter] = useState('');
  const [showSuspOnly, setShowSuspOnly] = useState(false);

  const visibleSet = useMemo(() => {
    if (!filter.trim() && !showSuspOnly) return null;
    const q = filter.trim().toLowerCase();
    const match = (n: TreeNode): boolean => {
      const d = derive(n, preset);
      const textOk =
        !q ||
        d.name.toLowerCase().includes(q) ||
        (d.cmd ?? '').toLowerCase().includes(q);
      const susOk = !showSuspOnly || subtreeMaxSus(n, preset) >= SUSPICIOUS_THRESHOLD;
      return textOk && susOk;
    };
    const set = new Set<string>();
    const walk = (n: TreeNode, chain: string[]) => {
      const next = [...chain, n.id];
      if (match(n)) for (const id of next) set.add(id);
      for (const c of n.children ?? []) walk(c, next);
    };
    nodes.forEach((r) => walk(r, []));
    return set;
  }, [filter, showSuspOnly, nodes, preset]);

  const focusSet = useMemo(() => {
    if (!focusedId) return null;
    const s = new Set<string>();
    let cur: string | null = focusedId;
    while (cur) {
      s.add(cur);
      cur = parentMap.get(cur) ?? null;
    }
    const subWalk = (n: TreeNode) => {
      s.add(n.id);
      for (const c of n.children ?? []) subWalk(c);
    };
    const focusedNode = flatById.get(focusedId);
    if (focusedNode) subWalk(focusedNode);
    return s;
  }, [focusedId, parentMap, flatById]);

  const handlePivot = useCallback(
    (node: TreeNode, display: DisplayNode) => {
      if (!onFilter) return;
      const value = String(node._data?.[config.child_field] ?? display.name ?? node.id);
      onFilter(config.child_field, value);
    },
    [onFilter, config.child_field],
  );

  // Empty state
  if (!nodes || nodes.length === 0) {
    return (
      <div className="flex flex-col min-h-0 min-w-0 overflow-hidden">
        <div className="py-2 px-3 border-b border-border flex items-center gap-2 font-mono text-[10.5px] tracking-[0.12em] uppercase text-foreground/70 font-semibold">
          <Layers className="w-[12px] h-[12px] text-primary" />
          <span>Tree</span>
          <span className="text-muted-foreground/60">·</span>
          <span className="normal-case tracking-normal text-foreground">{presetLabel}</span>
        </div>
        <div className="p-8 text-center text-muted-foreground text-sm">
          <GitBranch className="inline-block w-5 h-5 mb-2 text-muted-foreground/60" />
          <p className="text-sm text-foreground">No tree nodes returned</p>
          <p className="text-xs mt-1">Try a different root, broaden the scope, or verify the tree command.</p>
        </div>
      </div>
    );
  }

  const visibleRootNodes = nodes.slice(0, visibleRoots);
  const focusedNode = focusedId ? flatById.get(focusedId) : null;
  const focusedName = focusedNode ? derive(focusedNode, preset).name : null;

  return (
    <div className="flex flex-col min-h-0 overflow-hidden">
      {/* Header */}
      <div className="py-2 px-3 border-b border-border flex flex-wrap items-center gap-2 font-mono text-[10.5px] tracking-[0.12em] uppercase text-foreground/70 font-semibold whitespace-nowrap">
        <span className="flex items-center gap-1.5 shrink-0">
          <Layers className="w-[12px] h-[12px] text-primary" />
          <span>Tree</span>
          <span className="text-muted-foreground/60">·</span>
          <span className="normal-case tracking-normal text-foreground">{presetLabel}</span>
        </span>
        <HeaderChip label="parent" value={config.parent_field || '—'} />
        <HeaderChip label="child" value={config.child_field || '—'} />
        {config.prevalence_field && (
          <HeaderChip label="prevalence" value={config.prevalence_field} />
        )}
        {stats.flagged > 0 && (
          <span
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border text-[10px] normal-case tracking-normal font-semibold"
            style={{
              borderColor: 'oklch(62% 0.18 28 / 0.4)',
              color: NOTABLE_RED,
              background: 'oklch(62% 0.18 28 / 0.08)',
            }}
          >
            <AlertTriangle className="w-[10px] h-[10px]" />
            {stats.flagged} suspicious
          </span>
        )}
        {fieldsCollapsed && onExpandFields && (
          <button
            type="button"
            onClick={onExpandFields}
            className="inline-flex items-center gap-1.5 py-1 px-2 rounded-md border border-primary/25 bg-primary/8 text-primary text-[10px] font-medium cursor-pointer hover:bg-primary/14 transition-colors normal-case tracking-normal shrink-0"
            title="Show field index"
          >
            <span className="relative flex w-[7px] h-[7px] items-center justify-center">
              <span className="absolute inset-0 rounded-full bg-primary/50 animate-ping" />
              <span className="relative w-[4px] h-[4px] rounded-full bg-primary" />
            </span>
            <span className="font-mono uppercase tracking-[0.12em] text-[9.5px]">Fields</span>
            {fieldsCount !== undefined && (
              <span className="text-primary/70 tabular-nums text-[10px]">{fieldsCount}</span>
            )}
            <ArrowRight className="w-[10px] h-[10px]" />
          </button>
        )}
        <span className="flex-1" aria-hidden />
        <span className="text-muted-foreground font-mono normal-case tracking-normal">
          {stats.total} nodes
          {stats.unique > 0 && (
            <> · {stats.unique} unique hashes</>
          )}
          {' '}· depth {stats.depth}
        </span>
      </div>

      {/* Toolbar */}
      <div className="flex items-center gap-2 px-3 py-1.5 border-b border-border bg-muted/30">
        <div className="relative">
          <SearchIcon className="w-[11px] h-[11px] absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none" />
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter in tree (name or cmdline)…"
            className="pl-7 pr-2 h-6 w-[280px] rounded-md border border-border bg-card text-[11px] text-foreground font-mono outline-none focus:border-primary/40 placeholder:text-muted-foreground"
          />
        </div>
        <button
          type="button"
          onClick={() => setShowSuspOnly((v) => !v)}
          className={cn(
            'inline-flex items-center gap-1 px-2 h-6 rounded-md text-[10.5px] border transition-colors font-mono cursor-pointer',
            showSuspOnly
              ? 'bg-primary/12 text-primary border-primary/40'
              : 'text-muted-foreground border-border hover:text-foreground',
          )}
        >
          <AlertTriangle className="w-[10px] h-[10px]" />
          Suspicious only
        </button>
        <div className="w-px h-4 bg-border" aria-hidden />
        <button
          type="button"
          onClick={expandAll}
          className="inline-flex items-center px-2 h-6 rounded-md text-[10.5px] text-muted-foreground hover:text-foreground font-mono cursor-pointer"
        >
          Expand all
        </button>
        <button
          type="button"
          onClick={collapseAll}
          className="inline-flex items-center px-2 h-6 rounded-md text-[10.5px] text-muted-foreground hover:text-foreground font-mono cursor-pointer"
        >
          Collapse all
        </button>
        {focusedId && focusedName && (
          <>
            <div className="w-px h-4 bg-border" aria-hidden />
            <span className="inline-flex items-center gap-1.5 px-2 h-6 rounded-md border border-primary/40 bg-primary/10 text-[10.5px] font-mono">
              <Layers className="w-[10px] h-[10px] text-primary" />
              <span className="text-muted-foreground">Focus:</span>
              <span className="text-foreground font-semibold">{focusedName}</span>
              <button
                type="button"
                onClick={() => setFocusedId(null)}
                className="ml-1 text-muted-foreground hover:text-foreground cursor-pointer"
                title="Clear focus"
                aria-label="Clear focus"
              >
                <X className="w-[10px] h-[10px]" />
              </button>
            </span>
          </>
        )}
        <span className="flex-1" aria-hidden />
        <span className="text-[10px] text-muted-foreground font-mono">
          <kbd className="px-1 rounded border border-border bg-foreground/3">→</kbd>{' '}
          expand ·{' '}
          <kbd className="px-1 rounded border border-border bg-foreground/3">←</kbd>{' '}
          collapse
        </span>
      </div>

      {/* Legend (process preset only — generic trees don't have these semantics) */}
      {preset === 'process' && (
        <div className="flex items-center gap-4 px-3 py-1.5 border-b border-border bg-muted/20 font-mono text-[10px] text-muted-foreground">
          <LegendDot color={NOTABLE_RED} label={<>rare hash<span className="ml-0.5 tabular-nums">&lt;10%</span></>} />
          <LegendDot color={AMBER} label="encoded / LOLBin" />
          <LegendDot color="var(--muted-foreground)" label="common" muted />
          <span className="inline-flex items-center gap-1.5">
            <FileSignature className="w-[10px] h-[10px]" />
            signed
          </span>
          <span className="inline-flex items-center gap-1.5">
            <Globe className="w-[10px] h-[10px]" />
            network
          </span>
        </div>
      )}

      {/* Tree body */}
      <div className="flex-1 min-h-0 overflow-auto font-mono">
        <div className="py-1.5">
          {visibleRootNodes.map((root, i) => {
            // Ancestor-path display when root= pulled out a subtree
            const ancestors = root._ancestors ?? [];
            return (
              <div key={root.id}>
                {ancestors.length > 0 && (
                  <div className="mb-1 opacity-60 font-mono text-[11px] px-3">
                    {ancestors.map((a, j) => (
                      <div key={a.id} className="flex items-center py-0.5 gap-2">
                        {Array.from({ length: j }).map((_, k) => (
                          <span key={k} className="inline-block w-4 border-l border-muted-foreground/20" aria-hidden />
                        ))}
                        {j > 0 && <span className="inline-block w-4 text-muted-foreground/40">└─</span>}
                        <span className="text-muted-foreground">
                          {typeof a.label === 'string' ? a.label : String(a.id)}
                        </span>
                      </div>
                    ))}
                    <div className="flex items-center py-0.5">
                      {Array.from({ length: ancestors.length }).map((_, k) => (
                        <span key={k} className="inline-block w-4 border-l border-muted-foreground/20" aria-hidden />
                      ))}
                      <span className="inline-block w-4 text-muted-foreground/40">↓</span>
                    </div>
                  </div>
                )}
                <TreeNodeComponent
                  node={root}
                  depth={0}
                  ancestorLines={[]}
                  lastInGroup={i === visibleRootNodes.length - 1 && !hasMoreRoots}
                  preset={preset}
                  parentMap={parentMap}
                  flatById={flatById}
                  expanded={expanded}
                  onToggle={toggleNode}
                  selectedId={selectedId}
                  onSelect={(id) => setSelectedId((prev) => (prev === id ? null : id))}
                  visibleSet={visibleSet}
                  focusSet={focusSet}
                  focusedId={focusedId}
                  onFocus={setFocusedId}
                  onPivot={handlePivot}
                  hasPivot={!!onFilter}
                />
              </div>
            );
          })}
          <div ref={sentinelRef} className="h-1" aria-hidden />
          {hasMoreRoots && (
            <div className="p-3 text-center text-xs text-muted-foreground">
              Showing {visibleRoots.toLocaleString()} of {nodes.length.toLocaleString()} root nodes — scroll for more
            </div>
          )}
        </div>
      </div>

    </div>
  );
}

function HeaderChip({ label, value }: { label: string; value: string }) {
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-border text-[10px] normal-case tracking-normal font-semibold text-foreground">
      <span className="text-muted-foreground">{label}</span>
      <span className="text-primary font-mono">{value}</span>
    </span>
  );
}

function LegendDot({
  color,
  label,
  muted,
}: {
  color: string;
  label: React.ReactNode;
  muted?: boolean;
}) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        className={cn('w-2 h-2 rounded-sm', muted && 'opacity-60')}
        style={{ background: color }}
        aria-hidden
      />
      {label}
    </span>
  );
}
