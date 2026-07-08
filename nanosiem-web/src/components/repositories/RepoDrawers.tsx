// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-504 / NAN-505 — slide-over drawers for the redesigned Rule Repositories
// page. Hosts:
//   • SyncHistoryDrawer — single "last sync" entry until backend history lands.
//   • BulkImportDrawer  — per-rule severity/mode/source-merge with bulk-apply
//                         toolbar, folder grouping, and live progress.
//   • AddRepoDrawer     — wired to createRepository.
//   • FolderSelectionDrawer — sync scope picker (lists folders + rule counts,
//                         persists selected_paths, kicks a sync).

import { useEffect, useMemo, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  ArrowRight,
  Check,
  ChevronDown,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  Clock,
  Download,
  Folder,
  FolderTree,
  GitCommit,
  Loader2,
  RefreshCw,
  X,
  XCircle,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { api } from '@/lib/api';
import type { RuleRepository } from '@/lib/api/rule-repositories';
import { useToast } from '@/hooks/use-toast';
import { Chk, StatusChip } from './chips';
import { SourceTypeCombobox } from './SourceTypeCombobox';
import { folderOf, type RepoRuleView, type RepoView } from './helpers';

// ------------------------------------------------------------------
// Side drawer shell
// ------------------------------------------------------------------

interface DrawerShellProps {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: React.ReactNode;
  width?: number;
  footer?: React.ReactNode;
  children: React.ReactNode;
}

export function SideDrawer({
  open,
  onClose,
  title,
  subtitle,
  width = 460,
  footer,
  children,
}: DrawerShellProps) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div
        className="absolute right-0 top-0 bottom-0 border-l border-border bg-card flex flex-col shadow-2xl"
        style={{ width }}
      >
        <div className="flex items-start gap-2 px-4 pt-3 pb-3 border-b border-border shrink-0">
          <div className="flex-1 min-w-0">
            <div className="text-[13px] font-semibold text-foreground">{title}</div>
            {subtitle && (
              <div className="text-[11px] text-muted-foreground mt-0.5 truncate">{subtitle}</div>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="h-[24px] w-[24px] rounded-md flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-foreground/5"
            aria-label="Close drawer"
          >
            <X className="w-[13px] h-[13px]" strokeWidth={1.5} />
          </button>
        </div>
        <div className="flex-1 overflow-auto">{children}</div>
        {footer && (
          <div className="border-t border-border px-4 py-3 shrink-0 bg-card">{footer}</div>
        )}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------
// Sync history — single "last sync" entry until backend history lands.
// ------------------------------------------------------------------

interface SyncHistoryProps {
  open: boolean;
  onClose: () => void;
  repo: RepoView | null;
  syncing: boolean;
  onSyncNow: (id: string) => void;
}

export function SyncHistoryDrawer({
  open,
  onClose,
  repo,
  syncing,
  onSyncNow,
}: SyncHistoryProps) {
  if (!repo) return null;
  return (
    <SideDrawer
      open={open}
      onClose={onClose}
      title="Sync history"
      subtitle={<span className="font-mono">{repo.slug}</span>}
      width={460}
      footer={
        <div className="flex items-center gap-2">
          <div className="flex-1 text-[10.5px] text-muted-foreground font-mono">
            {repo.autoSync !== 'off' ? (
              <>
                next auto-sync in{' '}
                <span className="text-foreground/70">{repo.nextSync.in}</span> ·{' '}
                {repo.nextSync.cadence}
              </>
            ) : (
              'auto-sync disabled'
            )}
          </div>
          <button
            type="button"
            onClick={() => onSyncNow(repo.id)}
            disabled={syncing}
            className={cn(
              'h-[28px] px-3 rounded-md text-[11.5px] font-medium flex items-center gap-1.5 border',
              syncing
                ? 'border-border bg-foreground/5 text-muted-foreground cursor-not-allowed'
                : 'bg-primary border-primary text-primary-foreground hover:bg-primary/90',
            )}
          >
            <RefreshCw
              className={cn('w-[11px] h-[11px]', syncing && 'animate-spin')}
              strokeWidth={1.5}
            />
            {syncing ? 'Syncing' : 'Sync now'}
          </button>
        </div>
      }
    >
      <div className="p-4">
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2.5">
          Last sync
        </div>

        {repo.lastSync.ts ? (
          <ol className="relative border-l border-border ml-2 pl-4 space-y-3">
            <li className="relative">
              <span
                className="absolute -left-[21px] top-[5px] w-[9px] h-[9px] rounded-full ring-2 ring-card"
                style={{
                  background:
                    repo.lastSync.result === 'failed'
                      ? 'var(--color-destructive)'
                      : repo.lastSync.result === 'warn'
                        ? 'var(--color-warning)'
                        : 'var(--color-success)',
                }}
              />
              <div className="flex items-baseline gap-2">
                <span className="font-mono text-[11px] text-foreground/70">
                  {repo.lastSync.ts}
                </span>
                <span className="text-[10.5px] text-muted-foreground">
                  ({repo.lastSync.relative})
                </span>
              </div>
              <div className="mt-1 flex items-center gap-2 text-[10.5px] font-mono text-foreground/70">
                <GitCommit
                  className="w-[11px] h-[11px] text-muted-foreground"
                  strokeWidth={1.5}
                />
                <span>{repo.lastCommit.sha}</span>
              </div>
              <div className="mt-1 flex items-center gap-3 text-[10.5px]">
                <span className="text-foreground">
                  <span className="font-mono tabular-nums">{repo.total}</span> rules cached
                </span>
                {repo.counts.imported > 0 && (
                  <span className="text-success">
                    <span className="font-mono tabular-nums">{repo.counts.imported}</span> imported
                  </span>
                )}
                {repo.counts.needsUpdate > 0 && (
                  <span className="text-warning">
                    ↑<span className="font-mono tabular-nums">{repo.counts.needsUpdate}</span>{' '}
                    updated
                  </span>
                )}
                {repo.counts.deleted > 0 && (
                  <span className="text-destructive">
                    −<span className="font-mono tabular-nums">{repo.counts.deleted}</span>{' '}
                    deleted
                  </span>
                )}
              </div>
              {repo.raw.last_sync_error && (
                <div className="mt-1 rounded-md bg-destructive/10 text-destructive text-[10.5px] px-2 py-1">
                  {repo.raw.last_sync_error}
                </div>
              )}
            </li>
          </ol>
        ) : (
          <div className="text-[11px] text-muted-foreground">
            This repo has not been synced yet.
          </div>
        )}

        <div className="text-[10.5px] text-muted-foreground mt-4 leading-relaxed">
          Per-run history will appear here once the backend tracks it. For now we only surface the
          latest commit and outcome.
        </div>
      </div>
    </SideDrawer>
  );
}

// ------------------------------------------------------------------
// Bulk import — per-rule severity / mode / source-merge with bulk-apply
// toolbar, folder grouping, and live progress.
// ------------------------------------------------------------------

type ImportMode = 'staging' | 'live' | 'alerting';
const MODE_OPTIONS: { id: ImportMode; label: string }[] = [
  { id: 'staging', label: 'Staging' },
  { id: 'live', label: 'Live' },
  { id: 'alerting', label: 'Alerting' },
];

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'] as const;
type Severity = (typeof SEVERITIES)[number];

interface BulkRowConfig {
  selected: boolean;
  severity: Severity;
  mode: ImportMode;
  mergeSourceType: string;
}

export interface BulkImportItem {
  path: string;
  severity?: string;
  mode?: string;
  merge_to_single_source_type?: string;
}

interface BulkImportProps {
  open: boolean;
  onClose: () => void;
  rules: RepoRuleView[];
  availableSourceTypes: string[];
  onConfirm: (items: BulkImportItem[]) => Promise<void> | void;
  /** Live progress while a batch is in flight. `total` is the planned size. */
  progress?: {
    running: boolean;
    total: number;
    imported?: number;
    skipped?: number;
    failed?: number;
  };
}

export function BulkImportDrawer({
  open,
  onClose,
  rules,
  availableSourceTypes,
  onConfirm,
  progress,
}: BulkImportProps) {
  const [configs, setConfigs] = useState<Record<string, BulkRowConfig>>({});
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  // Reset on the false→true open transition only. The parent rebuilds the
  // `rules` array on every render, and 3s sync polling refetches while the
  // drawer is open — depending on `rules` here would wipe per-row edits
  // mid-edit. Capture rules at open time via a ref instead.
  const wasOpenRef = useRef(false);
  const rulesRef = useRef(rules);
  rulesRef.current = rules;
  useEffect(() => {
    if (!open) {
      wasOpenRef.current = false;
      return;
    }
    if (wasOpenRef.current) return;
    wasOpenRef.current = true;
    const init: Record<string, BulkRowConfig> = {};
    for (const r of rulesRef.current) {
      init[r.id] = {
        selected: r.status !== 'IMPORTED' && r.status !== 'DELETED',
        severity: (SEVERITIES.includes(r.severity as Severity)
          ? r.severity
          : 'medium') as Severity,
        mode: 'staging',
        mergeSourceType: '',
      };
    }
    setConfigs(init);
    setCollapsed(new Set());
  }, [open]);

  const grouped = useMemo(() => {
    const map = new Map<string, RepoRuleView[]>();
    for (const r of rules) {
      const f = folderOf(r.raw.file_path) || '(root)';
      const arr = map.get(f) ?? [];
      arr.push(r);
      map.set(f, arr);
    }
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [rules]);

  const selectedCount = useMemo(
    () => Object.values(configs).filter((c) => c.selected).length,
    [configs],
  );

  if (!open || rules.length === 0) return null;

  const updateConfig = (id: string, patch: Partial<BulkRowConfig>) => {
    setConfigs((c) => ({ ...c, [id]: { ...c[id], ...patch } }));
  };

  const toggleAll = (selected: boolean) => {
    setConfigs((c) => {
      const out = { ...c };
      for (const k of Object.keys(out)) out[k] = { ...out[k], selected };
      return out;
    });
  };

  const applyToSelected = (patch: Partial<BulkRowConfig>) => {
    setConfigs((c) => {
      const out = { ...c };
      for (const k of Object.keys(out)) {
        if (out[k].selected) out[k] = { ...out[k], ...patch };
      }
      return out;
    });
  };

  const toggleFolder = (folder: string) => {
    setCollapsed((s) => {
      const n = new Set(s);
      if (n.has(folder)) n.delete(folder);
      else n.add(folder);
      return n;
    });
  };

  const submit = () => {
    const items: BulkImportItem[] = rules
      .filter((r) => configs[r.id]?.selected)
      .map((r) => {
        const c = configs[r.id];
        return {
          path: r.raw.file_path,
          severity: c.severity,
          mode: c.mode,
          merge_to_single_source_type: c.mergeSourceType || undefined,
        };
      });
    onConfirm(items);
  };

  const running = !!progress?.running;
  const done =
    (progress?.imported ?? 0) + (progress?.skipped ?? 0) + (progress?.failed ?? 0);
  const pct = progress && progress.total > 0 ? (done / progress.total) * 100 : 0;

  return (
    <SideDrawer
      open={open}
      onClose={running ? () => undefined : onClose}
      title={`Import ${rules.length} rule${rules.length === 1 ? '' : 's'}`}
      subtitle={`${selectedCount} selected · ${grouped.length} folder${grouped.length === 1 ? '' : 's'}`}
      width={760}
      footer={
        <div className="flex items-center gap-2">
          <div className="flex-1 text-[10.5px] text-muted-foreground">
            {running
              ? 'Importing — please don\u2019t close this drawer'
              : 'Source type left blank uses upstream default'}
          </div>
          <button
            type="button"
            onClick={onClose}
            disabled={running}
            className="h-[28px] px-3 rounded-md text-muted-foreground hover:text-foreground hover:bg-foreground/5 text-[11.5px] disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={submit}
            disabled={running || selectedCount === 0}
            className="h-[28px] px-3 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 text-[11.5px] font-medium flex items-center gap-1.5 disabled:opacity-60 disabled:cursor-not-allowed"
          >
            <Download className="w-[11px] h-[11px]" strokeWidth={2} />
            {running ? 'Importing…' : `Import ${selectedCount}`}
          </button>
        </div>
      }
    >
      {/* Bulk-apply toolbar */}
      {!running && (
        <div className="px-4 pt-3 pb-2 border-b border-border bg-card/30 space-y-2">
          <div className="flex items-center gap-1.5 flex-wrap">
            <button
              type="button"
              onClick={() => toggleAll(true)}
              className="h-[24px] px-2 rounded-md text-[10.5px] font-mono uppercase tracking-wider text-muted-foreground hover:text-foreground hover:bg-foreground/5"
            >
              Select all
            </button>
            <button
              type="button"
              onClick={() => toggleAll(false)}
              className="h-[24px] px-2 rounded-md text-[10.5px] font-mono uppercase tracking-wider text-muted-foreground hover:text-foreground hover:bg-foreground/5"
            >
              Deselect all
            </button>
            <span className="w-px h-4 bg-border mx-1" />
            <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
              Set selected to:
            </span>
            <BulkSeverityMenu onApply={(s) => applyToSelected({ severity: s })} />
            <BulkModeMenu onApply={(m) => applyToSelected({ mode: m })} />
            <SourceTypeCombobox
              value=""
              onSelect={(s) => applyToSelected({ mergeSourceType: s })}
              sourceTypes={availableSourceTypes}
              placeholder="Merge source type…"
              size="sm"
              className="w-[160px]"
            />
          </div>
        </div>
      )}

      {/* Live progress */}
      {progress && (
        <div className="px-4 pt-3 pb-2 border-b border-border bg-card/30">
          <div className="h-1.5 rounded-full bg-foreground/10 overflow-hidden">
            <div
              className="h-full bg-primary transition-all"
              style={{ width: `${Math.min(100, pct)}%` }}
            />
          </div>
          <div className="mt-2 flex items-center gap-3 text-[10.5px] font-mono">
            <span className="text-success flex items-center gap-1">
              <CircleCheck className="w-[11px] h-[11px]" strokeWidth={2} />
              {progress.imported ?? 0} imported
            </span>
            <span className="text-muted-foreground flex items-center gap-1">
              <CircleAlert className="w-[11px] h-[11px]" strokeWidth={2} />
              {progress.skipped ?? 0} skipped
            </span>
            {(progress.failed ?? 0) > 0 && (
              <span className="text-destructive flex items-center gap-1">
                <XCircle className="w-[11px] h-[11px]" strokeWidth={2} />
                {progress.failed} failed
              </span>
            )}
            <span className="ml-auto text-muted-foreground">
              {done} / {progress.total}
            </span>
          </div>
        </div>
      )}

      {/* Folder-grouped rule list */}
      <div className="p-3 flex flex-col gap-2">
        {grouped.map(([folder, list]) => {
          const isCollapsed = collapsed.has(folder);
          const folderSelectedCount = list.filter((r) => configs[r.id]?.selected).length;
          return (
            <div key={folder} className="rounded-md border border-border bg-card">
              <button
                type="button"
                onClick={() => toggleFolder(folder)}
                className="w-full flex items-center gap-2 px-2.5 py-1.5 hover:bg-muted/40 rounded-t-md text-left"
              >
                {isCollapsed ? (
                  <ChevronRight className="w-[12px] h-[12px] text-muted-foreground" strokeWidth={1.5} />
                ) : (
                  <ChevronDown className="w-[12px] h-[12px] text-muted-foreground" strokeWidth={1.5} />
                )}
                <Folder className="w-[12px] h-[12px] text-muted-foreground" strokeWidth={1.5} />
                <span className="font-mono text-[11.5px] text-foreground truncate flex-1">
                  {folder}
                </span>
                <span className="text-[10px] font-mono text-muted-foreground tabular-nums">
                  {folderSelectedCount}/{list.length}
                </span>
              </button>
              {!isCollapsed && (
                <div className="border-t border-border divide-y divide-border/60">
                  {list.map((r) => {
                    const c = configs[r.id];
                    if (!c) return null;
                    return (
                      <BulkRow
                        key={r.id}
                        rule={r}
                        config={c}
                        availableSourceTypes={availableSourceTypes}
                        disabled={running}
                        onChange={(patch) => updateConfig(r.id, patch)}
                      />
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </SideDrawer>
  );
}

function BulkRow({
  rule,
  config,
  availableSourceTypes,
  disabled,
  onChange,
}: {
  rule: RepoRuleView;
  config: BulkRowConfig;
  availableSourceTypes: string[];
  disabled?: boolean;
  onChange: (patch: Partial<BulkRowConfig>) => void;
}) {
  return (
    <div
      className={cn(
        'px-2.5 py-2 flex items-center gap-2.5',
        !config.selected && 'opacity-60',
      )}
    >
      <Chk
        checked={config.selected}
        onChange={() => onChange({ selected: !config.selected })}
        disabled={disabled}
        ariaLabel={`Select ${rule.name}`}
      />
      <StatusChip status={rule.status} mini />
      <div className="flex-1 min-w-0">
        <div className="font-mono text-[11.5px] text-foreground truncate">{rule.name}</div>
        <div className="text-[10px] text-muted-foreground truncate">
          <span className="font-mono">{rule.source}</span> · {rule.desc}
        </div>
      </div>
      <SeveritySelect
        value={config.severity}
        onChange={(s) => onChange({ severity: s })}
        disabled={disabled || !config.selected}
      />
      <ModeSelect
        value={config.mode}
        onChange={(m) => onChange({ mode: m })}
        disabled={disabled || !config.selected}
      />
      <ArrowRight className="w-3 h-3 text-muted-foreground/60 shrink-0" strokeWidth={2} />
      <SourceTypeCombobox
        value={config.mergeSourceType}
        onSelect={(s) => onChange({ mergeSourceType: s })}
        sourceTypes={availableSourceTypes}
        placeholder={rule.source !== '—' ? rule.source : 'source…'}
        size="sm"
        overridden={!!config.mergeSourceType && config.mergeSourceType !== rule.source}
        className="w-[150px]"
      />
    </div>
  );
}

function SeveritySelect({
  value,
  onChange,
  disabled,
}: {
  value: Severity;
  onChange: (s: Severity) => void;
  disabled?: boolean;
}) {
  return (
    <select
      value={value}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value as Severity)}
      className={cn(
        'h-[22px] rounded-md border border-border bg-card text-[10.5px] font-mono px-1.5 focus:outline-none focus:border-primary disabled:opacity-50',
      )}
    >
      {SEVERITIES.map((s) => (
        <option key={s} value={s}>
          {s}
        </option>
      ))}
    </select>
  );
}

function ModeSelect({
  value,
  onChange,
  disabled,
}: {
  value: ImportMode;
  onChange: (m: ImportMode) => void;
  disabled?: boolean;
}) {
  return (
    <select
      value={value}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value as ImportMode)}
      className="h-[22px] rounded-md border border-border bg-card text-[10.5px] font-mono px-1.5 focus:outline-none focus:border-primary disabled:opacity-50"
    >
      {MODE_OPTIONS.map((m) => (
        <option key={m.id} value={m.id}>
          {m.label}
        </option>
      ))}
    </select>
  );
}

function BulkSeverityMenu({ onApply }: { onApply: (s: Severity) => void }) {
  return (
    <select
      defaultValue=""
      onChange={(e) => {
        if (!e.target.value) return;
        onApply(e.target.value as Severity);
        e.currentTarget.value = '';
      }}
      className="h-[24px] rounded-md border border-border bg-card text-[10.5px] font-mono px-1.5 focus:outline-none focus:border-primary"
    >
      <option value="" disabled>
        Severity…
      </option>
      {SEVERITIES.map((s) => (
        <option key={s} value={s}>
          {s}
        </option>
      ))}
    </select>
  );
}

function BulkModeMenu({ onApply }: { onApply: (m: ImportMode) => void }) {
  return (
    <select
      defaultValue=""
      onChange={(e) => {
        if (!e.target.value) return;
        onApply(e.target.value as ImportMode);
        e.currentTarget.value = '';
      }}
      className="h-[24px] rounded-md border border-border bg-card text-[10.5px] font-mono px-1.5 focus:outline-none focus:border-primary"
    >
      <option value="" disabled>
        Mode…
      </option>
      {MODE_OPTIONS.map((m) => (
        <option key={m.id} value={m.id}>
          {m.label}
        </option>
      ))}
    </select>
  );
}

// ------------------------------------------------------------------
// Add repo drawer — wired to createRepository
// ------------------------------------------------------------------

type RuleFormat = 'sigma' | 'nanosiem';

interface AddRepoProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (req: {
    name: string;
    url: string;
    branch: string;
    rules_path: string;
    rule_format: RuleFormat;
    auto_sync_enabled: boolean;
    sync_interval_hours: number;
  }) => Promise<void> | void;
  submitting?: boolean;
}

export function AddRepoDrawer({ open, onClose, onSubmit, submitting }: AddRepoProps) {
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [rulesPath, setRulesPath] = useState('');
  const [format, setFormat] = useState<RuleFormat>('nanosiem');
  const [cadence, setCadence] = useState<'off' | 'hourly' | '4h' | 'daily'>('hourly');

  useEffect(() => {
    if (open) {
      setName('');
      setUrl('');
      setBranch('main');
      setRulesPath('');
      setFormat('nanosiem');
      setCadence('hourly');
    }
  }, [open]);

  const cadenceHours =
    cadence === 'hourly' ? 1 : cadence === '4h' ? 4 : cadence === 'daily' ? 24 : 0;
  const valid = name.trim().length > 0 && url.trim().length > 0;

  const submit = () => {
    if (!valid) return;
    onSubmit({
      name: name.trim(),
      url: url.trim(),
      branch: branch.trim() || 'main',
      rules_path: rulesPath.trim(),
      rule_format: format,
      auto_sync_enabled: cadence !== 'off',
      sync_interval_hours: cadenceHours || 1,
    });
  };

  return (
    <SideDrawer
      open={open}
      onClose={onClose}
      title="Connect a rule repo"
      subtitle="GitHub, GitLab, or a public Git URL"
      width={460}
      footer={
        <div className="flex items-center justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="h-[28px] px-3 rounded-md text-muted-foreground hover:text-foreground hover:bg-foreground/5 text-[11.5px]"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={submit}
            disabled={!valid || submitting}
            className="h-[28px] px-3 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 text-[11.5px] font-medium disabled:opacity-60"
          >
            {submitting ? 'Connecting…' : 'Connect & sync'}
          </button>
        </div>
      }
    >
      <div className="p-4 space-y-3">
        <Field label="Display name">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="acme rules (internal)"
            className="w-full h-[30px] px-2.5 rounded-md border border-border bg-card text-[12px] focus:outline-none focus:border-primary"
          />
        </Field>
        <Field label="Repository URL">
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://github.com/acme-corp/nano-rules"
            className="w-full h-[30px] px-2.5 rounded-md border border-border bg-card text-[12px] font-mono placeholder:text-muted-foreground focus:outline-none focus:border-primary"
          />
        </Field>
        <div className="grid grid-cols-2 gap-2">
          <Field label="Branch">
            <input
              value={branch}
              onChange={(e) => setBranch(e.target.value)}
              className="w-full h-[30px] px-2.5 rounded-md border border-border bg-card text-[12px] font-mono focus:outline-none focus:border-primary"
            />
          </Field>
          <Field label="Rules path">
            <input
              value={rulesPath}
              onChange={(e) => setRulesPath(e.target.value)}
              placeholder="rules/"
              className="w-full h-[30px] px-2.5 rounded-md border border-border bg-card text-[12px] font-mono focus:outline-none focus:border-primary"
            />
          </Field>
        </div>
        <Field label="Rule format">
          <div className="flex items-center gap-1">
            {(['nanosiem', 'sigma'] as RuleFormat[]).map((f) => (
              <button
                key={f}
                type="button"
                onClick={() => setFormat(f)}
                className={cn(
                  'h-[26px] px-2.5 rounded-md text-[11.5px] border transition',
                  format === f
                    ? 'border-primary/40 bg-primary/10 text-primary'
                    : 'border-border bg-card text-foreground/70 hover:bg-muted',
                )}
              >
                {f === 'nanosiem' ? 'nPL (native)' : 'Sigma'}
              </button>
            ))}
          </div>
        </Field>
        <Field label="Auto-sync cadence">
          <div className="flex items-center gap-1">
            {(['off', 'hourly', '4h', 'daily'] as const).map((c) => (
              <button
                key={c}
                type="button"
                onClick={() => setCadence(c)}
                className={cn(
                  'h-[26px] px-2.5 rounded-md text-[11.5px] border transition',
                  cadence === c
                    ? 'border-primary/40 bg-primary/10 text-primary'
                    : 'border-border bg-card text-foreground/70 hover:bg-muted',
                )}
              >
                {c}
              </button>
            ))}
          </div>
        </Field>
        <div className="rounded-md border border-border bg-card/30 px-3 py-2 flex items-start gap-2">
          <Clock className="w-[12px] h-[12px] text-muted-foreground mt-0.5" strokeWidth={1.5} />
          <div className="text-[10.5px] text-muted-foreground leading-relaxed">
            After connecting, use the <span className="text-foreground/70">Configure folders</span>{' '}
            button on the repo card to scope which folders sync (especially for large upstream
            repos like SigmaHQ).
          </div>
        </div>
      </div>
    </SideDrawer>
  );
}

export function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">{label}</div>
      {children}
    </div>
  );
}

// ------------------------------------------------------------------
// Folder selection — sync scope picker. Lists folders with rule counts,
// persists `selected_paths`, kicks a sync.
// ------------------------------------------------------------------

interface FolderSelectionProps {
  repository: RuleRepository | null;
  open: boolean;
  onClose: () => void;
  onSyncStarted: () => void;
}

export function FolderSelectionDrawer({
  repository,
  open,
  onClose,
  onSyncStarted,
}: FolderSelectionProps) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [initialized, setInitialized] = useState(false);

  const { data: foldersData, isLoading } = useQuery({
    queryKey: ['rule-repository-folders', repository?.id],
    queryFn: () =>
      repository
        ? api.ruleRepositories.listFolders(repository.id)
        : Promise.resolve({ folders: [] }),
    enabled: open && !!repository,
  });

  const folders = foldersData?.folders ?? [];

  useEffect(() => {
    if (!open) {
      setInitialized(false);
      setSelected(new Set());
      return;
    }
    if (foldersData && !initialized) {
      const existing = repository?.selected_paths;
      if (existing && existing.length > 0) setSelected(new Set(existing));
      setInitialized(true);
    }
  }, [open, foldersData, initialized, repository?.selected_paths]);

  const updateMutation = useMutation({
    mutationFn: (paths: string[] | null) =>
      repository
        ? api.ruleRepositories.updateRepository(repository.id, {
            selected_paths: paths ?? undefined,
          })
        : Promise.reject(new Error('No repository')),
    onError: (err: Error) => {
      toast({
        title: 'Failed to update folders',
        description: err.message,
        variant: 'destructive',
      });
    },
  });

  const syncMutation = useMutation({
    mutationFn: () =>
      repository ? api.ruleRepositories.syncRepository(repository.id) : Promise.reject(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rule-repositories'] });
      toast({ title: 'Sync started', description: 'Rules are syncing in the background.' });
      onSyncStarted();
    },
    onError: (err: Error) => {
      toast({
        title: 'Sync failed to start',
        description: err.message,
        variant: 'destructive',
      });
    },
  });

  if (!repository) return null;

  const totalRules = folders.reduce((sum, f) => sum + f.rule_count, 0);
  const selectedRules = folders
    .filter((f) => selected.has(f.path))
    .reduce((sum, f) => sum + f.rule_count, 0);
  const isPending = updateMutation.isPending || syncMutation.isPending;
  const isSyncingAll = repository.selected_paths === null;

  const toggle = (path: string) => {
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(path)) n.delete(path);
      else n.add(path);
      return n;
    });
  };

  const handleSyncAll = async () => {
    await updateMutation.mutateAsync(null);
    syncMutation.mutate();
  };

  const handleSyncSelected = async () => {
    if (selected.size === 0) {
      toast({ title: 'Select at least one folder', variant: 'destructive' });
      return;
    }
    await updateMutation.mutateAsync([...selected]);
    syncMutation.mutate();
  };

  return (
    <SideDrawer
      open={open}
      onClose={isPending ? () => undefined : onClose}
      title="Configure folders"
      subtitle={
        <>
          <span className="font-mono">{repository.name}</span> · pick which folders to sync
        </>
      }
      width={520}
      footer={
        <div className="flex items-center gap-2">
          <div className="flex-1 text-[10.5px] text-muted-foreground">
            {selected.size > 0
              ? `${selected.size} folder${selected.size === 1 ? '' : 's'} · ~${selectedRules} rules`
              : isSyncingAll
                ? 'Currently syncing all folders'
                : 'No folders selected'}
          </div>
          <button
            type="button"
            onClick={onClose}
            disabled={isPending}
            className="h-[28px] px-3 rounded-md text-muted-foreground hover:text-foreground hover:bg-foreground/5 text-[11.5px]"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSyncSelected}
            disabled={isPending || selected.size === 0}
            className="h-[28px] px-3 rounded-md border border-border bg-card hover:bg-muted text-[11.5px] font-medium text-foreground/80 disabled:opacity-60 disabled:cursor-not-allowed flex items-center gap-1.5"
          >
            {isPending && selected.size > 0 ? (
              <Loader2 className="w-[11px] h-[11px] animate-spin" strokeWidth={1.5} />
            ) : (
              <RefreshCw className="w-[11px] h-[11px]" strokeWidth={1.5} />
            )}
            Sync selected
          </button>
          <button
            type="button"
            onClick={handleSyncAll}
            disabled={isPending}
            className="h-[28px] px-3 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 text-[11.5px] font-medium disabled:opacity-60 flex items-center gap-1.5"
          >
            {isPending && selected.size === 0 ? (
              <Loader2 className="w-[11px] h-[11px] animate-spin" strokeWidth={1.5} />
            ) : (
              <FolderTree className="w-[11px] h-[11px]" strokeWidth={1.5} />
            )}
            Sync all
          </button>
        </div>
      }
    >
      <div className="p-4 space-y-3">
        {repository.last_synced_at && (
          <div className="rounded-md border border-border bg-card/30 px-3 py-2 flex items-start gap-2 text-[10.5px] text-muted-foreground">
            <CircleAlert className="w-[12px] h-[12px] mt-0.5" strokeWidth={1.5} />
            <div className="leading-relaxed">
              Currently:{' '}
              {isSyncingAll ? (
                <span className="text-foreground/80">syncing all folders</span>
              ) : repository.selected_paths?.length ? (
                <span className="text-foreground/80">
                  syncing {repository.selected_paths.length} folder
                  {repository.selected_paths.length === 1 ? '' : 's'}
                </span>
              ) : (
                <span className="text-foreground/80">no folders selected</span>
              )}
            </div>
          </div>
        )}

        <div className="flex items-center justify-between text-[10.5px] text-muted-foreground">
          <span>
            <span className="font-mono tabular-nums">{selected.size}</span> /{' '}
            <span className="font-mono tabular-nums">{folders.length}</span> selected
            {selected.size > 0 && (
              <span className="ml-2">
                (~<span className="font-mono tabular-nums">{selectedRules}</span> rules)
              </span>
            )}
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setSelected(new Set(folders.map((f) => f.path)))}
              className="h-[22px] px-2 rounded-md text-[10.5px] font-mono uppercase tracking-wider text-muted-foreground hover:text-foreground hover:bg-foreground/5"
            >
              All
            </button>
            <button
              type="button"
              onClick={() => setSelected(new Set())}
              className="h-[22px] px-2 rounded-md text-[10.5px] font-mono uppercase tracking-wider text-muted-foreground hover:text-foreground hover:bg-foreground/5"
            >
              None
            </button>
          </div>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-8 text-muted-foreground">
            <Loader2 className="w-5 h-5 animate-spin" strokeWidth={1.5} />
          </div>
        ) : folders.length === 0 ? (
          <div className="text-center py-8">
            <div className="text-[12px] text-foreground/70 mb-1">No folders found</div>
            <div className="text-[10.5px] text-muted-foreground leading-relaxed max-w-[280px] mx-auto">
              Sync the repo first so we can enumerate folders, then come back here to scope which
              ones to keep.
            </div>
          </div>
        ) : (
          <div className="rounded-md border border-border max-h-[420px] overflow-auto divide-y divide-border/60">
            {folders.map((f) => {
              const checked = selected.has(f.path);
              return (
                <label
                  key={f.path}
                  className={cn(
                    'flex items-center gap-2 px-2.5 py-1.5 cursor-pointer hover:bg-muted/40',
                    checked && 'bg-primary/[0.04]',
                  )}
                >
                  <span className="shrink-0">
                    <Chk
                      checked={checked}
                      onChange={() => toggle(f.path)}
                      ariaLabel={`Toggle folder ${f.path}`}
                    />
                  </span>
                  <Folder className="w-[12px] h-[12px] text-muted-foreground" strokeWidth={1.5} />
                  <span className="flex-1 font-mono text-[11.5px] text-foreground truncate">
                    {f.path || f.name}
                  </span>
                  <span className="font-mono text-[10px] text-muted-foreground tabular-nums shrink-0">
                    {f.rule_count} rules
                  </span>
                </label>
              );
            })}
          </div>
        )}

        <div className="rounded-md border border-border bg-card/30 px-3 py-2 flex items-start gap-2">
          <AlertTriangle className="w-[12px] h-[12px] text-muted-foreground mt-0.5" strokeWidth={1.5} />
          <div className="text-[10.5px] text-muted-foreground leading-relaxed">
            Large upstream repos (e.g. SigmaHQ has 200+ folders / 3000+ rules) get unwieldy
            without scoping. Pick the few folders you want and resync — only matching files are
            fetched.
          </div>
        </div>
        <div className="text-[10px] font-mono text-muted-foreground/70 flex items-center gap-1.5">
          <Check className="w-[10px] h-[10px]" strokeWidth={2} /> total{' '}
          <span className="text-foreground/70">{totalRules}</span> rules across{' '}
          <span className="text-foreground/70">{folders.length}</span> folders
        </div>
      </div>
    </SideDrawer>
  );
}
