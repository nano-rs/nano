// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-504 / NAN-505 — right-side preview pane.
//
// Hosts the full per-rule import flow (preview → severity/mode/source-mapping →
// import) and the side-by-side upstream diff viewer for IMPORTED/UPDATED rules.
// Logic lifted from the deleted ImportRuleModal / UpstreamDiffModal; chrome is
// the redesign tab+drawer pattern, not Sheet/Dialog.

import { Fragment, useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import * as Diff from 'diff';
import {
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  Box,
  Check,
  Database,
  Download,
  ExternalLink,
  GitCommit,
  HelpCircle,
  Info,
  Minus,
  Plus,
  Settings2,
  Sparkles,
  X,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { api } from '@/lib/api';
import type { ImportRequest } from '@/lib/api/rule-repositories';
import { useToast } from '@/hooks/use-toast';
import { SeverityDot, StatusChip } from './chips';
import { SourceTypeCombobox } from './SourceTypeCombobox';
import {
  applyMergedSourceType,
  applySourceTypeMappings,
  type RepoRuleView,
} from './helpers';

// ------------------------------------------------------------------
// Public props
// ------------------------------------------------------------------

interface PreviewProps {
  rule: RepoRuleView | null;
  repositoryId: string | null;
  /** Active repo's rule format. Drives nPL-native vs Sigma copy. */
  ruleFormat: 'sigma' | 'nanosiem';
  availableSourceTypes: string[];
  onClose: () => void;
  /** Called when the user confirms import for an AVAILABLE rule. */
  onImport: (req: ImportRequest) => void;
  /** Called for non-import row actions (open imported, remove deleted, …). */
  onAction: (rule: RepoRuleView) => void;
  importing?: boolean;
}

type ImportMode = 'staging' | 'live' | 'alerting';
const MODE_LABELS: Record<ImportMode, string> = {
  staging: 'Staging',
  live: 'Live',
  alerting: 'Alerting',
};
const MODE_HINTS: Record<ImportMode, string> = {
  staging: 'Imported but not executed. Edit and promote when ready.',
  live: 'Bake-in: matches counted, no alerts fired.',
  alerting: 'Imported live — generates alerts immediately.',
};
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'] as const;
type Severity = (typeof SEVERITIES)[number];

// ------------------------------------------------------------------
// Component
// ------------------------------------------------------------------

export function RepoPreview({
  rule,
  repositoryId,
  ruleFormat,
  availableSourceTypes,
  onClose,
  onImport,
  onAction,
  importing,
}: PreviewProps) {
  const [tab, setTab] = useState<'overview' | 'yaml' | 'diff' | 'source'>('overview');

  // Per-rule import settings (reset whenever the selected rule changes).
  const [severity, setSeverity] = useState<Severity | ''>('');
  const [mode, setMode] = useState<ImportMode>('staging');
  const [mergeMode, setMergeMode] = useState(false);
  const [mergedSourceType, setMergedSourceType] = useState('');
  const [mappings, setMappings] = useState<Record<string, string>>({});

  const isAvailable = rule?.status === 'AVAILABLE';
  const hasDiff = rule?.status === 'UPDATED' || rule?.status === 'DRIFT';

  // Fetch preview only for AVAILABLE rules. The query call is lifted from the
  // deleted ImportRuleModal — drives Overview meta + Source mapping defaults.
  const { data: preview, isLoading: previewLoading } = useQuery({
    queryKey: ['rule-import-preview', repositoryId, rule?.raw.file_path],
    queryFn: () =>
      repositoryId && rule
        ? api.ruleRepositories.previewImport(repositoryId, rule.raw.file_path)
        : Promise.resolve(null),
    enabled: !!repositoryId && !!rule && isAvailable,
    staleTime: 30 * 1000,
  });

  const requiredTypes = preview?.required_source_types ?? [];
  const missingTypes = useMemo(() => {
    if (!preview) return [];
    return preview.required_source_types.filter(
      (st) => !availableSourceTypes.some((a) => a.toLowerCase() === st.toLowerCase()),
    );
  }, [preview, availableSourceTypes]);
  const hasMultipleSourceTypes = requiredTypes.length > 1;

  // Reset when selected rule changes.
  useEffect(() => {
    setTab('overview');
    setSeverity('');
    setMode('staging');
    setMergeMode(false);
    setMergedSourceType('');
    setMappings({});
  }, [rule?.id]);

  // Once preview lands, seed defaults.
  useEffect(() => {
    if (!preview) return;
    setSeverity((s) => s || (preview.proposed_severity as Severity));
    setMergeMode(hasMultipleSourceTypes);
    if (missingTypes.length > 0) {
      const init: Record<string, string> = {};
      for (const m of missingTypes) {
        const sugg = preview.source_type_suggestions?.find((s) => s.missing_type === m);
        init[m] = sugg?.suggested_type || '';
      }
      setMappings((cur) => (Object.keys(cur).length ? cur : init));
    }
  }, [preview, hasMultipleSourceTypes, missingTypes]);

  if (!rule) {
    return (
      <div className="h-full flex flex-col border-l border-border bg-card/30">
        <div className="flex-1 flex flex-col items-center justify-center p-6 text-center">
          <div className="w-10 h-10 rounded-full border border-dashed border-border flex items-center justify-center mb-3 text-muted-foreground">
            <Box className="w-[17px] h-[17px]" strokeWidth={1.5} />
          </div>
          <div className="text-[13px] font-medium text-foreground mb-1">Select a rule</div>
          <div className="text-[11.5px] text-muted-foreground max-w-[240px] leading-relaxed">
            Click any rule to preview the YAML, diff, and import options. Bulk-select with the
            checkboxes to import many at once.
          </div>
        </div>
      </div>
    );
  }

  const allMapped = mergeMode
    ? !!mergedSourceType
    : missingTypes.length === 0 || missingTypes.every((m) => mappings[m]);

  const handleImport = () => {
    let customNpl: string | undefined;
    const baseQuery = preview?.proposed_query || '';
    if (baseQuery) {
      if (mergeMode && mergedSourceType) {
        customNpl = applyMergedSourceType(baseQuery, mergedSourceType);
      } else {
        const hasMappings = Object.values(mappings).some((v) => v && v !== '__skip__');
        if (hasMappings) customNpl = applySourceTypeMappings(baseQuery, mappings);
      }
    }
    const activeMappings: Record<string, string> = {};
    if (!mergeMode) {
      for (const [k, v] of Object.entries(mappings)) {
        if (v && v !== '__skip__') activeMappings[k] = v;
      }
    }
    const req: ImportRequest = {
      import_type: 'forked',
      severity:
        severity && preview && severity !== preview.proposed_severity ? severity : undefined,
      mode,
      custom_npl: customNpl,
      source_type_mappings:
        Object.keys(activeMappings).length > 0 ? activeMappings : undefined,
      merge_to_single_source_type:
        mergeMode && mergedSourceType ? mergedSourceType : undefined,
    };
    onImport(req);
  };

  return (
    <div className="h-full flex flex-col border-l border-border bg-card/30 min-w-0">
      {/* Header */}
      <div className="px-4 pt-3 pb-0 shrink-0">
        <div className="flex items-start gap-2.5">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <StatusChip status={rule.status} />
              <SeverityDot sev={rule.severity} />
            </div>
            <div className="font-mono text-[14px] text-foreground leading-tight break-words">
              {rule.name}
            </div>
            <div className="text-[10.5px] text-muted-foreground font-mono mt-1 truncate">
              {rule.path}
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="h-[24px] w-[24px] shrink-0 rounded-md flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-foreground/5"
            aria-label="Close preview"
          >
            <X className="w-[13px] h-[13px]" strokeWidth={1.5} />
          </button>
        </div>

        <div className="mt-3 flex items-center gap-3 text-[10.5px] font-mono text-muted-foreground flex-wrap">
          <span className="flex items-center gap-1">
            <GitCommit className="w-[11px] h-[11px]" strokeWidth={1.5} />
            <span className="text-foreground/70">{rule.commit}</span>
          </span>
          <span>·</span>
          <span>{rule.updated}</span>
        </div>

        <div className="flex items-center gap-0.5 mt-3 -mb-px">
          {[
            { id: 'overview', label: 'Overview' },
            { id: 'yaml', label: 'YAML' },
            { id: 'diff', label: 'Diff', disabled: !hasDiff },
            { id: 'source', label: 'Source mapping', disabled: !isAvailable },
          ].map((t) => (
            <button
              key={t.id}
              type="button"
              disabled={t.disabled}
              onClick={() => setTab(t.id as typeof tab)}
              className={cn(
                'px-2.5 h-[28px] text-[11.5px] border-b-[1.5px] transition font-medium',
                tab === t.id
                  ? 'border-primary text-foreground'
                  : t.disabled
                    ? 'border-transparent text-muted-foreground/60 cursor-not-allowed'
                    : 'border-transparent text-muted-foreground hover:text-foreground',
              )}
            >
              {t.label}
              {t.id === 'diff' && rule.status === 'DRIFT' && (
                <span className="ml-1 font-mono text-[9.5px] text-destructive">DRIFT</span>
              )}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-auto border-t border-border min-w-0">
        {tab === 'overview' && (
          <OverviewTab
            rule={rule}
            preview={preview}
            previewLoading={previewLoading}
            missingTypes={missingTypes}
            severity={severity || (preview?.proposed_severity as Severity) || 'medium'}
            mode={mode}
            mergeMode={mergeMode}
            mergedSourceType={mergedSourceType}
            mappings={mappings}
            isAvailable={isAvailable}
            ruleFormat={ruleFormat}
          />
        )}
        {tab === 'yaml' && (
          <YamlTab yaml={rule.raw.raw_content || rule.raw.converted_npl || ''} />
        )}
        {tab === 'diff' && hasDiff && (
          <DiffTab rule={rule} onAdopt={() => onAction(rule)} />
        )}
        {tab === 'source' && isAvailable && (
          <SourceMappingTab
            rule={rule}
            preview={preview}
            previewLoading={previewLoading}
            availableSourceTypes={availableSourceTypes}
            missingTypes={missingTypes}
            mergeMode={mergeMode}
            onMergeModeChange={setMergeMode}
            mergedSourceType={mergedSourceType}
            onMergedSourceTypeChange={setMergedSourceType}
            mappings={mappings}
            onMappingsChange={setMappings}
          />
        )}
      </div>

      <div className="shrink-0 border-t border-border px-4 py-3 flex items-center gap-2 bg-card">
        {isAvailable && preview?.already_imported && (
          <div className="flex-1 flex items-center gap-1.5 text-[10.5px] text-warning">
            <AlertTriangle className="w-[11px] h-[11px]" strokeWidth={2} />
            Already imported — re-importing creates a fork
          </div>
        )}
        {isAvailable && !preview?.already_imported && (mergeMode ? mergedSourceType : !allMapped) && (
          <div className="flex-1 flex items-center gap-1.5 text-[10.5px] text-warning">
            {!allMapped ? (
              <>
                <AlertTriangle className="w-[11px] h-[11px]" strokeWidth={2} />
                Map missing source types in Source mapping
              </>
            ) : (
              <>
                <Info className="w-[11px] h-[11px]" strokeWidth={2} />
                Source merged → <span className="font-mono">{mergedSourceType}</span>
              </>
            )}
          </div>
        )}
        {!isAvailable && <div className="flex-1" />}

        {isAvailable ? (
          <>
            <ImportSettingsPopover
              severity={severity || (preview?.proposed_severity as Severity) || 'medium'}
              proposedSeverity={preview?.proposed_severity as Severity | undefined}
              onSeverity={setSeverity}
              mode={mode}
              onMode={setMode}
            />
            <button
              type="button"
              onClick={handleImport}
              disabled={importing || !allMapped}
              className="h-[28px] px-3 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 text-[11.5px] font-medium flex items-center gap-1.5 disabled:opacity-60 disabled:cursor-not-allowed"
            >
              <Download className="w-[12px] h-[12px]" strokeWidth={2} />
              {importing ? 'Importing…' : 'Import rule'}
            </button>
          </>
        ) : (
          <PrimaryActionBtn rule={rule} onAction={() => onAction(rule)} />
        )}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------
// Overview tab — preview-driven for AVAILABLE rules, fallback for the rest
// ------------------------------------------------------------------

function OverviewTab({
  rule,
  preview,
  previewLoading,
  missingTypes,
  severity,
  mode,
  mergeMode,
  mergedSourceType,
  mappings,
  isAvailable,
  ruleFormat,
}: {
  rule: RepoRuleView;
  preview: import('@/lib/api/rule-repositories').ImportPreview | null | undefined;
  previewLoading: boolean;
  missingTypes: string[];
  severity: Severity;
  mode: ImportMode;
  mergeMode: boolean;
  mergedSourceType: string;
  mappings: Record<string, string>;
  isAvailable: boolean;
  ruleFormat: 'sigma' | 'nanosiem';
}) {
  const isSigma = ruleFormat === 'sigma';
  const description = preview?.proposed_description ?? rule.desc;
  const proposedSeverity = (preview?.proposed_severity ?? rule.severity) as Severity;
  const conversionStatus = preview?.conversion_status ?? rule.raw.conversion_status;
  const conversionWarnings = preview?.conversion_warnings ?? rule.raw.conversion_warnings ?? [];

  const severityOverridden = isAvailable && severity !== proposedSeverity;

  // Active mappings (skipped entries collapse to no-op so they don't render).
  const activeMappings = Object.entries(mappings).filter(
    ([, v]) => v && v !== '__skip__',
  );
  const hasIndividualMappings = !mergeMode && activeMappings.length > 0;
  const hasMerge = mergeMode && !!mergedSourceType;
  const hasAnyOverride = isAvailable && (hasIndividualMappings || hasMerge);

  return (
    <div className="p-4 space-y-4">
      {preview?.already_imported && (
        <div className="rounded-md border border-warning/30 bg-warning/5 px-3 py-2.5">
          <div className="flex items-center gap-1.5 text-[11.5px] font-medium text-warning mb-1">
            <AlertTriangle className="w-[12px] h-[12px]" strokeWidth={2} />
            Already imported
          </div>
          <div className="text-[10.5px] text-foreground/70 leading-relaxed">
            A copy of this rule already exists in your library
            {preview.existing_import_type
              ? ` as a ${preview.existing_import_type} import`
              : ''}
            . Re-importing creates a fork — your existing copy is left alone.
          </div>
        </div>
      )}

      <div>
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">
          Description
        </div>
        <div className="text-[12.5px] text-foreground/80 leading-relaxed">
          {description || '—'}
        </div>
      </div>

      {/* Source → destination summary. Loud when there's an active override. */}
      <div>
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5 flex items-center gap-1.5">
          On import
          {hasAnyOverride && (
            <span className="font-mono text-[9px] uppercase tracking-wider text-warning border border-warning/50 bg-warning/10 rounded px-1 py-px">
              custom
            </span>
          )}
        </div>
        <div
          className={cn(
            'rounded-md border px-3 py-2.5 space-y-2',
            hasAnyOverride
              ? 'border-warning/40 bg-warning/[0.06]'
              : 'border-border bg-card/30',
          )}
        >
          {hasMerge ? (
            <SourceMapRow from={(preview?.required_source_types ?? [rule.source]).join(', ')} to={mergedSourceType} overridden />
          ) : hasIndividualMappings ? (
            <div className="space-y-1.5">
              {activeMappings.map(([from, to]) => (
                <SourceMapRow key={from} from={from} to={to} overridden />
              ))}
            </div>
          ) : (
            <SourceMapRow from={rule.source} to={rule.source} />
          )}
          <div className="flex items-center gap-3 pt-1.5 border-t border-border/60">
            <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
              Severity
            </span>
            <SeverityDot sev={severity as RepoRuleView['severity']} />
            {severityOverridden && (
              <span className="font-mono text-[9.5px] text-muted-foreground">
                was{' '}
                <span className="text-foreground/70 line-through">{proposedSeverity}</span>
              </span>
            )}
            {severityOverridden && (
              <span className="font-mono text-[9px] uppercase tracking-wider text-warning border border-warning/50 bg-warning/10 rounded px-1 py-px">
                custom
              </span>
            )}
            {isAvailable && (
              <>
                <span className="ml-auto text-[10px] uppercase tracking-wider text-muted-foreground">
                  Mode
                </span>
                <span className="font-mono text-[11px] text-foreground/80 capitalize">
                  {mode}
                </span>
              </>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <MetaField
          k="Conversion"
          v={
            <span className="font-mono text-foreground/80 capitalize">{conversionStatus}</span>
          }
        />
        <MetaField
          k="MITRE"
          v={
            rule.mitre.length === 0 ? (
              <span className="text-muted-foreground">—</span>
            ) : (
              <div className="flex flex-wrap gap-1">
                {rule.mitre.map((m) => (
                  <span
                    key={m}
                    className="font-mono text-[10px] text-foreground/70 border border-border rounded px-1 py-px"
                  >
                    {m}
                  </span>
                ))}
              </div>
            )
          }
        />
        <MetaField
          k="Path"
          v={
            <span className="font-mono text-[10.5px] text-muted-foreground truncate block">
              {rule.path}
            </span>
          }
        />
      </div>

      {previewLoading && (
        <div className="text-[10.5px] text-muted-foreground font-mono">
          Loading preview…
        </div>
      )}

      {missingTypes.length > 0 && (
        <div className="rounded-md border border-warning/30 bg-warning/5 px-3 py-2.5">
          <div className="flex items-center gap-1.5 text-[11.5px] font-medium text-warning mb-1">
            <AlertTriangle className="w-[12px] h-[12px]" strokeWidth={2} />
            Missing source coverage
          </div>
          <div className="text-[10.5px] text-foreground/70 leading-relaxed">
            This rule expects {missingTypes.length === 1 ? 'this source type' : 'these source types'} that
            you don't have ingested:
          </div>
          <div className="mt-1.5 flex flex-wrap gap-1">
            {missingTypes.map((m) => (
              <span
                key={m}
                className="font-mono text-[10px] text-warning border border-warning/30 rounded px-1.5 py-px"
              >
                {m}
              </span>
            ))}
          </div>
          <div className="text-[10px] text-muted-foreground mt-1.5 leading-relaxed">
            Use the Source mapping tab to remap or merge them onto a source type you do have.
          </div>
        </div>
      )}

      {preview?.proposed_query && (
        <div>
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5 flex items-center gap-1">
            {isSigma ? 'Proposed query' : 'Query'}
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  className="text-muted-foreground/70 hover:text-foreground"
                  aria-label="What is this?"
                >
                  <HelpCircle className="w-3 h-3" strokeWidth={1.5} />
                </button>
              </TooltipTrigger>
              <TooltipContent>
                {isSigma
                  ? 'Generated by Sigma → nPL conversion. Review and adjust before importing.'
                  : 'The rule body that will run when scheduled. Review before importing.'}
              </TooltipContent>
            </Tooltip>
          </div>
          <pre className="rounded-md border border-border bg-card px-2.5 py-2 text-[11px] font-mono leading-relaxed text-foreground/80 whitespace-pre-wrap break-words">
            {preview.proposed_query}
          </pre>
        </div>
      )}

      {conversionWarnings.length > 0 && (
        <div className="rounded-md border border-warning/30 bg-warning/5 px-3 py-2.5">
          <div className="flex items-center gap-1.5 text-[11.5px] font-medium text-warning mb-1">
            <AlertTriangle className="w-[12px] h-[12px]" strokeWidth={2} />
            {isSigma ? 'Conversion warnings' : 'Validation warnings'}
          </div>
          <ul className="text-[10.5px] text-foreground/70 leading-relaxed space-y-0.5 list-disc pl-4">
            {conversionWarnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      )}

      {rule.status === 'DELETED' && (
        <div className="rounded-md border border-border bg-foreground/[0.03] px-3 py-2.5">
          <div className="flex items-center gap-1.5 text-[11.5px] font-medium text-foreground/70 mb-1">
            <X className="w-[12px] h-[12px]" strokeWidth={2} />
            Removed upstream
          </div>
          <div className="text-[10.5px] text-muted-foreground leading-relaxed">
            This rule is no longer present in the upstream repository.
          </div>
        </div>
      )}
    </div>
  );
}

function MetaField({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="text-[9.5px] uppercase tracking-wider text-muted-foreground mb-0.5">{k}</div>
      <div className="text-[11.5px] text-foreground">{v}</div>
    </div>
  );
}

function SourceMapRow({
  from,
  to,
  overridden,
}: {
  from: string;
  to: string;
  overridden?: boolean;
}) {
  return (
    <div className="flex items-center gap-2">
      <span className="font-mono text-[11.5px] text-foreground/80 truncate min-w-0">
        {from}
      </span>
      <ArrowRight
        className={cn('w-3 h-3 shrink-0', overridden ? 'text-warning' : 'text-muted-foreground/60')}
        strokeWidth={2}
      />
      <span
        className={cn(
          'font-mono text-[11.5px] truncate min-w-0',
          overridden ? 'text-warning font-medium' : 'text-foreground/80',
        )}
      >
        {to}
      </span>
      {overridden && (
        <span className="ml-auto shrink-0 font-mono text-[9px] uppercase tracking-wider text-warning border border-warning/50 bg-warning/10 rounded px-1 py-px">
          custom
        </span>
      )}
    </div>
  );
}

// ------------------------------------------------------------------
// Source mapping tab — Map individually / Merge to single, with funnel viz
// ------------------------------------------------------------------

function SourceMappingTab({
  rule,
  preview,
  previewLoading,
  availableSourceTypes,
  missingTypes,
  mergeMode,
  onMergeModeChange,
  mergedSourceType,
  onMergedSourceTypeChange,
  mappings,
  onMappingsChange,
}: {
  rule: RepoRuleView;
  preview: import('@/lib/api/rule-repositories').ImportPreview | null | undefined;
  previewLoading: boolean;
  availableSourceTypes: string[];
  /** Recomputed against `availableSourceTypes` so the tab and the Overview agree. */
  missingTypes: string[];
  mergeMode: boolean;
  onMergeModeChange: (b: boolean) => void;
  mergedSourceType: string;
  onMergedSourceTypeChange: (s: string) => void;
  mappings: Record<string, string>;
  onMappingsChange: (m: Record<string, string>) => void;
}) {
  const required = preview?.required_source_types ?? (rule.source && rule.source !== '—' ? [rule.source] : []);
  const missing = missingTypes;
  const suggestions = preview?.source_type_suggestions ?? [];

  const setMapping = (original: string, replacement: string) => {
    onMappingsChange({ ...mappings, [original]: replacement });
  };

  return (
    <div className="p-4 space-y-4">
      {previewLoading && (
        <div className="text-[10.5px] text-muted-foreground font-mono">Loading preview…</div>
      )}

      <div>
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">
          Upstream source types
        </div>
        <div className="flex flex-col gap-1">
          {required.length === 0 && (
            <div className="text-[11px] text-muted-foreground italic">
              No source_type filter detected in this rule.
            </div>
          )}
          {required.map((s) => {
            const isMissing = missing.some((m) => m.toLowerCase() === s.toLowerCase());
            return (
              <div
                key={s}
                className={cn(
                  'rounded-md border bg-card px-3 py-2 flex items-center gap-2',
                  isMissing ? 'border-warning/40' : 'border-border',
                )}
              >
                <Database
                  className={cn(
                    'w-[13px] h-[13px]',
                    isMissing ? 'text-warning' : 'text-muted-foreground',
                  )}
                  strokeWidth={1.5}
                />
                <span className="font-mono text-[12px] text-foreground">{s}</span>
                {isMissing && (
                  <span className="ml-auto font-mono text-[9.5px] uppercase tracking-wider text-warning border border-warning/40 rounded px-1 py-px">
                    missing
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Mode toggle */}
      <div className="grid grid-cols-2 gap-1.5">
        <ModeCard
          active={!mergeMode}
          onClick={() => onMergeModeChange(false)}
          title="Map individually"
          sub="Replace each missing source type with one you already have."
        />
        <ModeCard
          active={mergeMode}
          onClick={() => onMergeModeChange(true)}
          title="Merge to single"
          sub="Collapse the entire OR-chain to one source type."
        />
      </div>

      {mergeMode ? (
        <div>
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">
            Merge target
          </div>
          {/* Funnel viz */}
          <div className="rounded-md border border-border bg-card/30 px-3 py-3 mb-2">
            <div className="flex flex-col items-center gap-2">
              <div className="flex flex-wrap justify-center gap-1.5 max-w-full">
                {(required.length ? required : ['(none)']).map((s) => (
                  <span
                    key={s}
                    className="font-mono text-[10px] text-foreground/70 border border-border rounded px-1.5 py-px"
                  >
                    {s}
                  </span>
                ))}
              </div>
              <FunnelSvg />
              {mergedSourceType ? (
                <span className="font-mono text-[12px] text-primary border border-primary/40 bg-primary/10 rounded px-2 py-1">
                  {mergedSourceType}
                </span>
              ) : (
                <span className="font-mono text-[10.5px] text-muted-foreground">
                  pick a target below
                </span>
              )}
            </div>
          </div>
          <SourceTypeCombobox
            value={mergedSourceType}
            onSelect={onMergedSourceTypeChange}
            sourceTypes={availableSourceTypes}
            placeholder="Select target source type…"
            overridden={!!mergedSourceType}
            className="w-full"
          />
        </div>
      ) : (
        <div>
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">
            Map missing source types
          </div>
          {missing.length === 0 ? (
            <div className="text-[11px] text-muted-foreground italic">
              All required source types are available — no remapping needed.
            </div>
          ) : (
            <div className="flex flex-col gap-1.5">
              {missing.map((m) => {
                const sugg = suggestions.find((s) => s.missing_type === m)?.suggested_type;
                return (
                  <div
                    key={m}
                    className="rounded-md border border-border bg-card px-3 py-2 flex items-center gap-2"
                  >
                    <span className="font-mono text-[11.5px] text-warning truncate min-w-[60px]">
                      {m}
                    </span>
                    <ArrowRight
                      className="w-3 h-3 text-muted-foreground/60 shrink-0"
                      strokeWidth={2}
                    />
                    <SourceTypeCombobox
                      value={mappings[m] || ''}
                      onSelect={(v) => setMapping(m, v)}
                      sourceTypes={availableSourceTypes}
                      suggestedType={sugg}
                      placeholder="Pick replacement…"
                      allowSkip
                      overridden={!!mappings[m] && mappings[m] !== '__skip__'}
                      className="flex-1 min-w-0"
                    />
                    {sugg && !mappings[m] && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <button
                            type="button"
                            onClick={() => setMapping(m, sugg)}
                            className="h-[22px] px-1.5 rounded-md border border-success/40 bg-success/10 text-[10px] font-mono text-success hover:bg-success/15 flex items-center gap-1 shrink-0"
                          >
                            <Sparkles className="w-[10px] h-[10px]" strokeWidth={1.5} />
                            {sugg}
                          </button>
                        </TooltipTrigger>
                        <TooltipContent>Apply suggested replacement</TooltipContent>
                      </Tooltip>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      <div className="rounded-md border border-border bg-card/30 px-3 py-2 flex items-start gap-2">
        <Info className="w-[12px] h-[12px] text-muted-foreground mt-0.5" strokeWidth={1.5} />
        <div className="text-[10.5px] text-muted-foreground leading-relaxed">
          {mergeMode
            ? "Merge collapses the rule's source-type filter into one value before import."
            : 'Field references stay as-is; only the source_type predicate is rewritten.'}
        </div>
      </div>
    </div>
  );
}

function ModeCard({
  active,
  onClick,
  title,
  sub,
}: {
  active: boolean;
  onClick: () => void;
  title: string;
  sub: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'text-left rounded-md border px-2.5 py-2 transition',
        active
          ? 'border-primary/50 bg-primary/5'
          : 'border-border bg-card hover:border-border/80 hover:bg-muted/40',
      )}
    >
      <div className={cn('text-[12px] font-medium', active ? 'text-foreground' : 'text-foreground/70')}>
        {title}
      </div>
      <div className="text-[10px] text-muted-foreground mt-0.5 leading-snug">{sub}</div>
    </button>
  );
}

function FunnelSvg() {
  return (
    <svg
      viewBox="0 0 60 30"
      className="w-12 h-7 text-muted-foreground/60"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M2 4h56l-20 14v8h-16v-8z" />
    </svg>
  );
}

// ------------------------------------------------------------------
// Diff tab — side-by-side via the `diff` package, gated by linked detection
// rule. Adopt → editor; Dismiss → dismissUpstreamChanges.
// ------------------------------------------------------------------

function DiffTab({ rule, onAdopt }: { rule: RepoRuleView; onAdopt: () => void }) {
  const detectionRuleId = rule.raw.linked_detection_rule_id;
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: diff, isLoading } = useQuery({
    queryKey: ['rule-upstream-diff', detectionRuleId],
    queryFn: () =>
      detectionRuleId
        ? api.ruleRepositories.getUpstreamDiff(detectionRuleId)
        : Promise.resolve(null),
    enabled: !!detectionRuleId,
  });

  const dismissMutation = useMutation({
    mutationFn: () =>
      detectionRuleId
        ? api.ruleRepositories.dismissUpstreamChanges(detectionRuleId)
        : Promise.resolve(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rule-repository-upstream'] });
      queryClient.invalidateQueries({ queryKey: ['rule-repository-rules'] });
      toast({ title: 'Upstream changes dismissed' });
    },
    onError: (err: Error) => {
      toast({ title: 'Failed to dismiss', description: err.message, variant: 'destructive' });
    },
  });

  if (!detectionRuleId) {
    return (
      <div className="p-4">
        <div className="rounded-md border border-border px-3 py-3 text-center">
          <div className="text-[12px] font-medium text-foreground mb-1">
            No linked detection rule
          </div>
          <div className="text-[11px] text-muted-foreground leading-relaxed">
            Diff requires an imported rule. Try syncing again.
          </div>
        </div>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="p-4 text-[11px] text-muted-foreground font-mono">Loading diff…</div>
    );
  }

  if (!diff) {
    return (
      <div className="p-4 text-[11px] text-muted-foreground font-mono">
        Failed to load diff.
      </div>
    );
  }

  const queriesMatch = diff.upstream_query === diff.current_query;

  return (
    <div className="p-4 space-y-3">
      {/* Stats / status */}
      <div className="flex flex-wrap items-center gap-1.5 text-[10.5px]">
        {queriesMatch ? (
          <span className="rounded-md border border-success/40 bg-success/10 px-1.5 py-px font-mono text-success flex items-center gap-1">
            <Check className="w-[10px] h-[10px]" strokeWidth={2} />
            queries match
          </span>
        ) : (
          <span className="rounded-md border border-warning/40 bg-warning/10 px-1.5 py-px font-mono text-warning">
            query changed
          </span>
        )}
        {diff.customizations_applied && (
          <span className="rounded-md border border-primary/40 bg-primary/10 px-1.5 py-px font-mono text-primary flex items-center gap-1">
            <Info className="w-[10px] h-[10px]" strokeWidth={2} />
            customizations applied
          </span>
        )}
        {diff.upstream_title && diff.upstream_title !== diff.current_title && (
          <span className="font-mono text-muted-foreground">
            <span className="text-destructive line-through">{diff.current_title}</span>
            <ArrowRight className="w-[10px] h-[10px] inline mx-1" strokeWidth={2} />
            <span className="text-success">{diff.upstream_title}</span>
          </span>
        )}
      </div>

      <DiffViewer oldText={diff.current_query} newText={diff.upstream_query} />

      <div className="flex items-center gap-2 pt-1">
        <button
          type="button"
          onClick={() => dismissMutation.mutate()}
          disabled={dismissMutation.isPending}
          className="h-[26px] px-2.5 rounded-md border border-border bg-card hover:bg-muted text-[11px] text-muted-foreground hover:text-foreground"
        >
          Dismiss
        </button>
        <span className="flex-1" />
        <button
          type="button"
          onClick={onAdopt}
          className="h-[26px] px-2.5 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 text-[11px] font-medium flex items-center gap-1"
        >
          <ArrowUpRight className="w-[11px] h-[11px]" strokeWidth={2} />
          Merge in editor
        </button>
      </div>
    </div>
  );
}

function DiffViewer({ oldText, newText }: { oldText: string; newText: string }) {
  const lines = useMemo(() => {
    const changes = Diff.diffLines(oldText || '', newText || '');
    const out: { type: 'added' | 'removed' | 'unchanged'; content: string }[] = [];
    for (const change of changes) {
      const seg = change.value.split('\n');
      if (seg[seg.length - 1] === '') seg.pop();
      for (const line of seg) {
        if (change.added) out.push({ type: 'added', content: line });
        else if (change.removed) out.push({ type: 'removed', content: line });
        else out.push({ type: 'unchanged', content: line });
      }
    }
    return out;
  }, [oldText, newText]);

  const stats = useMemo(() => {
    return {
      added: lines.filter((l) => l.type === 'added').length,
      removed: lines.filter((l) => l.type === 'removed').length,
    };
  }, [lines]);

  if (oldText === newText) {
    return (
      <div className="rounded-md border border-border bg-card/30 px-3 py-3 text-center text-[11px] text-muted-foreground flex items-center justify-center gap-1.5">
        <Check className="w-[12px] h-[12px] text-success" strokeWidth={2} />
        No differences — queries are identical
      </div>
    );
  }

  return (
    <div className="rounded-md border border-border overflow-hidden">
      <div className="flex items-center gap-3 px-2.5 py-1.5 bg-card border-b border-border text-[10.5px] font-mono">
        <span className="text-muted-foreground">your → upstream</span>
        <span className="flex items-center gap-1 text-success">
          <Plus className="w-[10px] h-[10px]" strokeWidth={2} />
          {stats.added}
        </span>
        <span className="flex items-center gap-1 text-destructive">
          <Minus className="w-[10px] h-[10px]" strokeWidth={2} />
          {stats.removed}
        </span>
      </div>
      <div className="max-h-[420px] overflow-auto font-mono text-[11px] leading-relaxed">
        {lines.map((line, i) => (
          <div
            key={`${line.type[0]}-${i}-${line.content.slice(0, 32)}`}
            className={cn(
              'flex',
              line.type === 'added'
                ? 'bg-success/10 text-success'
                : line.type === 'removed'
                  ? 'bg-destructive/10 text-destructive'
                  : 'text-foreground/80',
            )}
          >
            <span
              className={cn(
                'w-5 shrink-0 text-center select-none border-r border-border',
                line.type === 'added'
                  ? 'bg-success/15 text-success'
                  : line.type === 'removed'
                    ? 'bg-destructive/15 text-destructive'
                    : 'bg-card/30 text-muted-foreground',
              )}
            >
              {line.type === 'added' ? '+' : line.type === 'removed' ? '−' : ' '}
            </span>
            <pre className="flex-1 px-2 py-px whitespace-pre-wrap break-all">
              {line.content || ' '}
            </pre>
          </div>
        ))}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------
// YAML tab — light tokenizer
// ------------------------------------------------------------------

function YamlTab({ yaml }: { yaml: string }) {
  return (
    <pre className="text-[11.5px] font-mono leading-relaxed text-foreground p-4 whitespace-pre overflow-x-auto">
      {tokenizeYaml(yaml)}
    </pre>
  );
}

function tokenizeYaml(src: string): React.ReactNode {
  if (!src) return <span className="text-muted-foreground">(empty)</span>;
  const lines = src.split('\n');
  return lines.map((line, i) => {
    const parts: React.ReactNode[] = [];
    let remaining = line;

    const lead = remaining.match(/^\s*/)?.[0] || '';
    if (lead) parts.push(<span key="lead">{lead}</span>);
    remaining = remaining.slice(lead.length);

    if (remaining.startsWith('#')) {
      return (
        <Fragment key={i}>
          <span style={{ color: 'var(--color-muted-foreground)' }}>{line}</span>
          {'\n'}
        </Fragment>
      );
    }

    if (remaining.startsWith('- ')) {
      parts.push(
        <span key="dash" style={{ color: 'var(--color-primary)' }}>
          -
        </span>,
      );
      remaining = remaining.slice(2);
    }

    const kvMatch = remaining.match(/^([A-Za-z_][A-Za-z0-9_.-]*)(\s*:)/);
    if (kvMatch) {
      parts.push(
        <span key="key" style={{ color: 'var(--color-foreground)' }}>
          {kvMatch[1]}
        </span>,
      );
      parts.push(<span key="col">{kvMatch[2]}</span>);
      remaining = remaining.slice(kvMatch[0].length);
    }

    const tokens = remaining.split(/("[^"]*"|'[^']*')/g);
    tokens.forEach((t, j) => {
      if (!t) return;
      if (/^["']/.test(t)) {
        parts.push(
          <span key={`s${j}`} style={{ color: 'var(--color-brand-2, var(--color-primary))' }}>
            {t}
          </span>,
        );
      } else if (/^\s*\d+[smhd]?\s*$/.test(t) || /^\s*\d+\s*$/.test(t)) {
        parts.push(
          <span key={`n${j}`} style={{ color: 'var(--color-warning)' }}>
            {t}
          </span>,
        );
      } else {
        parts.push(
          <span key={`t${j}`} style={{ color: 'color-mix(in srgb, var(--color-foreground) 75%, transparent)' }}>
            {t}
          </span>,
        );
      }
    });

    return (
      <Fragment key={i}>
        {parts}
        {'\n'}
      </Fragment>
    );
  });
}

// ------------------------------------------------------------------
// Severity + mode popover (per-rule import)
// ------------------------------------------------------------------

function ImportSettingsPopover({
  severity,
  proposedSeverity,
  onSeverity,
  mode,
  onMode,
}: {
  severity: Severity;
  proposedSeverity: Severity | undefined;
  onSeverity: (s: Severity) => void;
  mode: ImportMode;
  onMode: (m: ImportMode) => void;
}) {
  const [open, setOpen] = useState(false);
  const overridden = proposedSeverity && severity !== proposedSeverity;

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <Tooltip>
        <TooltipTrigger asChild>
          <PopoverTrigger asChild>
            <button
              type="button"
              className="h-[28px] w-[28px] rounded-md border border-border bg-card hover:bg-muted text-foreground/70 hover:text-foreground flex items-center justify-center relative"
              aria-label="Import settings"
            >
              <Settings2 className="w-[13px] h-[13px]" strokeWidth={1.5} />
              {overridden && (
                <span className="absolute -top-px -right-px w-[6px] h-[6px] rounded-full bg-warning border border-card" />
              )}
            </button>
          </PopoverTrigger>
        </TooltipTrigger>
        <TooltipContent>Import settings</TooltipContent>
      </Tooltip>
      <PopoverContent align="end" className="w-[280px] p-3 space-y-3">
        <div>
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">
            Severity
          </div>
          <div className="flex flex-wrap gap-1">
            {SEVERITIES.map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => onSeverity(s)}
                className={cn(
                  'h-[24px] px-2 rounded-md text-[11px] border font-mono capitalize transition',
                  severity === s
                    ? 'border-primary/40 bg-primary/10 text-primary'
                    : 'border-border bg-card text-foreground/70 hover:bg-muted',
                )}
              >
                {s}
              </button>
            ))}
          </div>
          {overridden && (
            <div className="text-[10px] text-muted-foreground mt-1.5 flex items-center gap-1">
              <Info className="w-[10px] h-[10px]" strokeWidth={1.5} />
              Overrides upstream <span className="font-mono">{proposedSeverity}</span>
            </div>
          )}
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">
            Initial mode
          </div>
          <div className="flex flex-col gap-1">
            {(Object.keys(MODE_LABELS) as ImportMode[]).map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => onMode(m)}
                className={cn(
                  'text-left rounded-md border px-2.5 py-1.5 transition',
                  mode === m
                    ? 'border-primary/50 bg-primary/5'
                    : 'border-border bg-card hover:bg-muted/40',
                )}
              >
                <div
                  className={cn(
                    'text-[11.5px] font-medium',
                    mode === m ? 'text-foreground' : 'text-foreground/70',
                  )}
                >
                  {MODE_LABELS[m]}
                </div>
                <div className="text-[10px] text-muted-foreground leading-snug">
                  {MODE_HINTS[m]}
                </div>
              </button>
            ))}
          </div>
        </div>
      </PopoverContent>
    </Popover>
  );
}

// ------------------------------------------------------------------
// Primary action — non-import statuses
// ------------------------------------------------------------------

function PrimaryActionBtn({ rule, onAction }: { rule: RepoRuleView; onAction: () => void }) {
  if (rule.status === 'IMPORTED') {
    return (
      <button
        type="button"
        onClick={onAction}
        className="h-[28px] px-3 rounded-md border border-border bg-card hover:bg-muted text-[11.5px] font-medium text-foreground/80 flex items-center gap-1.5"
      >
        <ExternalLink className="w-[12px] h-[12px]" strokeWidth={1.5} />
        Open in editor
      </button>
    );
  }
  if (rule.status === 'DELETED') {
    return (
      <button
        type="button"
        onClick={onAction}
        className="h-[28px] px-3 rounded-md bg-destructive/10 border border-destructive/30 text-destructive text-[11.5px] font-medium hover:bg-destructive/15"
      >
        Remove from library
      </button>
    );
  }
  if (rule.status === 'DRIFT') {
    return (
      <button
        type="button"
        onClick={onAction}
        className="h-[28px] px-3 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 text-[11.5px] font-medium"
      >
        Resolve drift
      </button>
    );
  }
  if (rule.status === 'UPDATED') {
    return (
      <button
        type="button"
        onClick={onAction}
        className="h-[28px] px-3 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 text-[11.5px] font-medium flex items-center gap-1.5"
      >
        <ArrowUpRight className="w-[12px] h-[12px]" strokeWidth={2} />
        Update
      </button>
    );
  }
  return null;
}

