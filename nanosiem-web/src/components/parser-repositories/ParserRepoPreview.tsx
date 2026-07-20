// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-526 — right-side parser preview pane.
// Tabs: Overview | VRL | Schema | Import options
// Footer: Linked/Forked toggle · Source Config picker · Import as draft

import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowUpRight,
  Check,
  GitCommit,
  Info,
  Link as LinkIcon,
  Loader2,
  Eye,
  X,
  GitFork,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import type { SourceConfiguration } from '@/lib/api/types';
import type { ParserImportPreview } from '@/lib/api/parser-repositories';
import { CategoryChip, StatusChip, TransportChip } from './chips';
import type { RepoParserView, RepoTransport } from './helpers';

interface PreviewProps {
  parser: RepoParserView;
  preview: ParserImportPreview | null;
  previewLoading: boolean;
  importMode: 'linked' | 'forked';
  onChangeImportMode: (m: 'linked' | 'forked') => void;
  selectedConfigId: string | null;
  onChangeConfigId: (id: string | null) => void;
  sourceTypeInput: string;
  onChangeSourceType: (s: string) => void;
  configs: SourceConfiguration[];
  importing: boolean;
  onImport: () => void;
  onClose: () => void;
  onViewDiff: (logSourceId: string) => void;
  onOpenLogSource: (logSourceId: string) => void;
}

export function ParserRepoPreview({
  parser,
  preview,
  previewLoading,
  importMode,
  onChangeImportMode,
  selectedConfigId,
  onChangeConfigId,
  sourceTypeInput,
  onChangeSourceType,
  configs,
  importing,
  onImport,
  onClose,
  onViewDiff,
  onOpenLogSource,
}: PreviewProps) {
  const [tab, setTab] = useState<'overview' | 'vrl' | 'schema' | 'import'>('overview');

  useEffect(() => {
    setTab('overview');
  }, [parser.id]);

  const isImported = parser.status === 'IMPORTED';
  const isDrift = parser.status === 'DRIFT';
  const isUpdated = parser.status === 'UPDATED';
  const isDeleted = parser.status === 'DELETED';

  const linkedLogSourceId = parser.raw.linked_log_source_id ?? preview?.existing_log_source_id ?? null;

  return (
    <div className="h-full min-h-0 flex flex-col border-l border-border bg-card/30">
      {/* Header */}
      <div className="px-4 pt-3 pb-0 shrink-0">
        <div className="flex items-start gap-2.5">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              <StatusChip status={parser.status} />
              <CategoryChip cat={parser.category} />
              <TransportChip t={parser.transport} />
            </div>
            <div className="font-mono text-[14px] text-foreground leading-tight break-words">
              {parser.name}
            </div>
            <div className="text-[10.5px] text-muted-foreground mt-1 truncate">
              {[parser.vendor, parser.product].filter(Boolean).join(' · ') || '—'}
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="h-[24px] w-[24px] rounded-md flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-foreground/5 shrink-0"
            aria-label="Close preview"
          >
            <X className="w-[13px] h-[13px]" strokeWidth={1.5} />
          </button>
        </div>

        {/* Commit / author strip */}
        <div className="mt-3 flex items-center gap-2 text-[10.5px] font-mono text-muted-foreground flex-wrap">
          <span className="flex items-center gap-1">
            <GitCommit className="w-[11px] h-[11px]" strokeWidth={1.5} />
            <span className="text-foreground/70">{parser.commit}</span>
          </span>
          {parser.version && (
            <>
              <span>·</span>
              <span>v{parser.version}</span>
            </>
          )}
          {parser.updated && (
            <>
              <span>·</span>
              <span>{parser.updated}</span>
            </>
          )}
        </div>

        {/* Tabs */}
        <div className="flex items-center gap-0.5 mt-3 -mb-px">
          {(
            [
              { id: 'overview', label: 'Overview', disabled: false },
              { id: 'vrl', label: 'VRL', disabled: false },
              { id: 'schema', label: 'Schema', disabled: false },
              { id: 'import', label: 'Import', disabled: isDeleted || isImported },
            ] as const
          ).map((t) => (
            <button
              key={t.id}
              type="button"
              disabled={t.disabled}
              onClick={() => setTab(t.id)}
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
              {t.id === 'vrl' && isUpdated && (
                <span className="ml-1 font-mono text-[9.5px] text-warning">UPDATED</span>
              )}
              {t.id === 'vrl' && isDrift && (
                <span className="ml-1 font-mono text-[9.5px] text-destructive">DRIFT</span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 min-h-0 overflow-auto border-t border-border">
        {tab === 'overview' && (
          <OverviewPane
            parser={parser}
            onViewDiff={onViewDiff}
            importable={!isImported && !isDeleted}
            selectedConfigId={selectedConfigId}
            onChangeConfigId={onChangeConfigId}
            sourceTypeInput={sourceTypeInput}
            onChangeSourceType={onChangeSourceType}
            configs={configs}
          />
        )}
        {tab === 'vrl' && <VrlPane parser={parser} />}
        {tab === 'schema' && <SchemaPane parser={parser} />}
        {tab === 'import' && (
          <ImportOptionsPane
            parser={parser}
            preview={preview}
            previewLoading={previewLoading}
            importMode={importMode}
            onChangeImportMode={onChangeImportMode}
          />
        )}
      </div>

      {/* Footer actions */}
      <div className="shrink-0 border-t border-border px-4 py-3 flex items-center gap-2 bg-card">
        {isImported && linkedLogSourceId ? (
          <>
            <div className="flex-1 flex items-center gap-1.5 text-[11px] text-muted-foreground">
              <Check className="w-[11px] h-[11px] text-success" strokeWidth={2} />
              Feeding the imported log source
            </div>
            <button
              type="button"
              onClick={() => onOpenLogSource(linkedLogSourceId)}
              className="h-[28px] px-3 rounded-md border border-border bg-card hover:bg-muted text-[11.5px] font-medium text-foreground/80"
            >
              View log source
            </button>
          </>
        ) : isDeleted ? (
          <>
            <div className="flex-1 text-[11px] text-muted-foreground">
              This parser was removed upstream.
            </div>
            <button
              type="button"
              className="h-[28px] px-3 rounded-md text-destructive hover:bg-destructive/5 text-[11.5px]"
            >
              Remove
            </button>
          </>
        ) : isDrift && linkedLogSourceId ? (
          <>
            <div className="flex-1 text-[11px] text-muted-foreground">
              Forked copy diverges from upstream.
            </div>
            <button
              type="button"
              onClick={() => onViewDiff(linkedLogSourceId)}
              className="h-[28px] px-3 rounded-md border border-border bg-card hover:bg-muted text-[11.5px] font-medium text-foreground/80 flex items-center gap-1.5"
            >
              <Eye className="w-[12px] h-[12px]" strokeWidth={1.5} />
              Resolve
            </button>
          </>
        ) : (
          <>
            <div className="flex items-center rounded-md border border-border bg-background overflow-hidden shrink-0">
              <ModeBtn
                active={importMode === 'linked'}
                onClick={() => onChangeImportMode('linked')}
                label="Linked"
                tooltip="Auto-update from upstream"
              />
              <div className="w-px h-[22px] bg-border" />
              <ModeBtn
                active={importMode === 'forked'}
                onClick={() => onChangeImportMode('forked')}
                label="Forked"
                tooltip="Edit locally; drift surfaces when upstream changes"
              />
            </div>
            <div className="flex-1" />
            <button
              type="button"
              onClick={() => setTab('import')}
              className="h-[28px] px-2 rounded-md text-muted-foreground hover:text-foreground hover:bg-foreground/5 text-[11.5px] shrink-0"
            >
              Options
            </button>
            <button
              type="button"
              onClick={onImport}
              disabled={importing || previewLoading || (preview?.already_imported ?? false)}
              className={cn(
                'h-[28px] px-3 rounded-md text-[11.5px] font-medium flex items-center gap-1.5 shrink-0',
                importing || previewLoading
                  ? 'bg-primary/60 text-primary-foreground cursor-not-allowed'
                  : 'bg-primary text-primary-foreground hover:bg-primary/90',
              )}
            >
              {importing ? (
                <Loader2 className="w-[12px] h-[12px] animate-spin" strokeWidth={2} />
              ) : null}
              {isUpdated ? 'Update' : isDrift ? 'Resolve' : 'Import'}
            </button>
          </>
        )}
      </div>
    </div>
  );
}

function ModeBtn({
  active,
  onClick,
  label,
  tooltip,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
  tooltip: string;
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          onClick={onClick}
          className={cn(
            'h-[28px] px-2.5 flex items-center gap-1.5 text-[11px] font-medium transition',
            active
              ? 'bg-primary/10 text-primary'
              : 'text-muted-foreground hover:text-foreground hover:bg-foreground/5',
          )}
        >
          <span
            className={cn(
              'w-1.5 h-1.5 rounded-full',
              active ? 'bg-primary' : 'bg-muted-foreground/50',
            )}
          />
          {label}
        </button>
      </TooltipTrigger>
      <TooltipContent>{tooltip}</TooltipContent>
    </Tooltip>
  );
}

// ==================================================================
// Overview tab
// ==================================================================

function OverviewPane({
  parser,
  onViewDiff,
  importable,
  selectedConfigId,
  onChangeConfigId,
  sourceTypeInput,
  onChangeSourceType,
  configs,
}: {
  parser: RepoParserView;
  onViewDiff: (logSourceId: string) => void;
  importable: boolean;
  selectedConfigId: string | null;
  onChangeConfigId: (id: string | null) => void;
  sourceTypeInput: string;
  onChangeSourceType: (s: string) => void;
  configs: SourceConfiguration[];
}) {
  const linkedId = parser.raw.linked_log_source_id ?? null;
  // NAN-1149: enrichment parsers don't describe a log source_type/transport;
  // they route a per-source mapping into a target table. Surface that pair
  // instead of the log-routing fields.
  const isEnrichment = parser.raw.kind === 'enrichment';
  // NAN-1932: the source_type + dispatch controls used to live only in the
  // Import tab, which users didn't discover. Surface them here on the default
  // landing tab whenever the parser is actually importable (not already
  // imported/deleted) and not an enrichment parser (no log routing to pick).
  const showRouting = importable && !isEnrichment;
  return (
    <div className="p-4 space-y-4">
      <div>
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">
          Description
        </div>
        <div className="text-[12.5px] text-foreground/80 leading-relaxed">
          {parser.desc !== '—' ? parser.desc : 'No description provided.'}
        </div>
      </div>

      {/* Routing — source_type + dispatch config, the two fields users most
          often adjust before importing. Grouped in a card so they read as the
          actionable settings on this tab. */}
      {showRouting && (
        <div className="rounded-md border border-border bg-card p-3 space-y-4">
          <SourceTypeField
            sourceTypeInput={sourceTypeInput}
            onChangeSourceType={onChangeSourceType}
          />
          <DispatchFromField
            parser={parser}
            configs={configs}
            selectedConfigId={selectedConfigId}
            onChangeConfigId={onChangeConfigId}
          />
        </div>
      )}

      <div className="grid grid-cols-2 gap-3">
        {isEnrichment ? (
          <>
            <Meta
              k="Enrich kind"
              v={<span className="font-mono">{parser.raw.enrich_kind || '—'}</span>}
            />
            <Meta
              k="Enrich source"
              v={<span className="font-mono">{parser.raw.enrich_source || '—'}</span>}
            />
            <Meta
              k="Target table"
              v={<span className="font-mono">{parser.raw.target_table || '—'}</span>}
            />
          </>
        ) : (
          <>
            {/* When the editable Source type field is shown above, don't repeat
                it read-only here. */}
            {!showRouting && (
              <Meta
                k="Source type"
                v={<span className="font-mono">{parser.sourceType}</span>}
              />
            )}
            <Meta
              k="Transport"
              v={parser.transport ? <TransportChip t={parser.transport} /> : <span>—</span>}
            />
          </>
        )}
        <Meta
          k="Category"
          v={parser.category ? <CategoryChip cat={parser.category} /> : <span>—</span>}
        />
        <Meta
          k="Vendor / product"
          v={
            <span className="text-foreground/80">
              {[parser.vendor, parser.product].filter(Boolean).join(' · ') || '—'}
            </span>
          }
        />
        <Meta
          k="Path"
          v={
            <span className="font-mono text-[10.5px] text-muted-foreground truncate block">
              {parser.path}
            </span>
          }
        />
        <Meta
          k="Version"
          v={
            <span className="font-mono">
              {parser.version ? `v${parser.version}` : '—'}
              {parser.upstreamVersion &&
                parser.upstreamVersion !== parser.version &&
                parser.status === 'UPDATED' && (
                  <span className="text-muted-foreground line-through ml-2 text-[10.5px]">
                    v{parser.version}
                  </span>
                )}
            </span>
          }
        />
        {parser.importMode && parser.status !== 'AVAILABLE' && (
          <Meta
            k="Import mode"
            v={
              <span
                className={cn(
                  'font-mono text-[11px]',
                  parser.importMode === 'linked' ? 'text-success' : 'text-foreground/80',
                )}
              >
                {parser.importMode}
              </span>
            }
          />
        )}
      </div>

      {/* Drift warning */}
      {parser.status === 'DRIFT' && (
        <div className="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2.5">
          <div className="flex items-center gap-1.5 text-[11.5px] font-medium text-destructive mb-1">
            <AlertTriangle className="w-[12px] h-[12px]" strokeWidth={2} />
            Forked copy diverges from upstream
          </div>
          <div className="text-[10.5px] text-muted-foreground leading-relaxed">
            The upstream repository has new changes that differ from your forked copy. Open the diff
            to compare and decide whether to merge upstream into your fork or keep your local edits.
          </div>
          {linkedId && (
            <button
              type="button"
              onClick={() => onViewDiff(linkedId)}
              className="mt-2 h-[24px] px-2 rounded-md border border-destructive/30 bg-destructive/5 text-destructive text-[10.5px] font-mono hover:bg-destructive/10 inline-flex items-center gap-1"
            >
              <Eye className="w-[10px] h-[10px]" strokeWidth={1.5} />
              View diff
            </button>
          )}
        </div>
      )}

      {/* Updated hint */}
      {parser.status === 'UPDATED' && (
        <div className="rounded-md border border-warning/30 bg-warning/5 px-3 py-2.5">
          <div className="flex items-center gap-1.5 text-[11.5px] font-medium text-warning mb-1">
            <ArrowUpRight className="w-[12px] h-[12px]" strokeWidth={2} />
            Upstream update available
          </div>
          <div className="text-[10.5px] text-muted-foreground leading-relaxed">
            A newer version of this parser is available upstream. Use the Update button to apply it
            to the linked log source.
          </div>
          {parser.upstreamVersion && parser.version && (
            <div className="mt-1.5 font-mono text-[10px] text-muted-foreground">
              v{parser.version} → v{parser.upstreamVersion}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Meta({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="text-[9.5px] uppercase tracking-wider text-muted-foreground mb-0.5">{k}</div>
      <div className="text-[11.5px] text-foreground">{v}</div>
    </div>
  );
}

// ==================================================================
// Routing controls — the source_type name and the "Dispatch from"
// config picker. Shared by the Overview tab (importable parsers land
// here) so users don't have to hunt for them. NAN-1932.
// ==================================================================

function SourceTypeField({
  sourceTypeInput,
  onChangeSourceType,
}: {
  sourceTypeInput: string;
  onChangeSourceType: (s: string) => void;
}) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">
        Source type
      </div>
      <input
        type="text"
        value={sourceTypeInput}
        onChange={(e) => onChangeSourceType(e.target.value)}
        placeholder="e.g., apache"
        className="w-full h-[30px] px-2.5 rounded-md border border-border bg-card text-[12px] font-mono focus:outline-none focus:border-primary"
      />
      <div className="text-[10.5px] text-muted-foreground mt-1 leading-relaxed">
        {sourceTypeInput ? (
          <>
            Routes by <code className="text-foreground">source_type = &quot;{sourceTypeInput}&quot;</code>
          </>
        ) : (
          'Identifies this log type so the dispatch config can route events into the parser.'
        )}
      </div>
    </div>
  );
}

function DispatchFromField({
  parser,
  configs,
  selectedConfigId,
  onChangeConfigId,
}: {
  parser: RepoParserView;
  configs: SourceConfiguration[];
  selectedConfigId: string | null;
  onChangeConfigId: (id: string | null) => void;
}) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">
        Dispatch from
      </div>
      <div className="text-[11px] text-muted-foreground mb-2 leading-relaxed">
        The Source Config that will route events into this parser. Compatible configs are
        highlighted based on the parser's transport.
      </div>
      {configs.length === 0 ? (
        <div className="rounded-md border border-border bg-card px-3 py-2.5 text-[11px] text-muted-foreground leading-relaxed">
          No deployed source configurations. Create or deploy one before importing — the parser
          still imports as a draft, but no events will route into it until a config exists.
        </div>
      ) : (
        <div className="space-y-1.5">
          {configs.map((c) => {
            const compat = isTransportCompat(parser.transport, c.config_type);
            const active = selectedConfigId === c.id;
            return (
              <button
                key={c.id}
                type="button"
                onClick={() => onChangeConfigId(c.id)}
                className={cn(
                  'w-full text-left rounded-md border px-3 py-2 flex items-center gap-2.5 transition',
                  active
                    ? 'border-primary/40 bg-primary/5'
                    : 'border-border bg-card hover:border-border/80 hover:bg-muted/40',
                )}
              >
                <span
                  className={cn(
                    'w-[10px] h-[10px] rounded-full border-2',
                    active ? 'border-primary bg-primary' : 'border-muted-foreground/50 bg-transparent',
                  )}
                />
                <div className="flex-1 min-w-0">
                  <div className="text-[12px] font-medium text-foreground flex items-center gap-1.5">
                    {c.name}
                    {compat ? (
                      <span className="text-[9px] font-mono uppercase tracking-wider text-success border border-success/30 bg-success/5 rounded px-1 py-px">
                        compat
                      </span>
                    ) : (
                      <span className="text-[9px] font-mono uppercase tracking-wider text-muted-foreground border border-border rounded px-1 py-px">
                        {c.config_type}
                      </span>
                    )}
                  </div>
                  {c.description && (
                    <div className="text-[10.5px] text-muted-foreground truncate">
                      {c.description}
                    </div>
                  )}
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ==================================================================
// VRL tab — light syntax highlighting
// ==================================================================

function VrlPane({ parser }: { parser: RepoParserView }) {
  // NAN-1149: enrichment parsers carry their logic in `normalize_vrl` (the
  // mapping emitted into the enrichment lane), not a log `parser_vrl`.
  const isEnrichment = parser.raw.kind === 'enrichment';
  const vrl = (isEnrichment ? parser.raw.normalize_vrl : parser.raw.parser_vrl) ?? '';
  const tokens = useMemo(() => tokenizeVrl(vrl), [vrl]);
  if (!vrl) {
    return (
      <div className="p-4 text-[11.5px] text-muted-foreground">
        {isEnrichment
          ? 'No normalize VRL available for this enrichment parser.'
          : 'No VRL source available for this parser.'}
      </div>
    );
  }
  return (
    <pre className="text-[11.5px] font-mono leading-relaxed text-foreground p-4 whitespace-pre overflow-x-auto">
      {tokens}
    </pre>
  );
}

const VRL_KEYWORDS = new Set([
  'if',
  'else',
  'for',
  'return',
  'null',
  'true',
  'false',
  'exists',
  'downcase',
  'upcase',
  'del',
  'parse_timestamp',
  'parse_regex',
  'parse_json',
  'from_unix_timestamp',
  'to_int',
  'to_string',
  'is_string',
  'flatten',
  'match',
]);

function tokenizeVrl(src: string): React.ReactNode {
  if (!src) return null;
  const lines = src.split('\n');
  return lines.map((line, i) => {
    if (!line) return <div key={i}>{' '}</div>;
    const parts: React.ReactNode[] = [];
    let rem = line;

    const lead = rem.match(/^\s*/)![0];
    if (lead) parts.push(<span key="w">{lead}</span>);
    rem = rem.slice(lead.length);

    if (rem.startsWith('#')) {
      parts.push(
        <span key="c" style={{ color: 'var(--color-muted-foreground)' }}>
          {rem}
        </span>,
      );
      return <div key={i}>{parts}</div>;
    }

    const tokens = rem.split(
      /("[^"]*"|'[^']*'|r'[^']*'|\b[a-zA-Z_][a-zA-Z0-9_]*!?|\.[a-zA-Z_][a-zA-Z0-9_.]*|[{}()[\],|=!<>+\-*/])/g,
    );
    tokens.forEach((t, j) => {
      if (!t) return;
      const k = `t${j}`;
      if (/^["']/.test(t) || /^r'/.test(t))
        parts.push(
          <span key={k} style={{ color: 'oklch(72% 0.13 140)' }}>
            {t}
          </span>,
        );
      else if (/^\.[a-zA-Z_]/.test(t))
        parts.push(
          <span key={k} style={{ color: 'var(--color-primary)' }}>
            {t}
          </span>,
        );
      else if (/!$/.test(t))
        parts.push(
          <span key={k} style={{ color: 'oklch(78% 0.13 60)' }}>
            {t}
          </span>,
        );
      else if (VRL_KEYWORDS.has(t))
        parts.push(
          <span key={k} style={{ color: 'oklch(72% 0.14 290)' }}>
            {t}
          </span>,
        );
      else if (/^[0-9]+$/.test(t))
        parts.push(
          <span key={k} style={{ color: 'oklch(72% 0.13 60)' }}>
            {t}
          </span>,
        );
      else
        parts.push(
          <span key={k} style={{ color: 'var(--color-foreground)' }}>
            {t}
          </span>,
        );
    });
    return <div key={i}>{parts}</div>;
  });
}

// ==================================================================
// Schema tab — normalized fields the parser produces
// ==================================================================

function SchemaPane({ parser }: { parser: RepoParserView }) {
  // The backend doesn't yet expose a structured schema field list. As a
  // best-effort, surface the assignments parsed out of the VRL — any line
  // that begins with `.field = …`. Once the API exposes a typed schema
  // list, swap this for that.
  const fields = useMemo(() => extractFieldsFromVrl(parser.raw.parser_vrl), [parser.raw.parser_vrl]);
  return (
    <div className="p-4 space-y-3">
      <div>
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">
          Normalized fields
        </div>
        <div className="text-[11.5px] text-muted-foreground leading-relaxed">
          After this parser runs, events will expose the following fields. Search autocomplete and
          dashboards suggest from the union across imported log sources.
        </div>
      </div>
      {fields.length > 0 ? (
        <div className="flex flex-wrap gap-1.5">
          {fields.map((f) => (
            <span
              key={f}
              className="font-mono text-[10.5px] text-foreground bg-card border border-border rounded px-2 py-1 inline-flex items-center gap-1.5"
            >
              <span className="w-1 h-1 rounded-full bg-primary" />
              {f}
            </span>
          ))}
        </div>
      ) : (
        <div className="text-[11px] text-muted-foreground">
          Could not extract a field list from the VRL. The schema is determined at parse-time.
        </div>
      )}

      <div className="rounded-md border border-border px-3 py-2.5 bg-card">
        <div className="flex items-center gap-1.5 text-[11.5px] font-medium text-foreground/80 mb-1">
          <Info className="w-[12px] h-[12px]" strokeWidth={1.5} />
          Field index
        </div>
        <div className="text-[10.5px] text-muted-foreground leading-relaxed">
          Normalized fields from every imported parser feed the shared field index. Search
          autocomplete and dashboard builders suggest from the union across all your log sources.
        </div>
      </div>
    </div>
  );
}

function extractFieldsFromVrl(vrl: string | null | undefined): string[] {
  if (!vrl) return [];
  const seen = new Set<string>();
  const out: string[] = [];
  const re = /^\s*(\.[a-zA-Z_][a-zA-Z0-9_.]*)\s*[+|]?=/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(vrl))) {
    const f = m[1];
    if (!seen.has(f)) {
      seen.add(f);
      out.push(f);
    }
  }
  return out.slice(0, 64);
}

// ==================================================================
// Import options tab — Linked vs Forked + target config picker + naming
// ==================================================================

function ImportOptionsPane({
  parser,
  preview,
  previewLoading,
  importMode,
  onChangeImportMode,
}: {
  parser: RepoParserView;
  preview: ParserImportPreview | null;
  previewLoading: boolean;
  importMode: 'linked' | 'forked';
  onChangeImportMode: (m: 'linked' | 'forked') => void;
}) {
  // NAN-1149: enrichment imports have no source_type / dispatch-config routing
  // — the lane routes by enrich_source into target_table, both fixed by the
  // parser definition. Show that mapping instead.
  // NAN-1932: the source_type + dispatch-config controls moved to the Overview
  // tab (they're the common case); this tab keeps the advanced import options.
  const isEnrichment = parser.raw.kind === 'enrichment';
  return (
    <div className="p-4 space-y-4">
      {previewLoading && (
        <div className="flex items-center gap-2 text-[11.5px] text-muted-foreground">
          <Loader2 className="w-[13px] h-[13px] animate-spin" strokeWidth={1.5} />
          Loading import preview…
        </div>
      )}

      {preview?.already_imported && (
        <div className="rounded-md border border-warning/30 bg-warning/5 px-3 py-2.5 text-[11px] text-warning leading-relaxed">
          Already imported as <span className="font-mono">{preview.existing_import_type}</span>.
        </div>
      )}

      {/* Mode */}
      <div>
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2">
          Import mode
        </div>
        <div className="space-y-2">
          <ModeCard
            active={importMode === 'linked'}
            onClick={() => onChangeImportMode('linked')}
            title="Linked"
            tagline="Stay in sync with upstream"
            body="Auto-update whenever the upstream repo publishes a new version. You cannot edit the parser locally; changes must land in the upstream repo."
            Icon={LinkIcon}
          />
          <ModeCard
            active={importMode === 'forked'}
            onClick={() => onChangeImportMode('forked')}
            title="Forked"
            tagline="Edit the copy in your workspace"
            body="Take a snapshot of the current version. Edit freely. We'll surface DRIFT when upstream diverges so you can merge, rebase, or ignore."
            Icon={GitFork}
          />
        </div>
      </div>

      {/* Enrichment routing summary — replaces dispatch/source-type below */}
      {isEnrichment && (
        <div className="rounded-md border border-border bg-card px-3 py-2.5 space-y-1">
          <div className="flex items-center gap-1.5 text-[11.5px] font-medium text-foreground/80 mb-1">
            <Info className="w-[12px] h-[12px]" strokeWidth={1.5} />
            Enrichment routing
          </div>
          <div className="text-[10.5px] text-muted-foreground leading-relaxed">
            This parser normalizes pushed <span className="font-mono text-foreground">{parser.raw.enrich_source || '—'}</span>{' '}
            {parser.raw.enrich_kind || ''} records into{' '}
            <span className="font-mono text-foreground">{parser.raw.target_table || '—'}</span>. Routing is
            fixed by the parser definition — there is no source-type or dispatch config to pick.
          </div>
        </div>
      )}

      {/* Proposed metadata from preview */}
      {preview && !preview.already_imported && (
        <div className="rounded-md border border-border bg-card px-3 py-2.5 space-y-1">
          <div className="flex items-center gap-1.5 text-[11.5px] font-medium text-foreground/80 mb-1">
            <Info className="w-[12px] h-[12px]" strokeWidth={1.5} />
            Proposed log source
          </div>
          <Row k="Name" v={preview.proposed_name} />
          {preview.proposed_category && <Row k="Category" v={preview.proposed_category} />}
          {preview.proposed_vendor && <Row k="Vendor" v={preview.proposed_vendor} />}
          {preview.proposed_product && <Row k="Product" v={preview.proposed_product} />}
        </div>
      )}

      {/* Draft notice */}
      <div className="rounded-md border border-border bg-card px-3 py-2.5 text-[10.5px] text-muted-foreground leading-relaxed">
        <div className="flex items-center gap-1.5 text-foreground/80 font-medium mb-1">
          <Info className="w-[12px] h-[12px]" strokeWidth={1.5} />
          Imports as a draft
        </div>
        Drafts let you test-run the parser against live events before deploying. Nothing changes in
        production until you click <span className="font-mono text-foreground">Deploy</span> on the
        log source.
      </div>
    </div>
  );
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3 text-[11px]">
      <span className="text-muted-foreground shrink-0">{k}</span>
      <span className="text-foreground/80 font-mono truncate">{v}</span>
    </div>
  );
}

function ModeCard({
  active,
  onClick,
  title,
  tagline,
  body,
  Icon,
}: {
  active: boolean;
  onClick: () => void;
  title: string;
  tagline: string;
  body: string;
  Icon: typeof LinkIcon;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'w-full text-left rounded-md border px-3 py-2.5 transition',
        active ? 'border-primary/40 bg-primary/5' : 'border-border bg-card hover:border-border/80 hover:bg-muted/40',
      )}
    >
      <div className="flex items-start gap-2.5">
        <div
          className={cn(
            'w-[26px] h-[26px] rounded-md border flex items-center justify-center shrink-0',
            active ? 'border-primary/40 bg-primary/10' : 'border-border bg-background',
          )}
        >
          <Icon
            className={cn('w-[13px] h-[13px]', active ? 'text-primary' : 'text-muted-foreground')}
            strokeWidth={1.5}
          />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5">
            <span className="text-[12.5px] font-semibold text-foreground">{title}</span>
            <span className="text-[10.5px] text-muted-foreground">· {tagline}</span>
            {active && (
              <span className="ml-auto text-[9px] font-mono uppercase tracking-wider text-primary">
                selected
              </span>
            )}
          </div>
          <div className="text-[10.5px] text-muted-foreground mt-1 leading-relaxed">{body}</div>
        </div>
      </div>
    </button>
  );
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

function isTransportCompat(transport: RepoTransport | null, configType: string): boolean {
  if (!transport) return true;
  const t = configType.toLowerCase();
  if (transport === 's3') return t.includes('s3');
  if (transport === 'pubsub') return t.includes('pubsub') || t.includes('gcp');
  if (transport === 'kafka') return t === 'kafka';
  if (transport === 'syslog') return t === 'syslog';
  if (transport === 'splunk_hec') return t.includes('splunk');
  if (transport === 'vector') return t === 'vector';
  if (transport === 'http') return t === 'http' || t === 'routed';
  return false;
}
