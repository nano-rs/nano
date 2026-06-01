// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-509 (slice 2/3) — Lookup Tables create wizard. Ports
// `design-ref/shadcn/lookup-create.jsx` (mode picker + 3 modes) to the real
// app. Preserves the existing API wiring (createTable + createFromSchema +
// addRows + upsertIngestion + triggerIngestion).
//
// Update mode (query param `?update=<name>`) routes back into the upload
// mode pre-filled with the existing table's name. Replace-data flows from
// the detail page hit this same surface.

import { useCallback, useEffect, useMemo, useRef, useState, type RefObject } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  ArrowLeft,
  ArrowRight,
  ArrowUpRight,
  Check,
  CircleAlert,
  Download,
  Loader2,
  Pencil,
  Plus,
  RotateCw,
  X,
} from 'lucide-react';

import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useToast } from '@/hooks/use-toast';
import {
  useAddLookupRows,
  useCreateLookupTable,
  useCreateLookupTableFromSchema,
  useLookupTable,
  useLookupTables,
  usePreviewUpload,
  useTriggerLookupIngestion,
  useUpsertLookupIngestion,
} from '@/hooks/use-api';
import type {
  CreateLookupTableConfig,
  FileFormat,
  PreviewResult,
  UpsertLookupIngestionRequest,
} from '@/lib/api';
import { parseValueForType } from '@/lib/lookup-utils';
import { cn } from '@/lib/utils';
import { Checkbox } from '@/components/ui/checkbox';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';


// --------------------------------------------------------------------
// Types
// --------------------------------------------------------------------

type Mode = 'upload' | 'define' | 'url';

// Backend-canonical column types. Mockup uses richer labels (ip, cidr, enum,
// etc) but the backend persists `text | integer | float | boolean | timestamp
// | json`. We keep the backend names so saving doesn't need translation.
const BACKEND_COLUMN_TYPES = [
  { id: 'text',      label: 'text',      tone: 'neutral' as const, hint: 'free text' },
  { id: 'integer',   label: 'integer',   tone: 'primary' as const, hint: 'whole number' },
  { id: 'float',     label: 'float',     tone: 'primary' as const, hint: 'decimal' },
  { id: 'boolean',   label: 'boolean',   tone: 'primary' as const, hint: 'true / false' },
  { id: 'timestamp', label: 'timestamp', tone: 'success' as const, hint: 'ISO datetime' },
  { id: 'json',      label: 'json',      tone: 'warning' as const, hint: 'object / array' },
];

const TONE_CLASS = {
  neutral: 'text-foreground/80 bg-foreground/[0.06] border-border',
  primary: 'text-primary bg-primary/10 border-primary/30',
  warning: 'text-[var(--warning)] bg-[color-mix(in_srgb,var(--warning)_10%,transparent)] border-[color-mix(in_srgb,var(--warning)_30%,transparent)]',
  success: 'text-[var(--success)] bg-[color-mix(in_srgb,var(--success)_10%,transparent)] border-[color-mix(in_srgb,var(--success)_30%,transparent)]',
} as const;

interface SchemaColumn {
  name: string;
  data_type: string;
  nullable: boolean;
}

const CRON_PRESETS = [
  { label: 'Every hour',          value: '0 * * * *' },
  { label: 'Every 6 hours',       value: '0 */6 * * *' },
  { label: 'Daily at midnight',   value: '0 0 * * *' },
  { label: 'Daily at 6 AM',       value: '0 6 * * *' },
  { label: 'Weekly on Sunday',    value: '0 0 * * 0' },
  { label: 'Monthly on 1st',      value: '0 0 1 * *' },
];

const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB

// --------------------------------------------------------------------
// Atoms (local — not lifted into shared because they only fit Create)
// --------------------------------------------------------------------

function ColumnTypeChip({ type, size = 'sm' }: { type: string; size?: 'sm' | 'md' }) {
  const meta = BACKEND_COLUMN_TYPES.find((t) => t.id === type) ?? {
    id: type, label: type, tone: 'neutral' as const, hint: '',
  };
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-sm border font-mono leading-none tracking-[-0.01em]',
        TONE_CLASS[meta.tone],
        size === 'sm' ? 'text-[9.5px] px-1 py-[1px] h-[15px]' : 'text-[10.5px] px-1.5 py-[2px] h-[18px]',
      )}
    >
      {meta.label}
    </span>
  );
}

function ColumnTypePicker({
  value,
  onChange,
}: {
  value: string;
  onChange: (t: string) => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative inline-block">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="cursor-pointer hover:brightness-125"
      >
        <ColumnTypeChip type={value} size="md" />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div
            className="absolute top-full left-0 mt-1 z-50 w-[200px] rounded-md border border-border bg-card py-1"
            style={{ boxShadow: '0 12px 40px color-mix(in srgb, var(--foreground) 20%, transparent)' }}
          >
            {BACKEND_COLUMN_TYPES.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => { onChange(t.id); setOpen(false); }}
                className={cn(
                  'w-full px-2 py-1.5 flex items-center gap-2 hover:bg-foreground/5',
                  value === t.id && 'bg-primary/10',
                )}
              >
                <ColumnTypeChip type={t.id} size="md" />
                <span className="text-[10.5px] text-muted-foreground font-mono">{t.hint}</span>
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

interface CreateHeaderProps {
  mode: Mode;
  name: string;
  setName: (v: string) => void;
  desc: string;
  setDesc: (v: string) => void;
  onBack: () => void;
  onCancel: () => void;
  onSave: () => void;
  saveEnabled: boolean;
  saving: boolean;
  saveLabel?: string;
  isUpdate?: boolean;
  nameInputRef?: RefObject<HTMLInputElement | null>;
}

function CreateHeader({
  name,
  setName,
  desc,
  setDesc,
  onBack,
  onCancel,
  onSave,
  saveEnabled,
  saving,
  saveLabel = 'save table',
  isUpdate,
  nameInputRef,
}: CreateHeaderProps) {
  return (
    <div className="shrink-0 border-b border-border px-6 pt-4 pb-3 bg-card/40">
      <div className="flex items-start gap-3">
        <div className="flex-1 min-w-0">
          <input
            ref={nameInputRef}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="untitled_lookup_table"
            disabled={isUpdate}
            className="w-full bg-transparent text-[20px] font-semibold text-foreground tracking-[-0.015em] placeholder:text-muted-foreground/60 outline-none font-mono disabled:opacity-70"
          />
          <input
            value={desc}
            onChange={(e) => setDesc(e.target.value)}
            placeholder="Short description — what is this table for?"
            className="w-full bg-transparent text-[12px] text-foreground/80 placeholder:text-muted-foreground/60 outline-none mt-0.5"
          />
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {!isUpdate && (
            <button
              type="button"
              onClick={onBack}
              className="h-[30px] px-3 rounded-md border border-border text-[12px] text-muted-foreground hover:text-foreground font-mono flex items-center gap-1.5"
            >
              <ArrowLeft className="w-3 h-3" strokeWidth={2} />
              change mode
            </button>
          )}
          <button
            type="button"
            onClick={onCancel}
            className="h-[30px] px-3 rounded-md text-[12px] text-muted-foreground hover:text-foreground font-mono"
          >
            cancel
          </button>
          <button
            type="button"
            onClick={onSave}
            disabled={!saveEnabled || saving}
            className={cn(
              'h-[30px] px-4 rounded-md text-[12px] font-semibold flex items-center gap-1.5',
              saveEnabled && !saving
                ? 'bg-primary text-[var(--brand-ink)] hover:bg-primary/90'
                : 'bg-foreground/10 text-muted-foreground cursor-not-allowed',
            )}
          >
            {saving ? <Loader2 className="w-3 h-3 animate-spin" strokeWidth={2} /> : <Check className="w-3 h-3" strokeWidth={2} />}
            {saveLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------
// Mode picker
// --------------------------------------------------------------------

const MODE_CARDS = [
  {
    id: 'upload' as Mode,
    title: 'Upload a file',
    blurb: "Drop in a CSV, TSV, or JSON. We'll parse headers, infer column types, and let you review before saving.",
    Icon: Download,
    meta: 'CSV · TSV · JSON · up to 100 MB',
  },
  {
    id: 'define' as Mode,
    title: 'Define a schema',
    blurb: 'Start from an empty spreadsheet. Add columns, pick types, enter rows inline. Tab and arrows work.',
    Icon: Pencil,
    meta: 'blank table · best for small lists',
  },
  {
    id: 'url' as Mode,
    title: 'Import from URL',
    blurb: "Fetch from an HTTP endpoint. We'll pull a sample now and refresh on a schedule you configure later.",
    Icon: ArrowUpRight,
    meta: 'remote CSV / JSON · scheduled refresh',
  },
];

function ModePicker({
  onPick,
  onCancel,
}: {
  onPick: (m: Mode) => void;
  onCancel: () => void;
}) {
  return (
    <div className="flex-1 min-h-0 overflow-y-auto bg-background">
      <div className="max-w-[960px] mx-auto px-8 pt-8 pb-10">
        <div className="flex items-baseline gap-3">
          <h1 className="text-[22px] font-semibold tracking-[-0.015em] text-foreground">Create a lookup table</h1>
          <span className="text-[11.5px] font-mono text-muted-foreground">step 1 · pick a source</span>
        </div>
        <p className="text-[12.5px] text-muted-foreground mt-1 max-w-[520px]">
          Lookup tables enrich rule matches with extra context — threat intel, allowlists, CIDR mappings.
          Pick how you want to load rows.
        </p>

        <div className="grid grid-cols-1 @min-[760px]:grid-cols-3 gap-3 mt-6">
          {MODE_CARDS.map((m) => {
            const Icon = m.Icon;
            return (
              <button
                key={m.id}
                type="button"
                onClick={() => onPick(m.id)}
                className="group text-left rounded-lg border border-border bg-card hover:border-primary/40 hover:bg-primary/[0.02] transition-colors overflow-hidden"
              >
                <div className="h-[110px] border-b border-border bg-foreground/[0.02] relative flex items-center justify-center">
                  <div className="w-[22px] h-[22px] rounded-md bg-card border border-border flex items-center justify-center absolute top-2 left-2">
                    <Icon className="w-3 h-3 text-primary" strokeWidth={2} />
                  </div>
                  <ModeCardPreview mode={m.id} />
                </div>
                <div className="p-3.5">
                  <div className="flex items-center gap-2">
                    <h3 className="text-[13.5px] font-semibold text-foreground">{m.title}</h3>
                    <ArrowRight
                      className="w-3 h-3 text-muted-foreground opacity-0 group-hover:opacity-100 group-hover:text-primary transition-opacity ml-auto"
                      strokeWidth={2}
                    />
                  </div>
                  <p className="text-[11.5px] text-muted-foreground mt-1 leading-[1.45]">{m.blurb}</p>
                  <div className="text-[10px] font-mono text-muted-foreground/70 mt-2.5 uppercase tracking-[0.12em]">{m.meta}</div>
                </div>
              </button>
            );
          })}
        </div>

        <div className="mt-6 pt-4 border-t border-border flex items-center justify-between">
          <button
            type="button"
            onClick={onCancel}
            className="text-[12px] text-muted-foreground hover:text-foreground font-mono flex items-center gap-1.5"
          >
            <ArrowLeft className="w-3 h-3" strokeWidth={2} />
            back to library
          </button>
          <div className="text-[11px] font-mono text-muted-foreground/70">tip: most teams start with define for small lists</div>
        </div>
      </div>
    </div>
  );
}

function ModeCardPreview({ mode }: { mode: Mode }) {
  if (mode === 'upload') {
    return (
      <div className="flex flex-col items-center gap-1 text-muted-foreground">
        <div className="w-10 h-10 rounded-md border-2 border-dashed border-border flex items-center justify-center">
          <Download className="w-4 h-4 text-primary" strokeWidth={2} />
        </div>
        <span className="font-mono text-[9px]">drop file</span>
      </div>
    );
  }
  if (mode === 'define') {
    return (
      <div className="w-[120px] h-[80px] border border-border rounded-[2px] overflow-hidden font-mono">
        <div className="h-[12px] flex border-b border-border bg-foreground/[0.04]">
          <div className="flex-1 border-r border-border flex items-center px-1 text-[7px] text-primary">cidr</div>
          <div className="flex-1 border-r border-border flex items-center px-1 text-[7px] text-muted-foreground">site</div>
          <div className="flex-1 flex items-center px-1 text-[7px] text-[var(--success)]">zone</div>
        </div>
        <div className="h-[12px] flex border-b border-border">
          <div className="flex-1 border-r border-border px-1 text-[7px] text-foreground/70 flex items-center">10.0.0.0/8</div>
          <div className="flex-1 border-r border-border px-1 text-[7px] text-foreground/70 flex items-center">corp</div>
          <div className="flex-1 px-1 text-[7px] text-foreground/70 flex items-center">internal</div>
        </div>
        <div className="h-[12px] flex border-b border-border bg-primary/10 ring-1 ring-primary/40">
          <div className="flex-1 border-r border-border px-1 text-[7px] text-foreground flex items-center">10.44.0.0/16</div>
          <div className="flex-1 border-r border-border" />
          <div className="flex-1" />
        </div>
      </div>
    );
  }
  return (
    <div className="w-[180px] flex flex-col gap-1">
      <div className="h-[14px] rounded-sm bg-foreground/[0.05] border border-border px-1.5 flex items-center gap-1.5">
        <ArrowUpRight className="w-2 h-2 text-[var(--success)] shrink-0" strokeWidth={2} />
        <span className="font-mono text-[7.5px] text-muted-foreground truncate">https://intel.nano.internal/…</span>
      </div>
      <div className="flex items-center gap-1 font-mono text-[7.5px] text-muted-foreground/70">
        <span className="px-1 py-[0.5px] rounded-sm border border-border bg-foreground/[0.03]">CSV</span>
        <span className="px-1 py-[0.5px] rounded-sm border border-border bg-foreground/[0.03]">JSON</span>
        <span className="px-1 py-[0.5px] rounded-sm border border-primary/40 text-primary bg-primary/10">TSV</span>
      </div>
      <div className="h-[5px] rounded-full overflow-hidden bg-foreground/[0.05]">
        <div className="h-full bg-primary" style={{ width: '68%' }} />
      </div>
      <div className="font-mono text-[7.5px] text-primary">fetched 1,240 rows</div>
    </div>
  );
}

// --------------------------------------------------------------------
// Upload mode
// --------------------------------------------------------------------

interface UploadModeProps {
  onBack: () => void;
  onCancel: () => void;
  initialName?: string;
  isUpdate?: boolean;
}

function detectFormatFromFile(file: File): FileFormat | undefined {
  const ext = file.name.split('.').pop()?.toLowerCase();
  if (ext === 'csv' || ext === 'tsv') return 'csv';
  if (ext === 'json') return 'json';
  if (ext === 'ndjson' || ext === 'jsonl') return 'ndjson';
  return undefined;
}

function UploadMode({ onBack, onCancel, initialName, isUpdate }: UploadModeProps) {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { mutate: createTable } = useCreateLookupTable();
  const { mutate: previewUpload } = usePreviewUpload();
  // NAN-515 — list of existing tables, used to detect when the user's typed
  // name collides with a table that already exists. The wizard would
  // otherwise silently append (mode default is `append`).
  const { data: existingTables } = useLookupTables();

  const [stage, setStage] = useState<'drop' | 'preview'>('drop');
  const [file, setFile] = useState<File | null>(null);
  const [name, setName] = useState(initialName ?? '');
  const [desc, setDesc] = useState('');
  const [primaryKey, setPrimaryKey] = useState('');
  const [mode, setMode] = useState<'replace' | 'append'>(isUpdate ? 'replace' : 'append');
  const [flattenJson, setFlattenJson] = useState(false);
  const [columnTypes, setColumnTypes] = useState<Record<string, string>>({});
  const [progress, setProgress] = useState(0);
  const [saving, setSaving] = useState(false);
  const [preview, setPreview] = useState<PreviewResult | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  // NAN-515 — save-time confirm dialog when the user pushes through the
  // inline ribbon and saves with mode=append on an existing name.
  const [collisionConfirmOpen, setCollisionConfirmOpen] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const nameInputRef = useRef<HTMLInputElement>(null);

  // NAN-515 — case-insensitive name collision against existing tables.
  // `isUpdate` mode (Replace data flow) intentionally targets an existing
  // table, so collision is expected and not flagged.
  const trimmedName = name.trim();
  const collidingTable = useMemo(() => {
    if (!trimmedName || isUpdate || !existingTables) return null;
    const needle = trimmedName.toLowerCase();
    return existingTables.find((t) => t.name.toLowerCase() === needle) ?? null;
  }, [trimmedName, isUpdate, existingTables]);
  const showCollisionWarning = !!collidingTable && mode === 'append';

  const handleSelectFile = async (selected: File) => {
    if (selected.size > MAX_FILE_SIZE) {
      toast({ title: 'File too large', description: 'Max 100 MB', variant: 'destructive' });
      return;
    }
    setFile(selected);
    if (!isUpdate && !name) {
      const inferred = selected.name
        .replace(/\.[^.]+$/, '')
        .replace(/[^a-z0-9_]/gi, '_')
        .toLowerCase();
      setName(inferred);
    }
    if (!desc) setDesc(`Imported from ${selected.name}`);
    setStage('preview');
    setPreview(null);
    setPreviewError(null);
    setPreviewLoading(true);
    try {
      const result = await previewUpload({ file: selected, format: detectFormatFromFile(selected) });
      setPreview(result);
    } catch (err) {
      setPreviewError(err instanceof Error ? err.message : 'Preview failed');
    } finally {
      setPreviewLoading(false);
    }
  };

  const onDrop = (e: React.DragEvent<HTMLButtonElement>) => {
    e.preventDefault();
    const f = e.dataTransfer.files?.[0];
    if (f) handleSelectFile(f);
  };

  // NAN-515 — gate Save behind a confirm dialog when the user is about to
  // append into an existing table without explicitly choosing Replace.
  const handleSaveClick = () => {
    if (!file || !name.trim()) {
      toast({ title: 'Missing information', description: 'File + name required', variant: 'destructive' });
      return;
    }
    if (showCollisionWarning) {
      setCollisionConfirmOpen(true);
      return;
    }
    handleSave();
  };

  const handleSave = async () => {
    if (!file || !name.trim()) {
      toast({ title: 'Missing information', description: 'File + name required', variant: 'destructive' });
      return;
    }
    setSaving(true);
    setProgress(50);
    try {
      const config: CreateLookupTableConfig = {
        name: name.trim(),
        description: desc.trim() || undefined,
        primary_key: primaryKey || undefined,
        format: detectFormatFromFile(file),
        mode,
        flatten_json: flattenJson,
        column_types: Object.entries(columnTypes).map(([column, data_type]) => ({ column, data_type })),
      };
      const result = await createTable({ file, config });
      setProgress(100);
      const renames = result.renamed_columns ?? [];
      const baseDesc = `${result.records_inserted.toLocaleString()} rows imported`;
      const renameDesc = renames.length === 0
        ? ''
        : ` · renamed ${renames.length} column${renames.length === 1 ? '' : 's'}: ${renames
            .slice(0, 3)
            .map((r) => `${r.original} → ${r.sanitized}`)
            .join(', ')}${renames.length > 3 ? `, +${renames.length - 3} more` : ''}`;
      toast({
        title: isUpdate ? 'Data replaced' : 'Lookup table created',
        description: baseDesc + renameDesc,
      });
      navigate(`/rules/lookup-tables/${encodeURIComponent(result.table.name)}`);
    } catch (err) {
      toast({
        title: isUpdate ? 'Failed to replace data' : 'Failed to create table',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
      setProgress(0);
    } finally {
      setSaving(false);
    }
  };

  if (stage === 'drop') {
    return (
      <div className="flex-1 min-h-0 overflow-y-auto bg-background">
        <div className="max-w-[760px] mx-auto px-8 pt-6 pb-10">
          <h1 className="text-[22px] font-semibold tracking-[-0.015em] text-foreground">
            {isUpdate ? `Replace data in ${initialName}` : 'Upload a file'}
          </h1>
          <p className="text-[12.5px] text-muted-foreground mt-1">
            Headers will be parsed, column types inferred. You'll review before saving.
          </p>

          <input
            ref={fileInputRef}
            type="file"
            accept=".csv,.tsv,.json,.ndjson,.jsonl"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) handleSelectFile(f);
            }}
          />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            onDragOver={(e) => e.preventDefault()}
            onDrop={onDrop}
            className="mt-6 w-full rounded-lg border-2 border-dashed border-border hover:border-primary/40 hover:bg-primary/[0.02] transition-colors py-16 flex flex-col items-center gap-3"
          >
            <div className="w-14 h-14 rounded-full bg-primary/10 flex items-center justify-center">
              <Download className="w-5 h-5 text-primary" strokeWidth={2} />
            </div>
            <div className="text-center">
              <div className="text-[14px] text-foreground font-medium">Drop a file here</div>
              <div className="text-[11.5px] text-muted-foreground mt-0.5">
                or <span className="text-primary">click to browse</span>
              </div>
            </div>
            <div className="text-[10px] font-mono text-muted-foreground/70 uppercase tracking-[0.12em] mt-1">
              CSV · TSV · JSON · NDJSON · max 100 MB
            </div>
          </button>

          <div className="mt-4 flex items-center justify-between">
            {!isUpdate && (
              <button
                type="button"
                onClick={onBack}
                className="text-[12px] text-muted-foreground hover:text-foreground font-mono flex items-center gap-1.5"
              >
                <ArrowLeft className="w-3 h-3" strokeWidth={2} />
                change mode
              </button>
            )}
          </div>
        </div>
      </div>
    );
  }

  // Preview stage
  return (
    <div className="flex-1 min-h-0 overflow-hidden flex flex-col bg-background">
      <CreateHeader
        mode="upload"
        name={name}
        setName={setName}
        desc={desc}
        setDesc={setDesc}
        onBack={onBack}
        onCancel={onCancel}
        saveEnabled={!!file && !!name.trim() && !saving}
        saving={saving}
        onSave={handleSaveClick}
        saveLabel={isUpdate ? 'replace data' : 'save table'}
        isUpdate={isUpdate}
        nameInputRef={nameInputRef}
      />

      <div className="flex-1 min-h-0 overflow-y-auto">
        <div className="max-w-[1100px] mx-auto p-6 flex flex-col gap-4">
          {/* File card */}
          {file && (
            <div className="rounded-md border border-border bg-card p-3 flex items-center gap-3">
              <Download className="w-3.5 h-3.5 text-primary" strokeWidth={2} />
              <div className="flex-1 min-w-0">
                <div className="text-[12px] text-foreground truncate">{file.name}</div>
                <div className="text-[10.5px] font-mono text-muted-foreground">
                  {formatBytes(file.size)} · {detectFormatFromFile(file) ?? 'unknown'}
                </div>
              </div>
              <button
                type="button"
                onClick={() => {
                  setFile(null);
                  setStage('drop');
                  setPreview(null);
                  setPreviewError(null);
                }}
                className="text-[11px] text-muted-foreground hover:text-foreground font-mono"
              >
                replace file
              </button>
            </div>
          )}

          {/* NAN-515 — name-collision warning ribbon. Surfaces when the
              inferred (or typed) name matches an existing table and the
              default `append` mode would silently merge data. Hidden once
              the user picks Replace mode (showCollisionWarning gates on it). */}
          {showCollisionWarning && (
            <div className="rounded-md border border-[color-mix(in_srgb,var(--warning)_30%,transparent)] bg-[color-mix(in_srgb,var(--warning)_8%,transparent)] p-3 flex items-start gap-2.5">
              <CircleAlert className="w-3.5 h-3.5 text-[var(--warning)] mt-0.5 shrink-0" strokeWidth={2} />
              <div className="flex-1 min-w-0">
                <p className="text-[11.5px] text-foreground">
                  A lookup table named{' '}
                  <span className="font-mono text-[var(--warning)]">{trimmedName}</span>{' '}
                  already exists ({collidingTable!.row_count.toLocaleString()} rows). Append will silently merge new rows in.
                </p>
                <div className="mt-2 flex items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => {
                      nameInputRef.current?.focus();
                      nameInputRef.current?.select();
                    }}
                    className="h-[24px] px-2 rounded-md border border-border text-[11px] font-mono text-foreground/80 hover:text-foreground hover:border-border/80"
                  >
                    Use a different name
                  </button>
                  <button
                    type="button"
                    onClick={() => setMode('replace')}
                    className="h-[24px] px-2 rounded-md border border-[color-mix(in_srgb,var(--warning)_30%,transparent)] bg-[color-mix(in_srgb,var(--warning)_10%,transparent)] text-[var(--warning)] text-[11px] font-mono hover:brightness-110"
                  >
                    Replace existing data
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Config */}
          <div className="rounded-md border border-border bg-card p-4">
            <div className="text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70 mb-2.5 font-semibold">
              Settings
            </div>
            <div className="grid grid-cols-1 @min-[640px]:grid-cols-2 gap-3">
              <label className="flex flex-col gap-1.5">
                <span className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70">primary key (optional)</span>
                <input
                  value={primaryKey}
                  onChange={(e) => setPrimaryKey(e.target.value)}
                  placeholder="e.g. ip, user, hash"
                  className="h-[30px] rounded-md border border-border bg-background px-2 text-[12px] text-foreground placeholder:text-muted-foreground/60 outline-none focus:border-primary/50 font-mono"
                />
              </label>
              <label className="flex flex-col gap-1.5">
                <span className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70">mode</span>
                <select
                  value={mode}
                  onChange={(e) => setMode(e.target.value as 'replace' | 'append')}
                  className="h-[30px] rounded-md border border-border bg-background px-2 text-[12px] text-foreground outline-none focus:border-primary/50 font-mono"
                >
                  <option value="append">append (add to existing)</option>
                  <option value="replace">replace (drop existing)</option>
                </select>
              </label>
              <label className="flex items-center gap-2 col-span-full cursor-pointer">
                <Checkbox
                  checked={flattenJson}
                  onCheckedChange={(v) => setFlattenJson(Boolean(v))}
                />
                <span className="text-[12px] text-foreground">Flatten nested JSON into dotted columns</span>
              </label>
            </div>
          </div>

          {/* Column type overrides */}
          <div className="rounded-md border border-border bg-card p-4">
            <div className="flex items-baseline gap-2 mb-2">
              <div className="text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70 font-semibold">Column type overrides</div>
              <span className="text-[10.5px] text-muted-foreground">Optional. Backend infers types from the file by default.</span>
            </div>
            <ColumnOverrideEditor types={columnTypes} onChange={setColumnTypes} />
          </div>

          {/* Data preview */}
          <DataPreview loading={previewLoading} error={previewError} preview={preview} />

          {/* Save progress */}
          {saving && (
            <div className="rounded-md border border-border bg-card p-3">
              <div className="h-[6px] rounded-full overflow-hidden bg-foreground/[0.05]">
                <div className="h-full bg-primary transition-[width]" style={{ width: `${progress}%` }} />
              </div>
              <div className="mt-1.5 font-mono text-[10.5px] text-muted-foreground">
                Uploading + parsing… {progress}%
              </div>
            </div>
          )}
        </div>
      </div>

      {/* NAN-515 — last-line-of-defense confirm dialog. Fires if the user
          pushes Save while a name collision is still active in append mode. */}
      <ConfirmDialog
        open={collisionConfirmOpen}
        onOpenChange={setCollisionConfirmOpen}
        title="Append into existing table?"
        description={
          <>
            <span className="font-mono">{trimmedName}</span> already exists with{' '}
            <span className="font-mono tabular-nums">{collidingTable?.row_count.toLocaleString()}</span> rows. Saving will append{' '}
            <span className="font-mono tabular-nums">{preview?.total_rows_estimate.toLocaleString() ?? '?'}</span> new rows
            into it. Choose a different name to create a new table instead, or switch to Replace mode to drop existing rows first.
          </>
        }
        cancelLabel="Use a different name"
        confirmLabel="Append anyway"
        onCancel={() => {
          // Restore the NAN-515 affordance: refocus + select the name field so
          // the user can immediately type a new, non-colliding table name.
          nameInputRef.current?.focus();
          nameInputRef.current?.select();
        }}
        onConfirm={() => {
          setCollisionConfirmOpen(false);
          handleSave();
        }}
      >
        {/* Third action — switch to Replace mode instead of appending. Lives in
            the body because ConfirmDialog's footer only renders Cancel + Confirm. */}
        <button
          type="button"
          onClick={() => {
            setMode('replace');
            setCollisionConfirmOpen(false);
            handleSave();
          }}
          className="h-[36px] px-3 rounded-md border border-[color-mix(in_srgb,var(--warning)_30%,transparent)] bg-[color-mix(in_srgb,var(--warning)_10%,transparent)] text-[var(--warning)] text-[12px] font-mono hover:brightness-110"
        >
          Replace existing data
        </button>
      </ConfirmDialog>
    </div>
  );
}

function ColumnOverrideEditor({
  types,
  onChange,
}: {
  types: Record<string, string>;
  onChange: (next: Record<string, string>) => void;
}) {
  const [draftCol, setDraftCol] = useState('');
  const entries = Object.entries(types);
  return (
    <div className="flex flex-col gap-2">
      {entries.length > 0 && (
        <div className="flex flex-col gap-1.5">
          {entries.map(([col, t]) => (
            <div key={col} className="flex items-center gap-2 text-[11.5px]">
              <span className="font-mono text-foreground/80 flex-1">{col}</span>
              <ColumnTypePicker value={t} onChange={(nt) => onChange({ ...types, [col]: nt })} />
              <button
                type="button"
                onClick={() => {
                  const next = { ...types };
                  delete next[col];
                  onChange(next);
                }}
                className="text-muted-foreground/70 hover:text-destructive"
              >
                <X className="w-3 h-3" strokeWidth={2} />
              </button>
            </div>
          ))}
        </div>
      )}
      <div className="flex items-center gap-2">
        <input
          value={draftCol}
          onChange={(e) => setDraftCol(e.target.value)}
          placeholder="column name"
          className="h-[28px] flex-1 rounded-md border border-border bg-background px-2 text-[11.5px] text-foreground placeholder:text-muted-foreground/60 outline-none focus:border-primary/50 font-mono"
        />
        <button
          type="button"
          onClick={() => {
            const c = draftCol.trim();
            if (!c || c in types) return;
            onChange({ ...types, [c]: 'text' });
            setDraftCol('');
          }}
          disabled={!draftCol.trim()}
          className="h-[28px] px-2.5 rounded-md border border-border text-[11.5px] text-muted-foreground hover:text-foreground hover:border-border/80 font-mono flex items-center gap-1 disabled:opacity-50"
        >
          <Plus className="w-3 h-3" strokeWidth={2} />
          add
        </button>
      </div>
    </div>
  );
}

function DataPreview({
  loading,
  error,
  preview,
}: {
  loading: boolean;
  error: string | null;
  preview: PreviewResult | null;
}) {
  if (loading) {
    return (
      <div className="rounded-md border border-border bg-card p-4 flex items-center gap-2 text-[11.5px] font-mono text-muted-foreground">
        <Loader2 className="w-3.5 h-3.5 animate-spin" strokeWidth={2} />
        parsing file…
      </div>
    );
  }
  if (error) {
    return (
      <div className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-[11.5px] font-mono text-destructive">
        Preview failed: {error}
      </div>
    );
  }
  if (!preview) return null;

  const remaining = Math.max(0, preview.total_rows_estimate - preview.rows.length);
  return (
    <div>
      <div className="flex items-baseline gap-2 mb-2">
        <div className="text-[9.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70 font-semibold">Data preview</div>
        <span className="text-[10.5px] text-muted-foreground">
          First <span className="tabular-nums">{preview.rows.length}</span> of{' '}
          <span className="tabular-nums">{preview.total_rows_estimate.toLocaleString()}</span> rows
        </span>
      </div>
      <div className="rounded-md border border-border bg-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full font-mono text-[11px]" style={{ borderCollapse: 'collapse' }}>
            <thead>
              <tr className="border-b border-border bg-foreground/[0.02]">
                {preview.columns.map((c) => (
                  <th key={c.name} className="px-2.5 py-1.5 text-left align-top">
                    <div className="flex items-center gap-1.5">
                      <span className="text-[10.5px] text-foreground truncate">{c.name}</span>
                      <ColumnTypeChip type={c.detected_type} />
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {preview.rows.map((row, ri) => (
                <tr key={ri} className={ri !== preview.rows.length - 1 ? 'border-b border-border/40' : ''}>
                  {preview.columns.map((c) => {
                    const v = row[c.name];
                    const display =
                      v === null || v === undefined ? '·' :
                      typeof v === 'object' ? JSON.stringify(v) :
                      String(v);
                    return (
                      <td
                        key={c.name}
                        className="px-2.5 py-1 text-foreground/80 whitespace-nowrap truncate max-w-[260px]"
                        title={display}
                      >
                        {display}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {remaining > 0 && (
          <div className="h-[26px] px-3 flex items-center border-t border-border text-[10.5px] font-mono text-muted-foreground/70 tabular-nums">
            {remaining.toLocaleString()} more rows will be imported on save
          </div>
        )}
      </div>
    </div>
  );
}

// --------------------------------------------------------------------
// Define mode (spreadsheet)
// --------------------------------------------------------------------

const INITIAL_DEFINE_COLS: SchemaColumn[] = [
  { name: 'col_1', data_type: 'text', nullable: true },
  { name: 'col_2', data_type: 'text', nullable: true },
  { name: 'col_3', data_type: 'text', nullable: true },
];
const INITIAL_DEFINE_ROWS = 8;

function makeEmptyRows(colCount: number, rowCount: number): string[][] {
  return Array.from({ length: rowCount }, () => Array(colCount).fill(''));
}

function DefineMode({ onBack, onCancel }: { onBack: () => void; onCancel: () => void }) {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { mutate: createFromSchema } = useCreateLookupTableFromSchema();
  const { mutate: addRows } = useAddLookupRows();

  const [name, setName] = useState('');
  const [desc, setDesc] = useState('');
  const [primaryKey, setPrimaryKey] = useState('');
  const [cols, setCols] = useState<SchemaColumn[]>(INITIAL_DEFINE_COLS);
  const [rows, setRows] = useState<string[][]>(makeEmptyRows(INITIAL_DEFINE_COLS.length, INITIAL_DEFINE_ROWS));
  const [cursor, setCursor] = useState({ r: 0, c: 0 });
  const [editing, setEditing] = useState<{ r: number; c: number; value: string } | null>(null);
  const [saving, setSaving] = useState(false);
  const tableRef = useRef<HTMLDivElement>(null);

  useEffect(() => { tableRef.current?.focus(); }, []);

  const updateCell = (r: number, c: number, v: string) => {
    setRows((rs) => {
      const next = rs.map((row) => row.slice());
      while (next.length <= r) next.push(Array(cols.length).fill(''));
      next[r][c] = v;
      return next;
    });
  };

  const addRow = useCallback(() => {
    setRows((rs) => [...rs, Array(cols.length).fill('')]);
  }, [cols.length]);

  const addCol = () => {
    setCols((cs) => [...cs, { name: `col_${cs.length + 1}`, data_type: 'text', nullable: true }]);
    setRows((rs) => rs.map((r) => [...r, '']));
  };

  const deleteRow = (i: number) => setRows((rs) => rs.filter((_, ii) => ii !== i));
  const deleteCol = (i: number) => {
    if (cols.length <= 1) return;
    const removed = cols[i].name;
    setCols((cs) => cs.filter((_, ii) => ii !== i));
    setRows((rs) => rs.map((r) => r.filter((_, ii) => ii !== i)));
    if (primaryKey === removed) setPrimaryKey('');
  };

  const renameCol = (i: number, v: string) =>
    setCols((cs) => cs.map((c, ii) => (ii === i ? { ...c, name: v } : c)));
  const retypeCol = (i: number, t: string) =>
    setCols((cs) => cs.map((c, ii) => (ii === i ? { ...c, data_type: t } : c)));

  const onKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (editing) return;
    const { r, c } = cursor;
    if (e.key === 'ArrowRight') { e.preventDefault(); setCursor({ r, c: Math.min(cols.length - 1, c + 1) }); }
    else if (e.key === 'ArrowLeft')  { e.preventDefault(); setCursor({ r, c: Math.max(0, c - 1) }); }
    else if (e.key === 'ArrowDown')  { e.preventDefault(); if (r === rows.length - 1) addRow(); setCursor({ r: r + 1, c }); }
    else if (e.key === 'ArrowUp')    { e.preventDefault(); setCursor({ r: Math.max(0, r - 1), c }); }
    else if (e.key === 'Tab') {
      e.preventDefault();
      if (c === cols.length - 1) { if (r === rows.length - 1) addRow(); setCursor({ r: r + 1, c: 0 }); }
      else setCursor({ r, c: c + 1 });
    }
    else if (e.key === 'Enter' || e.key === 'F2') {
      e.preventDefault(); setEditing({ r, c, value: rows[r]?.[c] ?? '' });
    }
    else if (e.key === 'Delete' || e.key === 'Backspace') { e.preventDefault(); updateCell(r, c, ''); }
    else if (e.key.length === 1 && !e.metaKey && !e.ctrlKey) {
      setEditing({ r, c, value: e.key });
    }
  };

  const commitEdit = () => {
    if (!editing) return;
    updateCell(editing.r, editing.c, editing.value);
    setEditing(null);
    tableRef.current?.focus();
  };
  const cancelEdit = () => { setEditing(null); tableRef.current?.focus(); };

  const nonEmptyRows = useMemo(
    () => rows.filter((r) => r.some((c) => c !== '')).length,
    [rows],
  );
  const saveEnabled = name.trim() !== '' && cols.length > 0 && cols.every((c) => c.name.trim());

  const handleSave = async () => {
    setSaving(true);
    try {
      const validCols = cols.filter((c) => c.name.trim());
      const dupes = validCols
        .map((c) => c.name.trim().toLowerCase())
        .filter((n, i, a) => a.indexOf(n) !== i);
      if (dupes.length > 0) {
        toast({ title: 'Duplicate column names', description: dupes[0], variant: 'destructive' });
        setSaving(false);
        return;
      }
      const result = await createFromSchema({
        name: name.trim(),
        description: desc.trim() || undefined,
        columns: validCols.map((c) => ({ name: c.name.trim(), data_type: c.data_type, nullable: c.nullable })),
        primary_key: primaryKey || undefined,
      });
      const dataRows: Record<string, unknown>[] = [];
      for (const row of rows) {
        if (!row.some((cell) => cell.trim() !== '')) continue;
        const record: Record<string, unknown> = {};
        validCols.forEach((col) => {
          const idx = cols.indexOf(col);
          record[col.name] = parseValueForType(row[idx] || '', col.data_type);
        });
        dataRows.push(record);
      }
      let inserted = 0;
      if (dataRows.length > 0) {
        const res = await addRows({ name: result.name, rows: dataRows });
        inserted = res.inserted;
      }
      toast({
        title: 'Lookup table created',
        description: `${validCols.length} columns${inserted > 0 ? ` · ${inserted} rows` : ''}`,
      });
      navigate(`/rules/lookup-tables/${encodeURIComponent(result.name)}`);
    } catch (err) {
      toast({
        title: 'Failed to create table',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="flex-1 min-h-0 overflow-hidden flex flex-col bg-background">
      <CreateHeader
        mode="define"
        name={name}
        setName={setName}
        desc={desc}
        setDesc={setDesc}
        onBack={onBack}
        onCancel={onCancel}
        saveEnabled={saveEnabled && !saving}
        saving={saving}
        onSave={handleSave}
      />

      <div className="shrink-0 px-6 py-2 flex items-center gap-2 border-b border-border bg-card/40">
        <button
          type="button"
          onClick={addRow}
          className="h-[24px] px-2 rounded-md border border-border text-[11px] font-mono text-foreground/80 hover:text-foreground hover:border-border/80 flex items-center gap-1"
        >
          <Plus className="w-2.5 h-2.5" strokeWidth={2} />
          row
        </button>
        <button
          type="button"
          onClick={addCol}
          className="h-[24px] px-2 rounded-md border border-border text-[11px] font-mono text-foreground/80 hover:text-foreground hover:border-border/80 flex items-center gap-1"
        >
          <Plus className="w-2.5 h-2.5" strokeWidth={2} />
          column
        </button>
        <span className="w-px h-4 bg-border mx-1" />
        <label className="flex items-center gap-1.5 text-[11px] font-mono text-muted-foreground">
          primary key:
          <select
            value={primaryKey}
            onChange={(e) => setPrimaryKey(e.target.value)}
            className="h-[22px] rounded border border-border bg-background px-1.5 text-[11px] text-foreground outline-none focus:border-primary/50"
          >
            <option value="">— none —</option>
            {cols.map((c) => (
              <option key={c.name} value={c.name}>{c.name}</option>
            ))}
          </select>
        </label>
        <span className="text-[10.5px] font-mono text-muted-foreground/70">
          {cols.length} cols · {nonEmptyRows} filled · {rows.length - nonEmptyRows} empty
        </span>
        <span className="flex-1" />
        <span className="text-[10px] font-mono text-muted-foreground/70">arrows · tab · enter to edit · ⌫ clear</span>
      </div>

      <div className="flex-1 min-h-0 overflow-auto p-6">
        <div
          ref={tableRef}
          tabIndex={0}
          onKeyDown={onKeyDown}
          className="inline-block rounded-md border border-border overflow-hidden bg-card outline-none focus:ring-2 focus:ring-primary/30"
        >
          <table className="font-mono text-[11.5px]" style={{ borderCollapse: 'separate', borderSpacing: 0 }}>
            <thead>
              <tr className="bg-foreground/[0.04]">
                <th className="w-[32px] h-[28px] border-r border-b border-border text-[9px] text-muted-foreground/70 sticky left-0 bg-foreground/[0.04] z-10">
                  #
                </th>
                {cols.map((c, i) => (
                  <th key={i} className="min-w-[140px] h-[28px] border-r border-b border-border px-2 text-left group">
                    <div className="flex items-center gap-1.5">
                      <input
                        value={c.name}
                        onChange={(e) => renameCol(i, e.target.value)}
                        className="bg-transparent text-[11.5px] text-foreground outline-none w-full border-b border-transparent hover:border-border focus:border-primary"
                      />
                      <ColumnTypePicker value={c.data_type} onChange={(t) => retypeCol(i, t)} />
                      {cols.length > 1 && (
                        <button
                          type="button"
                          onClick={() => deleteCol(i)}
                          className="opacity-0 group-hover:opacity-100 text-muted-foreground/70 hover:text-destructive"
                        >
                          <X className="w-2.5 h-2.5" strokeWidth={2} />
                        </button>
                      )}
                    </div>
                  </th>
                ))}
                <th className="w-[32px] h-[28px] border-b border-border" />
              </tr>
            </thead>
            <tbody>
              {rows.map((row, r) => (
                <tr key={r} className="group/row">
                  <td className="w-[32px] h-[26px] border-r border-b border-border text-center text-[9.5px] text-muted-foreground/70 sticky left-0 bg-foreground/[0.04] z-[1] tabular-nums">
                    {r + 1}
                  </td>
                  {row.map((v, c) => {
                    const isCur = cursor.r === r && cursor.c === c;
                    const isEdit = editing?.r === r && editing?.c === c;
                    return (
                      <td
                        key={c}
                        onClick={() => { setCursor({ r, c }); tableRef.current?.focus(); }}
                        onDoubleClick={() => setEditing({ r, c, value: v })}
                        className={cn(
                          'h-[26px] px-2 border-r border-b border-border cursor-cell relative whitespace-nowrap',
                          isCur && !isEdit && 'ring-2 ring-primary ring-inset bg-primary/5 z-[2]',
                          isEdit && 'p-0 bg-card ring-2 ring-primary ring-inset z-[3]',
                        )}
                      >
                        {isEdit ? (
                          <input
                            autoFocus
                            value={editing.value}
                            onChange={(e) => setEditing({ ...editing, value: e.target.value })}
                            onBlur={commitEdit}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter') {
                                commitEdit();
                                setCursor((cur) => ({ r: Math.min(rows.length - 1, cur.r + 1), c: cur.c }));
                              } else if (e.key === 'Escape') cancelEdit();
                              else if (e.key === 'Tab') {
                                e.preventDefault();
                                commitEdit();
                                if (c === cols.length - 1) {
                                  if (r === rows.length - 1) addRow();
                                  setCursor({ r: r + 1, c: 0 });
                                } else setCursor({ r, c: c + 1 });
                              }
                            }}
                            className="w-full h-full px-2 bg-transparent text-foreground outline-none"
                          />
                        ) : (
                          <span className={cn('block truncate max-w-[220px]', v ? 'text-foreground/80' : 'text-muted-foreground/70')}>
                            {v || '·'}
                          </span>
                        )}
                      </td>
                    );
                  })}
                  <td className="w-[32px] h-[26px] border-b border-border text-center">
                    {rows.length > 1 && (
                      <button
                        type="button"
                        onClick={() => deleteRow(r)}
                        className="opacity-0 group-hover/row:opacity-100 text-muted-foreground/70 hover:text-destructive w-full h-full flex items-center justify-center"
                      >
                        <X className="w-2.5 h-2.5" strokeWidth={2} />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              <tr>
                <td colSpan={cols.length + 2} className="h-[26px]">
                  <button
                    type="button"
                    onClick={addRow}
                    className="w-full h-full text-left px-3 text-[10.5px] font-mono text-muted-foreground/70 hover:text-primary hover:bg-primary/5 flex items-center gap-1.5"
                  >
                    <Plus className="w-2.5 h-2.5" strokeWidth={2} />
                    add row
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------
// URL mode
// --------------------------------------------------------------------

function UrlMode({ onBack, onCancel }: { onBack: () => void; onCancel: () => void }) {
  const navigate = useNavigate();
  const { toast } = useToast();
  const { mutate: createFromSchema } = useCreateLookupTableFromSchema();
  const { mutate: upsertIngestion } = useUpsertLookupIngestion();
  const { mutate: triggerIngestion } = useTriggerLookupIngestion();

  const [name, setName] = useState('');
  const [desc, setDesc] = useState('');
  const [url, setUrl] = useState('');
  const [format, setFormat] = useState<'csv' | 'tsv' | 'json' | 'ndjson'>('csv');
  const [cron, setCron] = useState('0 0 * * *');
  const [mode, setMode] = useState<'replace' | 'append'>('replace');
  const [enabled, setEnabled] = useState(true);
  const [saving, setSaving] = useState(false);

  const saveEnabled = !!name.trim() && !!url.trim();

  const handleSave = async () => {
    setSaving(true);
    try {
      // Create placeholder schema, then attach ingestion + trigger first fetch.
      await createFromSchema({
        name: name.trim(),
        description: desc.trim() || undefined,
        columns: [{ name: '_placeholder', data_type: 'text', nullable: true }],
      });
      const ingestionReq: UpsertLookupIngestionRequest = {
        url,
        cron_expression: cron,
        parser_config: { format, csv_has_headers: true },
        mode,
        enabled,
      };
      await upsertIngestion({ name: name.trim(), request: ingestionReq });
      try {
        const trig = await triggerIngestion(name.trim());
        if (trig.status === 'success') {
          toast({ title: 'Lookup table created', description: `${trig.records_ingested ?? 0} rows imported` });
        } else {
          toast({
            title: 'Created · first fetch failed',
            description: trig.error || 'Will run on schedule',
            variant: 'destructive',
          });
        }
      } catch {
        toast({ title: 'Created · first fetch failed', description: 'Will run on schedule' });
      }
      navigate(`/rules/lookup-tables/${encodeURIComponent(name.trim())}`);
    } catch (err) {
      toast({
        title: 'Failed to create table',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="flex-1 min-h-0 overflow-hidden flex flex-col bg-background">
      <CreateHeader
        mode="url"
        name={name}
        setName={setName}
        desc={desc}
        setDesc={setDesc}
        onBack={onBack}
        onCancel={onCancel}
        saveEnabled={saveEnabled && !saving}
        saving={saving}
        onSave={handleSave}
      />

      <div className="flex-1 min-h-0 overflow-y-auto">
        <div className="max-w-[1000px] mx-auto px-6 py-6 flex flex-col gap-4">
          {/* URL + format */}
          <div className="rounded-md border border-border bg-card p-4">
            <label className="text-[10.5px] font-mono text-muted-foreground/70 uppercase tracking-[0.12em]">
              source URL
            </label>
            <div className="mt-1.5 flex items-center gap-2">
              <div className="flex-1 relative">
                <ArrowUpRight className="w-3 h-3 absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--success)]" strokeWidth={2} />
                <input
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://intel.example.com/feeds/ips.csv"
                  className="w-full h-[32px] pl-8 pr-3 rounded-md border border-border bg-background text-[12px] text-foreground placeholder:text-muted-foreground/60 outline-none focus:border-primary/50 font-mono"
                />
              </div>
              <div className="flex items-center gap-px p-0.5 rounded-md border border-border bg-foreground/[0.03]">
                {(['csv', 'tsv', 'json'] as const).map((f) => (
                  <button
                    key={f}
                    type="button"
                    onClick={() => setFormat(f)}
                    className={cn(
                      'h-[26px] px-2.5 rounded-[3px] text-[11px] font-mono uppercase',
                      format === f
                        ? 'bg-primary/10 text-primary'
                        : 'text-muted-foreground hover:text-foreground',
                    )}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </div>
            <div className="mt-2 text-[10.5px] font-mono text-muted-foreground/70">
              <span className="text-muted-foreground">tip:</span> we'll GET this URL now and on the schedule below.
            </div>
          </div>

          {/* Schedule */}
          <div className="rounded-md border border-border bg-card p-4">
            <label className="text-[10.5px] font-mono text-muted-foreground/70 uppercase tracking-[0.12em]">
              refresh schedule
            </label>
            <div className="mt-1.5 grid grid-cols-1 @min-[640px]:grid-cols-[1fr_auto] gap-2">
              <input
                value={cron}
                onChange={(e) => setCron(e.target.value)}
                placeholder="0 0 * * *"
                className="h-[32px] rounded-md border border-border bg-background px-3 text-[12px] text-foreground placeholder:text-muted-foreground/60 outline-none focus:border-primary/50 font-mono"
              />
              <select
                value={cron}
                onChange={(e) => setCron(e.target.value)}
                className="h-[32px] rounded-md border border-border bg-background px-2 text-[12px] text-foreground outline-none focus:border-primary/50 font-mono"
              >
                {CRON_PRESETS.map((p) => (
                  <option key={p.value} value={p.value}>{p.label}</option>
                ))}
              </select>
            </div>
            <div className="mt-3 grid grid-cols-1 @min-[640px]:grid-cols-2 gap-3">
              <label className="flex flex-col gap-1.5">
                <span className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground/70">mode</span>
                <select
                  value={mode}
                  onChange={(e) => setMode(e.target.value as 'replace' | 'append')}
                  className="h-[30px] rounded-md border border-border bg-background px-2 text-[12px] text-foreground outline-none focus:border-primary/50 font-mono"
                >
                  <option value="replace">replace (drop existing on each fetch)</option>
                  <option value="append">append (add new rows only)</option>
                </select>
              </label>
              <label className="flex items-center gap-2 mt-auto cursor-pointer">
                <Checkbox
                  checked={enabled}
                  onCheckedChange={(v) => setEnabled(Boolean(v))}
                />
                <span className="text-[12px] text-foreground">Enable scheduled refresh</span>
              </label>
            </div>
          </div>

          {/* Help */}
          <div className="rounded-md border border-dashed border-border bg-foreground/[0.02] p-4 text-[11.5px] text-muted-foreground">
            <div className="flex items-center gap-1.5 font-mono text-[10.5px] uppercase tracking-[0.12em] text-muted-foreground/70 mb-1.5 font-semibold">
              <RotateCw className="w-3 h-3" strokeWidth={2} />
              How URL ingestion works
            </div>
            On save we'll create the table, attach the schedule, and trigger an initial fetch. Column
            types are inferred from the first response. You can adjust them later from the table detail view.
          </div>
        </div>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------
// Main page
// --------------------------------------------------------------------

export function LookupTableCreate() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const updateName = searchParams.get('update');
  const isUpdate = !!updateName;

  const { data: existingTable } = useLookupTable(updateName ?? undefined);

  // In update mode (replace data) we skip the picker entirely — the only
  // sensible flow is upload, and the existing table's name + desc seed the
  // form.
  const [mode, setMode] = useState<Mode | null>(isUpdate ? 'upload' : null);
  useEffect(() => {
    if (isUpdate && mode === null) setMode('upload');
  }, [isUpdate, mode]);

  useDocumentTitle(isUpdate ? `Replace data · ${updateName}` : 'New lookup table');

  const onCancel = () => navigate('/rules/lookup-tables');
  const onBack = () => setMode(null);

  if (mode === null) {
    return (
      <div
        className="-m-3 flex h-[calc(100%+1.5rem)] overflow-hidden min-h-0 flex-col bg-background"
        style={{ containerType: 'inline-size' }}
      >
        <ModePicker onPick={setMode} onCancel={onCancel} />
      </div>
    );
  }

  return (
    <div
      className="-m-3 flex h-[calc(100%+1.5rem)] overflow-hidden min-h-0 flex-col bg-background"
      style={{ containerType: 'inline-size' }}
    >
      {mode === 'upload' && (
        <UploadMode
          onBack={onBack}
          onCancel={onCancel}
          initialName={isUpdate ? existingTable?.name : undefined}
          isUpdate={isUpdate}
        />
      )}
      {mode === 'define' && <DefineMode onBack={onBack} onCancel={onCancel} />}
      {mode === 'url' && <UrlMode onBack={onBack} onCancel={onCancel} />}
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export default LookupTableCreate;
