// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-510 — LookupTableView (slice 3).
// PR 1: outer shell + density tokens (header / cards / grid).
// PR 2: right Details inspector with show/hide toggle (Source / Stats /
//       Ownership / Usage / Danger zone). Owner wired (NAN-514); Usage
//       wired (NAN-511).
// PR 3 (planned): Schema + Usage + History tabs, gated on NAN-511 / NAN-512.
// All cell-editing / ingestion / paste / search-by-key handlers from the
// pre-redesign page are preserved verbatim.
import { useState, useRef, useEffect, useCallback, type ReactNode } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { useBreadcrumbTitle } from '@/hooks/useBreadcrumbTitle';
import { Card, CardContent } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import {
  Loader2,
  Database,
  Key,
  Search,
  CircleAlert,
  Plus,
  X,
  ChevronLeft,
  ChevronRight,
  ClipboardPaste,
  RefreshCw,
  ChevronDown,
  Globe,
  Play,
  Trash2,
  Save,
  Clock,
  CircleCheck,
  XCircle,
  Download,
  PanelRight,
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { parseValueForType } from '@/lib/lookup-utils';
import { formatUTC } from '@/lib/date-utils';
import type { FileFormat, UpsertLookupIngestionRequest } from '@/lib/api';
import { SourceTag, type LookupSource } from '@/components/lookup/shared';
import {
  useLookupTable,
  useLookupQuery,
  useLookupRows,
  useAddLookupRows,
  useUpdateLookupRow,
  useDeleteLookupRow,
  useDeleteLookupTable,
  useLookupIngestion,
  useLookupUsage,
  useUpsertLookupIngestion,
  useDeleteLookupIngestion,
  useTriggerLookupIngestion,
  useToggleLookupIngestion,
  useValidateCron,
} from '@/hooks/use-api';

const PAGE_SIZE = 50;

const CRON_PRESETS = [
  { label: 'Every hour', value: '0 * * * *' },
  { label: 'Every 6 hours', value: '0 */6 * * *' },
  { label: 'Daily at midnight', value: '0 0 * * *' },
  { label: 'Daily at 6 AM', value: '0 6 * * *' },
  { label: 'Weekly on Sunday', value: '0 0 * * 0' },
  { label: 'Monthly on 1st', value: '0 0 1 * *' },
];

function StatusPill({ status }: { status?: string }) {
  const map: Record<string, { label: string; cls: string }> = {
    success: { label: 'success', cls: 'text-[var(--success)] bg-[color-mix(in_srgb,var(--success)_10%,transparent)] border-[color-mix(in_srgb,var(--success)_30%,transparent)]' },
    failed:  { label: 'failed',  cls: 'text-destructive bg-destructive/10 border-destructive/30' },
    running: { label: 'running', cls: 'text-primary bg-primary/10 border-primary/30' },
  };
  const meta = (status && map[status]) || { label: 'never run', cls: 'text-muted-foreground bg-foreground/[0.05] border-border' };
  return (
    <span className={`inline-flex items-center h-[18px] px-1.5 rounded-sm border font-mono text-[10.5px] ${meta.cls}`}>
      {meta.label}
    </span>
  );
}

function getStatusIcon(status?: string) {
  switch (status) {
    case 'success':
      return <CircleCheck className="w-3.5 h-3.5 text-[var(--success)]" strokeWidth={2} />;
    case 'failed':
      return <XCircle className="w-3.5 h-3.5 text-destructive" strokeWidth={2} />;
    case 'running':
      return <Loader2 className="w-3.5 h-3.5 text-primary animate-spin" strokeWidth={2} />;
    default:
      return <Clock className="w-3.5 h-3.5 text-muted-foreground" strokeWidth={2} />;
  }
}

export function LookupTableView() {
  const { name } = useParams<{ name: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();
  const { data: table, loading: tableLoading, refetch: refetchTable } = useLookupTable(name);

  useDocumentTitle(table?.name || name || 'Lookup Table', [table?.id]);
  useBreadcrumbTitle(table?.name || name);

  const [page, setPage] = useState(1);
  const { data: rowsPage, loading: rowsLoading, refetch: refetchRows } = useLookupRows(name, page, PAGE_SIZE);
  // NAN-511: rules referencing this table — feeds the Usage section of the
  // forthcoming DetailInspector (NAN-510). Until that lands, the count
  // surfaces as a small badge in the header so users know whether the table
  // is still depended on before they edit/delete it.
  const { data: usage } = useLookupUsage(name);
  const { mutate: queryLookup, loading: queryLoading } = useLookupQuery();
  const { mutate: addRows } = useAddLookupRows();
  const { mutate: updateRow } = useUpdateLookupRow();
  const { mutate: deleteRowMutate } = useDeleteLookupRow();

  // Ingestion state
  const { data: ingestion, loading: ingestionLoading, refetch: refetchIngestion } = useLookupIngestion(name);
  const { mutate: upsertIngestion, loading: savingIngestion } = useUpsertLookupIngestion();
  const { mutate: deleteIngestion } = useDeleteLookupIngestion();
  const { mutate: triggerIngestion, loading: triggering } = useTriggerLookupIngestion();
  const { mutate: toggleIngestion } = useToggleLookupIngestion();
  const { mutate: validateCronMutate } = useValidateCron();

  const [ingestionOpen, setIngestionOpen] = useState(false);
  const [ingestionForm, setIngestionForm] = useState<{
    url: string; cron_expression: string; format: FileFormat; mode: 'replace' | 'append'; enabled: boolean;
  } | null>(null);
  const [ingestionDirty, setIngestionDirty] = useState(false);
  const [cronDescription, setCronDescription] = useState('');
  const [cronError, setCronError] = useState('');
  const [deleteIngestionDialog, setDeleteIngestionDialog] = useState(false);

  // Right Details inspector (NAN-510 PR 2). Default visible; persisted across
  // page loads so the analyst's choice sticks.
  const [showInspector, setShowInspector] = useState<boolean>(() => {
    try {
      return localStorage.getItem('lookup-table-view.inspector') !== 'hidden';
    } catch { return true; }
  });
  useEffect(() => {
    try {
      localStorage.setItem('lookup-table-view.inspector', showInspector ? 'visible' : 'hidden');
    } catch { /* localStorage unavailable — silently ignore */ }
  }, [showInspector]);

  // Delete-table action (Danger zone in inspector)
  const { mutate: deleteTable } = useDeleteLookupTable();
  const [deleteTableDialog, setDeleteTableDialog] = useState(false);

  // Initialize ingestion form when data loads
  useEffect(() => {
    if (ingestion && !ingestionForm) {
      setIngestionForm({
        url: ingestion.url,
        cron_expression: ingestion.cron_expression,
        format: ingestion.parser_config.format,
        mode: ingestion.destination.mode || 'replace',
        enabled: ingestion.enabled,
      });
      setIngestionOpen(true);
    }
  }, [ingestion, ingestionForm]);

  const updateIngestionField = <K extends keyof NonNullable<typeof ingestionForm>>(key: K, value: NonNullable<typeof ingestionForm>[K]) => {
    setIngestionForm((prev) => prev ? { ...prev, [key]: value } : prev);
    setIngestionDirty(true);
  };

  const handleCronChange = async (expression: string) => {
    updateIngestionField('cron_expression', expression);
    setCronError('');
    setCronDescription('');
    if (!expression) return;
    try {
      const result = await validateCronMutate(expression);
      if (result.valid) setCronDescription(result.description || '');
      else setCronError('Invalid cron expression');
    } catch { setCronError('Failed to validate'); }
  };

  const handleSaveIngestion = async () => {
    if (!name || !ingestionForm) return;
    const request: UpsertLookupIngestionRequest = {
      url: ingestionForm.url,
      cron_expression: ingestionForm.cron_expression,
      parser_config: { format: ingestionForm.format, csv_has_headers: true },
      mode: ingestionForm.mode,
      enabled: ingestionForm.enabled,
    };
    try {
      await upsertIngestion({ name, request });
      toast({ title: 'Ingestion saved' });
      setIngestionDirty(false);
      refetchIngestion();
    } catch (err) {
      toast({ title: 'Failed to save ingestion', description: err instanceof Error ? err.message : 'Unknown error', variant: 'destructive' });
    }
  };

  const handleTriggerIngestion = async () => {
    if (!name) return;
    try {
      const result = await triggerIngestion(name);
      if (result.status === 'success') {
        toast({ title: 'Ingestion triggered', description: `${result.records_ingested ?? 0} records ingested` });
      } else {
        toast({ title: 'Ingestion failed', description: result.error || 'Unknown error', variant: 'destructive' });
      }
      refetchIngestion();
      refetchRows();
      refetchTable();
    } catch (err) {
      toast({ title: 'Failed to trigger', description: err instanceof Error ? err.message : 'Unknown error', variant: 'destructive' });
    }
  };

  const handleToggleIngestion = async () => {
    if (!name || !ingestion) return;
    try {
      await toggleIngestion({ name, enabled: !ingestion.enabled });
      toast({ title: ingestion.enabled ? 'Ingestion disabled' : 'Ingestion enabled' });
      setIngestionForm((prev) => prev ? { ...prev, enabled: !ingestion.enabled } : prev);
      refetchIngestion();
    } catch (err) {
      toast({ title: 'Failed to toggle', description: err instanceof Error ? err.message : 'Unknown error', variant: 'destructive' });
    }
  };

  const handleDeleteIngestion = async () => {
    if (!name) return;
    try {
      await deleteIngestion(name);
      toast({ title: 'Ingestion removed' });
      setDeleteIngestionDialog(false);
      setIngestionForm(null);
      setIngestionDirty(false);
      refetchIngestion();
    } catch (err) {
      toast({ title: 'Failed to remove', description: err instanceof Error ? err.message : 'Unknown error', variant: 'destructive' });
    }
  };

  const startNewIngestion = () => {
    setIngestionForm({ url: '', cron_expression: '0 0 * * *', format: 'csv', mode: 'replace', enabled: true });
    setIngestionDirty(true);
    setIngestionOpen(true);
  };

  const handleDeleteTable = async () => {
    if (!name) return;
    try {
      await deleteTable(name);
      toast({ title: 'Lookup table deleted', description: name });
      navigate('/rules/lookup-tables');
    } catch (err) {
      toast({ title: 'Failed to delete', description: err instanceof Error ? err.message : 'Unknown error', variant: 'destructive' });
    }
  };

  const [searchValue, setSearchValue] = useState('');
  const [searchResult, setSearchResult] = useState<Record<string, unknown> | null>(null);
  const [searched, setSearched] = useState(false);
  const [notFound, setNotFound] = useState(false);

  // Grid interaction state
  const [activeCell, setActiveCell] = useState<{ rowIdx: number; col: string } | null>(null);
  const [editValue, setEditValue] = useState('');
  const cellInputRef = useRef<HTMLInputElement>(null);
  const gridRef = useRef<HTMLDivElement>(null);
  const savingRef = useRef(false); // Guard against double-save from blur + keyboard nav

  // New row being added (inline at bottom)
  const [addingRow, setAddingRow] = useState(false);
  const [newRowData, setNewRowData] = useState<Record<string, string>>({});

  // Delete state
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [rowToDelete, setRowToDelete] = useState<number | null>(null);

  // Paste dialog
  const [pasteDialogOpen, setPasteDialogOpen] = useState(false);
  const [pasteText, setPasteText] = useState('');
  const [parsedPasteRows, setParsedPasteRows] = useState<Record<string, unknown>[]>([]);

  // Search handlers
  const handleSearch = async () => {
    if (!table || !searchValue.trim()) return;

    const keyField = table.primary_key || table.columns[0]?.name;
    if (!keyField) {
      toast({ title: 'Cannot search', description: 'No columns available to search', variant: 'destructive' });
      return;
    }

    try {
      setSearched(true);
      setNotFound(false);
      const result = await queryLookup({
        table_name: table.name,
        key_field: keyField,
        key_value: searchValue.trim(),
      });

      if ('found' in result && result.found && result.fields) {
        setSearchResult(result.fields);
        setNotFound(false);
      } else {
        setSearchResult(null);
        setNotFound(true);
      }
    } catch (err) {
      toast({ title: 'Search failed', description: err instanceof Error ? err.message : 'Unknown error', variant: 'destructive' });
      setSearchResult(null);
      setNotFound(true);
    }
  };

  const clearSearch = () => {
    setSearchValue('');
    setSearchResult(null);
    setSearched(false);
    setNotFound(false);
  };

  // Focus cell input when active cell changes
  useEffect(() => {
    if (activeCell && cellInputRef.current) {
      cellInputRef.current.focus();
      cellInputRef.current.select();
    }
  }, [activeCell]);

  // Inline edit handlers
  const startEdit = (rowIdx: number, col: string, currentValue: unknown) => {
    setEditValue(currentValue === null || currentValue === undefined ? '' : String(currentValue));
    setActiveCell({ rowIdx, col });
  };

  const saveEdit = async () => {
    if (savingRef.current) return; // Prevent re-entrant calls from blur after keyboard nav
    if (!activeCell || !table || !name) return;

    const currentRow = rows[activeCell.rowIdx];
    if (!currentRow) return;
    const rowId = currentRow._row_id as number;

    const fields: Record<string, unknown> = {};
    table.columns.forEach((col) => {
      if (col.name === activeCell.col) {
        fields[col.name] = parseValueForType(editValue, col.data_type);
      } else {
        fields[col.name] = currentRow[col.name];
      }
    });

    savingRef.current = true;
    setActiveCell(null);

    try {
      await updateRow({ name, rowId, fields });
      refetchRows();
    } catch (err) {
      toast({ title: 'Failed to update', description: err instanceof Error ? err.message : 'Unknown error', variant: 'destructive' });
    } finally {
      savingRef.current = false;
    }
  };

  // Cell keyboard navigation
  const handleCellKeyDown = (e: React.KeyboardEvent<HTMLInputElement>, rowIdx: number, colName: string) => {
    const input = e.currentTarget;
    const atStart = input.selectionStart === 0 && input.selectionEnd === 0;
    const atEnd = input.selectionStart === input.value.length && input.selectionEnd === input.value.length;
    const colIdx = displayColumns.findIndex((c) => c.name === colName);

    if (e.key === 'Tab') {
      e.preventDefault();
      saveEdit();
      const nextColIdx = e.shiftKey ? colIdx - 1 : colIdx + 1;
      if (nextColIdx >= 0 && nextColIdx < displayColumns.length) {
        const nextCol = displayColumns[nextColIdx].name;
        const row = rows[rowIdx];
        if (row) startEdit(rowIdx, nextCol, row[nextCol]);
      } else if (!e.shiftKey && nextColIdx >= displayColumns.length && rowIdx + 1 < rows.length) {
        const nextCol = displayColumns[0].name;
        const row = rows[rowIdx + 1];
        if (row) startEdit(rowIdx + 1, nextCol, row[nextCol]);
      }
    } else if (e.key === 'Enter') {
      e.preventDefault();
      saveEdit();
      if (rowIdx + 1 < rows.length) {
        const row = rows[rowIdx + 1];
        if (row) startEdit(rowIdx + 1, colName, row[colName]);
      }
    } else if (e.key === 'Escape') {
      setActiveCell(null);
      input.blur();
    } else if (e.key === 'ArrowUp' && rowIdx > 0) {
      e.preventDefault();
      saveEdit();
      const row = rows[rowIdx - 1];
      if (row) startEdit(rowIdx - 1, colName, row[colName]);
    } else if (e.key === 'ArrowDown' && rowIdx + 1 < rows.length) {
      e.preventDefault();
      saveEdit();
      const row = rows[rowIdx + 1];
      if (row) startEdit(rowIdx + 1, colName, row[colName]);
    } else if (e.key === 'ArrowLeft' && atStart && colIdx > 0) {
      e.preventDefault();
      saveEdit();
      const prevCol = displayColumns[colIdx - 1].name;
      const row = rows[rowIdx];
      if (row) startEdit(rowIdx, prevCol, row[prevCol]);
    } else if (e.key === 'ArrowRight' && atEnd && colIdx < displayColumns.length - 1) {
      e.preventDefault();
      saveEdit();
      const nextCol = displayColumns[colIdx + 1].name;
      const row = rows[rowIdx];
      if (row) startEdit(rowIdx, nextCol, row[nextCol]);
    }
  };

  // Paste in grid
  const handleGridPaste = useCallback((e: React.ClipboardEvent) => {
    if (!activeCell || !table || !name) return;

    const text = e.clipboardData.getData('text/plain');
    if (!text) return;

    const pastedLines = text.split('\n').filter((l) => l.length > 0);
    // If more than one line or tabs, open paste dialog instead
    if (pastedLines.length > 1 || pastedLines[0]?.includes('\t')) {
      e.preventDefault();
      setPasteText(text);
      setPasteDialogOpen(true);
      return;
    }
    // Single value paste — let the browser handle it into the input
  }, [activeCell, table, name]);

  // Add row handlers
  const startAddRow = () => {
    if (!table) return;
    const emptyRow: Record<string, string> = {};
    table.columns.forEach((col) => { emptyRow[col.name] = ''; });
    setNewRowData(emptyRow);
    setAddingRow(true);
  };

  const cancelAddRow = () => {
    setAddingRow(false);
    setNewRowData({});
  };

  const saveNewRow = async () => {
    if (!table || !name) return;

    const record: Record<string, unknown> = {};
    table.columns.forEach((col) => {
      const val = newRowData[col.name];
      record[col.name] = parseValueForType(val, col.data_type);
    });

    try {
      await addRows({ name, rows: [record] });
      toast({ title: 'Row added' });
      setAddingRow(false);
      setNewRowData({});
      refetchRows();
      refetchTable();
    } catch (err) {
      toast({ title: 'Failed to add row', description: err instanceof Error ? err.message : 'Unknown error', variant: 'destructive' });
    }
  };

  // New row keyboard navigation
  const handleNewRowKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      saveNewRow();
    } else if (e.key === 'Escape') {
      cancelAddRow();
    } else if (e.key === 'Tab') {
      // Let browser handle tab between inputs in the new row
    }
  };

  // Delete handlers
  const confirmDelete = (rowId: number) => {
    setRowToDelete(rowId);
    setDeleteDialogOpen(true);
  };

  const handleDelete = async () => {
    if (rowToDelete === null || !name) return;

    try {
      await deleteRowMutate({ name, rowId: rowToDelete });
      toast({ title: 'Row deleted' });
      setDeleteDialogOpen(false);
      setRowToDelete(null);
      refetchRows();
      refetchTable();
    } catch (err) {
      toast({ title: 'Failed to delete', description: err instanceof Error ? err.message : 'Unknown error', variant: 'destructive' });
    }
  };

  // Paste dialog handlers
  const parsePasteText = useCallback((text: string) => {
    if (!table || !text.trim()) {
      setParsedPasteRows([]);
      return;
    }

    const lines = text.trim().split('\n').filter((l) => l.trim());
    if (lines.length === 0) {
      setParsedPasteRows([]);
      return;
    }

    const columns = table.columns;

    const firstLineParts = lines[0].split('\t');
    const hasHeader = columns.length > 1 && firstLineParts.length === columns.length &&
      firstLineParts.some((p) => columns.some((c) => c.name.toLowerCase() === p.trim().toLowerCase()));

    const dataLines = hasHeader ? lines.slice(1) : lines;

    if (columns.length === 1) {
      const pastedRows = dataLines.map((line) => ({
        [columns[0].name]: parseValueForType(line.trim(), columns[0].data_type),
      }));
      setParsedPasteRows(pastedRows);
    } else {
      const pastedRows = dataLines.map((line) => {
        const parts = line.split('\t');
        const row: Record<string, unknown> = {};
        columns.forEach((col, i) => {
          row[col.name] = i < parts.length ? parseValueForType(parts[i].trim(), col.data_type) : null;
        });
        return row;
      });
      setParsedPasteRows(pastedRows);
    }
  }, [table]);

  useEffect(() => {
    parsePasteText(pasteText);
  }, [pasteText, parsePasteText]);

  const handlePasteSubmit = async () => {
    if (!name || parsedPasteRows.length === 0) return;

    try {
      const result = await addRows({ name, rows: parsedPasteRows });
      toast({ title: 'Rows added', description: `Added ${result.inserted} rows` });
      setPasteDialogOpen(false);
      setPasteText('');
      setParsedPasteRows([]);
      refetchRows();
      refetchTable();
    } catch (err) {
      toast({ title: 'Failed to add rows', description: err instanceof Error ? err.message : 'Unknown error', variant: 'destructive' });
    }
  };

  if (tableLoading || (rowsLoading && !rowsPage)) {
    return (
      <div className="p-8">
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-8 h-8 animate-spin text-primary" />
        </div>
      </div>
    );
  }

  if (!table) {
    return (
      <div className="p-6">
        <div className="rounded-lg border border-border bg-card py-12 text-center">
          <Database className="w-10 h-10 mx-auto text-muted-foreground mb-3" strokeWidth={1.5} />
          <p className="text-[12px] font-mono text-muted-foreground">Lookup table not found</p>
        </div>
      </div>
    );
  }

  const keyField = table.primary_key || table.columns[0]?.name;
  const displayColumns = table.columns;
  const rows = rowsPage?.rows || [];
  const totalPages = rowsPage?.total_pages || 1;
  const total = rowsPage?.total || 0;
  const pageOffset = (page - 1) * PAGE_SIZE;
  // TODO(NAN-509-followup): backend doesn't expose `source` directly. Infer
  // from ingestion presence — same fallback as the list page (LookupTables.tsx).
  const source: LookupSource = ingestion ? 'url' : 'upload';

  return (
    <div className="-m-3 flex h-[calc(100%+1.5rem)] overflow-hidden min-h-0 bg-background">
    <div className="flex-1 min-w-0 overflow-y-auto p-6 space-y-3">
      {/* Header — icon tile / mono title / meta row / action rail.
          (Breadcrumb is rendered by the global TopBar via AppBreadcrumbs.) */}
      <div>
        <div className="flex items-start gap-3">
          <div className="w-[40px] h-[40px] rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0">
            <Database className="w-[18px] h-[18px] text-primary" strokeWidth={2} />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-[20px] font-semibold tracking-[-0.015em] text-foreground font-mono truncate">
                {table.name}
              </h1>
              {table.primary_key && (
                <span className="inline-flex items-center gap-1 h-[18px] px-1.5 rounded-sm border border-[color-mix(in_srgb,var(--warning)_30%,transparent)] bg-[color-mix(in_srgb,var(--warning)_10%,transparent)] text-[var(--warning)] font-mono text-[10.5px]">
                  <Key className="w-3 h-3" strokeWidth={2} />
                  pk: {table.primary_key}
                </span>
              )}
            </div>
            {table.description && (
              <p className="text-[12px] text-muted-foreground mt-0.5">{table.description}</p>
            )}
            <div className="mt-1.5 flex items-center gap-2 text-[10.5px] font-mono text-muted-foreground flex-wrap">
              <span className="tabular-nums text-foreground/80">{total.toLocaleString()}</span>
              <span>rows</span>
              <span className="text-muted-foreground/50">·</span>
              <span className="tabular-nums text-foreground/80">{displayColumns.length}</span>
              <span>cols</span>
              <span className="text-muted-foreground/50">·</span>
              <SourceTag source={source} />
              <span className="text-muted-foreground/50">·</span>
              <span>updated {formatUTC(table.updated_at)}</span>
            </div>
          </div>
          <div className="flex items-center gap-1.5 shrink-0">
            <button
              type="button"
              onClick={() => navigate(`/rules/lookup-tables/new?update=${encodeURIComponent(table.name)}`)}
              className="h-[30px] px-3 rounded-md border border-border text-[12px] font-mono text-foreground/80 hover:text-foreground hover:border-border/80 flex items-center gap-1.5"
            >
              <RefreshCw className="w-[12px] h-[12px]" strokeWidth={2} />
              Replace data
            </button>
            <button
              type="button"
              onClick={() => setShowInspector((s) => !s)}
              title={showInspector ? 'Hide details' : 'Show details'}
              aria-pressed={showInspector}
              className={`h-[30px] w-[30px] rounded-md border flex items-center justify-center transition-colors ${
                showInspector
                  ? 'border-primary/40 bg-primary/10 text-primary'
                  : 'border-border text-muted-foreground hover:text-foreground hover:border-border/80'
              }`}
            >
              <PanelRight className="w-[14px] h-[14px]" strokeWidth={2} />
            </button>
          </div>
        </div>
      </div>

      {/* Ingestion Section */}
      {!ingestionLoading && (
        <Collapsible open={ingestionOpen} onOpenChange={setIngestionOpen}>
          <Card className="rounded-lg border border-border bg-card shadow-none">
            <CollapsibleTrigger asChild>
              <button className="w-full flex items-center justify-between px-3 py-2.5 hover:bg-foreground/[0.02] rounded-lg transition-colors">
                <div className="flex items-center gap-2.5">
                  <Download className="w-3.5 h-3.5 text-muted-foreground" strokeWidth={2} />
                  <span className="text-[12px] font-medium text-foreground">Automated ingestion</span>
                  {ingestion && (
                    <div className="flex items-center gap-1.5">
                      {getStatusIcon(ingestion.last_run_status)}
                      <span className={`inline-flex items-center h-[18px] px-1.5 rounded-sm border font-mono text-[10.5px] ${ingestion.enabled ? 'text-[var(--success)] bg-[color-mix(in_srgb,var(--success)_10%,transparent)] border-[color-mix(in_srgb,var(--success)_30%,transparent)]' : 'text-muted-foreground bg-foreground/[0.05] border-border'}`}>
                        {ingestion.enabled ? 'enabled' : 'disabled'}
                      </span>
                    </div>
                  )}
                  {!ingestion && !ingestionForm && (
                    <span className="text-[11px] font-mono text-muted-foreground">not configured</span>
                  )}
                </div>
                <ChevronDown className={`w-3.5 h-3.5 text-muted-foreground transition-transform ${ingestionOpen ? 'rotate-180' : ''}`} strokeWidth={2} />
              </button>
            </CollapsibleTrigger>
            <CollapsibleContent>
              <CardContent className="px-3 pb-3 pt-0">
                {!ingestion && !ingestionForm ? (
                  <div className="text-center py-6">
                    <Globe className="w-7 h-7 mx-auto text-muted-foreground mb-2.5" strokeWidth={1.5} />
                    <p className="text-[11.5px] text-muted-foreground mb-3">
                      Set up automated ingestion to keep this lookup table up-to-date from a remote URL.
                    </p>
                    <button
                      type="button"
                      onClick={startNewIngestion}
                      className="h-[28px] px-3 rounded-md bg-primary text-[var(--brand-ink)] hover:bg-primary/90 text-[12px] font-semibold inline-flex items-center"
                    >
                      Configure ingestion
                    </button>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {/* Status row (only when saved) */}
                    {ingestion && (
                      <div className="grid gap-3 md:grid-cols-3 pb-3 border-b border-border/50">
                        <div>
                          <p className="text-[9.5px] font-mono uppercase tracking-wider text-muted-foreground/70 mb-1">Last run</p>
                          <StatusPill status={ingestion.last_run_status} />
                          {ingestion.last_run_at && (
                            <p className="text-[10.5px] font-mono text-muted-foreground mt-1">{formatUTC(ingestion.last_run_at)}</p>
                          )}
                        </div>
                        <div>
                          <p className="text-[9.5px] font-mono uppercase tracking-wider text-muted-foreground/70 mb-1">Next run</p>
                          {ingestion.next_run_at ? (
                            <p className="text-[11px] font-mono text-foreground/80">{formatUTC(ingestion.next_run_at)}</p>
                          ) : (
                            <p className="text-[11px] font-mono text-muted-foreground/70 italic">Not scheduled</p>
                          )}
                        </div>
                        <div className="flex items-end gap-1.5 justify-end">
                          <button
                            type="button"
                            onClick={handleTriggerIngestion}
                            disabled={triggering}
                            className="h-[26px] px-2 rounded-md border border-border text-[11px] font-mono text-foreground/80 hover:text-foreground hover:border-border/80 inline-flex items-center gap-1 disabled:opacity-50"
                          >
                            {triggering ? <Loader2 className="w-3 h-3 animate-spin" strokeWidth={2} /> : <Play className="w-3 h-3" strokeWidth={2} />}
                            Run now
                          </button>
                          <button
                            type="button"
                            onClick={handleToggleIngestion}
                            className="h-[26px] px-2 rounded-md border border-border text-[11px] font-mono text-foreground/80 hover:text-foreground hover:border-border/80"
                          >
                            {ingestion.enabled ? 'Disable' : 'Enable'}
                          </button>
                          <button
                            type="button"
                            onClick={() => setDeleteIngestionDialog(true)}
                            className="h-[26px] w-[26px] rounded-md border border-border text-destructive hover:bg-destructive/10 inline-flex items-center justify-center"
                            aria-label="Remove ingestion"
                          >
                            <Trash2 className="w-3 h-3" strokeWidth={2} />
                          </button>
                        </div>
                      </div>
                    )}
                    {ingestion?.last_run_error && (
                      <div className="flex items-start gap-2 p-2.5 bg-destructive/5 rounded-md border border-destructive/20">
                        <CircleAlert className="w-3.5 h-3.5 text-destructive mt-0.5 shrink-0" strokeWidth={2} />
                        <p className="text-[11px] font-mono text-destructive">{ingestion.last_run_error}</p>
                      </div>
                    )}

                    {/* Form */}
                    {ingestionForm && (
                      <div className="space-y-3">
                        <div className="space-y-1.5">
                          <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground/70">Source URL</Label>
                          <div className="flex items-center gap-2">
                            <Globe className="w-3.5 h-3.5 text-muted-foreground shrink-0" strokeWidth={2} />
                            <Input
                              value={ingestionForm.url}
                              onChange={(e) => updateIngestionField('url', e.target.value)}
                              placeholder="https://example.com/data.csv"
                              className="border-border rounded-md h-[30px] text-[12px] font-mono"
                            />
                          </div>
                        </div>

                        <div className="space-y-1.5">
                          <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground/70">Schedule</Label>
                          <div className="flex gap-2">
                            <Input
                              value={ingestionForm.cron_expression}
                              onChange={(e) => handleCronChange(e.target.value)}
                              placeholder="0 0 * * *"
                              className="border-border rounded-md font-mono h-[30px] text-[12px]"
                            />
                            <Select onValueChange={handleCronChange}>
                              <SelectTrigger className="w-[140px] border-border rounded-md h-[30px] text-[12px]">
                                <SelectValue placeholder="Presets" />
                              </SelectTrigger>
                              <SelectContent className="rounded-md">
                                {CRON_PRESETS.map((preset) => (
                                  <SelectItem key={preset.value} value={preset.value} className="text-foreground text-[12px]">
                                    {preset.label}
                                  </SelectItem>
                                ))}
                              </SelectContent>
                            </Select>
                          </div>
                          {cronDescription && <p className="text-[10.5px] font-mono text-[var(--success)]">{cronDescription}</p>}
                          {cronError && <p className="text-[10.5px] font-mono text-destructive">{cronError}</p>}
                        </div>

                        <div className="grid grid-cols-2 gap-3">
                          <div className="space-y-1.5">
                            <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground/70">Format</Label>
                            <Select value={ingestionForm.format} onValueChange={(v) => updateIngestionField('format', v as FileFormat)}>
                              <SelectTrigger className="border-border rounded-md h-[30px] text-[12px]">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent className="rounded-md">
                                <SelectItem value="csv" className="text-foreground">CSV</SelectItem>
                                <SelectItem value="json" className="text-foreground">JSON</SelectItem>
                                <SelectItem value="ndjson" className="text-foreground">NDJSON</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                          <div className="space-y-1.5">
                            <Label className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground/70">Mode</Label>
                            <Select value={ingestionForm.mode} onValueChange={(v) => updateIngestionField('mode', v as 'replace' | 'append')}>
                              <SelectTrigger className="border-border rounded-md h-[30px] text-[12px]">
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent className="rounded-md">
                                <SelectItem value="replace" className="text-foreground">Replace</SelectItem>
                                <SelectItem value="append" className="text-foreground">Append</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                        </div>

                        <div className="flex items-center justify-between">
                          <Label className="text-[11px] text-foreground/80">Enabled</Label>
                          <Switch
                            checked={ingestionForm.enabled}
                            onCheckedChange={(v) => updateIngestionField('enabled', v)}
                          />
                        </div>

                        {ingestionDirty && (
                          <div className="flex gap-2 pt-1">
                            <button
                              type="button"
                              onClick={() => {
                                if (ingestion) {
                                  setIngestionForm({
                                    url: ingestion.url,
                                    cron_expression: ingestion.cron_expression,
                                    format: ingestion.parser_config.format,
                                    mode: ingestion.destination.mode || 'replace',
                                    enabled: ingestion.enabled,
                                  });
                                } else {
                                  setIngestionForm(null);
                                }
                                setIngestionDirty(false);
                                setCronDescription('');
                                setCronError('');
                              }}
                              className="flex-1 h-[30px] px-3 rounded-md border border-border text-[12px] font-mono text-foreground/80 hover:text-foreground hover:border-border/80"
                            >
                              {ingestion ? 'Discard changes' : 'Cancel'}
                            </button>
                            <button
                              type="button"
                              onClick={handleSaveIngestion}
                              disabled={savingIngestion || !ingestionForm.url || !ingestionForm.cron_expression}
                              className="flex-1 h-[30px] px-3 rounded-md bg-primary text-[var(--brand-ink)] hover:bg-primary/90 text-[12px] font-semibold inline-flex items-center justify-center gap-1.5 disabled:opacity-50"
                            >
                              {savingIngestion ? <Loader2 className="w-3.5 h-3.5 animate-spin" strokeWidth={2} /> : <Save className="w-3.5 h-3.5" strokeWidth={2} />}
                              Save
                            </button>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </CollapsibleContent>
          </Card>
        </Collapsible>
      )}

      {/* Delete Ingestion Confirmation */}
      <ConfirmDialog
        open={deleteIngestionDialog}
        onOpenChange={setDeleteIngestionDialog}
        variant="danger"
        title="Remove ingestion"
        description="Remove the automated ingestion config? The table data will not be affected."
        confirmLabel="Remove"
        onConfirm={handleDeleteIngestion}
      />

      {/* Search bar — lookup by primary key */}
      <div className="flex items-center gap-2">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground" strokeWidth={2} />
          <input
            type="search"
            placeholder={`lookup by ${keyField || 'value'}…`}
            value={searchValue}
            onChange={(e) => setSearchValue(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            className="h-[30px] w-full pl-7 pr-2 rounded-md border border-border bg-card text-[12px] text-foreground placeholder:text-muted-foreground/60 outline-none focus:border-primary/50 font-mono"
          />
        </div>
        <button
          type="button"
          onClick={handleSearch}
          disabled={queryLoading || !searchValue.trim()}
          className="h-[30px] px-3 rounded-md bg-primary text-[var(--brand-ink)] hover:bg-primary/90 text-[12px] font-semibold inline-flex items-center disabled:opacity-50"
        >
          {queryLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" strokeWidth={2} /> : 'Search'}
        </button>
        {searched && (
          <button
            type="button"
            onClick={clearSearch}
            className="h-[30px] px-3 rounded-md border border-border text-[12px] font-mono text-muted-foreground hover:text-foreground hover:border-border/80"
          >
            Clear
          </button>
        )}
        <span className="flex-1" />
        <button
          type="button"
          onClick={() => setPasteDialogOpen(true)}
          className="h-[30px] px-3 rounded-md border border-border text-[12px] font-mono text-foreground/80 hover:text-foreground hover:border-border/80 inline-flex items-center gap-1.5"
        >
          <ClipboardPaste className="w-3.5 h-3.5" strokeWidth={2} />
          Paste
        </button>
      </div>

      {/* Search Result */}
      {searched && (
        <div>
          {notFound ? (
            <div className="flex items-center gap-2 text-muted-foreground py-2 text-[11.5px] font-mono">
              <CircleAlert className="w-3.5 h-3.5" strokeWidth={2} />
              <span>No match found for &quot;{searchValue}&quot;</span>
            </div>
          ) : searchResult ? (
            <div className="rounded-lg border border-border bg-card overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow className="border-border hover:bg-transparent">
                    <TableHead className="text-muted-foreground font-mono text-[10px] uppercase tracking-wider w-1/3 h-[28px]">Field</TableHead>
                    <TableHead className="text-muted-foreground font-mono text-[10px] uppercase tracking-wider h-[28px]">Value</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {Object.entries(searchResult).map(([key, value]) => (
                    <TableRow key={key} className="border-border hover:bg-foreground/[0.02]">
                      <TableCell className="font-mono text-[12px] text-foreground py-1.5">{key}</TableCell>
                      <TableCell className="text-foreground py-1.5">
                        <CellDisplay value={value} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : null}
        </div>
      )}

      {/* Spreadsheet Grid */}
      <div
        ref={gridRef}
        className="rounded-lg border border-border overflow-x-auto bg-card"
        onPaste={handleGridPaste}
      >
        <table className="w-full border-collapse font-mono text-[11px]">
          <thead>
            <tr className="border-b border-border">
              {/* Row number header */}
              <th className="w-10 min-w-[40px] h-[28px] px-2 py-0 bg-foreground/[0.02] border-r border-border text-center text-[9px] text-muted-foreground font-normal select-none" />
              {displayColumns.map((col) => (
                <th
                  key={col.name}
                  className="min-w-[140px] h-[28px] border-r border-border bg-foreground/[0.02] px-2.5 py-1.5 text-left select-none"
                >
                  <div className="flex items-center gap-1.5">
                    <span className="text-[10.5px] text-foreground truncate">
                      {col.name}
                    </span>
                    {col.name === table.primary_key && (
                      <Key className="w-3 h-3 text-[var(--warning)] shrink-0" strokeWidth={2} />
                    )}
                    <span className="text-[9.5px] text-muted-foreground/70 ml-auto shrink-0 uppercase tracking-wider">
                      {col.data_type}
                    </span>
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, rowIdx) => {
              const rowId = row._row_id as number;
              const rowNum = pageOffset + rowIdx + 1;
              return (
                <tr key={rowId} className="border-b border-border/40 group/row hover:bg-foreground/[0.02]">
                  {/* Row number / delete */}
                  <td className="w-10 min-w-[40px] h-[24px] px-2 py-0 bg-foreground/[0.02] border-r border-border/50 text-center text-[9.5px] text-muted-foreground select-none relative tabular-nums">
                    <span className="group-hover/row:hidden">{rowNum}</span>
                    <button
                      onClick={() => confirmDelete(rowId)}
                      className="hidden group-hover/row:flex items-center justify-center w-full text-muted-foreground hover:text-destructive transition-colors"
                      title="Delete row"
                    >
                      <X className="w-3 h-3" strokeWidth={2} />
                    </button>
                  </td>
                  {displayColumns.map((col) => {
                    const isActive = activeCell?.rowIdx === rowIdx && activeCell?.col === col.name;
                    return (
                      <td
                        key={col.name}
                        className={`border-r border-border/40 p-0 ${
                          isActive ? 'ring-2 ring-primary ring-inset bg-primary/5' : ''
                        }`}
                        onClick={() => {
                          if (!isActive) startEdit(rowIdx, col.name, row[col.name]);
                        }}
                      >
                        {isActive ? (
                          <input
                            ref={cellInputRef}
                            type="text"
                            value={editValue}
                            onChange={(e) => setEditValue(e.target.value)}
                            onKeyDown={(e) => handleCellKeyDown(e, rowIdx, col.name)}
                            onBlur={() => saveEdit()}
                            className="w-full h-[24px] px-2.5 bg-transparent text-foreground font-mono text-[11px] outline-none"
                          />
                        ) : (
                          <div className="px-2.5 py-[5px] h-[24px] cursor-cell truncate">
                            <CellDisplay value={row[col.name]} />
                          </div>
                        )}
                      </td>
                    );
                  })}
                </tr>
              );
            })}

            {/* New row being added */}
            {addingRow && (
              <tr className="border-b border-border/40 bg-primary/5">
                <td className="w-10 min-w-[40px] h-[24px] px-2 py-0 bg-foreground/[0.02] border-r border-border/50 text-center">
                  <button
                    onClick={cancelAddRow}
                    className="text-muted-foreground hover:text-destructive transition-colors"
                    title="Cancel"
                  >
                    <X className="w-3 h-3" strokeWidth={2} />
                  </button>
                </td>
                {displayColumns.map((col, colIdx) => (
                  <td key={col.name} className="border-r border-border/40 p-0">
                    <input
                      type="text"
                      value={newRowData[col.name] || ''}
                      onChange={(e) => setNewRowData((prev) => ({ ...prev, [col.name]: e.target.value }))}
                      placeholder={col.data_type}
                      className="w-full h-[24px] px-2.5 bg-transparent text-foreground font-mono text-[11px] outline-none placeholder:text-muted-foreground/40"
                      onKeyDown={handleNewRowKeyDown}
                      autoFocus={colIdx === 0}
                    />
                  </td>
                ))}
              </tr>
            )}

            {/* Add row button */}
            <tr>
              <td className="w-10 min-w-[40px] h-[26px] px-2 py-0 bg-foreground/[0.02] border-r border-border/50">
                <button
                  onClick={startAddRow}
                  className="w-full h-full flex items-center justify-center text-muted-foreground hover:text-primary transition-colors"
                  title="Add row"
                  disabled={addingRow}
                >
                  <Plus className="w-3 h-3" strokeWidth={2} />
                </button>
              </td>
              <td
                colSpan={displayColumns.length}
                className="text-[10.5px] text-muted-foreground px-2.5 py-1.5 h-[26px] cursor-pointer hover:text-foreground transition-colors"
                onClick={() => !addingRow && startAddRow()}
              >
                {addingRow ? 'type values and press Enter to save' : 'click to add a row, or paste data (Ctrl+V)'}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-[11px] font-mono text-muted-foreground">
            Page <span className="tabular-nums text-foreground/80">{page}</span> of <span className="tabular-nums text-foreground/80">{totalPages}</span>
          </p>
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="h-[28px] px-2.5 rounded-md border border-border text-[11.5px] font-mono text-foreground/80 hover:text-foreground hover:border-border/80 inline-flex items-center gap-1 disabled:opacity-40"
            >
              <ChevronLeft className="w-3 h-3" strokeWidth={2} />
              Previous
            </button>
            <button
              type="button"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="h-[28px] px-2.5 rounded-md border border-border text-[11.5px] font-mono text-foreground/80 hover:text-foreground hover:border-border/80 inline-flex items-center gap-1 disabled:opacity-40"
            >
              Next
              <ChevronRight className="w-3 h-3" strokeWidth={2} />
            </button>
          </div>
        </div>
      )}

      {/* Delete Confirmation */}
      <ConfirmDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        variant="danger"
        title="Delete row"
        description="Permanently delete this row? This action cannot be undone."
        confirmLabel="Delete"
        onConfirm={handleDelete}
      />

      {/* Paste Data Dialog */}
      <Sheet open={pasteDialogOpen} onOpenChange={setPasteDialogOpen}>
        <SheetContent className="w-[480px] sm:w-[560px] overflow-y-auto">
          <SheetHeader>
            <SheetTitle className="text-[14px]">Paste data</SheetTitle>
            <SheetDescription className="text-[11.5px]">
              {table.columns.length === 1
                ? 'Paste one value per line.'
                : 'Paste tab-separated values. An optional header row is detected automatically.'}
            </SheetDescription>
          </SheetHeader>

          <div className="space-y-3 mt-4">
            <Textarea
              value={pasteText}
              onChange={(e) => setPasteText(e.target.value)}
              placeholder={table.columns.length === 1
                ? `value1\nvalue2\nvalue3`
                : table.columns.map((c) => c.name).join('\t') + '\nvalue1\tvalue2\t...'
              }
              className="min-h-[150px] font-mono text-[12px] border-border rounded-md"
            />

            {parsedPasteRows.length > 0 && (
              <div>
                <p className="text-[10.5px] font-mono uppercase tracking-wider text-muted-foreground/70 mb-1.5">
                  Preview · <span className="tabular-nums text-foreground/80">{parsedPasteRows.length}</span> row{parsedPasteRows.length !== 1 ? 's' : ''} parsed
                </p>
                <div className="rounded-md border border-border bg-card overflow-x-auto max-h-[200px]">
                  <Table>
                    <TableHeader>
                      <TableRow className="border-border hover:bg-transparent">
                        {displayColumns.map((col) => (
                          <TableHead key={col.name} className="text-muted-foreground font-mono text-[10px] uppercase tracking-wider whitespace-nowrap h-[26px]">
                            {col.name}
                          </TableHead>
                        ))}
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {parsedPasteRows.slice(0, 10).map((row, i) => (
                        <TableRow key={i} className="border-border/40">
                          {displayColumns.map((col) => (
                            <TableCell key={col.name} className="text-foreground py-1 font-mono text-[11px]">
                              <CellDisplay value={row[col.name]} />
                            </TableCell>
                          ))}
                        </TableRow>
                      ))}
                      {parsedPasteRows.length > 10 && (
                        <TableRow className="border-border/40">
                          <TableCell colSpan={displayColumns.length} className="text-center text-muted-foreground text-[10.5px] font-mono py-2">
                            …and {parsedPasteRows.length - 10} more rows
                          </TableCell>
                        </TableRow>
                      )}
                    </TableBody>
                  </Table>
                </div>
              </div>
            )}
          </div>

          <SheetFooter className="mt-6 gap-2">
            <button
              type="button"
              onClick={() => { setPasteDialogOpen(false); setPasteText(''); setParsedPasteRows([]); }}
              className="h-[30px] px-3 rounded-md border border-border text-[12px] font-mono text-foreground/80 hover:text-foreground hover:border-border/80"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handlePasteSubmit}
              disabled={parsedPasteRows.length === 0}
              className="h-[30px] px-3 rounded-md bg-primary text-[var(--brand-ink)] hover:bg-primary/90 text-[12px] font-semibold disabled:opacity-50"
            >
              Add {parsedPasteRows.length} row{parsedPasteRows.length !== 1 ? 's' : ''}
            </button>
          </SheetFooter>
        </SheetContent>
      </Sheet>
    </div>
    {showInspector && (
      <DetailInspector
        table={table}
        ingestion={ingestion}
        source={source}
        total={total}
        cols={displayColumns}
        usage={usage}
        triggering={triggering}
        onTrigger={handleTriggerIngestion}
        onDelete={() => setDeleteTableDialog(true)}
      />
    )}
    <ConfirmDialog
      open={deleteTableDialog}
      onOpenChange={setDeleteTableDialog}
      variant="danger"
      title="Delete lookup table"
      description={
        <>
          Permanently delete <span className="font-mono">{table.name}</span>? All rows
          and ingestion config are removed; rules referencing it will fail until rewired.
        </>
      }
      confirmLabel="Delete"
      onConfirm={handleDeleteTable}
    />
    </div>
  );
}

// --------------------------------------------------------------------
// Right Details inspector (NAN-510 PR 2). Per `design-ref/shadcn/lookup-detail.jsx`.
// Owner wired (NAN-514) + usage rule count wired (NAN-511).
// --------------------------------------------------------------------

const SOURCE_LABELS: Record<LookupSource, string> = {
  upload: 'Uploaded file',
  define: 'Manually defined',
  url:    'URL import',
};

interface DetailInspectorProps {
  table: {
    name: string;
    size_bytes: number;
    updated_at: string;
    created_by?: { name: string; email: string } | null;
  };
  ingestion: { url: string; parser_config: { format: string }; last_run_status?: string } | null | undefined;
  source: LookupSource;
  total: number;
  cols: { name: string }[];
  usage: { rule_id: string; rule_name: string }[] | null | undefined;
  triggering: boolean;
  onTrigger: () => void;
  onDelete: () => void;
}

/**
 * Two-letter initials for an avatar — first letter of the first and last
 * whitespace-separated tokens of the display name. Falls back to the first
 * two letters of the name when there's only one token, and to `··` when no
 * name is available.
 */
function ownerInitials(name: string | undefined): string {
  if (!name) return '··';
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return '··';
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  const first = parts[0]?.[0] ?? '';
  const last = parts[parts.length - 1]?.[0] ?? '';
  return `${first}${last}`.toUpperCase();
}

function DetailInspector({
  table,
  ingestion,
  source,
  total,
  cols,
  usage,
  triggering,
  onTrigger,
  onDelete,
}: DetailInspectorProps) {
  const sourceDetail = source === 'url' ? (ingestion?.url ?? '—') : '—';
  const format = ingestion?.parser_config?.format ?? '—';
  return (
    <aside className="w-[280px] shrink-0 border-l border-border flex flex-col overflow-hidden bg-card/30">
      <div className="shrink-0 h-[36px] px-3 flex items-center border-b border-border">
        <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Details</span>
      </div>
      <div className="flex-1 min-h-0 overflow-y-auto p-4 flex flex-col gap-4">
        <InspectorSection label="Source">
          <div className="flex items-center gap-2 mb-1">
            <SourceTag source={source} />
            <span className="text-[11px] font-mono text-muted-foreground">· {SOURCE_LABELS[source]}</span>
          </div>
          <div className="text-[10.5px] font-mono text-muted-foreground/80 break-all">{sourceDetail}</div>
          {source === 'url' && ingestion && (
            <button
              type="button"
              onClick={onTrigger}
              disabled={triggering}
              className="mt-2 w-full h-[26px] rounded-md border border-border text-[11px] font-mono text-foreground/80 hover:text-foreground hover:border-border/80 inline-flex items-center justify-center gap-1.5 disabled:opacity-50"
            >
              {triggering ? <Loader2 className="w-3 h-3 animate-spin" strokeWidth={2} /> : <RefreshCw className="w-3 h-3" strokeWidth={2} />}
              refresh now
            </button>
          )}
        </InspectorSection>

        <div className="h-px bg-border" />

        <InspectorSection label="Stats">
          <div className="grid grid-cols-2 gap-y-2 gap-x-3">
            <MetaPill label="rows" value={total.toLocaleString()} />
            <MetaPill label="size" value={formatBytes(table.size_bytes)} />
            <MetaPill label="cols" value={cols.length} />
            <MetaPill label="format" value={format} />
          </div>
        </InspectorSection>

        <div className="h-px bg-border" />

        <InspectorSection label="Ownership">
          <div className="flex flex-col gap-1.5">
            <div className="flex items-center gap-2">
              {table.created_by ? (
                <>
                  <span
                    className="w-[20px] h-[20px] rounded-full bg-primary/10 border border-primary/30 text-primary flex items-center justify-center font-mono font-semibold text-[9px] shrink-0"
                    title={table.created_by.email}
                  >
                    {ownerInitials(table.created_by.name)}
                  </span>
                  <span
                    className="text-[11.5px] font-mono text-foreground/90 truncate"
                    title={table.created_by.email}
                  >
                    {table.created_by.name || table.created_by.email}
                  </span>
                </>
              ) : (
                <>
                  <span className="w-[20px] h-[20px] rounded-full bg-foreground/[0.06] border border-border text-muted-foreground/60 flex items-center justify-center font-mono font-semibold text-[9px] shrink-0">
                    ··
                  </span>
                  <span className="text-[11.5px] font-mono text-muted-foreground/60 truncate">—</span>
                </>
              )}
            </div>
            <div className="text-[10.5px] font-mono text-muted-foreground">updated {formatUTC(table.updated_at)}</div>
          </div>
        </InspectorSection>

        <div className="h-px bg-border" />

        <InspectorSection label="Usage">
          <div className="rounded-md border border-border bg-card p-2.5">
            <div className="flex items-baseline gap-1">
              {usage == null ? (
                <span className="text-[20px] font-semibold text-muted-foreground/40 tabular-nums leading-none">—</span>
              ) : (
                <span className={`text-[20px] font-semibold tabular-nums leading-none ${usage.length === 0 ? 'text-muted-foreground/60' : 'text-foreground'}`}>
                  {usage.length}
                </span>
              )}
              <span className="text-[10.5px] font-mono text-muted-foreground">rule{usage?.length === 1 ? '' : 's'}</span>
            </div>
            <div className="text-[9.5px] font-mono text-muted-foreground/70 mt-0.5">reference this table</div>
          </div>
        </InspectorSection>

        <div className="h-px bg-border" />

        <InspectorSection label="Danger zone">
          <button
            type="button"
            onClick={onDelete}
            className="w-full h-[26px] px-2.5 rounded-md border border-destructive/30 text-[11px] font-mono text-destructive hover:bg-destructive/10 text-left"
          >
            delete permanently
          </button>
        </InspectorSection>
      </div>
    </aside>
  );
}

function InspectorSection({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <div className="text-[9.5px] font-mono uppercase tracking-wider text-muted-foreground/70 mb-1.5">{label}</div>
      {children}
    </div>
  );
}

function MetaPill({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[9.5px] font-mono uppercase tracking-wider text-muted-foreground/60">{label}</span>
      <span className="text-[11.5px] font-mono text-foreground/90 truncate">{value}</span>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function CellDisplay({ value }: { value: unknown }) {
  if (value === null || value === undefined) {
    return <span className="text-muted-foreground/40">·</span>;
  }

  if (typeof value === 'object') {
    return (
      <code className="text-[10.5px] font-mono bg-foreground/5 px-1 py-[1px] rounded-sm text-primary">
        {JSON.stringify(value)}
      </code>
    );
  }

  if (typeof value === 'boolean') {
    return (
      <span className={value ? 'text-primary' : 'text-muted-foreground'}>
        {value ? 'true' : 'false'}
      </span>
    );
  }

  if (typeof value === 'number') {
    return <span className="text-primary tabular-nums">{value}</span>;
  }

  return <span className="text-foreground/90">{String(value)}</span>;
}
