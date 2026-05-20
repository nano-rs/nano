// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * ParserTestLab — Right-side panel for testing parsers.
 *
 * Structured test results with:
 * - Card-style event rows with colored left border (green/red)
 * - Key field preview in collapsed state + field count badge
 * - Two-column grid layout for parsed fields when expanded
 * - Paste box pinned at the bottom for custom log input
 */

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import {
  Play,
  Database,
  Loader2,
  FlaskConical,
  Clipboard,
  CircleCheck,
  XCircle,
  ChevronRight,
  ChevronDown,
} from 'lucide-react';
import { useTestLogSourceVrl, useTestLogSourceVrlLive } from '@/hooks/use-api';
import { useToast } from '@/hooks/use-toast';
import { extractFields } from './TestResultRow';
import type { LiveTestResult } from '@/lib/api/types';

interface ParserTestLabProps {
  vrlCode: string;
  sourceType: string;
  currentDeployedVrl?: string;
  /**
   * NAN-874: when present, the paste test runs `vrlCode → extensionVrl` as a chain
   * (matches the production extension pipeline). Live test is hidden in this mode
   * pending chain-aware comparison support on the backend.
   */
  extensionVrl?: string;
}

/** Key fields to preview in collapsed row — shown as badges */
const PREVIEW_FIELDS = ['event_type', 'src_ip', 'dest_host', 'dest_ip', 'user', 'process_name', 'http_method', 'src_host'];

/** Render parsed fields — diffs grouped at top, unchanged in grid below */
function FieldGrid({
  newFields,
  currentFields,
}: {
  newFields: Record<string, string>;
  currentFields?: Record<string, string>;
}) {
  const allKeys = [...new Set([
    ...Object.keys(newFields),
    ...(currentFields ? Object.keys(currentFields) : []),
  ])].sort();

  if (allKeys.length === 0) {
    return <p className="text-[11px] text-muted-foreground p-3">No fields extracted</p>;
  }

  // Separate changed vs unchanged fields
  const changed: string[] = [];
  const unchanged: string[] = [];
  for (const key of allKeys) {
    const curr = currentFields?.[key];
    const next = newFields[key];
    if (currentFields && ((!curr && next) || (curr && !next) || (curr && next && curr !== next))) {
      changed.push(key);
    } else {
      unchanged.push(key);
    }
  }

  const udmUnchanged = unchanged.filter(k => !k.startsWith('ext.'));
  const extUnchanged = unchanged.filter(k => k.startsWith('ext.'));

  const renderFieldRow = (key: string) => {
    const curr = currentFields?.[key];
    const next = newFields[key];
    const isNew = !curr && next;
    const isRemoved = curr && !next;
    const isChanged = curr && next && curr !== next;

    let valueBg = '';
    let valueColor = 'text-foreground';
    if (isNew) { valueBg = 'bg-green-500/10'; valueColor = 'text-green-400'; }
    else if (isRemoved) { valueBg = 'bg-red-500/10'; valueColor = 'text-red-400'; }
    else if (isChanged) { valueBg = 'bg-yellow-500/10'; valueColor = 'text-yellow-400'; }

    return (
      <div key={key} className={`flex items-baseline gap-2 px-3 py-1 rounded ${valueBg}`}>
        <span className="text-muted-foreground text-[11px] font-mono shrink-0 w-[140px] truncate" title={key}>
          {key}
        </span>
        <span className={`text-[11px] font-mono ${valueColor} truncate`} title={next || curr || ''}>
          {isRemoved ? (
            <span className="line-through">{curr}</span>
          ) : (
            next || <span className="text-muted-foreground/30">—</span>
          )}
          {isChanged && (
            <span className="text-muted-foreground/50 ml-1 text-[10px]">was: {curr}</span>
          )}
        </span>
      </div>
    );
  };

  return (
    <div className="py-1">
      {/* Diff section — full width, grouped at top */}
      {changed.length > 0 && (
        <div className="mb-1">
          {changed.map(renderFieldRow)}
        </div>
      )}

      {/* Unchanged UDM fields — two-column grid */}
      {udmUnchanged.length > 0 && (
        <>
          {changed.length > 0 && (
            <div className="border-t border-border/20 mx-3 my-1" />
          )}
          <div className="grid grid-cols-2 gap-x-1">
            {udmUnchanged.map(renderFieldRow)}
          </div>
        </>
      )}

      {/* Unchanged ext fields */}
      {extUnchanged.length > 0 && (
        <>
          <div className="px-3 pt-2 pb-1">
            <span className="text-[10px] uppercase tracking-wider text-muted-foreground/60 font-medium">Extended Fields</span>
          </div>
          <div className="grid grid-cols-2 gap-x-1">
            {extUnchanged.map(renderFieldRow)}
          </div>
        </>
      )}
    </div>
  );
}

/** Collapsed event row — shows key field badges + field count */
function EventRowHeader({
  result,
  fields,
  fieldCount,
  expanded,
  onToggle,
}: {
  result: { success: boolean; error?: string };
  fields: Record<string, string>;
  fieldCount: number;
  expanded: boolean;
  onToggle: () => void;
}) {
  const previewEntries = PREVIEW_FIELDS
    .filter(k => fields[k])
    .slice(0, 4)
    .map(k => ({ key: k, value: fields[k] }));

  return (
    <button
      className="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-muted/20 transition-colors"
      onClick={onToggle}
    >
      {result.success ? (
        <CircleCheck className="w-3.5 h-3.5 text-green-400 shrink-0" />
      ) : (
        <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
      )}

      <div className="flex items-center gap-1.5 flex-1 min-w-0 overflow-hidden">
        {previewEntries.map(({ key, value }) => (
          <span
            key={key}
            className="inline-flex items-center gap-1 text-[10px] bg-muted/50 rounded px-1.5 py-0.5 font-mono truncate max-w-[120px]"
            title={`${key}: ${value}`}
          >
            <span className="text-muted-foreground">{key}:</span>
            <span className="text-foreground truncate">{value}</span>
          </span>
        ))}
        {previewEntries.length === 0 && result.error && (
          <span className="text-red-400 text-[10px] truncate">{result.error}</span>
        )}
      </div>

      <Badge variant="secondary" className="text-[10px] px-1.5 py-0 rounded shrink-0 font-mono">
        {fieldCount}
      </Badge>

      {expanded ? (
        <ChevronDown className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
      ) : (
        <ChevronRight className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
      )}
    </button>
  );
}

export function ParserTestLab({ vrlCode, sourceType, currentDeployedVrl, extensionVrl }: ParserTestLabProps) {
  const { toast } = useToast();
  const { mutate: testVrl, loading: testLoading } = useTestLogSourceVrl();
  const { mutate: testVrlLive, loading: liveLoading } = useTestLogSourceVrlLive();

  // Paste test state — each non-blank line is tested as a separate event.
  const [pasteInput, setPasteInput] = useState('');
  const [pasteResults, setPasteResults] = useState<Array<{
    input: string;
    success: boolean;
    output?: Record<string, unknown>;
    error?: string;
  }> | null>(null);

  // Live events state
  const [liveResults, setLiveResults] = useState<LiveTestResult[] | null>(null);
  const [expandedResult, setExpandedResult] = useState<number | null>(null);
  const [liveLimit, setLiveLimit] = useState('10');

  const livePassed = liveResults?.filter(r => r.new_parse.success).length ?? 0;
  const liveFailed = liveResults ? liveResults.length - livePassed : 0;

  const handlePasteTest = async () => {
    // Split on newlines — every non-blank line is its own event. Pasting 5
    // log lines runs 5 separate tests, not 1 collapsed test. Cap to keep a
    // runaway paste from fanning out 100+ concurrent backend calls.
    const MAX_PASTE_EVENTS = 20;
    const lines = pasteInput.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);
    if (lines.length === 0) {
      toast({ title: 'No input', description: 'Paste one or more raw events to test', variant: 'destructive' });
      return;
    }
    const capped = lines.slice(0, MAX_PASTE_EVENTS);
    if (lines.length > MAX_PASTE_EVENTS) {
      toast({
        title: `Capped at ${MAX_PASTE_EVENTS} events`,
        description: `Testing the first ${MAX_PASTE_EVENTS} of ${lines.length} lines.`,
      });
    }
    try {
      const results = await Promise.all(
        capped.map((line) =>
          testVrl({ vrlCode, sampleLog: line, extensionVrl }).then((r) => ({
            input: line,
            success: r.success,
            output: r.output as Record<string, unknown> | undefined,
            error: r.error ?? undefined,
          })),
        ),
      );
      setPasteResults(results);
    } catch (err) {
      toast({ title: 'Test error', description: err instanceof Error ? err.message : 'Failed to test', variant: 'destructive' });
    }
  };

  const handleLiveTest = async () => {
    try {
      const results = await testVrlLive({
        vrlCode,
        sourceType,
        currentVrl: currentDeployedVrl,
        limit: parseInt(liveLimit, 10),
      });
      setLiveResults(results);
      setExpandedResult(0);
      const passed = results.filter(r => r.new_parse.success).length;
      const failed = results.length - passed;
      if (failed === 0) {
        toast({ title: 'All tests passed', description: `${passed} events parsed successfully` });
      } else {
        toast({ title: `${failed} of ${results.length} failed`, variant: 'destructive' });
      }
    } catch (err) {
      toast({ title: 'Live test error', description: err instanceof Error ? err.message : 'Failed', variant: 'destructive' });
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      handlePasteTest();
    }
  };

  const pastePassed = pasteResults?.filter((r) => r.success).length ?? 0;
  const pasteFailed = pasteResults ? pasteResults.length - pastePassed : 0;

  return (
    <div className="bg-card border-0 flex flex-col h-full min-h-0 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-border shrink-0">
        <div className="flex items-center gap-2">
          <FlaskConical className="w-3.5 h-3.5 text-muted-foreground" />
          <span className="text-[11.5px] font-medium text-foreground">Test Lab</span>
          {liveResults && (
            <div className="flex items-center gap-1.5 font-mono text-[10.5px] text-muted-foreground">
              <span className="text-green-400">{livePassed}</span>
              <span>/</span>
              <span>{liveResults.length}</span>
              {liveFailed > 0 && (
                <Badge variant="destructive" className="text-[9.5px] rounded-md px-1 py-0 font-mono">
                  {liveFailed}
                </Badge>
              )}
            </div>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={handleLiveTest}
            disabled={liveLoading || !!extensionVrl}
            title={
              extensionVrl
                ? 'Live test against deployed events is not yet supported for parser extensions — use paste mode'
                : undefined
            }
            className="h-7 text-[11.5px] rounded-md border-border gap-1"
          >
            {liveLoading ? (
              <Loader2 className="w-3 h-3 animate-spin" />
            ) : (
              <Database className="w-3 h-3" />
            )}
            {liveLoading ? 'Fetching...' : 'Fetch Events'}
          </Button>
          <Select value={liveLimit} onValueChange={setLiveLimit} disabled={!!extensionVrl}>
            <SelectTrigger className="w-16 h-7 text-[11.5px] rounded-md border-border">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="5">5</SelectItem>
              <SelectItem value="10">10</SelectItem>
              <SelectItem value="20">20</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* Live event results */}
      <ScrollArea className="flex-1 min-h-0">
        <div className="p-3 space-y-3">
          {liveResults ? (
            liveResults.map((result, idx) => {
              const isExpanded = expandedResult === idx;
              const newFields = extractFields(result.new_parse.output);
              const currentFields = result.current_parse ? extractFields(result.current_parse.output) : undefined;
              const fieldCount = Object.keys(newFields).length;

              return (
                <div
                  key={idx}
                  className={`rounded-md border bg-background overflow-hidden ${
                    result.new_parse.success ? 'border-border' : 'border-red-500/30'
                  }`}
                  style={{
                    borderLeftWidth: '3px',
                    borderLeftColor: result.new_parse.success ? 'rgb(74 222 128)' : 'rgb(248 113 113)',
                  }}
                >
                  <EventRowHeader
                    result={result.new_parse}
                    fields={newFields}
                    fieldCount={fieldCount}
                    expanded={isExpanded}
                    onToggle={() => setExpandedResult(isExpanded ? null : idx)}
                  />

                  {isExpanded && (
                    <div className="border-t border-border/40">
                      {/* Raw log preview */}
                      <div className="px-3 py-1.5 bg-muted/20 border-b border-border/20">
                        <p className="text-[10px] text-muted-foreground font-mono leading-relaxed break-all line-clamp-2">
                          {result.input}
                        </p>
                      </div>
                      <FieldGrid newFields={newFields} currentFields={currentFields} />
                    </div>
                  )}
                </div>
              );
            })
          ) : !pasteResults ? (
            <div className="text-center py-12 text-[11px] text-muted-foreground/80">
              Click <strong className="text-foreground/80">Fetch Events</strong> to test against real ingested data
            </div>
          ) : null}

          {/* Paste result cards — one per non-blank input line, rendered after the live results */}
          {pasteResults && pasteResults.map((r, idx) => {
            const fields = extractFields(r.output);
            const fieldCount = Object.keys(fields).length;
            return (
              <div
                key={idx}
                className={`rounded-md border bg-background overflow-hidden ${
                  r.success ? 'border-border' : 'border-red-500/30'
                }`}
                style={{
                  borderLeftWidth: '3px',
                  borderLeftColor: r.success ? 'rgb(74 222 128)' : 'rgb(248 113 113)',
                }}
              >
                <div className="flex items-center gap-2 px-3 py-2">
                  {r.success ? (
                    <CircleCheck className="w-3.5 h-3.5 text-green-400 shrink-0" />
                  ) : (
                    <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                  )}
                  <span className="font-mono text-[10.5px] text-muted-foreground">
                    Event {idx + 1}
                  </span>
                  <Badge variant="secondary" className="text-[9.5px] px-1.5 py-0 rounded font-mono">
                    {fieldCount}
                  </Badge>
                </div>
                <div className="border-t border-border/40">
                  <div className="px-3 py-1.5 bg-muted/20 border-b border-border/20">
                    <p className="text-[10px] text-muted-foreground font-mono leading-relaxed break-all line-clamp-2">
                      {r.input}
                    </p>
                  </div>
                  {r.error ? (
                    <p className="text-red-400 text-[11px] px-3 py-2">{r.error}</p>
                  ) : (
                    <FieldGrid newFields={fields} />
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </ScrollArea>

      {/* Paste input — pinned at bottom, always editable */}
      <div className="shrink-0 border-t border-border p-3">
        <div className="flex items-center gap-2 mb-2">
          <Clipboard className="w-3 h-3 text-muted-foreground" />
          <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
            Paste raw logs (one per line)
          </span>
          {pasteResults && pasteResults.length > 0 && (
            <span className="font-mono text-[10px] text-muted-foreground/80">
              <span className="text-green-400">{pastePassed}</span>
              <span className="text-muted-foreground/60"> / </span>
              <span>{pasteResults.length}</span>
              {pasteFailed > 0 && (
                <span className="text-red-400"> · {pasteFailed} failed</span>
              )}
            </span>
          )}
        </div>
        <div className="flex gap-2 items-start">
          <textarea
            className="flex-1 bg-background font-mono text-[11px] text-foreground p-2 rounded-md border border-border resize-y outline-none placeholder:text-muted-foreground/50 min-h-[100px] max-h-[320px] focus:min-h-[160px] transition-[min-height] duration-150 focus:border-primary focus:ring-1 focus:ring-primary/30"
            placeholder="Paste 1+ raw events, one per line. Cmd/Ctrl+Enter to run."
            value={pasteInput}
            onChange={(e) => setPasteInput(e.target.value)}
            onKeyDown={handleKeyDown}
            spellCheck={false}
          />
          <Button
            size="sm"
            className="h-8 shrink-0 rounded-md px-3 text-[11.5px]"
            onClick={handlePasteTest}
            disabled={testLoading || !pasteInput.trim()}
          >
            {testLoading ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span className="ml-1.5">{pasteResults ? 'Re-test' : 'Test'}</span>
              </>
            )}
          </Button>
        </div>
      </div>
    </div>
  );
}
