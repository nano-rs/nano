// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-574 — Marketplace preview output sheet (DetailSheet since NAN-3209).
 *
 * Triggered from the "preview output" button in the drawer header. Calls
 * POST /api/marketplace/catalog/{slug}/preview with a sample artifact and
 * renders the parsed AgentEnrichmentResult JSON. Handles three states:
 *
 * - `note` returned: backend declined to run (native/identity backend, or
 *   missing code). Render the note as plain copy.
 * - `success === false` and an `error` returned: sandbox-level failure;
 *   render error + stderr.
 * - `success === true`: pretty-print `output`, plus a duration chip and
 *   a "what was tested" line ("ran ip = 8.8.8.8 in 412 ms").
 */

import { useEffect, useState } from 'react';
import {
  AlertTriangle, CheckCircle, Eye, RefreshCw,
} from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { DetailSheet } from '@/components/ui/detail-sheet';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import { api } from '@/lib/api';
import type { PreviewResponse } from '@/lib/api/marketplace';
import { cn } from '@/lib/utils';

const ARTIFACT_TYPES = [
  { value: 'ip',       label: 'IP',       sample: '8.8.8.8' },
  { value: 'domain',   label: 'Domain',   sample: 'example.com' },
  { value: 'hash',     label: 'Hash',     sample: '44d88612fea8a8f36de82e1278abb02f' },
  { value: 'url',      label: 'URL',      sample: 'https://example.com/test' },
  { value: 'email',    label: 'Email',    sample: 'test@example.com' },
  { value: 'filename', label: 'Filename', sample: 'example.txt' },
] as const;

interface PreviewModalProps {
  /** Catalog slug; null closes the modal. */
  slug: string | null;
  /** Display name for the modal title. */
  name: string | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function PreviewModal({ slug, name, open, onOpenChange }: PreviewModalProps) {
  const [artifactType, setArtifactType] = useState<string>('ip');
  const [artifact, setArtifact] = useState<string>('');
  const [running, setRunning] = useState(false);
  const [response, setResponse] = useState<PreviewResponse | null>(null);

  // Reset when the slug changes (different enrichment opened).
  useEffect(() => {
    if (slug && open) {
      setArtifactType('ip');
      setArtifact('');
      setResponse(null);
      // Auto-run on open so the user sees a result immediately.
      void run('ip', '');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [slug, open]);

  const run = async (typeOverride?: string, valueOverride?: string) => {
    if (!slug) return;
    setRunning(true);
    setResponse(null);
    try {
      const resp = await api.marketplace.previewEnrichment(slug, {
        artifact_type: typeOverride ?? artifactType,
        artifact: (valueOverride ?? artifact).trim() || undefined,
      });
      setResponse(resp);
    } catch (e) {
      setResponse({
        success: false,
        artifact: valueOverride ?? artifact,
        artifact_type: typeOverride ?? artifactType,
        output: null,
        stdout: '',
        stderr: '',
        duration_ms: 0,
        note: null,
        error: e instanceof Error ? e.message : 'Preview failed',
      });
    } finally {
      setRunning(false);
    }
  };

  const sample = ARTIFACT_TYPES.find(t => t.value === artifactType)?.sample;

  return (
    <DetailSheet
      open={open}
      onOpenChange={onOpenChange}
      size="md"
      breadcrumb={['Marketplace', name ?? slug ?? undefined]}
      icon={<Eye className="w-[14px] h-[14px] text-primary" />}
      title="Preview output"
      description="Runs the enrichment once against a sample artifact in the Deno sandbox. Credentials and allowed-domains use the saved configuration."
      meta={slug ? <span>{slug}</span> : undefined}
      bodyClassName="p-0"
    >
        {/* Inputs row */}
        <div className="sticky top-0 z-10 bg-card px-4 py-3 border-b border-border/60 flex items-end gap-2">
          <div className="w-[110px]">
            <Label className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
              Type
            </Label>
            <Select value={artifactType} onValueChange={setArtifactType}>
              <SelectTrigger className="h-8 mt-1 rounded-md text-[12px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ARTIFACT_TYPES.map(t => (
                  <SelectItem key={t.value} value={t.value} className="text-[12px]">
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex-1">
            <Label className="text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground">
              Artifact
            </Label>
            <Input
              value={artifact}
              onChange={(e) => setArtifact(e.target.value)}
              placeholder={sample}
              className="h-8 mt-1 rounded-md font-mono text-[12px]"
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !running) {
                  e.preventDefault();
                  void run();
                }
              }}
            />
          </div>
          <Button
            size="sm"
            className="h-8 rounded-md text-[12px]"
            onClick={() => run()}
            disabled={running || !slug}
          >
            {running ? <LoadingIcon className="w-3.5 h-3.5" /> : <RefreshCw className="w-3.5 h-3.5" />}
            Run
          </Button>
        </div>

        {/* Result body */}
        <div>
          {!response && running && (
            <div className="px-4 py-12 flex items-center justify-center text-[12px] text-muted-foreground">
              <LoadingIcon className="w-4 h-4 mr-2" /> running sandbox…
            </div>
          )}
          {response && (
            <PreviewResultBody response={response} />
          )}
        </div>
    </DetailSheet>
  );
}

function PreviewResultBody({ response }: { response: PreviewResponse }) {
  // 1. Backend-declined preview (native / identity / missing code) — show note.
  if (response.note) {
    return (
      <div className="px-4 py-4 text-[12.5px] text-muted-foreground" style={{ textWrap: 'pretty' }}>
        <div className="flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
          <span>{response.note}</span>
        </div>
      </div>
    );
  }

  return (
    <div className="px-4 py-3 space-y-3">
      {/* Status row */}
      <div className="flex items-center gap-2 text-[11px] font-mono">
        {response.success ? (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border bg-emerald-500/10 border-emerald-500/30 text-emerald-500 uppercase tracking-[0.1em]">
            <CheckCircle className="w-[10px] h-[10px]" /> ok
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border bg-red-500/10 border-red-500/30 text-red-500 uppercase tracking-[0.1em]">
            <AlertTriangle className="w-[10px] h-[10px]" /> failed
          </span>
        )}
        <span className="text-muted-foreground">
          ran <span className="text-foreground">{response.artifact_type}</span> ={' '}
          <span className="text-foreground">{response.artifact}</span>
        </span>
        <span className="text-muted-foreground/60">·</span>
        <span className="text-muted-foreground tabular-nums">{response.duration_ms} ms</span>
      </div>

      {/* Error banner */}
      {response.error && (
        <div className="rounded-md border border-red-500/30 bg-red-500/5 px-3 py-2 text-[11.5px] text-red-500 font-mono whitespace-pre-wrap break-words">
          {response.error}
        </div>
      )}

      {/* Output JSON */}
      {response.output && (
        <div>
          <div className="font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground mb-1.5">
            Output
          </div>
          <pre className="rounded-md border border-border/60 bg-muted/20 p-3 font-mono text-[11.5px] text-foreground/90 leading-[1.55] overflow-x-auto whitespace-pre">
            {JSON.stringify(response.output, null, 2)}
          </pre>
        </div>
      )}

      {/* Stderr (only if non-empty and meaningful) */}
      {response.stderr && response.stderr.trim().length > 0 && (
        <details className="group">
          <summary
            className={cn(
              'cursor-pointer font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground',
              'hover:text-foreground select-none',
            )}
          >
            Stderr
          </summary>
          <pre className="mt-1.5 rounded-md border border-border/60 bg-muted/20 p-3 font-mono text-[11px] text-muted-foreground leading-[1.55] overflow-x-auto whitespace-pre-wrap">
            {response.stderr}
          </pre>
        </details>
      )}
    </div>
  );
}
