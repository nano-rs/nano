// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Saved parser samples of a hosted-shared log source (NAN-2617, design §7.2
 * step 3). The samples belong to the source's active published version and
 * are what the next parser rollout's build runs through `vector test`.
 * `GET` / `PUT /api/log-sources/{id}/samples`; editing needs
 * `log_sources:edit`.
 */

import { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, Plus, RotateCcw, Save, X } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { useAuth } from '@/contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/lib/api';
import type { TenantParserSamples } from '@/lib/api/types';
import { cn } from '@/lib/utils';
import { DEFAULT_MAX_SAMPLES, DEFAULT_MAX_SAMPLE_BYTES, PARSER_SAMPLES_QUERY_KEY, checkSamples } from '@/lib/parser-samples';


function sameSamples(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((s, i) => s === b[i]);
}

export function ParserSamplesEditor({ logSourceId }: { logSourceId: string }) {
  const { hasPermission } = useAuth();
  const canEdit = hasPermission('log_sources:edit');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: PARSER_SAMPLES_QUERY_KEY(logSourceId),
    queryFn: () => api.getLogSourceSamples(logSourceId),
  });
  const saved = query.data;
  const savedSamples = useMemo(() => saved?.samples ?? [], [saved]);
  const maxSamples = saved?.max_samples || DEFAULT_MAX_SAMPLES;
  const maxBytes = saved?.max_sample_bytes || DEFAULT_MAX_SAMPLE_BYTES;
  const published = saved?.version_id != null;

  const [drafts, setDrafts] = useState<string[]>([]);
  // Reset the drafts whenever the server copy changes (load, save, another tab).
  useEffect(() => {
    setDrafts(savedSamples);
  }, [savedSamples]);

  const check = checkSamples(drafts, maxSamples, maxBytes);
  const dirty = !sameSamples(drafts, savedSamples);
  const valid = Object.keys(check.problems).length === 0 && !check.tooMany;
  const editable = canEdit && published;

  const save = useMutation({
    mutationFn: (samples: string[]) => api.putLogSourceSamples(logSourceId, samples),
    onSuccess: (next: TenantParserSamples) => {
      queryClient.setQueryData(PARSER_SAMPLES_QUERY_KEY(logSourceId), next);
      toast({
        title: 'Samples saved',
        description: `${next.samples.length} sample${next.samples.length === 1 ? '' : 's'}; the next rollout tests the parser against them.`,
      });
    },
  });

  return (
    <section className="rounded-md border border-border bg-card" data-testid="parser-samples-editor">
      <header className="flex flex-wrap items-center gap-x-2.5 gap-y-1 px-4 py-2 border-b border-border">
        <span className="font-mono text-[10.5px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">Parser samples</span>
        {saved && (
          <span className="font-mono text-[10.5px] text-muted-foreground tabular-nums" data-testid="parser-samples-count">
            {check.samples.length}/{maxSamples}
          </span>
        )}
        {saved?.version_number != null && (
          <span className="font-mono text-[11px] px-1.5 py-px rounded-[3px] bg-muted text-muted-foreground">v{saved.version_number}</span>
        )}
        <span className="flex-1" />
        {editable && (
          <>
            <button
              type="button"
              onClick={() => setDrafts(savedSamples)}
              disabled={!dirty || save.isPending}
              className="inline-flex items-center gap-1.5 h-7 px-2.5 rounded-md text-[11.5px] font-medium text-muted-foreground hover:bg-muted hover:text-foreground disabled:opacity-50"
            >
              <RotateCcw className="h-3.5 w-3.5" strokeWidth={1.5} />
              Revert
            </button>
            <button
              type="button"
              onClick={() => save.mutate(check.samples)}
              disabled={!dirty || !valid || save.isPending}
              className="inline-flex items-center gap-1.5 h-7 px-2.5 rounded-md border border-border text-[11.5px] font-medium text-foreground hover:bg-muted disabled:opacity-50"
            >
              {save.isPending ? <LoadingIcon className="h-3.5 w-3.5" strokeWidth={1.5} /> : <Save className="h-3.5 w-3.5" strokeWidth={1.5} />}
              Save samples
            </button>
          </>
        )}
      </header>

      <div className="p-4 space-y-3">
        <p className="max-w-[760px] text-[11.5px] leading-[17px] text-muted-foreground">
          Raw events, one per entry. The next parser rollout runs <span className="font-mono text-foreground">vector test</span> with
          them: each must parse before the bundle reaches your parser cell. Saving does not start a rollout.
        </p>

        {query.isLoading && (
          <div className="flex items-center gap-2 text-[11.5px] text-muted-foreground">
            <LoadingIcon className="h-3.5 w-3.5" strokeWidth={1.5} /> Loading samples…
          </div>
        )}
        {query.isError && (
          <div className="text-[11.5px] text-red-500" role="alert">
            Samples unavailable: {query.error instanceof Error ? query.error.message : 'unknown error'}
          </div>
        )}
        {saved && !published && (
          <div className="rounded-md border border-dashed border-border px-3 py-3 text-[11.5px] text-muted-foreground" data-testid="parser-samples-unpublished">
            Nothing to save yet: samples are stored with the source&apos;s published version. Publish or deploy the
            parser first.
          </div>
        )}
        {saved && published && !canEdit && (
          <div className="text-[12px] text-muted-foreground">
            Read only: editing samples needs <span className="font-mono">log_sources:edit</span>.
          </div>
        )}

        {saved && published && (
          <ol className="space-y-2" aria-label="Parser samples">
            {drafts.map((draft, i) => (
              <li key={i} className="flex items-start gap-2">
                <span className="w-5 pt-2.5 text-right font-mono text-[11px] text-muted-foreground tabular-nums">{i + 1}</span>
                <div className="flex-1 min-w-0">
                  <textarea
                    aria-label={`Sample ${i + 1}`}
                    value={draft}
                    readOnly={!editable}
                    rows={Math.min(6, Math.max(2, draft.split('\n').length))}
                    onChange={(e) => setDrafts((prev) => prev.map((d, j) => (j === i ? e.target.value : d)))}
                    className={cn(
                      'w-full rounded-md border bg-background px-3 py-2.5 font-mono text-[12px] leading-[18px] text-foreground focus:outline-none focus:border-primary',
                      check.problems[i] ? 'border-red-500/60' : 'border-input',
                    )}
                  />
                  {check.problems[i] && (
                    <div className="mt-1 text-[12px] text-red-500" role="alert">
                      {check.problems[i]}
                    </div>
                  )}
                </div>
                {editable && (
                  <button
                    type="button"
                    aria-label={`Remove sample ${i + 1}`}
                    onClick={() => setDrafts((prev) => prev.filter((_, j) => j !== i))}
                    className="mt-2 h-6 w-6 inline-flex items-center justify-center rounded-md text-muted-foreground hover:text-foreground hover:bg-muted"
                  >
                    <X className="h-3.5 w-3.5" strokeWidth={1.5} />
                  </button>
                )}
              </li>
            ))}
            {drafts.length === 0 && (
              <li className="rounded-md border border-dashed border-border px-3 py-6 text-center text-[11.5px] text-muted-foreground">
                No samples saved. The build validates the parser without them.
              </li>
            )}
          </ol>
        )}

        {editable && (
          <button
            type="button"
            onClick={() => setDrafts((prev) => [...prev, ''])}
            disabled={drafts.length >= maxSamples}
            className="inline-flex items-center gap-1.5 h-7 px-2.5 rounded-md border border-dashed border-border text-[11.5px] font-medium text-muted-foreground hover:bg-muted hover:text-foreground disabled:opacity-50"
          >
            <Plus className="h-3.5 w-3.5" strokeWidth={1.5} />
            Add sample
          </button>
        )}
        {check.tooMany && (
          <div className="text-[11.5px] text-red-500" role="alert">
            At most <span className="font-mono">{maxSamples}</span> samples per source.
          </div>
        )}
        {save.isError && (
          <div className="flex items-start gap-2 rounded-md border border-red-500/30 bg-red-500/[0.06] px-3 py-2.5 text-[11.5px]" role="alert">
            <AlertTriangle className="h-3.5 w-3.5 mt-px text-red-500 shrink-0" strokeWidth={1.5} />
            <span>Save failed: {save.error instanceof Error ? save.error.message : 'unknown error'}</span>
          </div>
        )}
      </div>
    </section>
  );
}
