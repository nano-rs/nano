// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-5575: agent-written SQL, shown as nPL.
 *
 * Machines run SQL; people read nPL. Wherever a person sees a query an agent
 * ran over Agent Lane, this shows the nPL as the primary view, with "Open in
 * Search" over the query's time range. The SQL stays one click away ("SQL"
 * toggle, copy). States:
 * - exact: the compiled nPL provably matches the SQL. Shown plainly.
 * - broader / inexact: converted, with the differences in a tooltip.
 * - approximate: an AI translation (explicit click only), marked with the
 *   pivt mark and its differences.
 * - can't convert: the reason, with the SQL shown and copyable.
 *
 * Conversion is lazy (only once visible) and batched / cached in
 * `lib/sql-to-npl`. The AI fallback never runs on its own.
 */
import { useEffect, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { useMutation } from '@tanstack/react-query';
import { PivtIcon } from '@/components/icons/PivtIcon';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { useCapabilitiesOptional } from '@/hooks/use-capabilities';
import { useInView } from '@/hooks/use-in-view';
import { api } from '@/lib/api';
import type { SqlToNplResponse } from '@/lib/api/types';
import { copyText } from '@/lib/clipboard';
import { sqlNplSearchUrl, useSqlToNpl } from '@/lib/sql-to-npl';
import { cn } from '@/lib/utils';
import { Term } from '@/components/ui/term';

export interface SqlAsNplProps {
  /** The SQL the agent ran (Agent Lane placeholders and all). */
  sql: string;
  /** What the `{earliest:…}` / `{latest:…}` placeholders stood for. */
  windowStart?: string | null;
  windowEnd?: string | null;
  /** Lines of nPL / SQL shown before scrolling. */
  maxLines?: number;
  className?: string;
}

const linkClass =
  'rounded-sm text-primary hover:underline focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring';
const quietButton =
  'rounded-sm text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:opacity-50';

/**
 * Whether this install offers AI translation. The permission (`melod:query`)
 * is enforced by the endpoint; a refusal is reported inline.
 */
function useAiConversion(): boolean {
  return !!useCapabilitiesOptional()?.capabilities.melod;
}

function DifferencesBadge({ result, children }: { result: SqlToNplResponse; children: ReactNode }) {
  return (
    <TooltipProvider delayDuration={150}>
      <Tooltip>
        <TooltipTrigger asChild>
          <button type="button" className="inline-flex items-center gap-1 rounded-sm border border-border px-1 font-mono text-[10px] leading-4 text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring">
            {children}
          </button>
        </TooltipTrigger>
        <TooltipContent className="max-w-sm">
          <ul className="flex flex-col gap-1 text-[11px]">
            {result.differences.map((d, i) => (
              <li key={i}>
                <span className="font-mono text-[10px] text-muted-foreground">{d.kind}</span> {d.detail}
              </li>
            ))}
            {result.differences.length === 0 && <li>No difference found against the SQL.</li>}
          </ul>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

/**
 * AI can only improve on a refusal or a real difference: a table Search has
 * no dataset for, or a result that is only broader (nPL's case-insensitive
 * matching), is as good as nPL gets.
 */
function aiCanHelp(result: SqlToNplResponse): boolean {
  if (result.exact || result.approximate || result.no_search_dataset) return false;
  if (!result.npl) return true;
  return result.differences.some((d) => d.kind !== 'broader');
}

function aiErrorText(error: unknown): string {
  const status = (error as { status?: number } | null)?.status;
  if (status === 403) return 'AI conversion needs the melod:query permission';
  if (status === 503) return 'AI is not configured on this install';
  return 'AI conversion failed';
}

function stateBadge(result: SqlToNplResponse): ReactNode {
  if (result.approximate) {
    return (
      <DifferencesBadge result={result}>
        <PivtIcon className="h-3 w-3" aria-hidden />
        approximate
      </DifferencesBadge>
    );
  }
  if (result.exact || !result.npl) return null;
  const broaderOnly = result.differences.every((d) => d.kind === 'broader');
  return <DifferencesBadge result={result}>{broaderOnly ? 'broader' : 'inexact'}</DifferencesBadge>;
}

export function SqlAsNpl({ sql, windowStart, windowEnd, maxLines = 6, className }: SqlAsNplProps) {
  const [el, setEl] = useState<HTMLDivElement | null>(null);
  const inView = useInView(el);
  const [seen, setSeen] = useState(false);
  // Convert once first seen; keep the result when scrolled away.
  useEffect(() => {
    if (inView) setSeen(true);
  }, [inView]);
  const request = { sql, window_start: windowStart ?? null, window_end: windowEnd ?? null };
  const conversion = useSqlToNpl(request, seen);
  const ai = useMutation({ mutationFn: () => api.sqlToNplAi(request) });
  const resetAi = ai.reset;
  // An AI result belongs to one SQL: drop it when the component is reused.
  useEffect(() => {
    resetAi();
  }, [sql, windowStart, windowEnd, resetAi]);
  const aiAllowed = useAiConversion();
  const [showSql, setShowSql] = useState(false);
  const [copied, setCopied] = useState(false);

  const result: SqlToNplResponse | undefined = ai.data ?? conversion.data;
  const converted = !!result?.npl;
  const maxHeight = { maxHeight: `${maxLines * 1.45}em` };

  const copySql = async () => {
    if (await copyText(sql)) {
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    }
  };

  return (
    <div ref={setEl} className={cn('flex min-w-0 flex-col gap-1', className)} data-testid="sql-as-npl">
      {!result ? (
        conversion.isError ? (
          <div className="text-[11px] text-muted-foreground">
            Could not convert to <Term id="npl">nPL</Term>.
          </div>
        ) : (
          <div className="font-mono text-[11px] text-muted-foreground">Converting to nPL…</div>
        )
      ) : converted ? (
        <pre
          className="overflow-auto whitespace-pre-wrap break-words font-mono text-[11px] leading-[1.45] text-fg-2 [overflow-wrap:anywhere]"
          style={maxHeight}
          data-testid="sql-as-npl-npl"
        >
          {result.dataset && result.dataset !== 'logs' && (
            <span className="mr-1.5 text-muted-foreground" data-testid="sql-as-npl-dataset">
              dataset={result.dataset}
            </span>
          )}
          {result.npl}
        </pre>
      ) : (
        <div
          className={cn('text-[11px]', result.no_search_dataset ? 'text-muted-foreground' : 'text-warn')}
          data-testid="sql-as-npl-unsupported"
        >
          Can't convert to <Term id="npl">nPL</Term>: {result.unsupported_reason}
        </div>
      )}

      {(showSql || (result && !converted)) && (
        <pre
          className="overflow-auto whitespace-pre-wrap break-words rounded-sm border border-border bg-muted/40 px-1.5 py-1 font-mono text-[10.5px] leading-[1.45] text-muted-foreground [overflow-wrap:anywhere]"
          style={maxHeight}
          data-testid="sql-as-npl-sql"
        >
          {sql}
        </pre>
      )}

      <div className="flex flex-wrap items-center gap-x-2.5 gap-y-0.5 font-mono text-[10.5px]">
        {result && stateBadge(result)}
        {converted && result?.npl && (
          <Link to={sqlNplSearchUrl(result.npl, result.earliest, result.latest, result.dataset)} className={linkClass}>
            Open in Search
          </Link>
        )}
        {converted && (
          <button type="button" className={quietButton} onClick={() => setShowSql((v) => !v)} aria-expanded={showSql}>
            {showSql ? 'Hide SQL' : 'SQL'}
          </button>
        )}
        <button type="button" className={quietButton} onClick={copySql}>
          {copied ? 'Copied' : 'Copy SQL'}
        </button>
        {aiAllowed && result && aiCanHelp(result) && (
          <button
            type="button"
            className={cn(quietButton, 'inline-flex items-center gap-1')}
            onClick={() => ai.mutate()}
            disabled={ai.isPending}
          >
            <PivtIcon className="h-3 w-3" aria-hidden />
            {ai.isPending ? 'Converting…' : 'Try AI conversion'}
          </button>
        )}
        {ai.isError && <span className="text-warn">{aiErrorText(ai.error)}</span>}
      </div>
    </div>
  );
}
