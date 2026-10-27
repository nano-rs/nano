// SPDX-License-Identifier: AGPL-3.0-or-later

import { Link } from 'react-router-dom';
import { isPlaceholderDimensionDetail } from '@/lib/siem-health-placeholders';
import { useSiemHealthLatest, useIngestionHistory } from '@/hooks/use-api';
import { useCurrentPageTitle } from '@/components/layout/AppBreadcrumbs';
import { useLayoutOptional } from '@/contexts/LayoutContext';
import { formatEventsPerMin, formatIngestScore, formatPlatformStatus } from './status-bar-format';

/**
 * Strip markdown so AI-generated narrative renders cleanly inside the
 * single-line footer cell. The full markdown source still flows to
 * `/platform/health` where `<Markdown>` formats it properly; here we
 * collapse both block-level structures (tables, code fences, lists,
 * blockquotes — which `truncate` would otherwise render as literal `|`,
 * `>`, `-`) and inline markers (`**bold**`, `*italic*`, `` `code` ``)
 * to plain prose, then squash whitespace so the footer reads as one
 * legible sentence (NAN-914 F-2, NAN-936 F-2).
 */
function stripInlineMarkdown(text: string): string {
  // Skip underscore-italic stripping — UDM field names (src_ip,
  // windows_event_log, src_ip_filled_pct, etc.) routinely appear in the
  // narrative and the `_..._` regex would mangle them. The AI prompt
  // produces `**bold**`/`*italic*` style markdown, not underscore italics.
  const blockStripped = text
    // Fenced code blocks: ```...``` (multi-line)
    .replace(/```[\s\S]*?```/g, '')
    // Markdown table rows: any line that starts and ends with a pipe,
    // including the `|---|---|` separator. The footer's `truncate`
    // flattens these to literal `|` glyphs across the visible line.
    .replace(/^\s*\|.*\|\s*$/gm, '')
    // List bullets and numbered list markers at line start
    .replace(/^\s*[-*+]\s+/gm, '')
    .replace(/^\s*\d+\.\s+/gm, '')
    // Blockquote bars
    .replace(/^\s*>\s*/gm, '')
    // Heading hashes
    .replace(/^\s*#{1,6}\s+/gm, '');

  return blockStripped
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/\*([^*]+)\*/g, '$1')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    // Collapse any whitespace run (including newlines left by stripped
    // blocks) to a single space; `truncate` would do the same visually
    // but normalizing here avoids stray gaps where rows used to be.
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Status bar — 22px-tall strip at the bottom. Mono text on --panel bg.
 * Wired to SIEM health + ingestion history. Rendered on every page, so queries
 * should stay cheap (both return single aggregates / small arrays).
 */
export function StatusBar() {
  const currentTitle = useCurrentPageTitle();
  // SIEM Health: the endpoint, status classifier (Fresh/Stalled/Live),
  // overall_score, and the stalled-ingestion narrative are all core
  // heuristics (`nanosiem-core/src/siem_health/analyzer.rs`). Only the
  // per-dimension Live-state commentary is AI-driven; the core fallback
  // fills it with the literal string "AI analysis unavailable", which
  // we filter out below so open builds don't render that placeholder.
  const { data: siemHealth } = useSiemHealthLatest();
  const { data: ingestHistory } = useIngestionHistory(1);
  const layout = useLayoutOptional();

  // Platform status: tint the leading dot + label by SIEM overall_status.
  // Missing/partial health renders an em dash, never "platform unknown".
  const status = formatPlatformStatus(siemHealth);
  const statusColor = status === 'healthy'
    ? 'var(--success)'
    : status === 'degraded'
    ? 'var(--warning)'
    : status === 'unhealthy' || status === 'critical'
    ? 'var(--destructive)'
    : 'var(--muted-foreground)';

  // Ingest summary: prefer the backend's human-readable ingestion detail; fall
  // back to "N% ingest" from the score if the string isn't populated. Filter
  // out the AI-unavailable placeholder so open builds drop down to score.
  const rawIngestDetail = siemHealth?.dimension_details?.ingestion?.trim();
  const ingestDetail = isPlaceholderDimensionDetail(rawIngestDetail) ? undefined : rawIngestDetail;
  // The narrative is markdown; strip inline formatting for the single-line
  // footer cell so `**foo**` etc. don't render as literal asterisks (F-2).
  const ingestDetailDisplay = ingestDetail ? stripInlineMarkdown(ingestDetail) : undefined;
  // Null (segment omitted) when the score is missing or not finite — never "NaN% ingest".
  const ingestScore = formatIngestScore(siemHealth);

  // Events/min: sum the last hour of ingestion-history points across source
  // types, divide by 60. IngestionHistoryPoint[] bucketing varies, but hours=1
  // typically returns ~60 per-minute buckets or a handful of per-hour ones.
  const eventsLabel = formatEventsPerMin(ingestHistory);

  // When a page has contributed page-specific status (e.g. Search's query
  // stats), show it in place of the default ingest detail + events-per-min.
  // Platform dot + page name on the right are preserved.
  const pageStatus = layout?.pageStatus;

  return (
    <footer
      className="hidden md:flex items-center px-3.5 h-[22px] border-t border-border font-mono text-[10.5px] text-muted-foreground gap-[18px] tracking-wide shrink-0"
      style={{ background: 'var(--panel)' }}
    >
      <span style={{ color: statusColor }}>● platform {status}</span>
      {pageStatus ? (
        <span className="flex items-center gap-[18px] min-w-0">{pageStatus}</span>
      ) : (
        <>
          {ingestDetailDisplay ? (
            // AI narrative is the meaningful content — wire the cell as a link
            // to the full /platform/health report so the truncated text has a
            // clear expand-on-click affordance (NAN-914 F-6).
            <Link
              to="/platform/health"
              className="hidden lg:inline truncate max-w-[280px] hover:text-foreground transition-colors"
              title={ingestDetailDisplay}
            >
              {ingestDetailDisplay}
            </Link>
          ) : ingestScore ? (
            <span
              className="hidden lg:inline truncate max-w-[280px]"
              title={ingestScore}
            >
              {ingestScore}
            </span>
          ) : null}
          {eventsLabel && <span className="hidden lg:inline">{eventsLabel}</span>}
        </>
      )}
      <span className="flex-1" />
      <span>nano · {currentTitle.toLowerCase()}</span>
    </footer>
  );
}
