// SPDX-License-Identifier: AGPL-3.0-or-later

import { Shield, Focus as FocusIcon, ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';

interface AssetTopStripProps {
  /** UDM field the entity was resolved on (src_host, src_ip, user, mac, ...) */
  entityField: string;
  /** Resolved entity value (e.g. WIN-HR11) */
  entityValue: string;
  /** kind label — shown next to "ASSET" (e.g. "host dossier", "user dossier") */
  kindLabel: string;
  /** Number of fields currently visible in the fields panel (22 in the mockup) */
  fieldsCount?: number;
  /** Callback to expand the collapsed fields panel */
  onExpandFields?: () => void;
  /** Whether focus mode is on */
  focus: boolean;
  /** Toggle focus mode */
  onToggleFocus: () => void;
  /** Supplementary resolved-sources summary, shown on the right in non-focus mode */
  resolvedSourcesLabel?: string;
  /** Last observation timestamp label */
  lastObservationLabel?: string;
  /** Cache-transparency notice (NAN-1595), rendered in the header meta row. */
  cachedNotice?: React.ReactNode;
}

export function AssetTopStrip({
  entityField,
  entityValue,
  kindLabel,
  fieldsCount,
  onExpandFields,
  focus,
  onToggleFocus,
  resolvedSourcesLabel,
  lastObservationLabel,
  cachedNotice,
}: AssetTopStripProps) {
  return (
    <div className="py-2 px-3 border-b border-border flex items-center gap-2 font-mono text-[10.5px] tracking-[0.12em] uppercase text-foreground/70 font-semibold whitespace-nowrap shrink-0">
      <span className="flex items-center gap-1.5 shrink-0">
        <Shield className="w-[12px] h-[12px] text-primary" />
        Asset ·{' '}
        <span className="normal-case tracking-normal text-foreground">{kindLabel}</span>
      </span>

      <Chip label="field" value={entityField} />
      <Chip label="resolved" value={entityValue} />

      {typeof fieldsCount === 'number' && onExpandFields && (
        <button
          onClick={onExpandFields}
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-primary/40 text-[10px] normal-case tracking-normal font-semibold text-primary hover:bg-primary/10 transition-colors"
        >
          <span className="w-1.5 h-1.5 rounded-full bg-primary/70" />
          Fields <span className="font-mono">{fieldsCount}</span>
          <ChevronRight className="w-3 h-3" />
        </button>
      )}

      <span className="flex-1" />

      {cachedNotice && (
        <span className="normal-case tracking-normal shrink-0">{cachedNotice}</span>
      )}

      <button
        onClick={onToggleFocus}
        title={
          focus
            ? 'Exit focus — show full dossier'
            : 'Focus mode — hide dossier, show prevalence + stream only'
        }
        className={cn(
          'inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md border text-[10px] normal-case tracking-normal font-semibold transition-colors shrink-0',
          focus
            ? 'border-primary/40 bg-primary/10 text-primary hover:bg-primary/15'
            : 'border-border text-muted-foreground hover:text-foreground hover:bg-foreground/5'
        )}
      >
        <FocusIcon className="w-[11px] h-[11px]" />
        {focus ? 'In investigation' : 'Focus'}
      </button>

      {!focus && resolvedSourcesLabel && (
        <span className="text-muted-foreground/70 font-mono normal-case tracking-normal">
          {resolvedSourcesLabel}
          {lastObservationLabel && (
            <>
              {' · '}last observation{' '}
              <span className="text-foreground tabular-nums">{lastObservationLabel}</span>
            </>
          )}
        </span>
      )}
    </div>
  );
}

function Chip({ label, value }: { label: string; value: string }) {
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-border text-[10px] normal-case tracking-normal font-semibold text-foreground">
      <span className="text-muted-foreground/70">{label}</span>
      <span className="text-primary font-mono">{value}</span>
    </span>
  );
}
