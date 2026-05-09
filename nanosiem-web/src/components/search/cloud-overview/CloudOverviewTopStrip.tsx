// SPDX-License-Identifier: AGPL-3.0-or-later

import { Cloud, ChevronRight } from 'lucide-react';

interface CloudOverviewTopStripProps {
  provider: string;
  account: string | null;
  windowLabel: string | null;
  fieldsCount?: number;
  onExpandFields?: () => void;
}

export function CloudOverviewTopStrip({
  provider,
  account,
  windowLabel,
  fieldsCount,
  onExpandFields,
}: CloudOverviewTopStripProps) {
  return (
    <div className="py-2 px-3 border-b border-border flex items-center gap-2 font-mono text-[10.5px] tracking-[0.12em] uppercase text-foreground/70 font-semibold whitespace-nowrap shrink-0">
      <span className="flex items-center gap-1.5 shrink-0">
        <Cloud className="w-[12px] h-[12px] text-primary" />
        Cloud · <span className="normal-case tracking-normal text-foreground">org overview</span>
      </span>

      <Chip label="provider" value={provider} />
      {account && <Chip label="account" value={account} />}
      {windowLabel && <Chip label="window" value={windowLabel} />}

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

      <span className="text-muted-foreground/70 font-mono normal-case tracking-normal">
        posture · <span className="text-foreground">CloudTrail · IAM · GuardDuty · Access Analyzer</span> · click any principal to pivot to dossier
      </span>
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
