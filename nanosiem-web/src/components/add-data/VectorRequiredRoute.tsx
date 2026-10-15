// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-3844: route guard for pages that only create Vector-delivered sources
 * (the Add data wizard, custom pull collectors). On an `install.sh --tenzir`
 * install the page is replaced by its title, the one-line note and a link to
 * the Tenzir bucket drop on Log sources.
 */

import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';

import { TenzirOnlyNote } from '@/components/add-data/TenzirOnlyNote';
import { useIngestGate } from '@/hooks/use-capabilities';

export function VectorRequiredRoute({ title, children }: { title: string; children: ReactNode }) {
  const { tenzirOnly, unknown } = useIngestGate();
  if (unknown) {
    // Capabilities still loading: neither the wizard nor the note yet.
    return (
      <div className="space-y-3 px-5 py-4" data-testid="vector-required-pending" aria-busy="true">
        <div className="h-5 w-40 bg-muted/60" />
        <div className="h-7 w-full max-w-xl border border-border" />
      </div>
    );
  }
  if (!tenzirOnly) return <>{children}</>;
  return (
    <div className="space-y-3 px-5 py-4" data-testid="vector-required-page">
      <h1 className="text-[16px] font-semibold tracking-[-0.01em] text-foreground">{title}</h1>
      <div className="font-mono text-[10.5px] text-muted-foreground">ingest · tenzir_only</div>
      <TenzirOnlyNote />
      <Link to="/ingestion/log-sources" className="inline-block text-[11.5px] text-primary hover:underline">
        Add a Tenzir bucket drop source on Log sources
      </Link>
    </div>
  );
}
