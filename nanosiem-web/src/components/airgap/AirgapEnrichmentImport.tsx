// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Air-gapped enrichment bundle import (WS3 / NAN-1205).
 *
 * Self-contained dense section for the air-gap import page (WS2 owns the page
 * shell). Two upload slots — IP geo/ASN and IOC — both POST a signed bundle to
 * `/api/airgap/enrichment/import` as multipart `file`. The backend reads the
 * manifest's `bundle_type` to discriminate, so this component just hands the
 * archive over; an operator dropping the wrong bundle into the wrong slot still
 * gets a clear server-side rejection.
 *
 * Deliberately NOT imported from `@/enterprise/*` (no open-core stub needed):
 * the endpoint is enterprise-gated server-side, but the upload widget is plain
 * UI that posts to it.
 */

import { useState, useRef } from 'react';
import {
  importEnrichmentBundle,
  type AirgapEnrichmentImportResponse as ImportResult,
} from '@/lib/api/airgap';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
} from '@/components/ui/card';

interface SlotProps {
  title: string;
  description: string;
  accept: string;
}

function ImportSlot({ title, description, accept }: SlotProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);
  const [result, setResult] = useState<ImportResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const onFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0] ?? null;
    setFileName(file?.name ?? null);
    setResult(null);
    setError(null);
  };

  const onImport = async () => {
    const file = inputRef.current?.files?.[0];
    if (!file) return;
    setImporting(true);
    setResult(null);
    setError(null);
    try {
      setResult(await importEnrichmentBundle(file));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Import failed');
    } finally {
      setImporting(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-[13px]">{title}</CardTitle>
        <CardDescription className="text-[12px]">{description}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-center gap-2">
          <input
            ref={inputRef}
            type="file"
            accept={accept}
            onChange={onFile}
            className="block text-[12px] text-muted-foreground file:mr-3 file:rounded-none file:border file:border-border file:bg-muted file:px-2 file:py-1 file:text-[12px] file:font-mono"
          />
          <Button onClick={onImport} disabled={!fileName || importing} size="sm">
            {importing ? 'Importing…' : 'Import'}
          </Button>
        </div>

        {result && (
          <Alert>
            <AlertDescription className="text-[12px]">
              Imported{' '}
              <span className="font-mono">
                {result.records_imported.toLocaleString()}
              </span>{' '}
              records from{' '}
              <span className="font-mono">{result.bundle_type}</span> bundle{' '}
              <span className="font-mono">{result.content_version}</span>.
              {result.dictionary_reloaded
                ? ' Dictionary reloaded.'
                : ' Dictionary reload skipped (zero rows).'}
            </AlertDescription>
          </Alert>
        )}

        {error && (
          <Alert variant="destructive">
            <AlertDescription className="text-[12px] font-mono">
              {error}
            </AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  );
}

export function AirgapEnrichmentImport() {
  return (
    <div className="space-y-4">
      <ImportSlot
        title="IP geo / ASN bundle"
        description="Signed IPinfo-Lite-format bundle. Loads into the IP enrichment dictionary; large payloads stream server-side."
        accept=".tar.gz,.tgz,application/gzip"
      />
      <ImportSlot
        title="IOC bundle"
        description="Signed indicator-of-compromise bundle (NDJSON). Loads into the canonical ClickHouse IOC store and reloads the IOC dictionary."
        accept=".tar.gz,.tgz,application/gzip"
      />
    </div>
  );
}
