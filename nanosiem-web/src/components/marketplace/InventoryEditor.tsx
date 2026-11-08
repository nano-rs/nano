// SPDX-License-Identifier: AGPL-3.0-or-later
import { Suspense, useState } from 'react';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/contexts/AuthContext';
import { useCapabilities } from '@/hooks/use-capabilities';
import { lazyWithRetry } from '@/lib/lazyWithRetry';
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from '@/components/ui/sheet';

const CustomEnrichmentWizard = lazyWithRetry(() => import('@/enterprise/pages/CustomEnrichmentWizard').then(m => ({ default: m.CustomEnrichmentWizard })));

const LookupEditor = lazyWithRetry(() => import('@/pages/LookupTableCreate').then(m => ({ default: m.LookupTableCreate })));

/** NAN-4946: no repository mode. Marketplace content comes only from nano's first-party catalogs. */
export type InventoryEditorMode = 'provider' | 'lookup';

export function InventoryEditor({ definitionId, onClose, onSaved, initialMode }: {
  definitionId: string;
  initialMode?: InventoryEditorMode;
  onClose: () => void;
  onSaved: (id: string) => void;
}) {
  const { hasPermission } = useAuth();
  const { capabilities } = useCapabilities();
  // Custom providers run on the enterprise enrichment runtime; the open
  // edition offers lookups and Git bundles only (no dead provider button).
  const canProvider = capabilities.customEnrichment && hasPermission('enrichments:custom:create') && hasPermission('enrichments:code');
  const canLookup = hasPermission('lookup:create') && hasPermission('lookup:view');
  const [mode, setMode] = useState<InventoryEditorMode>(definitionId !== 'new' ? 'provider'
    : initialMode === 'lookup' && canLookup ? 'lookup'
    : canProvider ? 'provider' : 'lookup');
  const tab = (value: InventoryEditorMode) => `h-7 text-[11.5px] ${mode === value ? 'border-primary/50 text-primary' : ''}`;
  const [lookupSaved, setLookupSaved] = useState<string>();
  return <Sheet open onOpenChange={open => { if (!open) onClose(); }}>
    <SheetContent className="w-full overflow-y-auto text-[12px] sm:max-w-5xl">
      <SheetHeader>
        <SheetTitle>Marketplace · {definitionId === 'new' ? 'Create / Connect' : 'Custom provider'}</SheetTitle>
        <SheetDescription>Author a provider or add a lookup table. Marketplace integrations come from nano's catalogs.</SheetDescription>
      </SheetHeader>
      {definitionId === 'new' && <div className="my-3 flex gap-2">
        {canProvider && <Button size="sm" variant="outline" className={tab('provider')} aria-pressed={mode === 'provider'} onClick={() => setMode('provider')}>TI / Asset provider</Button>}
        {canLookup && <Button size="sm" variant="outline" className={tab('lookup')} aria-pressed={mode === 'lookup'} onClick={() => setMode('lookup')}>Lookup table</Button>}
      </div>}
      {lookupSaved && <p role="status">Saved lookup <span className="font-mono">{lookupSaved}</span></p>}
      <Suspense fallback={<p role="status">Loading provider editor…</p>}>
        {definitionId === 'new' && !canProvider && !canLookup ? <p role="alert">Authoring permission required.</p> : mode === 'lookup' ? <div className="min-h-[600px] p-3"><LookupEditor key={lookupSaved ?? 'new'} tableName={lookupSaved} onClose={onClose} onSaved={setLookupSaved} /></div>
          : <CustomEnrichmentWizard key={definitionId} definitionId={definitionId} onClose={onClose} onSaved={onSaved} />}
      </Suspense>
    </SheetContent>
  </Sheet>;
}
