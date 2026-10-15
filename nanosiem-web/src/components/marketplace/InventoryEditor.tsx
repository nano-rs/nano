// SPDX-License-Identifier: AGPL-3.0-or-later
import { Suspense, useState } from 'react';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/contexts/AuthContext';
import { lazyWithRetry } from '@/lib/lazyWithRetry';
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from '@/components/ui/sheet';

const CustomEnrichmentWizard = lazyWithRetry(() => import('@/enterprise/pages/CustomEnrichmentWizard').then(m => ({ default: m.CustomEnrichmentWizard })));

const LookupEditor = lazyWithRetry(() => import('@/pages/LookupTableCreate').then(m => ({ default: m.LookupTableCreate })));
const RepositoryEditor = lazyWithRetry(() => import('./InventoryRepositoryEditor').then(m => ({ default: m.InventoryRepositoryEditor })));

export function InventoryEditor({ definitionId, onClose, onSaved }: {
  definitionId: string;
  onClose: () => void;
  onSaved: (id: string) => void;
}) {
  const { hasPermission } = useAuth();
  const canProvider = hasPermission('enrichments:custom:create') && hasPermission('enrichments:code');
  const canRepository = hasPermission('enrichments:configure');
  const canLookup = hasPermission('lookup:create') && hasPermission('lookup:view');
  const [mode, setMode] = useState<'provider' | 'lookup' | 'repository'>(definitionId !== 'new' || canProvider ? 'provider' : canLookup ? 'lookup' : 'repository');
  const [lookupSaved, setLookupSaved] = useState<string>();
  return <Sheet open onOpenChange={open => { if (!open) onClose(); }}>
    <SheetContent className="w-full overflow-y-auto text-[12px] sm:max-w-5xl">
      <SheetHeader>
        <SheetTitle>Marketplace · Custom provider</SheetTitle>
        <SheetDescription>Configure, author, validate and run this tenant's provider.</SheetDescription>
      </SheetHeader>
      {definitionId === 'new' && <div className="my-3 flex gap-2">
        {canProvider && <Button variant="outline" onClick={() => setMode('provider')}>TI / Asset provider</Button>}
        {canLookup && <Button variant="outline" onClick={() => setMode('lookup')}>Lookup table</Button>}
        {canRepository && <Button variant="outline" onClick={() => setMode('repository')}>Git bundle</Button>}
      </div>}
      {lookupSaved && <p role="status">Saved lookup <span className="font-mono">{lookupSaved}</span></p>}
      <Suspense fallback={<p role="status">Loading provider editor…</p>}>
        {definitionId === 'new' && !canProvider && !canLookup && !canRepository ? <p role="alert">Authoring permission required.</p> : mode === 'lookup' ? <div className="min-h-[600px] p-3"><LookupEditor key={lookupSaved ?? 'new'} tableName={lookupSaved} onClose={onClose} onSaved={setLookupSaved} /></div>
          : mode === 'repository' ? <RepositoryEditor />
          : <CustomEnrichmentWizard key={definitionId} definitionId={definitionId} onClose={onClose} onSaved={onSaved} />}
      </Suspense>
    </SheetContent>
  </Sheet>;
}
