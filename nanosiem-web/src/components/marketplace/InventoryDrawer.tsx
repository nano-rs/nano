// SPDX-License-Identifier: AGPL-3.0-or-later
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from '@/components/ui/sheet';
import { Button } from '@/components/ui/button';
import { inventoryAction, inventoryReason, type InventoryItem } from '@/lib/api/marketplace-inventory';
import type { ReactNode } from 'react';
import { capabilityLabel, executionStageLabel, inventoryHealthLabel } from '@/lib/marketplace-labels';
export function InventoryDrawer({ item, onClose, onToggle, onEdit, onConnect, purchaseStatus, onPurchase, busy }: { item: InventoryItem; onClose: () => void; onToggle: () => void; onEdit?: () => void; onConnect?: () => void; purchaseStatus?: ReactNode; onPurchase?: () => void; busy: boolean }) {
  return <Sheet open onOpenChange={open => { if (!open) onClose(); }}>
    <SheetContent className="text-[12px]">
      <SheetHeader><SheetTitle>{item.name}</SheetTitle><SheetDescription>{inventoryReason(item)}</SheetDescription></SheetHeader>
      <dl className="my-4 grid grid-cols-[110px_1fr] gap-2">
        <dt>Item</dt><dd className="font-mono break-all">{item.id}</dd>
        <dt>Execution</dt><dd className="font-mono">{executionStageLabel(item.execution_stage)}</dd>
        <dt>Health</dt><dd>{inventoryHealthLabel(item.effective_health)}</dd>
        <dt>Revision</dt><dd className="font-mono">{item.revision ?? '—'}</dd>
        <dt>Last sync</dt><dd className="font-mono">{item.last_sync ?? 'Not recorded'}</dd>
        <dt>Next refresh</dt><dd className="font-mono">{item.next_refresh ?? 'Not scheduled'}</dd>
        {item.kind === 'custom' ? <>
          <dt>Author</dt><dd className="font-mono break-all">{item.author}</dd>
          <dt>Tenant scope</dt><dd className="font-mono break-all">{item.tenant_id}</dd>
          <dt>Connector</dt><dd className="font-mono break-all">{item.connector}</dd>
          <dt>Repository</dt><dd className="font-mono break-all">{item.repository_id ?? 'None'}</dd>
          <dt>Repo commit</dt><dd className="font-mono">{item.repo_commit ?? 'Not recorded'}</dd>
          <dt>Artifact</dt><dd className="font-mono break-all">{item.artifact_id ?? 'Not deployed'}</dd>
          <dt>Artifact SHA256</dt><dd className="font-mono break-all">{item.artifact_sha256 ?? 'Not deployed'}</dd>
        </> : <>
          <dt>Grant revision</dt><dd className="font-mono">{item.grant_revision ?? 'None'}</dd>
          <dt>Feed revision</dt><dd className="font-mono">{item.feed_revision ?? 'None'}</dd>
        </>}
        <dt>Capabilities</dt><dd>{item.capabilities.map(capabilityLabel).join(', ') || 'None'}</dd>
      </dl>
      {item.kind === 'premium' && purchaseStatus}
      {item.kind === 'baseline' ? <p>Included · On</p> : item.kind === 'premium' && !item.entitled ? <div>
        <Button disabled={!onPurchase || busy} onClick={onPurchase}>Purchase</Button><p className="mt-2 text-muted-foreground">Payment is confirmed by billing verification.</p>
      </div> : <Button disabled={busy || !item.can_toggle} onClick={onToggle}>{inventoryAction(item)}</Button>}
      {item.kind === 'custom' && item.can_edit && onEdit && <Button variant="outline" className="ml-2" onClick={onEdit}>Edit provider</Button>}
      {item.kind === 'custom' && onConnect && <Button variant="outline" className="ml-2" onClick={onConnect}>Configure connection</Button>}
    </SheetContent>
  </Sheet>;
}
