// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ReactNode } from 'react';
import { DetailSheet } from '@/components/ui/detail-sheet';
import { Button } from '@/components/ui/button';
import { inventoryAction, inventoryReason, type InventoryItem } from '@/lib/api/marketplace-inventory';
import { capabilityLabel, executionStageLabel, humanizeEnum, inventoryHealthLabel } from '@/lib/marketplace-labels';
import { formatUTCCompact } from '@/lib/date-utils';
import { BundleFeedStatus } from './BundleFeedStatus';
import { SandboxBadge } from './InventoryCard';

export interface InventoryDrawerActions {
  onInstall?: () => void;
  onToggle?: () => void;
  onConfigure?: () => void;
  onConnect?: () => void;
  onEdit?: () => void;
  onUninstall?: () => void;
}

/** Inventory detail sheet: provenance, state and the actions this caller may take. */
export function InventoryDrawer({ item, onClose, busy, entitlement, actions }: {
  item: InventoryItem;
  onClose: () => void;
  busy: boolean;
  entitlement?: ReactNode;
  actions: InventoryDrawerActions;
}) {
  const { onInstall, onToggle, onConfigure, onConnect, onEdit, onUninstall } = actions;
  const btn = 'h-7 text-[11.5px]';
  return <DetailSheet open onOpenChange={open => { if (!open) onClose(); }} size="md" breadcrumb={['Marketplace', humanizeEnum(item.kind)]}
    title={item.name} description={item.description || inventoryReason(item)}
    meta={<span className="font-mono">{item.id} · {inventoryHealthLabel(item.effective_health)}</span>}
    footer={<>
      {item.installed && onUninstall && <Button size="sm" variant="outline" className={`${btn} mr-auto`} disabled={busy} onClick={onUninstall}>Uninstall</Button>}
      {item.can_edit && onEdit && <Button size="sm" variant="outline" className={btn} disabled={busy} onClick={onEdit}>Edit provider</Button>}
      {onConnect && <Button size="sm" variant="outline" className={btn} disabled={busy} onClick={onConnect}>Configure connection</Button>}
      {item.installed && onConfigure && <Button size="sm" variant="outline" className={btn} disabled={busy} onClick={onConfigure}>Configure</Button>}
      {/* A feed the nano bundle provides is managed in Platform feeds, not toggled here. */}
      {item.installed && onToggle && !item.provided_by_bundle && <Button size="sm" className={btn} disabled={busy || !item.can_toggle} onClick={onToggle}>{inventoryAction(item)}</Button>}
      {!item.installed && !item.requirement && !item.provided_by_bundle && onInstall && <Button size="sm" className={btn} disabled={busy} onClick={onInstall}>Install</Button>}
    </>}>
    <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1.5 text-[12px]" data-testid="inventory-details">
      <dt className="text-muted-foreground">Item</dt><dd className="font-mono break-all">{item.id}</dd>
      <dt className="text-muted-foreground">Category</dt><dd>{humanizeEnum(item.category)}</dd>
      <dt className="text-muted-foreground">Execution</dt><dd className="font-mono">{executionStageLabel(item.execution_stage)}</dd>
      <dt className="text-muted-foreground">Health</dt><dd>{item.reason ? `${inventoryHealthLabel(item.effective_health)} · ${inventoryReason(item)}` : inventoryHealthLabel(item.effective_health)}</dd>
      {item.sandbox && <><dt className="text-muted-foreground">Sandbox</dt><dd data-testid="inventory-sandbox">
        <SandboxBadge item={item} />
        {item.sandbox.compile_status === 'needs_attention' && <p className="mt-1 text-[11.5px] text-muted-foreground break-words">
          {item.sandbox.reason ?? 'It cannot run on the wasm sandbox; open the enrichment code to see why.'}
        </p>}
        {item.sandbox.compile_status === 'needs_attention' && <p className="mt-1 text-[11.5px] text-muted-foreground break-words" data-testid="inventory-sandbox-fixes">
          Runs are refused until it is fixed; other enrichments are unaffected. Common fixes: use the vendor's https endpoint, send credentials as-is in request headers (not the URL or body), pick an auth type instead of encoding or signing a key in code, or switch to a declarative connector.
        </p>}
        {!item.sandbox.current && <p className="mt-1 text-[11.5px] text-muted-foreground">Changed since the last check; rechecking.</p>}
      </dd></>}
      <dt className="text-muted-foreground">Version</dt><dd className="font-mono">{item.version ?? '—'}</dd>
      <dt className="text-muted-foreground">Last sync</dt><dd className="font-mono">{item.last_sync ? formatUTCCompact(item.last_sync) : 'Not recorded'}</dd>
      {item.record_count !== null && <><dt className="text-muted-foreground">Records</dt><dd className="font-mono tabular-nums">{item.record_count}</dd></>}
      <dt className="text-muted-foreground">Author</dt><dd className="font-mono break-all">{item.author}</dd>
      <dt className="text-muted-foreground">Repository</dt><dd className="font-mono break-all">{item.repository_name ?? (item.source === 'custom_enrichment' ? 'Authored here' : 'Built in')}</dd>
      {item.repo_commit && <><dt className="text-muted-foreground">Repo commit</dt><dd className="font-mono">{item.repo_commit.slice(0, 12)}</dd></>}
      <dt className="text-muted-foreground">Capabilities</dt><dd>{item.capabilities.map(capabilityLabel).join(', ') || 'None'}</dd>
    </dl>
    {entitlement}
    {/* NAN-4959: revision, last update and next refresh from the platform feed status. */}
    {item.provided_by_bundle && <BundleFeedStatus provision={item.provided_by_bundle} className="mt-4 pt-3 border-t border-border/60" />}
  </DetailSheet>;
}
