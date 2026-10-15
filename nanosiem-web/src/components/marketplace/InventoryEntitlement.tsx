// SPDX-License-Identifier: AGPL-3.0-or-later
import { Button } from '@/components/ui/button';
import { entitlementLabel, type MarketplaceEntitlement } from '@/lib/api/marketplace-inventory';

export function InventoryEntitlement({ status, loading, failed, onRefresh, checkoutPending }: {
  status: MarketplaceEntitlement | null | undefined;
  checkoutPending?: boolean;
  loading: boolean;
  failed: boolean;
  onRefresh: () => void;
}) {
  return <section aria-label="Purchase status" className="my-3 border-t pt-3">
    {loading ? <p role="status">Checking purchase status…</p>
      : failed ? <p role="alert">Could not verify purchase status.</p>
      : status ? <>
        <p role="status">{entitlementLabel(status)}</p>
        <dl className="my-2 grid grid-cols-[110px_1fr] gap-2">
          <dt>Paid through</dt><dd className="font-mono">{status.expires_at ?? 'Not recorded'}</dd>
          <dt>Entitlement revision</dt><dd className="font-mono">{status.revision}</dd>
        </dl>
        {status.state === 'pending' && <p>Waiting for verified payment confirmation. You can reload this item safely.</p>}
        {status.state === 'active' && <p>Renewals update the paid-through date after billing verification and preserve your enable/disable preference.</p>}
      </> : <p>{checkoutPending ? "Checkout started · awaiting verified billing confirmation" : "No purchase is recorded."}</p>}
    <Button variant="outline" disabled={loading} onClick={onRefresh}>Refresh purchase status</Button>
  </section>;
}
