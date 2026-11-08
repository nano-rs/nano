// SPDX-License-Identifier: AGPL-3.0-or-later
import type { InventoryRequirement } from '@/lib/api/marketplace-inventory';
import type { BuildEdition } from '@/hooks/use-capabilities';

/**
 * What an item is entitled to on this deployment (NAN-4946). Main showed the
 * hosted purchase state here; a single-tenant install has no purchase, so the
 * entitlement is the build itself: the capability the item needs and whether
 * this edition ships it. Read from `/api/capabilities`, never a hosted flag.
 */
export function InventoryEntitlement({ requirement, edition }: { requirement: InventoryRequirement; edition: BuildEdition }) {
  return <section aria-label="Entitlement" className="my-3 rounded-md border border-border px-3 py-2.5">
    <p role="status" className="text-[12px] text-foreground">Requires the {requirement.label}</p>
    <dl className="my-2 grid grid-cols-[110px_1fr] gap-1.5 text-[11.5px]">
      <dt className="text-muted-foreground">Capability</dt><dd className="font-mono">{requirement.capability}</dd>
      <dt className="text-muted-foreground">This build</dt><dd className="font-mono">{edition}</dd>
    </dl>
    <p className="text-[11px] leading-[1.45] text-muted-foreground">
      This edition does not include the runtime this integration executes on, so it cannot be installed here.
      It installs and runs unchanged on an enterprise deployment.
    </p>
  </section>;
}
