// SPDX-License-Identifier: AGPL-3.0-or-later
import { Link } from 'react-router-dom';
import { requirementSentence, type InventoryRequirement } from '@/lib/api/marketplace-inventory';
import type { BuildEdition } from '@/hooks/use-capabilities';

/**
 * What an item is entitled to on this deployment (NAN-4946). Main showed the
 * hosted purchase state here; a single-tenant install has no purchase, so the
 * entitlement is the build and its licence: the capability the item needs and
 * why it is missing. Read from `/api/capabilities`, never a hosted flag.
 *
 * NAN-5088: on an enterprise build a licensed capability is false only when
 * licence admission is not active, so that case points at Settings › Licence
 * instead of claiming the edition lacks the runtime.
 */
export function InventoryEntitlement({ requirement, edition, canManageLicence = false }: {
  requirement: InventoryRequirement;
  edition: BuildEdition;
  /** `settings:system`: the licence page is reachable, so link it. */
  canManageLicence?: boolean;
}) {
  const licence = requirement.cause === 'licence';
  return <section aria-label="Entitlement" className="my-3 rounded-md border border-border px-3 py-2.5">
    <p role="status" className="text-[12px] text-foreground">{requirementSentence(requirement)}</p>
    <dl className="my-2 grid grid-cols-[110px_1fr] gap-1.5 text-[11.5px]">
      <dt className="text-muted-foreground">Capability</dt><dd className="font-mono">{requirement.capability}</dd>
      <dt className="text-muted-foreground">This build</dt><dd className="font-mono">{edition}</dd>
      {licence && <><dt className="text-muted-foreground">Licence</dt><dd className="font-mono">not active</dd></>}
    </dl>
    {licence
      ? <p className="text-[11px] leading-[1.45] text-muted-foreground">
          Licensed features are unavailable on this deployment, so this integration cannot be installed or run until a licence is active.{' '}
          {canManageLicence
            ? <Link to="/settings/license" className="text-primary hover:underline">Install or renew it in Settings › Licence</Link>
            : 'Ask an administrator to install or renew it.'}
        </p>
      : <p className="text-[11px] leading-[1.45] text-muted-foreground">
          This edition does not include the runtime this integration executes on, so it cannot be installed here.
          It installs and runs unchanged on an enterprise deployment.
        </p>}
  </section>;
}
