// SPDX-License-Identifier: AGPL-3.0-or-later
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import type { PlatformCatalog } from '@/hooks/repository-sync-state';

interface PlatformCatalogSettingUpProps {
  /** What the catalog holds, e.g. "detection rules". */
  content: string;
  catalog: PlatformCatalog;
}

/**
 * NAN-3436: shown on a new hosted-shared workspace while its platform
 * catalog is still being copied in the background after activation.
 */
export function PlatformCatalogSettingUp({ content, catalog }: PlatformCatalogSettingUpProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      data-testid="platform-catalog-setting-up"
      className="flex items-center justify-center p-8 text-center"
    >
      <div className="max-w-md">
        <div className="flex items-center justify-center gap-2 text-[13px] font-medium text-foreground mb-2">
          <LoadingIcon className="w-[13px] h-[13px] text-muted-foreground" strokeWidth={1.5} />
          Setting up content…
        </div>
        <div className="text-[12px] text-muted-foreground leading-relaxed">
          Your workspace's {content} are being added from{' '}
          <code className="font-mono text-[11px] text-foreground/80">{catalog}</code>. This usually takes
          under a minute; this page updates on its own.
        </div>
      </div>
    </div>
  );
}
