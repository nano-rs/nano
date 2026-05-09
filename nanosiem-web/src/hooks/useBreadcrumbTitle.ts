// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect } from 'react';
import { useBreadcrumbContext } from '@/contexts/BreadcrumbContext';

/**
 * Sets the breadcrumb title for the current page.
 * Used by detail pages to display dynamic entity names (e.g., "CASE-42").
 * Clears the title on unmount.
 */
export function useBreadcrumbTitle(title: string | null | undefined) {
  const { setPageTitle } = useBreadcrumbContext();

  useEffect(() => {
    setPageTitle(title ?? null);
    return () => {
      setPageTitle(null);
    };
  }, [title, setPageTitle]);
}
