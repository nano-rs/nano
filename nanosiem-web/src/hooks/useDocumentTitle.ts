// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect } from 'react';

const BASE_TITLE = 'nano';

/**
 * Sets the document title, appending the base app name.
 * @param title - Page title (e.g., "Search" becomes "Search | nano")
 * @param deps - Optional dependencies to trigger title updates
 */
export function useDocumentTitle(title: string | null | undefined, deps: unknown[] = []) {
  useEffect(() => {
    const previousTitle = document.title;

    if (title) {
      document.title = `${title} | ${BASE_TITLE}`;
    } else {
      document.title = BASE_TITLE;
    }

    return () => {
      document.title = previousTitle;
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [title, ...deps]);
}
