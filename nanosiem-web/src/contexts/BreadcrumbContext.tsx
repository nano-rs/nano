// SPDX-License-Identifier: AGPL-3.0-or-later

import { createContext, useContext, useState, useCallback, ReactNode } from 'react';

interface BreadcrumbContextType {
  pageTitle: string | null;
  setPageTitle: (title: string | null) => void;
}

const BreadcrumbContext = createContext<BreadcrumbContextType | null>(null);

export function BreadcrumbProvider({ children }: { children: ReactNode }) {
  const [pageTitle, setPageTitleState] = useState<string | null>(null);

  const setPageTitle = useCallback((title: string | null) => {
    setPageTitleState(title);
  }, []);

  return (
    <BreadcrumbContext.Provider value={{ pageTitle, setPageTitle }}>
      {children}
    </BreadcrumbContext.Provider>
  );
}

export function useBreadcrumbContext() {
  const context = useContext(BreadcrumbContext);
  if (!context) {
    throw new Error('useBreadcrumbContext must be used within a BreadcrumbProvider');
  }
  return context;
}
