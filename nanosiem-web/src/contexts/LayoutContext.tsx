// SPDX-License-Identifier: AGPL-3.0-or-later

import { createContext, useContext, useState, useCallback, ReactNode } from 'react';

interface LayoutContextType {
  /** When true, the outer scroll container is disabled and the page handles its own scrolling */
  fullHeightMode: boolean;
  /** Set full height mode - page will fill available space and handle its own scroll */
  setFullHeightMode: (enabled: boolean) => void;
  /** When true, a fixed bottom bar (e.g. search stats) is visible and sidebar needs extra padding */
  bottomBarVisible: boolean;
  setBottomBarVisible: (visible: boolean) => void;
  /** Page-specific content injected into the global StatusBar middle slot
      (between the platform dot and the nano · pagename label). Pages call
      `setPageStatus(<fragment/>)` to contribute; pass `null` to restore the
      StatusBar's default platform-info content. */
  pageStatus: ReactNode;
  setPageStatus: (content: ReactNode) => void;
}

const LayoutContext = createContext<LayoutContextType | null>(null);

export function LayoutProvider({ children }: { children: ReactNode }) {
  const [fullHeightMode, setFullHeightModeState] = useState(false);
  const [bottomBarVisible, setBottomBarVisibleState] = useState(false);
  const [pageStatus, setPageStatusState] = useState<ReactNode>(null);

  const setFullHeightMode = useCallback((enabled: boolean) => {
    setFullHeightModeState(enabled);
  }, []);

  const setBottomBarVisible = useCallback((visible: boolean) => {
    setBottomBarVisibleState(visible);
  }, []);

  const setPageStatus = useCallback((content: ReactNode) => {
    setPageStatusState(content);
  }, []);

  return (
    <LayoutContext.Provider value={{ fullHeightMode, setFullHeightMode, bottomBarVisible, setBottomBarVisible, pageStatus, setPageStatus }}>
      {children}
    </LayoutContext.Provider>
  );
}

export function useLayout() {
  const context = useContext(LayoutContext);
  if (!context) {
    throw new Error('useLayout must be used within a LayoutProvider');
  }
  return context;
}

/** Optional hook that returns null if not in provider (for components that may be outside layout) */
export function useLayoutOptional() {
  return useContext(LayoutContext);
}
