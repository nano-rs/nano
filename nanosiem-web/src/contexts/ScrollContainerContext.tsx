// SPDX-License-Identifier: AGPL-3.0-or-later

import { createContext, useContext, RefObject } from 'react';

const ScrollContainerContext = createContext<RefObject<HTMLDivElement | null> | null>(null);

export const ScrollContainerProvider = ScrollContainerContext.Provider;

export function useScrollContainer() {
  return useContext(ScrollContainerContext);
}
