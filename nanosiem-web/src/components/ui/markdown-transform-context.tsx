// SPDX-License-Identifier: AGPL-3.0-or-later

import { createContext, useContext, type ReactNode } from 'react';

/**
 * A children-transform callback. When a consumer provides one via
 * `<MarkdownTransformProvider>`, the `Markdown` primitive runs it over
 * the text-bearing children of each paragraph / list / heading / cell.
 *
 * The transform is intentionally generic — it knows nothing about entities
 * or any domain concept — so the UI primitive stays decoupled from feature
 * code. Domain-specific logic (e.g. wrapping entity mentions in chips) lives
 * wherever the provider is set up.
 */
export type MarkdownTransform = (children: ReactNode) => ReactNode;

const MarkdownTransformContext = createContext<MarkdownTransform | null>(null);

export function MarkdownTransformProvider({
  transform,
  children,
}: {
  transform: MarkdownTransform | null;
  children: ReactNode;
}) {
  return (
    <MarkdownTransformContext.Provider value={transform}>
      {children}
    </MarkdownTransformContext.Provider>
  );
}

export function useMarkdownTransform(): MarkdownTransform | null {
  return useContext(MarkdownTransformContext);
}
