// SPDX-License-Identifier: AGPL-3.0-or-later

import { useEffect, useState } from 'react';

/**
 * Reports whether `el` is (near) visible — live: `true` on enter, `false` on
 * leave. `rootMargin` pre-arms slightly before the element actually reaches the
 * viewport so downstream work can start a beat early.
 *
 * Pass `root` = the scrolling container (e.g. a dashboard's `overflow-auto`
 * body) when the content scrolls inside a container rather than the window;
 * `null` (default) observes against the browser viewport.
 *
 * The caller owns the observed element — drive it with a callback ref
 * (`const [el, setEl] = useState<Element|null>(null); <div ref={setEl}/>`) so
 * the observer re-attaches if the node or root changes.
 */
export function useInView(
  el: Element | null,
  opts: { root?: Element | null; rootMargin?: string } = {},
): boolean {
  const { root = null, rootMargin = '200px' } = opts;
  const [inView, setInView] = useState(false);

  useEffect(() => {
    if (!el || typeof IntersectionObserver === 'undefined') return;
    const observer = new IntersectionObserver(
      ([entry]) => setInView(entry.isIntersecting),
      { root, rootMargin },
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [el, root, rootMargin]);

  return inView;
}
