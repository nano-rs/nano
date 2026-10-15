// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * App-wide loading indicator (NAN-2585) — replaces lucide `Loader2`.
 *
 * Eight 2×2 pixel-dot clusters on a 15-unit ring; each cluster fades
 * 1 → 0.2 on a staggered 1s linear cycle, so a bright head chases
 * clockwise. The keyframes live in `src/index.css` (`.nano-loading-icon`),
 * including the `prefers-reduced-motion` static fallback.
 *
 * Drop-in for `<Loader2 className="h-4 w-4 animate-spin" />`: same 24px
 * default size, sized by className, colored by `currentColor`. It animates
 * itself, so an `animate-spin` class is stripped rather than rotating the
 * ring. Fill-based by design (pixel dots) — the 1.5 stroke-width icon
 * convention does not apply.
 *
 * Geometry and timing recreated from the "loading" spinner in loading-dev
 * (https://loading.dev/spinners/loading):
 *   MIT License, Copyright (c) 2026 Jakub Krehel
 *   https://github.com/jakubkrehel/loading/blob/main/LICENSE.md
 */
import { forwardRef, type CSSProperties, type SVGProps } from 'react';
import { cn } from '@/lib/utils';

/** One cluster: four 1×1 dots on a 3×3 grid. */
const CLUSTER = 'M0 0h1v1H0zM2 0h1v1H2zM0 2h1v1H0zM2 2h1v1H2z';

/** Cluster origins, clockwise from 3 o'clock. */
const SEGMENTS: ReadonlyArray<readonly [number, number]> = [
  [12, 6],
  [10, 10],
  [6, 12],
  [2, 10],
  [0, 6],
  [2, 2],
  [6, 0],
  [10, 2],
];

function withoutSpin(className: string | undefined): string | undefined {
  return className
    ?.split(/\s+/)
    .filter((c) => c !== 'animate-spin')
    .join(' ');
}

export const LoadingIcon = forwardRef<SVGSVGElement, SVGProps<SVGSVGElement>>(
  ({ className, ...props }, ref) => (
    <svg
      ref={ref}
      xmlns="http://www.w3.org/2000/svg"
      width={24}
      height={24}
      // Edge-to-edge like the source: at the 12-16px sizes most call sites
      // use, any padding shrinks the 1-unit dots below a device pixel.
      viewBox="0 0 15 15"
      fill="currentColor"
      aria-hidden="true"
      className={cn('nano-loading-icon', withoutSpin(className))}
      {...props}
    >
      {SEGMENTS.map(([x, y], i) => (
        <path
          key={i}
          d={CLUSTER}
          transform={`translate(${x} ${y})`}
          style={{ '--nano-loading-step': i } as CSSProperties}
        />
      ))}
    </svg>
  ),
);

LoadingIcon.displayName = 'LoadingIcon';
