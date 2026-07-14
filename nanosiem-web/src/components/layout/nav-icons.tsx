// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Custom nav icons ported 1:1 from design-ref/shadcn/icons.jsx (NAN-369).
 *
 * Design-kit icons are lucide-style stroke SVGs (24×24 viewBox, 1.5 stroke)
 * but simpler / more geometric than lucide's equivalents — e.g., Home has
 * no door detail, Shield is a clean silhouette.
 *
 * Keep these in sync with design-ref/shadcn/icons.jsx when the kit updates.
 */

import type { SVGProps, ReactNode } from 'react';

type IconProps = SVGProps<SVGSVGElement>;

function Ic({ children, className = 'w-[15px] h-[15px]', ...rest }: IconProps & { children: ReactNode }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      {...rest}
    >
      {children}
    </svg>
  );
}

export const NavHome = (p: IconProps) => (
  <Ic {...p}>
    <path d="M3 12l9-8 9 8v8a2 2 0 0 1-2 2h-4v-6h-6v6H5a2 2 0 0 1-2-2z" />
  </Ic>
);

export const NavPlusCross = (p: IconProps) => (
  <Ic {...p}>
    <path d="M12 3v18M3 12h18" />
  </Ic>
);

export const NavSearch = (p: IconProps) => (
  <Ic {...p}>
    <circle cx="11" cy="11" r="7" />
    <path d="m20 20-3.5-3.5" />
  </Ic>
);

export const NavGrid = (p: IconProps) => (
  <Ic {...p}>
    <rect x="3" y="4" width="18" height="4" rx="1" />
    <rect x="3" y="12" width="18" height="8" rx="1" />
  </Ic>
);

export const NavLayers = (p: IconProps) => (
  <Ic {...p}>
    <path d="M12 2 2 7l10 5 10-5z" />
    <path d="M2 17l10 5 10-5M2 12l10 5 10-5" />
  </Ic>
);

export const NavShield = (p: IconProps) => (
  <Ic {...p}>
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </Ic>
);

export const NavList = (p: IconProps) => (
  <Ic {...p}>
    <path d="M4 6h16M4 12h16M4 18h10" />
  </Ic>
);

export const NavChart = (p: IconProps) => (
  <Ic {...p}>
    <path d="M3 3v18h18" />
    <path d="M7 14l4-4 4 4 5-5" />
  </Ic>
);

// Pulse / activity line — the observability glyph (distinct from NavChart's bar/line).
export const NavActivity = (p: IconProps) => (
  <Ic {...p}>
    <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
  </Ic>
);

export const NavBars = (p: IconProps) => (
  <Ic {...p}>
    <path d="M4 20V10M10 20V4M16 20v-8M22 20h-20" />
  </Ic>
);

export const NavInfo = (p: IconProps) => (
  <Ic {...p}>
    <circle cx="12" cy="12" r="10" />
    <path d="M12 16v-4M12 8h.01" />
  </Ic>
);

export const NavSquares = (p: IconProps) => (
  <Ic {...p}>
    <rect x="3" y="3" width="7" height="7" rx="1" />
    <rect x="14" y="3" width="7" height="7" rx="1" />
    <rect x="3" y="14" width="7" height="7" rx="1" />
    <rect x="14" y="14" width="7" height="7" rx="1" />
  </Ic>
);

export const NavDownload = (p: IconProps) => (
  <Ic {...p}>
    <path d="M12 3v12m-5-5 5 5 5-5M5 21h14" />
  </Ic>
);

export const NavGear = (p: IconProps) => (
  <Ic {...p}>
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h0a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h0a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v0a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
  </Ic>
);

export const NavSidebar = (p: IconProps) => (
  <Ic {...p}>
    <rect x="3" y="4" width="18" height="16" rx="2" />
    <path d="M9 4v16" />
  </Ic>
);

export const NavBell = (p: IconProps) => (
  <Ic {...p}>
    <path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9M10 21a2 2 0 0 0 4 0" />
  </Ic>
);

export const NavChevDown = (p: IconProps) => (
  <Ic {...p}>
    <path d="M6 9l6 6 6-6" />
  </Ic>
);

/**
 * Collapse/expand rail toggle. Matches the custom SVG in design-ref/shadcn/app.jsx.
 * Rotate 180° via className when collapsed so the inner chevron points out (to expand).
 */
export const NavCollapse = (p: IconProps) => (
  <Ic {...p}>
    <rect x="3" y="4" width="18" height="16" rx="2" />
    <path d="M9 4v16" />
    <path d="M15 10l-3 2 3 2" />
  </Ic>
);
