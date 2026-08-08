// SPDX-License-Identifier: AGPL-3.0-or-later

// Lives in CORE, not src/enterprise/ (NAN-2356). NAN-745 lifted it out as
// "pivt branding is enterprise-only", which left the open build resolving it to
// a `return null` stub — and an icon is sometimes the ENTIRE visible content of
// a control. `WhatsNew.tsx` renders `<Button size="icon"><PivtIcon /></Button>`
// for a dialog that is pure core, so the null icon left an invisible button in
// the topbar. The icon is just an icon; the enterprise part is the meloD
// features behind it, and those are gated on capabilities at their call sites.

/**
 * pivt AI icon — "Code Pivot" design
 * Angle brackets with center dot, representing code meets intelligence.
 * Variants: base (default), plus (new chat trigger with + badge)
 */
import { forwardRef, type SVGProps } from 'react';

export const PivtIcon = forwardRef<SVGSVGElement, SVGProps<SVGSVGElement> & { variant?: 'base' | 'plus' }>(
  ({ className, variant = 'base', ...props }, ref) => {
    return (
      <svg
        ref={ref}
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
        className={className}
        xmlns="http://www.w3.org/2000/svg"
        {...props}
      >
        <path d="M9 4L4 12L9 20" />
        <path d="M15 4L20 12L15 20" opacity="0.4" />
        <circle cx="12" cy="12" r="2" fill="currentColor" stroke="none" />
        {variant === 'plus' && (
          <>
            <circle cx="19" cy="5" r="4.5" fill="currentColor" stroke="none" opacity="0.15" />
            <path d="M19 3V7" strokeWidth="1.5" />
            <path d="M17 5H21" strokeWidth="1.5" />
          </>
        )}
      </svg>
    );
  }
);

PivtIcon.displayName = 'PivtIcon';
