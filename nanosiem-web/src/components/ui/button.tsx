// SPDX-License-Identifier: AGPL-3.0-or-later

import * as React from 'react';
import { Slot } from '@radix-ui/react-slot';
import { cva, type VariantProps } from 'class-variance-authority';

import { cn } from '@/lib/utils';

// `gap-1.5` belongs in the BASE (NAN-2362). Upstream shadcn carries `gap-2`
// here; our copy lost it, so `<Button><Icon/>Label</Button>` rendered flush —
// "⟳Refresh", "✏Edit dashboard".
//
// Of 354 icon+label call sites at the time of the fix: 83 were genuinely flush,
// 86 set their own `gap-*`, and 185 spaced the icon with `mr-*` instead. That
// last group is why this change could not be a one-liner — tailwind-merge
// resolves a `gap` against a `gap`, but nothing cancels a CHILD's margin, so
// adding the base alone would have double-spaced 185 buttons to fix 83. The
// redundant `mr-*` were removed in the same commit; `gap-1.5` (not shadcn's
// looser `gap-2`) matches what the 86 hand-gapped sites had already converged on
// for this density.
//
// Safe by construction: text-only and `size="icon"` buttons have a single child
// so a gap is a no-op, and `cn()` is tailwind-merge — a `className` gap at a
// call site still overrides this. Icon-only buttons keep their margins (there
// the margin is positioning, not label spacing).
const buttonVariants = cva(
  'inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-md text-[12px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50',
  {
    variants: {
      variant: {
        default:
          'bg-primary text-primary-foreground shadow hover:bg-primary/90',
        destructive:
          'bg-destructive text-destructive-foreground shadow-sm hover:bg-destructive/90',
        outline:
          'border border-border bg-transparent text-foreground hover:bg-accent',
        secondary:
          'bg-secondary text-secondary-foreground hover:bg-secondary/80',
        ghost: 'text-foreground hover:bg-accent',
        link: 'text-primary underline-offset-4 hover:underline',
      },
      size: {
        default: 'h-8 px-3.5 py-1.5',
        sm: 'h-8 rounded-md px-3 text-xs',
        lg: 'h-10 rounded-md px-8',
        icon: 'h-8 w-8',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

function Button({ className, variant, size, asChild = false, ref, ...props }: ButtonProps & { ref?: React.Ref<HTMLButtonElement> }) {
  const Comp = asChild ? Slot : 'button';
  return (
    <Comp
      className={cn(buttonVariants({ variant, size, className }))}
      ref={ref}
      {...props}
    />
  );
}

export { Button, buttonVariants };
