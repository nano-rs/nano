// SPDX-License-Identifier: AGPL-3.0-or-later

import * as React from 'react';
import * as TooltipPrimitive from '@radix-ui/react-tooltip';

import { cn } from '@/lib/utils';

/**
 * NAN-5698: Radix throws "`Tooltip` must be used within `TooltipProvider`"
 * when a Tooltip renders without an ancestor provider, which takes down the
 * whole route (the alert page crashed on every risk notable). App mounts one
 * provider at the root; this marker lets a Tooltip rendered outside any
 * provider (a test, a portal host mounted elsewhere) fall back to its own
 * instead of crashing, while local providers keep their own delay settings.
 */
const HasTooltipProvider = React.createContext(false);

function TooltipProvider({ children, ...props }: React.ComponentProps<typeof TooltipPrimitive.Provider>) {
  return (
    <TooltipPrimitive.Provider {...props}>
      <HasTooltipProvider.Provider value={true}>{children}</HasTooltipProvider.Provider>
    </TooltipPrimitive.Provider>
  );
}

function Tooltip(props: React.ComponentProps<typeof TooltipPrimitive.Root>) {
  const hasProvider = React.useContext(HasTooltipProvider);
  if (hasProvider) return <TooltipPrimitive.Root {...props} />;
  return (
    <TooltipProvider>
      <TooltipPrimitive.Root {...props} />
    </TooltipProvider>
  );
}

const TooltipTrigger = TooltipPrimitive.Trigger;

function TooltipContent({
  className,
  sideOffset = 4,
  ref,
  ...props
}: React.ComponentPropsWithoutRef<typeof TooltipPrimitive.Content> & {
  ref?: React.Ref<React.ComponentRef<typeof TooltipPrimitive.Content>>;
}) {
  // Portal the content to document.body so positioning works correctly when the
  // trigger is inside a table, a scrollable container, or any element with
  // overflow / transform that would otherwise confuse Radix's Floating UI
  // computation. Without Portal, tooltips on table rows render in the wrong
  // place (e.g. pinned to the top-left of the viewport).
  return (
    <TooltipPrimitive.Portal>
      <TooltipPrimitive.Content
        ref={ref}
        sideOffset={sideOffset}
        className={cn(
          'z-50 overflow-hidden rounded-md border bg-popover px-3 py-1.5 text-xs text-popover-foreground shadow-md animate-in fade-in-0 zoom-in-95 data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2',
          className
        )}
        {...props}
      />
    </TooltipPrimitive.Portal>
  );
}

export { Tooltip, TooltipTrigger, TooltipContent, TooltipProvider };
