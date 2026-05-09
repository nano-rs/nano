// SPDX-License-Identifier: AGPL-3.0-or-later

import * as React from 'react';
import * as SwitchPrimitives from '@radix-ui/react-switch';

import { cn } from '@/lib/utils';

function Switch({
  className,
  ref,
  ...props
}: React.ComponentPropsWithoutRef<typeof SwitchPrimitives.Root> & {
  ref?: React.Ref<React.ComponentRef<typeof SwitchPrimitives.Root>>;
}) {
  return (
    <SwitchPrimitives.Root
      className={cn(
        'peer inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:bg-primary data-[state=unchecked]:bg-gray-300 dark:data-[state=unchecked]:bg-gray-700',
        className
      )}
      {...props}
      ref={ref}
    >
      <SwitchPrimitives.Thumb
        className={cn(
          // Thumb sizes from the track (h-full aspect-square) so consumers can
          // override the root to h-4 w-7 / h-6 w-11 / etc. without the thumb
          // overflowing. translate-x-[100%] moves by exactly the thumb's own
          // width, landing its right edge on the inner track edge.
          'pointer-events-none block h-full aspect-square rounded-full bg-white shadow-lg ring-0 transition-transform data-[state=checked]:translate-x-[100%] data-[state=unchecked]:translate-x-0'
        )}
      />
    </SwitchPrimitives.Root>
  );
}

export { Switch };
