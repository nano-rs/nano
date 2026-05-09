// SPDX-License-Identifier: AGPL-3.0-or-later

import { DragHandleDots2Icon } from '@radix-ui/react-icons';
import {
  Group,
  Panel,
  Separator,
  type PanelImperativeHandle,
} from 'react-resizable-panels';

import { cn } from '@/lib/utils';

const ResizablePanelGroup = ({
  className,
  ...props
}: React.ComponentProps<typeof Group>) => (
  // v4 Group sets flex-direction inline based on `orientation`, so the
  // outer container only needs sizing.
  <Group className={cn('h-full w-full', className)} {...props} />
);

const ResizablePanel = Panel;

// Horizontal-only styling. v4 dropped the data-panel-group-direction attribute
// that the v3 wrapper used to flip dimensions for vertical groups. If a future
// consumer needs a vertical group, add a `vertical` prop here and swap the
// w-px / h-px / pseudo-element axis explicitly.
const ResizableHandle = ({
  withHandle,
  className,
  ...props
}: React.ComponentProps<typeof Separator> & {
  withHandle?: boolean;
}) => (
  <Separator
    className={cn(
      'relative flex w-px items-center justify-center bg-border after:absolute after:inset-y-0 after:left-1/2 after:w-1 after:-translate-x-1/2 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring focus-visible:ring-offset-1',
      className
    )}
    {...props}
  >
    {withHandle && (
      <div className="z-10 flex h-4 w-3 items-center justify-center rounded-sm border bg-border">
        <DragHandleDots2Icon className="h-2.5 w-2.5" />
      </div>
    )}
  </Separator>
);

export { ResizablePanelGroup, ResizablePanel, ResizableHandle };
export type { PanelImperativeHandle };
