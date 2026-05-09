// SPDX-License-Identifier: AGPL-3.0-or-later

import * as React from 'react';

import { cn } from '@/lib/utils';

export type TextareaProps = React.TextareaHTMLAttributes<HTMLTextAreaElement>;

function Textarea({ className, ref, ...props }: TextareaProps & { ref?: React.Ref<HTMLTextAreaElement> }) {
  return (
    <textarea
      className={cn(
        'flex min-h-[60px] w-full rounded-md border border-border bg-transparent px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50',
        className
      )}
      ref={ref}
      {...props}
    />
  );
}

export { Textarea };
