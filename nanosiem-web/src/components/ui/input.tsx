// SPDX-License-Identifier: AGPL-3.0-or-later

import * as React from 'react';

import { cn } from '@/lib/utils';

export type InputProps = React.InputHTMLAttributes<HTMLInputElement>;

function Input({ className, type, ref, ...props }: InputProps & { ref?: React.Ref<HTMLInputElement> }) {
  return (
    <input
      type={type}
      className={cn(
        'flex h-8 w-full rounded-md border border-border bg-input px-3 py-1 text-[12px] text-foreground transition-colors file:border-0 file:bg-transparent file:text-[12px] file:font-medium file:text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50',
        className
      )}
      ref={ref}
      {...props}
    />
  );
}

export { Input };
