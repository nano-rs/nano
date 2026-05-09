// SPDX-License-Identifier: AGPL-3.0-or-later

import { ChevronLeftIcon, ChevronRightIcon } from '@radix-ui/react-icons';
import * as React from 'react';
import {
  DayPicker,
  DayFlag,
  SelectionState,
  UI,
  type ChevronProps,
} from 'react-day-picker';

import { buttonVariants } from '@/components/ui/button';
import { cn } from '@/lib/utils';

export type CalendarProps = React.ComponentProps<typeof DayPicker>;

function Calendar({
  className,
  classNames,
  showOutsideDays = true,
  ...props
}: CalendarProps) {
  return (
    <DayPicker
      showOutsideDays={showOutsideDays}
      className={cn('p-3', className)}
      classNames={{
        [UI.Months]: 'flex flex-col sm:flex-row space-y-4 sm:space-x-4 sm:space-y-0',
        [UI.Month]: 'space-y-4',
        [UI.MonthCaption]: 'flex justify-center pt-1 relative items-center',
        [UI.CaptionLabel]: 'text-sm font-medium',
        [UI.Nav]: 'space-x-1 flex items-center',
        [UI.PreviousMonthButton]: cn(
          buttonVariants({ variant: 'outline' }),
          'absolute left-1 h-7 w-7 bg-transparent p-0 opacity-50 hover:opacity-100'
        ),
        [UI.NextMonthButton]: cn(
          buttonVariants({ variant: 'outline' }),
          'absolute right-1 h-7 w-7 bg-transparent p-0 opacity-50 hover:opacity-100'
        ),
        [UI.MonthGrid]: 'w-full border-collapse space-y-1',
        [UI.Weekdays]: 'flex',
        [UI.Weekday]: 'text-muted-foreground rounded-md w-8 font-normal text-[0.8rem]',
        [UI.Week]: 'flex w-full mt-2',
        // Rounding is owned by SelectionState keys (range_start/range_end/
        // selected) so it only applies to actual selected cells, not every
        // first/last day in a week.
        [UI.Day]: 'relative p-0 text-center text-sm focus-within:relative focus-within:z-20',
        [UI.DayButton]: cn(
          buttonVariants({ variant: 'ghost' }),
          'h-8 w-8 p-0 font-normal aria-selected:opacity-100'
        ),
        // Selection states are applied to UI.Day in v9 (no longer wrapped via
        // :has() on a parent cell). Range endpoints drop their inner rounding
        // so two adjacent selected days fuse into a single pill.
        [SelectionState.range_start]: 'bg-accent rounded-l-md rounded-r-none',
        [SelectionState.range_end]: 'bg-accent rounded-r-md rounded-l-none',
        [SelectionState.range_middle]:
          'bg-accent rounded-none [&>button]:rounded-none [&>button]:bg-primary/60 [&>button]:text-primary-foreground [&>button]:hover:bg-primary/60 [&>button]:hover:text-primary-foreground',
        [SelectionState.selected]:
          'bg-accent [&>button]:bg-primary [&>button]:text-primary-foreground [&>button]:hover:bg-primary [&>button]:hover:text-primary-foreground [&>button]:focus:bg-primary [&>button]:focus:text-primary-foreground',
        [DayFlag.today]: '[&>button]:bg-accent [&>button]:text-accent-foreground',
        [DayFlag.outside]:
          'text-muted-foreground opacity-50 aria-selected:bg-accent/50 aria-selected:text-muted-foreground aria-selected:opacity-30',
        [DayFlag.disabled]: 'text-muted-foreground opacity-50',
        [DayFlag.hidden]: 'invisible',
        ...classNames,
      }}
      components={{
        Chevron: ({ orientation, className: chevronClassName }: ChevronProps) => {
          const Icon = orientation === 'right' ? ChevronRightIcon : ChevronLeftIcon;
          return <Icon className={cn('h-4 w-4', chevronClassName)} />;
        },
      }}
      {...props}
    />
  );
}

export { Calendar };
