// SPDX-License-Identifier: AGPL-3.0-or-later

import * as React from 'react';
import { ChevronRightIcon, DotsHorizontalIcon } from '@radix-ui/react-icons';
import { Slot } from '@radix-ui/react-slot';

import { cn } from '@/lib/utils';

function Breadcrumb({
  ref,
  ...props
}: React.ComponentPropsWithoutRef<'nav'> & {
  separator?: React.ReactNode;
} & {
  ref?: React.Ref<HTMLElement>;
}) {
  return <nav ref={ref} aria-label="breadcrumb" {...props} />;
}

function BreadcrumbList({
  className,
  ref,
  ...props
}: React.ComponentPropsWithoutRef<'ol'> & {
  ref?: React.Ref<HTMLOListElement>;
}) {
  return (
    <ol
      ref={ref}
      className={cn(
        'flex flex-wrap items-center gap-1.5 break-words text-sm text-muted-foreground sm:gap-2.5',
        className
      )}
      {...props}
    />
  );
}

function BreadcrumbItem({
  className,
  ref,
  ...props
}: React.ComponentPropsWithoutRef<'li'> & {
  ref?: React.Ref<HTMLLIElement>;
}) {
  return (
    <li
      ref={ref}
      className={cn('inline-flex items-center gap-1.5', className)}
      {...props}
    />
  );
}

function BreadcrumbLink({
  asChild,
  className,
  ref,
  ...props
}: React.ComponentPropsWithoutRef<'a'> & {
  asChild?: boolean;
} & {
  ref?: React.Ref<HTMLAnchorElement>;
}) {
  const Comp = asChild ? Slot : 'a';

  return (
    <Comp
      ref={ref}
      className={cn('transition-colors hover:text-primary', className)}
      {...props}
    />
  );
}

function BreadcrumbPage({
  className,
  ref,
  ...props
}: React.ComponentPropsWithoutRef<'span'> & {
  ref?: React.Ref<HTMLSpanElement>;
}) {
  return (
    <span
      ref={ref}
      role="link"
      aria-disabled="true"
      aria-current="page"
      className={cn('font-normal text-foreground', className)}
      {...props}
    />
  );
}

const BreadcrumbSeparator = ({
  children,
  className,
  ...props
}: React.ComponentProps<'li'>) => (
  <li
    role="presentation"
    aria-hidden="true"
    className={cn('[&>svg]:size-3.5', className)}
    {...props}
  >
    {children ?? <ChevronRightIcon />}
  </li>
);

const BreadcrumbEllipsis = ({
  className,
  ...props
}: React.ComponentProps<'span'>) => (
  <span
    role="presentation"
    aria-hidden="true"
    className={cn('flex h-9 w-9 items-center justify-center', className)}
    {...props}
  >
    <DotsHorizontalIcon className="h-4 w-4" />
    <span className="sr-only">More</span>
  </span>
);

export {
  Breadcrumb,
  BreadcrumbList,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbPage,
  BreadcrumbSeparator,
  BreadcrumbEllipsis,
};
