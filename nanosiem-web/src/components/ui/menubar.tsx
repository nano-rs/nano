// SPDX-License-Identifier: AGPL-3.0-or-later

import * as React from 'react';
import {
  CheckIcon,
  ChevronRightIcon,
  DotFilledIcon,
} from '@radix-ui/react-icons';
import * as MenubarPrimitive from '@radix-ui/react-menubar';

import { cn } from '@/lib/utils';

const MenubarMenu = MenubarPrimitive.Menu;

const MenubarGroup = MenubarPrimitive.Group;

const MenubarPortal = MenubarPrimitive.Portal;

const MenubarSub = MenubarPrimitive.Sub;

const MenubarRadioGroup = MenubarPrimitive.RadioGroup;

function Menubar({
  className,
  ref,
  ...props
}: React.ComponentPropsWithoutRef<typeof MenubarPrimitive.Root> & {
  ref?: React.Ref<React.ComponentRef<typeof MenubarPrimitive.Root>>;
}) {
  return (
    <MenubarPrimitive.Root
      ref={ref}
      className={cn(
        'flex h-9 items-center space-x-1 rounded-md border bg-background p-1 shadow-sm',
        className
      )}
      {...props}
    />
  );
}

function MenubarTrigger({
  className,
  ref,
  ...props
}: React.ComponentPropsWithoutRef<typeof MenubarPrimitive.Trigger> & {
  ref?: React.Ref<React.ComponentRef<typeof MenubarPrimitive.Trigger>>;
}) {
  return (
    <MenubarPrimitive.Trigger
      ref={ref}
      className={cn(
        'flex cursor-default select-none items-center rounded-sm px-3 py-1 text-sm font-medium outline-none focus:bg-accent focus:text-accent-foreground data-[state=open]:bg-accent data-[state=open]:text-accent-foreground',
        className
      )}
      {...props}
    />
  );
}

function MenubarSubTrigger({
  className,
  inset,
  children,
  ref,
  ...props
}: React.ComponentPropsWithoutRef<typeof MenubarPrimitive.SubTrigger> & {
  inset?: boolean;
  ref?: React.Ref<React.ComponentRef<typeof MenubarPrimitive.SubTrigger>>;
}) {
  return (
    <MenubarPrimitive.SubTrigger
      ref={ref}
      className={cn(
        'flex cursor-default select-none items-center rounded-sm px-2 py-1.5 text-sm outline-none focus:bg-accent focus:text-accent-foreground data-[state=open]:bg-accent data-[state=open]:text-accent-foreground',
        inset && 'pl-8',
        className
      )}
      {...props}
    >
      {children}
      <ChevronRightIcon className="ml-auto h-4 w-4" />
    </MenubarPrimitive.SubTrigger>
  );
}

function MenubarSubContent({
  className,
  ref,
  ...props
}: React.ComponentPropsWithoutRef<typeof MenubarPrimitive.SubContent> & {
  ref?: React.Ref<React.ComponentRef<typeof MenubarPrimitive.SubContent>>;
}) {
  return (
    <MenubarPrimitive.SubContent
      ref={ref}
      className={cn(
        'z-50 min-w-[8rem] overflow-hidden rounded-md border bg-popover p-1 text-popover-foreground shadow-lg data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2',
        className
      )}
      {...props}
    />
  );
}

function MenubarContent({
  className,
  align = 'start',
  alignOffset = -4,
  sideOffset = 8,
  ref,
  ...props
}: React.ComponentPropsWithoutRef<typeof MenubarPrimitive.Content> & {
  ref?: React.Ref<React.ComponentRef<typeof MenubarPrimitive.Content>>;
}) {
  return (
    <MenubarPrimitive.Portal>
      <MenubarPrimitive.Content
        ref={ref}
        align={align}
        alignOffset={alignOffset}
        sideOffset={sideOffset}
        className={cn(
          'z-50 min-w-[12rem] overflow-hidden rounded-md border bg-popover p-1 text-popover-foreground shadow-md data-[state=open]:animate-in data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2',
          className
        )}
        {...props}
      />
    </MenubarPrimitive.Portal>
  );
}

function MenubarItem({
  className,
  inset,
  ref,
  ...props
}: React.ComponentPropsWithoutRef<typeof MenubarPrimitive.Item> & {
  inset?: boolean;
  ref?: React.Ref<React.ComponentRef<typeof MenubarPrimitive.Item>>;
}) {
  return (
    <MenubarPrimitive.Item
      ref={ref}
      className={cn(
        'relative flex cursor-default select-none items-center rounded-sm px-2 py-1.5 text-sm outline-none focus:bg-accent focus:text-accent-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50',
        inset && 'pl-8',
        className
      )}
      {...props}
    />
  );
}

function MenubarCheckboxItem({
  className,
  children,
  checked,
  ref,
  ...props
}: React.ComponentPropsWithoutRef<typeof MenubarPrimitive.CheckboxItem> & {
  ref?: React.Ref<React.ComponentRef<typeof MenubarPrimitive.CheckboxItem>>;
}) {
  return (
    <MenubarPrimitive.CheckboxItem
      ref={ref}
      className={cn(
        'relative flex cursor-default select-none items-center rounded-sm py-1.5 pl-8 pr-2 text-sm outline-none focus:bg-accent focus:text-accent-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50',
        className
      )}
      checked={checked}
      {...props}
    >
      <span className="absolute left-2 flex h-3.5 w-3.5 items-center justify-center">
        <MenubarPrimitive.ItemIndicator>
          <CheckIcon className="h-4 w-4" />
        </MenubarPrimitive.ItemIndicator>
      </span>
      {children}
    </MenubarPrimitive.CheckboxItem>
  );
}

function MenubarRadioItem({
  className,
  children,
  ref,
  ...props
}: React.ComponentPropsWithoutRef<typeof MenubarPrimitive.RadioItem> & {
  ref?: React.Ref<React.ComponentRef<typeof MenubarPrimitive.RadioItem>>;
}) {
  return (
    <MenubarPrimitive.RadioItem
      ref={ref}
      className={cn(
        'relative flex cursor-default select-none items-center rounded-sm py-1.5 pl-8 pr-2 text-sm outline-none focus:bg-accent focus:text-accent-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50',
        className
      )}
      {...props}
    >
      <span className="absolute left-2 flex h-3.5 w-3.5 items-center justify-center">
        <MenubarPrimitive.ItemIndicator>
          <DotFilledIcon className="h-4 w-4 fill-current" />
        </MenubarPrimitive.ItemIndicator>
      </span>
      {children}
    </MenubarPrimitive.RadioItem>
  );
}

function MenubarLabel({
  className,
  inset,
  ref,
  ...props
}: React.ComponentPropsWithoutRef<typeof MenubarPrimitive.Label> & {
  inset?: boolean;
  ref?: React.Ref<React.ComponentRef<typeof MenubarPrimitive.Label>>;
}) {
  return (
    <MenubarPrimitive.Label
      ref={ref}
      className={cn(
        'px-2 py-1.5 text-sm font-semibold',
        inset && 'pl-8',
        className
      )}
      {...props}
    />
  );
}

function MenubarSeparator({
  className,
  ref,
  ...props
}: React.ComponentPropsWithoutRef<typeof MenubarPrimitive.Separator> & {
  ref?: React.Ref<React.ComponentRef<typeof MenubarPrimitive.Separator>>;
}) {
  return (
    <MenubarPrimitive.Separator
      ref={ref}
      className={cn('-mx-1 my-1 h-px bg-muted', className)}
      {...props}
    />
  );
}

const MenubarShortcut = ({
  className,
  ...props
}: React.HTMLAttributes<HTMLSpanElement>) => {
  return (
    <span
      className={cn(
        'ml-auto text-xs tracking-widest text-muted-foreground',
        className
      )}
      {...props}
    />
  );
};

export {
  Menubar,
  MenubarMenu,
  MenubarTrigger,
  MenubarContent,
  MenubarItem,
  MenubarSeparator,
  MenubarLabel,
  MenubarCheckboxItem,
  MenubarRadioGroup,
  MenubarRadioItem,
  MenubarPortal,
  MenubarSubContent,
  MenubarSubTrigger,
  MenubarGroup,
  MenubarSub,
  MenubarShortcut,
};
