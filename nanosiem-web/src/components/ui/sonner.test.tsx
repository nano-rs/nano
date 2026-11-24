// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-5834: toasts stay off the bottom-right primary-action corner, every toast
// can be closed, and a long description scrolls in a capped body.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { act, cleanup, fireEvent, render, waitFor } from '@testing-library/react';
import { toast as sonnerToast } from 'sonner';
import { Toaster } from './sonner';
import { Dialog, DialogContent, DialogTitle } from './dialog';
import { Sheet, SheetContent, SheetTitle } from './sheet';
import { toast } from '@/hooks/use-toast';

// jsdom has no pointer capture; Sonner calls it on pointerdown.
Element.prototype.setPointerCapture ??= () => {};
Element.prototype.releasePointerCapture ??= () => {};
Element.prototype.hasPointerCapture ??= () => false;

afterEach(() => {
  act(() => {
    sonnerToast.dismiss();
  });
  cleanup();
});

it('renders bottom-center, clear of the status bar, with a close button on every toast', async () => {
  render(<Toaster />);
  act(() => {
    toast({ title: 'VRL invalid', description: 'one error', variant: 'destructive' });
    toast({ title: 'Saved' });
  });
  const toaster = await waitFor(() => {
    const el = document.querySelector('[data-sonner-toaster]');
    expect(el).not.toBeNull();
    return el as HTMLElement;
  });
  expect(toaster.getAttribute('data-y-position')).toBe('bottom');
  expect(toaster.getAttribute('data-x-position')).toBe('center');
  expect(toaster.style.getPropertyValue('--offset-bottom')).toBe('34px');
  await waitFor(() => expect(document.querySelectorAll('[data-sonner-toast]')).toHaveLength(2));
  expect(document.querySelectorAll('[data-sonner-toast] [data-close-button]')).toHaveLength(2);
});

it('a caller can still override the defaults', async () => {
  render(<Toaster position="top-right" />);
  act(() => {
    toast({ title: 'x' });
  });
  await waitFor(() => expect(document.querySelector('[data-sonner-toaster]')?.getAttribute('data-x-position')).toBe('right'));
});

it('index.css caps a toast description and scrolls the rest', () => {
  const css = readFileSync(join(process.cwd(), 'src/index.css'), 'utf8');
  const rule = css.match(/\[data-sonner-toast\] \[data-description\] \{([^}]*)\}/);
  expect(rule, 'toast description rule').not.toBeNull();
  expect(rule![1]).toMatch(/max-height:\s*\d+px/);
  expect(rule![1]).toMatch(/overflow-y:\s*auto/);
});

const css = () => readFileSync(join(process.cwd(), 'src/index.css'), 'utf8');
const ruleBody = (selector: RegExp) => {
  const m = css().match(new RegExp(`${selector.source}\\{([^}]*)\\}`));
  return m ? m[1] : null;
};

it('visible toasts take pointer events while a modal disables them on <body>', () => {
  expect(
    ruleBody(/:root \[data-sonner-toaster\] \[data-sonner-toast\]:not\(\[data-visible='false'\]\):not\(\[data-removed='true'\]\) /),
  ).toMatch(/pointer-events:\s*auto/);
  // Hidden (queued past visibleToasts) and removed toasts keep Sonner's
  // pointer-events:none: no other rule turns them back on.
  const autoRules = [...css().matchAll(/([^{}]*)\{[^}]*pointer-events:\s*auto[^}]*\}/g)]
    .map((m) => m[1].trim())
    .filter((sel) => sel.includes('data-sonner-toast'));
  expect(autoRules).toHaveLength(1);
  expect(autoRules[0]).toContain(":not([data-visible='false'])");
  expect(autoRules[0]).toContain(":not([data-removed='true'])");
});

it('the 4th+ queued toast is rendered hidden, matching what the rule excludes', async () => {
  render(<Toaster />);
  act(() => {
    for (const title of ['a', 'b', 'c', 'd']) toast({ title });
  });
  await waitFor(() => expect(document.querySelectorAll('[data-sonner-toast]')).toHaveLength(4));
  const hidden = document.querySelectorAll('[data-sonner-toast][data-visible="false"]');
  expect(hidden).toHaveLength(1);
  expect(hidden[0].matches("[data-sonner-toast]:not([data-visible='false']):not([data-removed='true'])")).toBe(false);
  expect(document.querySelectorAll("[data-sonner-toast]:not([data-visible='false']):not([data-removed='true'])")).toHaveLength(3);
});

it('toast focus and close-button hover use the theme tokens', () => {
  const focus = css().match(/\[data-sonner-toast\]:focus-visible,[\s\S]*?\{([^}]*)\}/);
  expect(focus?.[1]).toMatch(/box-shadow:\s*0 0 0 2px var\(--ring\)/);
  expect(focus?.[0]).toContain('[data-close-button]:focus-visible');
  expect(ruleBody(/\[data-close-button\]:hover /)).toMatch(/var\(--normal-bg-hover\)/);
});

it('a lifted toaster clears the bulk-action bar', () => {
  expect(ruleBody(/:root\[data-toast-lift\] \[data-sonner-toaster\]\[data-y-position='bottom'\] /)).toMatch(
    /--offset-bottom:\s*\d+px !important/,
  );
});

// A toast's close button sits above an open Dialog/Sheet: clicking it must
// not count as an outside click that dismisses the modal.
it.each([
  ['dialog', (onOpenChange: (o: boolean) => void) => (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent aria-describedby={undefined}><DialogTitle>t</DialogTitle></DialogContent>
    </Dialog>
  )],
  ['sheet', (onOpenChange: (o: boolean) => void) => (
    <Sheet open onOpenChange={onOpenChange}>
      <SheetContent aria-describedby={undefined}><SheetTitle>t</SheetTitle></SheetContent>
    </Sheet>
  )],
])('clicking a toast keeps an open %s open', async (_kind, modal) => {
  const changes: boolean[] = [];
  render(
    <>
      {modal((o) => changes.push(o))}
      <Toaster />
    </>,
  );
  act(() => {
    toast({ title: 'Saved' });
  });
  const close = await waitFor(() => {
    const el = document.querySelector('[data-sonner-toast] [data-close-button]');
    expect(el).not.toBeNull();
    return el as HTMLElement;
  });
  fireEvent.pointerDown(close);
  fireEvent.mouseDown(close);
  fireEvent.pointerUp(close);
  fireEvent.click(close);
  expect(changes).not.toContain(false);
  // Control: a press on the page outside both does dismiss it.
  fireEvent.pointerDown(document.body);
  fireEvent.click(document.body);
  await waitFor(() => expect(changes).toContain(false));
});
