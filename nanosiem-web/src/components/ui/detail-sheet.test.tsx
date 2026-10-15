// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { useState } from 'react';
import { DetailSheet, FormSheet, type DetailSheetSize } from './detail-sheet';

beforeAll(() => {
  // jsdom lacks matchMedia (useIsMobile) — desktop by default.
  if (!window.matchMedia) {
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: (query: string) => ({
        matches: false,
        media: query,
        onchange: null,
        addEventListener: () => {},
        removeEventListener: () => {},
        addListener: () => {},
        removeListener: () => {},
        dispatchEvent: () => false,
      }),
    });
  }
});

afterEach(cleanup);

function sheetEl() {
  return document.querySelector('[data-detail-sheet]') as HTMLElement;
}

describe('DetailSheet', () => {
  it.each([
    ['sm', 'w-[420px]'],
    ['md', 'w-[560px]'],
    ['lg', 'w-[760px]'],
    ['xl', 'w-[960px]'],
  ] as [DetailSheetSize, string][])('size %s renders %s clamped to the viewport', (size, cls) => {
    render(
      <DetailSheet open onOpenChange={() => {}} size={size} title="t">
        body
      </DetailSheet>,
    );
    const el = sheetEl();
    expect(el.getAttribute('data-size')).toBe(size);
    expect(el.className).toContain(cls);
    expect(el.className).toContain('max-w-[calc(100vw-24px)]');
  });

  it('renders breadcrumb, title, meta, description, actions and footer slots', () => {
    render(
      <DetailSheet
        open
        onOpenChange={() => {}}
        breadcrumb={['Risk', 'host']}
        title="ws-eng-012"
        description="Risk object detail"
        meta={<span>score 840</span>}
        actions={<button type="button">Investigate</button>}
        footer={<button type="button">Done</button>}
      >
        <p>body</p>
      </DetailSheet>,
    );
    const dialog = screen.getByRole('dialog', { name: 'ws-eng-012' });
    const crumbs = within(dialog).getByRole('navigation', { name: 'Breadcrumb' });
    expect(crumbs.textContent).toBe('Risk/host');
    expect(crumbs.className).toContain('font-mono');
    const meta = dialog.querySelector('[data-slot="meta"]') as HTMLElement;
    expect(meta.textContent).toBe('score 840');
    expect(meta.className).toContain('font-mono');
    expect(within(dialog).getByText('Risk object detail')).toBeTruthy();
    expect(within(dialog).getByRole('button', { name: 'Investigate' })).toBeTruthy();
    expect(within(dialog).getByRole('button', { name: 'Done' }).closest('footer')).toBeTruthy();
    // Exactly one close control: the header X, no stock absolute X.
    expect(within(dialog).getAllByRole('button', { name: 'Close' })).toHaveLength(1);
  });

  it('closes on Esc and on the header close button', () => {
    const onOpenChange = vi.fn();
    render(
      <DetailSheet open onOpenChange={onOpenChange} title="t">
        body
      </DetailSheet>,
    );
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' });
    expect(onOpenChange).toHaveBeenLastCalledWith(false);
    onOpenChange.mockClear();
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it('guardDirty asks before discarding and keeps the sheet on "Keep editing"', () => {
    const onOpenChange = vi.fn();
    render(
      <DetailSheet open onOpenChange={onOpenChange} title="t" guardDirty>
        body
      </DetailSheet>,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(onOpenChange).not.toHaveBeenCalled();
    expect(screen.getByText('Discard unsaved changes?')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Keep editing' }));
    expect(onOpenChange).not.toHaveBeenCalled();

    fireEvent.keyDown(screen.getByRole('dialog', { name: 't' }), { key: 'Escape' });
    expect(onOpenChange).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Discard' }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it('renders as a bottom sheet when side="bottom"', () => {
    render(
      <DetailSheet open onOpenChange={() => {}} title="t" side="bottom">
        body
      </DetailSheet>,
    );
    expect(sheetEl().className).toContain('bottom-0');
    expect(sheetEl().className).not.toContain('w-[560px]');
  });
});

describe('FormSheet', () => {
  function Harness({ onSubmit, dirty = false }: { onSubmit: () => void; dirty?: boolean }) {
    const [open, setOpen] = useState(true);
    return (
      <FormSheet
        open={open}
        onOpenChange={setOpen}
        title="New queue"
        submitLabel="Create"
        guardDirty={dirty}
        onSubmit={() => {
          onSubmit();
          setOpen(false);
        }}
      >
        <input aria-label="Name" />
      </FormSheet>
    );
  }

  it('submits through the footer button and lets the caller close', () => {
    const onSubmit = vi.fn();
    render(<Harness onSubmit={onSubmit} />);
    fireEvent.click(screen.getByRole('button', { name: 'Create' }));
    expect(onSubmit).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('Cancel respects the dirty guard', () => {
    render(<Harness onSubmit={() => {}} dirty />);
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.getByText('Discard unsaved changes?')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Discard' }));
    expect(screen.queryByRole('dialog', { name: 'New queue' })).toBeNull();
  });

  it('pending disables submit', () => {
    const onSubmit = vi.fn();
    render(
      <FormSheet open onOpenChange={() => {}} title="t" pending onSubmit={onSubmit}>
        <input aria-label="Name" />
      </FormSheet>,
    );
    const submit = screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
  });
});
