// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// NAN-3220: raw event text is selectable/copyable; the row expands only via the
// chevron button or a plain click on the timestamp/gutter.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { SearchResults } from './SearchResults';

vi.mock('@/lib/api', () => ({
  api: { getSchemaFields: async () => ({ schema: 'udm', fields: [] }) },
}));
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => false }));
// jsdom has no layout, so the real virtualizer renders nothing; render every row.
vi.mock('@tanstack/react-virtual', () => ({
  useVirtualizer: ({ count }: { count: number }) => ({
    getVirtualItems: () => Array.from({ length: count }, (_, index) => ({ index, key: index, start: index * 120 })),
    getTotalSize: () => count * 120,
    measureElement: () => {},
    range: { startIndex: 0, endIndex: Math.max(0, count - 1) },
  }),
}));
vi.mock('./EventInspectorPanel', () => ({
  EventInspectorPanel: ({ event }: { event: { id: string } }) => <div data-testid="inspector">{event.id}</div>,
}));

const RAW_WORD = 'needle';
const results = [
  {
    id: 'evt-1',
    timestamp: new Date('2026-10-07T12:00:00Z'),
    source: 'test',
    fullEvent: true,
    fields: { message: `login ${RAW_WORD} from host`, src_ip: '10.0.0.1', user: 'jsmith' },
  },
];

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(['schema-fields'], { schema: 'udm', fields: [] });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <SearchResults
          results={results}
          totalCount={1}
          isSearching={false}
          hasSearched
          isAggregateQuery={false}
          displayType="events"
          onAddToQuery={vi.fn()}
          onLoadMore={vi.fn()}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

// hidden: an open modal menu aria-hides the rest of the page.
const chevron = () => screen.getByRole('button', { name: /expand event|collapse event|open event in inspector/i, hidden: true });
const isExpanded = () => chevron().getAttribute('aria-expanded') === 'true';
const rawText = () => screen.getByText((_, el) => el?.hasAttribute('data-row-text') === true && (el.textContent ?? '').includes(RAW_WORD));
const timestamp = () => chevron().nextElementSibling as HTMLElement;

/** A mouse drag from (10,10) to (90,10) ending on `el`, as the browser reports it. */
function drag(el: HTMLElement) {
  fireEvent.mouseDown(el, { clientX: 10, clientY: 10, detail: 1 });
  fireEvent.mouseUp(el, { clientX: 90, clientY: 10, detail: 1 });
  fireEvent.click(el, { clientX: 90, clientY: 10, detail: 1 });
}

/** A double-click on `el`: two clicks (detail 1, 2) then dblclick. */
function doubleClick(el: HTMLElement) {
  for (const detail of [1, 2]) {
    fireEvent.mouseDown(el, { clientX: 20, clientY: 20, detail });
    fireEvent.mouseUp(el, { clientX: 20, clientY: 20, detail });
    fireEvent.click(el, { clientX: 20, clientY: 20, detail });
  }
  fireEvent.dblClick(el, { clientX: 20, clientY: 20, detail: 2 });
}

function plainClick(el: HTMLElement) {
  fireEvent.mouseDown(el, { clientX: 30, clientY: 30, detail: 1 });
  fireEvent.mouseUp(el, { clientX: 30, clientY: 30, detail: 1 });
  fireEvent.click(el, { clientX: 30, clientY: 30, detail: 1 });
}

afterEach(() => {
  cleanup();
  window.getSelection()?.removeAllRanges();
});

describe.each([
  ['inline', () => isExpanded(), () => screen.queryByText('src_ip', { selector: 'span[title]' }) !== null],
  ['panel', () => isExpanded(), () => screen.queryByTestId('inspector') !== null],
] as const)('%s mode', (mode, chevronOpen, contentOpen) => {
  beforeEach(() => {
    localStorage.clear();
    localStorage.setItem('nanosiem-detail-view-mode', mode);
  });

  it('drag-selecting raw text does not toggle the row', () => {
    mount();
    drag(rawText());
    expect(chevronOpen()).toBe(false);
    expect(contentOpen()).toBe(false);
  });

  it('a drag that ends on the timestamp does not toggle the row', () => {
    mount();
    drag(timestamp());
    expect(chevronOpen()).toBe(false);
    expect(contentOpen()).toBe(false);
  });

  it('a click on the gutter while text is selected does not toggle the row', () => {
    mount();
    const range = document.createRange();
    range.selectNodeContents(timestamp());
    window.getSelection()?.addRange(range);
    plainClick(timestamp());
    expect(chevronOpen()).toBe(false);
  });

  it('double-clicking a word in the raw text does not toggle the row', () => {
    mount();
    doubleClick(rawText());
    expect(chevronOpen()).toBe(false);
    expect(contentOpen()).toBe(false);
  });

  it('a plain click on the raw text body does not toggle the row', () => {
    mount();
    plainClick(rawText());
    expect(chevronOpen()).toBe(false);
  });

  it('the chevron click toggles the row', async () => {
    mount();
    fireEvent.click(chevron(), { detail: 1 });
    expect(chevronOpen()).toBe(true);
    await waitFor(() => expect(contentOpen()).toBe(true));
    if (mode === 'inline') {
      expect(chevron().getAttribute('aria-label')).toBe('Collapse event');
      fireEvent.click(chevron(), { detail: 1 });
      expect(chevronOpen()).toBe(false);
      expect(contentOpen()).toBe(false);
    }
  });

  it.each(['Enter', ' '])('pressing %j on the chevron toggles the row exactly once', async key => {
    mount();
    const button = chevron();
    button.focus();
    fireEvent.keyDown(button, { key });
    // The browser's synthesized click for the same key press (detail 0) must not undo it.
    fireEvent.click(button, { detail: 0 });
    fireEvent.keyUp(button, { key });
    expect(chevronOpen()).toBe(true);
    await waitFor(() => expect(contentOpen()).toBe(true));
  });

  it('a later keyboard-style click (detail 0) still toggles after a key press', async () => {
    mount();
    const button = chevron();
    fireEvent.keyDown(button, { key: 'Enter' });
    fireEvent.keyUp(button, { key: 'Enter' });
    // Browser suppressed the click for the prevented keydown; the flag must clear.
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(chevronOpen()).toBe(true);
    if (mode === 'inline') {
      fireEvent.click(chevron(), { detail: 0 });
      expect(chevronOpen()).toBe(false);
    }
  });

  it('a plain click on the timestamp toggles the row', async () => {
    mount();
    plainClick(timestamp());
    expect(chevronOpen()).toBe(true);
    await waitFor(() => expect(contentOpen()).toBe(true));
  });
});

describe('long message expander and value menus', () => {
  beforeEach(() => {
    localStorage.clear();
    localStorage.setItem('nanosiem-detail-view-mode', 'inline');
  });

  it('the "…" expander expands and collapses again without toggling the row', () => {
    const long = { ...results[0], fields: { message: `${RAW_WORD} ${'x'.repeat(600)}` } };
    const client = new QueryClient();
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <SearchResults results={[long]} totalCount={1} isSearching={false} hasSearched isAggregateQuery={false}
            displayType="events" onAddToQuery={vi.fn()} onLoadMore={vi.fn()} />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Expand message' }), { detail: 1 });
    expect(screen.getByRole('button', { name: 'Collapse message' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Collapse message' }), { detail: 1 });
    expect(screen.getByRole('button', { name: 'Expand message' })).toBeTruthy();
    expect(isExpanded()).toBe(false);
  });

  it('a key-chip value opens its filter menu on click, but not at the end of a drag', async () => {
    mount();
    const chipValue = within(document.body).getByText('10.0.0.1', { selector: '[aria-haspopup="menu"]' });
    drag(chipValue);
    expect(screen.queryByText('Add to filter')).toBeNull();
    expect(isExpanded()).toBe(false);
    plainClick(chipValue);
    await waitFor(() => expect(screen.getByText('Add to filter')).toBeTruthy());
    expect(isExpanded()).toBe(false);
  });
});
