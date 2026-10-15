// SPDX-License-Identifier: AGPL-3.0-or-later

// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { LookupTableCreate } from './LookupTableCreate';

const mocks = vi.hoisted(() => ({
  create: vi.fn(),
  preview: vi.fn(),
  toast: vi.fn(),
  tables: [] as Array<{ name: string; row_count: number }>,
}));
vi.mock('@/hooks/use-api', () => ({
  useCreateLookupTable: () => ({ mutate: mocks.create }),
  usePreviewUpload: () => ({ mutate: mocks.preview }),
  useLookupTables: () => ({ data: mocks.tables }),
  useCreateLookupTableFromSchema: () => ({ mutate: vi.fn() }),
  useAddLookupRows: () => ({ mutate: vi.fn() }),
  useUpsertLookupIngestion: () => ({ mutate: vi.fn() }),
  useTriggerLookupIngestion: () => ({ mutate: vi.fn() }),
}));
vi.mock('@/hooks/use-toast', () => ({ useToast: () => ({ toast: mocks.toast }) }));

afterEach(() => { cleanup(); vi.clearAllMocks(); mocks.tables = []; });

it('pre-fills the existing name before the lookup fetch and sends replace on upload', async () => {
  mocks.preview.mockResolvedValue({ columns: [], rows: [], total_rows_estimate: 1 });
  mocks.create.mockResolvedValue({ table: { name: 'original' }, records_inserted: 1, renamed_columns: [] });
  render(<MemoryRouter initialEntries={['/rules/lookup-tables/new?update=original']}><LookupTableCreate onSaved={vi.fn()} /></MemoryRouter>);
  expect(screen.getByText('Replace data in original')).toBeTruthy();

  const file = new File(['id\n2\n'], 'replacement.csv', { type: 'text/csv' });
  fireEvent.change(document.querySelector('input[type="file"]')!, { target: { files: [file] } });
  await waitFor(() => expect(screen.getByDisplayValue('original')).toBeTruthy());
  fireEvent.click(screen.getByRole('button', { name: 'replace data' }));
  await waitFor(() => expect(mocks.create).toHaveBeenCalledOnce());
  expect(mocks.create.mock.calls[0][0].config).toMatchObject({ name: 'original', mode: 'replace' });
  expect(mocks.create.mock.calls[0][0].config.description).toBeUndefined();
});

it('sends replace from the name-collision dialog in the same click', async () => {
  mocks.tables = [{ name: 'original', row_count: 2 }];
  mocks.preview.mockResolvedValue({ columns: [], rows: [], total_rows_estimate: 1 });
  mocks.create.mockResolvedValue({ table: { name: 'original' }, records_inserted: 1, renamed_columns: [] });
  render(<MemoryRouter><LookupTableCreate onSaved={vi.fn()} /></MemoryRouter>);
  fireEvent.click(screen.getByText('Upload a file'));
  fireEvent.change(document.querySelector('input[type="file"]')!, {
    target: { files: [new File(['id\n2\n'], 'original.csv', { type: 'text/csv' })] },
  });
  await waitFor(() => expect(screen.getByDisplayValue('original')).toBeTruthy());
  fireEvent.click(screen.getByRole('button', { name: 'save table' }));
  await waitFor(() => expect(screen.getByText('Append into existing table?')).toBeTruthy());
  fireEvent.click(screen.getAllByRole('button', { name: 'Replace existing data' }).at(-1)!);
  await waitFor(() => expect(mocks.create).toHaveBeenCalledOnce());
  expect(mocks.create.mock.calls[0][0].config.mode).toBe('replace');
});
