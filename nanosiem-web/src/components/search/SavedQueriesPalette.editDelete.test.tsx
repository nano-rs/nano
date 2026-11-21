// @vitest-environment jsdom
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// NAN-5695: a saved query can be edited (name, query, description) and
// deleted, with confirmation, from the saved-queries palette — only the
// analyst's own queries, since both are owner-only on the server.
import React from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SavedQueriesPalette } from './SavedQueriesPalette';
import type { SavedSearch } from '@/lib/api';

const mine: SavedSearch = {
  id: 'ss_mine',
  name: 'failed logins',
  query: 'activity_name="Logon" status="Failure"',
  description: 'Brute-force triage',
  query_mode: 'piped',
  created_at: '2026-11-12T00:00:00.000Z',
  updated_at: '2026-11-12T00:00:00.000Z',
  user_id: 'u_me',
  visibility: 'private',
};
const theirs: SavedSearch = {
  ...mine,
  id: 'ss_theirs',
  name: 'team dns hunt',
  description: null,
  user_id: 'u_other',
  visibility: 'public',
};

afterEach(cleanup);

function renderPalette(props: Partial<React.ComponentProps<typeof SavedQueriesPalette>> = {}) {
  const onUpdateQuery = vi.fn(async () => ({}));
  const onDeleteQuery = vi.fn(async () => undefined);
  const onSelectQuery = vi.fn();
  render(
    <SavedQueriesPalette
      open
      onOpenChange={() => {}}
      savedSearches={[mine]}
      sharedSearches={[theirs]}
      currentUserId="u_me"
      onSelectQuery={onSelectQuery}
      onUpdateQuery={onUpdateQuery}
      onDeleteQuery={onDeleteQuery}
      {...props}
    />,
  );
  return { onUpdateQuery, onDeleteQuery, onSelectQuery };
}

function row(name: string): HTMLElement {
  return screen.getByText(name).closest('.group') as HTMLElement;
}

describe('SavedQueriesPalette edit and delete (NAN-5695)', () => {
  it('offers Edit and Delete on the analyst\'s own query only', () => {
    renderPalette();
    expect(within(row('failed logins')).getByRole('button', { name: 'Edit query' })).toBeTruthy();
    expect(within(row('failed logins')).getByRole('button', { name: 'Delete query' })).toBeTruthy();
    expect(within(row('team dns hunt')).queryByRole('button', { name: 'Edit query' })).toBeNull();
    expect(within(row('team dns hunt')).queryByRole('button', { name: 'Delete query' })).toBeNull();
  });

  it('offers neither without handlers', () => {
    renderPalette({ onUpdateQuery: undefined, onDeleteQuery: undefined });
    expect(screen.queryByRole('button', { name: 'Edit query' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Delete query' })).toBeNull();
  });

  it('shows the description on the row and matches it in the filter', () => {
    renderPalette();
    expect(screen.getByText('Brute-force triage')).toBeTruthy();
    fireEvent.change(screen.getByPlaceholderText(/Search saved queries/), { target: { value: 'brute' } });
    expect(screen.getByText('failed logins')).toBeTruthy();
    expect(screen.queryByText('team dns hunt')).toBeNull();
  });

  it('edits name, query and description and saves trimmed values', async () => {
    const { onUpdateQuery, onSelectQuery } = renderPalette();
    fireEvent.click(within(row('failed logins')).getByRole('button', { name: 'Edit query' }));
    expect(onSelectQuery).not.toHaveBeenCalled();

    const form = screen.getByTestId('saved-query-edit-form');
    fireEvent.change(within(form).getByLabelText('Name'), { target: { value: ' root logins ' } });
    fireEvent.change(within(form).getByLabelText('Query'), { target: { value: 'actor.user.name="root"' } });
    fireEvent.change(within(form).getByLabelText(/Description/), { target: { value: '' } });
    await act(async () => { fireEvent.click(within(form).getByRole('button', { name: 'Save' })); });

    expect(onUpdateQuery).toHaveBeenCalledWith('ss_mine', {
      name: 'root logins',
      query: 'actor.user.name="root"',
      description: '',
    });
    await waitFor(() => expect(screen.queryByTestId('saved-query-edit-form')).toBeNull());
  });

  it('keeps the editor open and shows the error when the save fails', async () => {
    const onUpdateQuery = vi.fn(async () => { throw new Error('Only the owner can update this saved search'); });
    renderPalette({ onUpdateQuery });
    fireEvent.click(within(row('failed logins')).getByRole('button', { name: 'Edit query' }));
    await act(async () => {
      fireEvent.click(within(screen.getByTestId('saved-query-edit-form')).getByRole('button', { name: 'Save' }));
    });
    expect(screen.getByRole('alert').textContent).toContain('Only the owner');
    expect(screen.getByTestId('saved-query-edit-form')).toBeTruthy();
  });

  it('does not save an empty name', () => {
    const { onUpdateQuery } = renderPalette();
    fireEvent.click(within(row('failed logins')).getByRole('button', { name: 'Edit query' }));
    const form = screen.getByTestId('saved-query-edit-form');
    fireEvent.change(within(form).getByLabelText('Name'), { target: { value: '   ' } });
    expect((within(form).getByRole('button', { name: 'Save' }) as HTMLButtonElement).disabled).toBe(true);
    expect(onUpdateQuery).not.toHaveBeenCalled();
  });

  it('Cancel leaves the query unchanged', () => {
    const { onUpdateQuery } = renderPalette();
    fireEvent.click(within(row('failed logins')).getByRole('button', { name: 'Edit query' }));
    fireEvent.click(within(screen.getByTestId('saved-query-edit-form')).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByTestId('saved-query-edit-form')).toBeNull();
    expect(onUpdateQuery).not.toHaveBeenCalled();
  });

  it('deletes only after confirmation', async () => {
    const { onDeleteQuery, onSelectQuery } = renderPalette();
    fireEvent.click(within(row('failed logins')).getByRole('button', { name: 'Delete query' }));
    expect(onSelectQuery).not.toHaveBeenCalled();
    expect(onDeleteQuery).not.toHaveBeenCalled();

    const dialog = await screen.findByRole('alertdialog');
    expect(dialog.textContent).toContain('failed logins');
    await act(async () => { fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' })); });
    expect(onDeleteQuery).toHaveBeenCalledWith('ss_mine');
  });

  it('cancelling the confirmation deletes nothing', async () => {
    const { onDeleteQuery } = renderPalette();
    fireEvent.click(within(row('failed logins')).getByRole('button', { name: 'Delete query' }));
    const dialog = await screen.findByRole('alertdialog');
    await act(async () => { fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' })); });
    expect(onDeleteQuery).not.toHaveBeenCalled();
  });

  it('reports a failed delete in the palette', async () => {
    const onDeleteQuery = vi.fn(async () => { throw new Error('Saved search not found'); });
    renderPalette({ onDeleteQuery });
    fireEvent.click(within(row('failed logins')).getByRole('button', { name: 'Delete query' }));
    const dialog = await screen.findByRole('alertdialog');
    await act(async () => { fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' })); });
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('Saved search not found'));
  });

  // Review finding on #10108: clicks inside the confirmation's portal bubbled
  // (React tree) to the backdrop and closed the whole palette, hiding a
  // failed delete's error. The harness keeps `open` in real state.
  function StatefulPalette({ onOpenChange, onDeleteQuery }: {
    onOpenChange: (open: boolean) => void;
    onDeleteQuery: (id: string) => Promise<unknown>;
  }) {
    const [open, setOpen] = React.useState(true);
    return (
      <SavedQueriesPalette
        open={open}
        onOpenChange={(o) => { onOpenChange(o); setOpen(o); }}
        savedSearches={[mine]}
        currentUserId="u_me"
        onSelectQuery={() => {}}
        onDeleteQuery={onDeleteQuery}
      />
    );
  }

  it('cancelling the confirmation keeps the palette open', async () => {
    const onOpenChange = vi.fn();
    render(<StatefulPalette onOpenChange={onOpenChange} onDeleteQuery={vi.fn(async () => undefined)} />);
    fireEvent.click(within(row('failed logins')).getByRole('button', { name: 'Delete query' }));
    const dialog = await screen.findByRole('alertdialog');
    fireEvent.click(dialog);
    await act(async () => { fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' })); });
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
    expect(screen.getByText('failed logins')).toBeTruthy();
  });

  it('a failed delete keeps the palette open and shows the error', async () => {
    const onOpenChange = vi.fn();
    render(
      <StatefulPalette
        onOpenChange={onOpenChange}
        onDeleteQuery={vi.fn(async () => { throw new Error('Saved search not found'); })}
      />,
    );
    fireEvent.click(within(row('failed logins')).getByRole('button', { name: 'Delete query' }));
    const dialog = await screen.findByRole('alertdialog');
    await act(async () => { fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' })); });
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('Saved search not found'));
  });

  it('a click on the backdrop still closes the palette', () => {
    const onOpenChange = vi.fn();
    render(<StatefulPalette onOpenChange={onOpenChange} onDeleteQuery={vi.fn(async () => undefined)} />);
    const backdrop = screen.getByPlaceholderText(/Search saved queries/).closest('.fixed') as HTMLElement;
    fireEvent.click(backdrop);
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });
});
