// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
import { afterEach, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { Dialog, DialogContent, DialogTitle } from './dialog';
import { AlertDialog, AlertDialogContent, AlertDialogTitle } from './alert-dialog';

afterEach(cleanup);

it('renders the built-in close by default', () => {
  render(
    <Dialog open>
      <DialogContent aria-describedby={undefined}>
        <DialogTitle>t</DialogTitle>
      </DialogContent>
    </Dialog>,
  );
  expect(screen.getAllByRole('button', { name: 'Close' })).toHaveLength(1);
});

it('hideClose leaves only the caller header close (NAN-5782)', () => {
  render(
    <Dialog open>
      <DialogContent hideClose aria-describedby={undefined}>
        <DialogTitle>t</DialogTitle>
        <button type="button" aria-label="Close">x</button>
      </DialogContent>
    </Dialog>,
  );
  expect(screen.getAllByRole('button', { name: 'Close' })).toHaveLength(1);
});

// NAN-5779: the grid's implicit `auto` column sizes to the widest child's
// min-content, so a non-wrapping row pushed every section past the box.
it('both dialog shells pin their single grid column to the box width', () => {
  render(
    <>
      <Dialog open>
        <DialogContent data-testid="dlg" aria-describedby={undefined}>
          <DialogTitle>t</DialogTitle>
        </DialogContent>
      </Dialog>
      <AlertDialog open>
        <AlertDialogContent data-testid="alert" aria-describedby={undefined}>
          <AlertDialogTitle>t</AlertDialogTitle>
        </AlertDialogContent>
      </AlertDialog>
    </>,
  );
  expect(screen.getByTestId('dlg').className).toContain('grid-cols-[minmax(0,1fr)]');
  expect(screen.getByTestId('alert').className).toContain('grid-cols-[minmax(0,1fr)]');
});
