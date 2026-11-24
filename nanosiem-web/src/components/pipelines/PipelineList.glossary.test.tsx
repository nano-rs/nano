// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom

// NAN-5867 review: a glossary Term inside a clickable, focusable row shows its
// definition but never opens the row, and the row stays the one tab stop.

import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

import { PipelineList } from './PipelineList';
import type { PipelineSummary } from '@/lib/pipeline-types';

afterEach(cleanup);

const pipeline: PipelineSummary = {
  id: 'ls_1', name: 'fw-edge', description: '', sourceId: 'ls_1', sourceName: 'fw-edge', sourceType: 'paloalto',
  activeRevision: 1, draftRevision: 1, hasDraft: false, stepPlan: false, stepCount: 0, enabled: true, deployed: true,
  updatedAt: '2026-11-22T00:00:00Z',
};

describe('PipelineList glossary Term in a row', () => {
  it('a click or Enter on the VRL term does not open the pipeline', () => {
    const onOpen = vi.fn();
    render(
      <MemoryRouter>
        <PipelineList pipelines={[pipeline]} loading={false} canCreate onCreate={() => {}} onOpen={onOpen} onRetry={() => {}} />
      </MemoryRouter>,
    );
    const term = document.querySelector('[data-term="vrl"]') as HTMLElement;
    expect(term).toBeTruthy();
    fireEvent.click(term);
    fireEvent.keyDown(term, { key: 'Enter' });
    expect(onOpen).not.toHaveBeenCalled();
    // The row is the tab stop; the term inside it is not a second one.
    expect(term.getAttribute('tabindex')).toBeNull();
    // A click on the row itself still opens it.
    fireEvent.click(screen.getByText('fw-edge'));
    expect(onOpen).toHaveBeenCalledWith('ls_1');
  });
});
