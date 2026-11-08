// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, it, vi } from 'vitest';

import { runSearchSubmit, SEARCH_SUBMIT_KEY } from './SearchQueryEditor';

describe('search submit shortcut', () => {
  it('binds the advertised Cmd/Ctrl+Enter shortcut to search submission', () => {
    const submit = vi.fn();

    expect(SEARCH_SUBMIT_KEY).toBe('Mod-Enter');
    expect(runSearchSubmit(submit)).toBe(true);
    expect(submit).toHaveBeenCalledOnce();
  });
});
