// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it, vi } from 'vitest';
import { IocListsApi } from './ioc-lists';

describe('IOC streaming upload client', () => {
  it('sends the File directly and keeps Unicode metadata out of the URL', async () => {
    const request = vi.fn().mockResolvedValue({ id: 'list' });
    const api = new IocListsApi(request);
    const file = new File(['a.example'], 'campaign.csv');
    const read = vi.fn();
    Object.defineProperty(file, 'text', { value: read });
    await api.create({ name: 'campaign', format: 'csv', default_note: '案件 🔎' }, file);
    const [path, options] = request.mock.calls[0];
    expect(path).toBe('/api/ioc-lists/upload?format=csv');
    expect(options.body).toBe(file);
    expect(read).not.toHaveBeenCalled();
    const metadata = options.headers['x-ioc-list-options'];
    expect([...metadata].every((character: string) => character.charCodeAt(0) < 128)).toBe(true);
    expect(JSON.parse(metadata)).toEqual({ name: 'campaign', default_note: '案件 🔎' });
  });

  it('streams pasted content while preserving the format and append mode', async () => {
    const request = vi.fn().mockResolvedValue({ id: 'list' });
    const api = new IocListsApi(request);
    await api.update('list', { content: 'a.example', format: 'text', mode: 'append' });
    const [path, options] = request.mock.calls[0];
    expect(path).toBe('/api/ioc-lists/list/upload?format=text');
    expect(await options.body.text()).toBe('a.example');
    expect(JSON.parse(options.headers['x-ioc-list-options'])).toEqual({ mode: 'append' });
  });
});
