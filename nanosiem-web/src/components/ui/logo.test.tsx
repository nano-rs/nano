// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFileSync } from 'node:fs';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { Logo } from './logo';

describe('Logo', () => {
  for (const size of ['small', 'normal'] as const) {
    it(`preserves ${size} geometry and uses theme colours`, () => {
      const markup = renderToStaticMarkup(<Logo size={size} />);
      const paths = [...markup.matchAll(/<path\b[^>]*>/g)].map(([path]) => path);
      const dot = paths.at(-1)!;

      expect(dot).toContain('d="M22.11,99.48');
      expect(dot).toContain('fill="var(--primary)"');
      expect(markup).not.toMatch(/#[0-9a-f]{3,8}\b/i);
      expect(markup).toContain('fill="currentColor"');
      expect(markup).toContain('fill-rule="evenodd"');
      expect(paths.filter((path) => path.includes('fill='))).toEqual([dot]);

      for (const appearance of ['light', 'dark']) {
        const filename = `logo_${size === 'small' ? 'small_' : ''}${appearance}_theme.svg`;
        const source = readFileSync(`public/${filename}`, 'utf8');
        expect(markup.match(/viewBox="[^"]+"/)?.[0]).toBe(source.match(/viewBox="[^"]+"/)?.[0]);
        expect([...markup.matchAll(/\bd="([^"]+)"/g)].map((match) => match[1]))
          .toEqual([...source.matchAll(/\bd="([^"]+)"/g)].map((match) => match[1]));
      }
    });
  }

  it('preserves accessible labels and sizing props', () => {
    const markup = renderToStaticMarkup(<Logo alt="Custom logo" className="h-6 w-auto" />);
    const titleId = markup.match(/<title id="([^"]+)"/)?.[1];
    expect(markup).toContain('role="img"');
    expect(markup).toContain(`aria-labelledby="${titleId}"`);
    expect(markup).toContain('>Custom logo</title>');
    expect(markup).toContain('class="h-6 w-auto object-contain"');
    expect(renderToStaticMarkup(<Logo />)).toContain('>nano</title>');
    expect(renderToStaticMarkup(<Logo alt="" />)).toContain('aria-hidden="true"');
  });
});
