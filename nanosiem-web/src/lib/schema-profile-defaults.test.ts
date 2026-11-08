// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4903 repo contract: new installs default to OCSF, but every fallback for
 * an ABSENT NANO_SCHEMA_PROFILE stays `udm` — an .env without the key predates
 * the profile choice and holds UDM data, so flipping a fallback would silently
 * repoint an existing deployment at an empty table.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const repo = (p: string) => readFileSync(fileURLToPath(new URL(`../../../${p}`, import.meta.url)), 'utf8');

describe('schema profile defaults', () => {
  it.each(['docker-compose.opensource.yml', 'docker-compose.siem-only.yml'])(
    '%s falls back to udm for a key-less .env, never ocsf',
    (file) => {
      const text = repo(file);
      const fallbacks = [...text.matchAll(/\$\{NANO_SCHEMA_PROFILE:-(\w+)\}/g)].map((m) => m[1]);
      expect(fallbacks.length).toBeGreaterThan(0);
      expect(new Set(fallbacks)).toEqual(new Set(['udm']));
    },
  );

  it.each(['.env.opensource.example', 'dev/local-stack/local.env.example'])('%s writes ocsf for new installs', (file) => {
    expect(repo(file)).toMatch(/^NANO_SCHEMA_PROFILE=ocsf$/m);
  });

  it('install.sh defaults new installs to ocsf and pins key-less .env files to udm', () => {
    const sh = repo('install.sh');
    expect(sh).toMatch(/prompt_tty[\s\S]{0,200}"ocsf"\)/);
    expect(sh).toContain('echo "NANO_SCHEMA_PROFILE=udm" >> .env');
  });
});
