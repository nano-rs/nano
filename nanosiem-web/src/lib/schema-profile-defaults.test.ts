// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4903 / NAN-5271 L repo contract: new installs default to OCSF, and since
 * 862fc74a6 (#9258) an ABSENT NANO_SCHEMA_PROFILE also resolves to `ocsf` in
 * the compose fallbacks. Existing UDM installs are protected by pinning `udm`
 * into a key-less .env instead (install.sh here; `nano upgrade` and the
 * migrator's unset-profile guard elsewhere), never by a `udm` fallback.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const repo = (p: string) => readFileSync(fileURLToPath(new URL(`../../../${p}`, import.meta.url)), 'utf8');

describe('schema profile defaults', () => {
  it.each(['docker-compose.opensource.yml', 'docker-compose.siem-only.yml'])(
    '%s falls back to ocsf for a key-less .env (#9258)',
    (file) => {
      const text = repo(file);
      const fallbacks = [...text.matchAll(/\$\{NANO_SCHEMA_PROFILE:-(\w+)\}/g)].map((m) => m[1]);
      expect(fallbacks.length).toBeGreaterThan(0);
      expect(new Set(fallbacks)).toEqual(new Set(['ocsf']));
    },
  );

  it.each(['.env.opensource.example', 'dev/local-stack/local.env.example'])('%s writes ocsf for new installs', (file) => {
    expect(repo(file)).toMatch(/^NANO_SCHEMA_PROFILE=ocsf$/m);
  });

  it('install.sh defaults new installs to ocsf and pins key-less .env files to udm', () => {
    const sh = repo('install.sh');
    expect(sh).toMatch(/prompt_tty[\s\S]{0,200}"ocsf"\)/);
    // b1b2855f0 (#9204) moved the pin from `echo >> .env` to nano_env_set_keys.
    expect(sh).toMatch(/nano_env_set_keys \.env "NANO_SCHEMA_PROFILE=udm"/);
  });
});
