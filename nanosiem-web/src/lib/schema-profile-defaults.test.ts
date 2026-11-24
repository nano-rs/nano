// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4903 / NAN-5271 L repo contract: new installs default to OCSF, and since
 * 862fc74a6 (#9258) an ABSENT NANO_SCHEMA_PROFILE also resolves to `ocsf` in
 * the compose fallbacks. Existing UDM installs are protected by pinning `udm`
 * into a key-less .env instead (install.sh here; `nano upgrade` and the
 * migrator's unset-profile guard elsewhere), never by a `udm` fallback.
 */
import { spawnSync } from 'node:child_process';
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

  // NAN-5809: the schema question is asked by the answer step (interactive
  // review flow) or, without it, by prompt_tty; --non-interactive never asks.
  // Run the real install.sh code in bash with only the terminal I/O stubbed,
  // and check what a new install ends up with when nobody picks a profile.
  describe('install.sh defaults new installs to ocsf', () => {
    const sh = repo('install.sh');
    const cut = (re: RegExp, what: string) => {
      const m = sh.match(re);
      if (!m) throw new Error(`install.sh no longer has ${what} (update this test)`);
      return m[0];
    };
    const hasTty = cut(/^have_controlling_tty\(\) \{\n[\s\S]*?\n\}\n/m, 'have_controlling_tty()');
    const resolve = cut(
      /^ {4}BUNDLE_TENZIR=0\n {4}SCHEMA_PROFILE="\$\{NANO_SCHEMA_PROFILE:-\$\{ANS_SCHEMA:-\}\}"\n[\s\S]*?\n {4}fi\n/m,
      "the first-install schema resolution block",
    );
    const step = cut(/^ {8}schema\)\n[\s\S]*?\n {12}done ;;\n/m, 'the schema answer step');
    // Enter at a prompt takes its [default]: the stubs answer with it.
    const stubs = [
      'warn() { :; }',
      'fail() { echo "FAIL $*" >&2; exit 1; }',
      'answer_read() { echo "asked-step default=$2" >&2; ANSWER_REPLY=$2; }',
      'prompt_tty() { echo "asked-prompt default=$2" >&2; printf %s "$2"; }',
    ].join('\n');
    const run = (body: string, env: Record<string, string>) => {
      const script = `set -euo pipefail\n${stubs}\n${hasTty}\n${body}\nprintf '%s %s\\n' "$SCHEMA_PROFILE" "$BUNDLE_TENZIR"`;
      const r = spawnSync('bash', ['-c', script], {
        env: { PATH: process.env.PATH ?? '/usr/bin:/bin', MULTI_NODE: '0', ...env },
        encoding: 'utf8',
      });
      expect(r.status, r.stderr).toBe(0);
      return { out: r.stdout.trim(), err: r.stderr };
    };

    it('--non-interactive (NANO_NONINTERACTIVE=1): ocsf without asking', () => {
      const { out, err } = run(resolve, { NANO_NONINTERACTIVE: '1' });
      expect(out).toBe('ocsf 0');
      expect(err).not.toContain('asked');
    });

    it('interactive answer step: Enter at the schema question gives ocsf', () => {
      const body = `ask() { case "$1" in\n${step}    esac; }\nask schema\nhave_controlling_tty() { return 0; }\n${resolve}`;
      const { out, err } = run(body, { NANO_NONINTERACTIVE: '0' });
      expect(err).toContain('asked-step default=ocsf');
      expect(err).not.toContain('asked-prompt');
      expect(out).toBe('ocsf 0');
    });

    it('interactive prompt_tty fallback: Enter gives ocsf', () => {
      const body = `have_controlling_tty() { return 0; }\n${resolve}`;
      const { out, err } = run(body, { NANO_NONINTERACTIVE: '0' });
      expect(err).toContain('asked-prompt default=ocsf');
      expect(out).toBe('ocsf 0');
    });

    it.each([
      ['udm', 'udm 0'],
      ['ocsf+tenzir', 'ocsf 1'],
    ])('an explicit NANO_SCHEMA_PROFILE=%s wins in either mode, without asking', (profile, want) => {
      const nonInteractive = run(resolve, { NANO_NONINTERACTIVE: '1', NANO_SCHEMA_PROFILE: profile });
      expect(nonInteractive.out).toBe(want);
      expect(nonInteractive.err).not.toContain('asked');
      const interactive = run(`have_controlling_tty() { return 0; }\n${resolve}`, {
        NANO_NONINTERACTIVE: '0',
        NANO_SCHEMA_PROFILE: profile,
      });
      expect(interactive.out).toBe(want);
      expect(interactive.err).not.toContain('asked');
    });
  });

  it('install.sh pins key-less .env files to udm', () => {
    // b1b2855f0 (#9204) moved the pin from `echo >> .env` to nano_env_set_keys.
    expect(repo('install.sh')).toMatch(/nano_env_set_keys \.env "NANO_SCHEMA_PROFILE=udm"/);
  });
});
