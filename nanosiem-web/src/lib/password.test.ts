// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import {
  generateSecurePassword,
  PASSWORD_HINT,
  PASSWORD_MAX_BYTES,
  PASSWORD_MIN_BYTES,
  PASSWORD_SPECIAL_CHARACTERS,
  unmetPasswordRequirements,
  validatePassword,
} from './password.ts';

const RUST_POLICY = new URL('../../../nanosiem-core/src/auth/password.rs', import.meta.url);
const SETUP_PAGE = new URL('../pages/Setup.tsx', import.meta.url);

async function rustPolicySource(): Promise<string> {
  return readFile(fileURLToPath(RUST_POLICY), 'utf8');
}

/** Pull the char literals out of the `is_special_char` match arm. */
function rustSpecialCharacters(source: string): string[] {
  const start = source.indexOf('fn is_special_char');
  assert.ok(start >= 0, 'is_special_char must still exist');
  const body = source.slice(start, source.indexOf('\n}\n', start));
  const literals = body.match(/'(?:\\.|[^'\\])'/g) ?? [];
  return literals.map((literal) => {
    const inner = literal.slice(1, -1);
    return inner.startsWith('\\') ? inner.slice(1) : inner;
  });
}

test('special-character class matches is_special_char exactly', async () => {
  const rust = rustSpecialCharacters(await rustPolicySource());
  assert.ok(rust.length > 0, 'failed to parse the Rust special-character set');
  assert.deepEqual(
    [...rust].sort(),
    [...PASSWORD_SPECIAL_CHARACTERS].sort(),
    'the browser set drifted from is_special_char',
  );
});

test('length bounds stay in lockstep with the Rust policy', async () => {
  const policy = await rustPolicySource();
  assert.match(policy, new RegExp(`min_length: ${PASSWORD_MIN_BYTES},`));
  assert.match(
    policy,
    new RegExp(`MAX_PASSWORD_BYTES: usize = ${PASSWORD_MAX_BYTES};`),
    'MAX_PASSWORD_BYTES must live in auth/password.rs',
  );
  for (const requirement of [
    'require_uppercase: true',
    'require_lowercase: true',
    'require_digit: true',
    'require_special: true',
  ]) {
    assert.ok(policy.includes(requirement), `server still enforces ${requirement}`);
  }
});

test('the max-length cap is not re-declared outside auth/password.rs', async () => {
  for (const relative of [
    '../../../nanosiem-core/src/enterprise_shared_activation.rs',
    '../../../nanosiem-core/src/enterprise_shared_member_activation.rs',
  ]) {
    const source = await readFile(fileURLToPath(new URL(relative, import.meta.url)), 'utf8');
    assert.doesNotMatch(
      source,
      /const MAX_PASSWORD_BYTES/,
      `${relative} must import MAX_PASSWORD_BYTES, not redeclare it`,
    );
    assert.match(source, /MAX_PASSWORD_BYTES/, `${relative} must still enforce the cap`);
  }
});

test('every character the server accepts as special is accepted here', () => {
  for (const character of PASSWORD_SPECIAL_CHARACTERS) {
    assert.deepEqual(
      validatePassword(`Passphrase123${character}`),
      [],
      `${JSON.stringify(character)} must satisfy the special-character rule`,
    );
  }
});

test('validatePassword reports every unmet requirement', () => {
  assert.deepEqual(validatePassword('Strong-Passphrase-2361!'), []);
  assert.deepEqual(validatePassword(''), ['Enter a password.']);
  assert.deepEqual(validatePassword('Short-1a'), [
    `Password must be at least ${PASSWORD_MIN_BYTES} characters long.`,
  ]);
  assert.deepEqual(validatePassword('alllowercase-1'), [
    'Password must contain at least one uppercase letter.',
  ]);
  assert.deepEqual(validatePassword('ALLUPPERCASE-1'), [
    'Password must contain at least one lowercase letter.',
  ]);
  assert.deepEqual(validatePassword('NoDigitsHere-x'), [
    'Password must contain at least one digit.',
  ]);
  assert.deepEqual(validatePassword('NoSpecials2361x'), [
    'Password must contain at least one special character.',
  ]);
});

test('length is measured in bytes, like str::len', () => {
  // 11 em-dashes are 33 bytes but only 11 characters.
  assert.ok(
    !validatePassword('Aa1!———————').includes(
      `Password must be at least ${PASSWORD_MIN_BYTES} characters long.`,
    ),
  );
  assert.deepEqual(validatePassword(`Aa1!${'x'.repeat(PASSWORD_MAX_BYTES)}`), [
    `Password must be at most ${PASSWORD_MAX_BYTES} characters long.`,
  ]);
  assert.deepEqual(validatePassword(`Aa1!${'x'.repeat(PASSWORD_MAX_BYTES - 4)}`), []);
});

test('checklist labels are derived from the same rules as the messages', () => {
  assert.deepEqual(unmetPasswordRequirements('Strong-Passphrase-2361!'), []);
  assert.deepEqual(unmetPasswordRequirements('NoSpecials2361x'), [
    'At least one special character',
  ]);
  assert.deepEqual(unmetPasswordRequirements('x'), [
    `At least ${PASSWORD_MIN_BYTES} characters`,
    'At least one uppercase letter',
    'At least one digit',
    'At least one special character',
  ]);
  // One label per message, always.
  assert.equal(unmetPasswordRequirements('x').length, validatePassword('x').length);
});

test('the hint names the policy', () => {
  assert.match(PASSWORD_HINT, new RegExp(`${PASSWORD_MIN_BYTES} characters`));
  assert.match(PASSWORD_HINT, /uppercase/);
  assert.match(PASSWORD_HINT, /lowercase/);
  assert.match(PASSWORD_HINT, /digit/);
  assert.match(PASSWORD_HINT, /special character/);
});

test('the setup page uses the shared mirror instead of its own rules', async () => {
  const page = await readFile(fileURLToPath(SETUP_PAGE), 'utf8');
  assert.match(page, /unmetPasswordRequirements/);
  assert.match(page, /from '@\/lib\/password'/);
  // The old narrower class, and any hand-rolled re-derivation of the rules.
  assert.doesNotMatch(page, /\[!@#\$%\^&\*\(\),\.\?":\{\}\|<>\]/);
  assert.doesNotMatch(page, /password\.length < 12/);
  assert.doesNotMatch(page, /\/\[A-Z\]\/\.test\(password\)/);
  assert.doesNotMatch(page, /minLength=\{12\}|maxLength=\{1024\}/);
  assert.match(page, /minLength=\{PASSWORD_MIN_BYTES\}/);
  assert.match(page, /maxLength=\{PASSWORD_MAX_BYTES\}/);
});

test('generated admin passwords always satisfy the policy', () => {
  for (let i = 0; i < 2000; i += 1) {
    const generated = generateSecurePassword();
    assert.deepEqual(
      validatePassword(generated),
      [],
      // Length only — never echo a generated credential into test output.
      `generated password of length ${generated.length} failed the policy`,
    );
  }
});

test('generated passwords honour the requested length and the minimum floor', () => {
  assert.equal(generateSecurePassword().length, 16);
  assert.equal(generateSecurePassword(24).length, 24);
  assert.equal(generateSecurePassword(64).length, 64);
  // A caller asking for less than the policy minimum gets the minimum.
  assert.equal(generateSecurePassword(4).length, PASSWORD_MIN_BYTES);
  assert.deepEqual(validatePassword(generateSecurePassword(4)), []);
});

test('generated passwords are not class-ordered and vary between calls', () => {
  const samples = Array.from({ length: 200 }, () => generateSecurePassword());
  assert.equal(new Set(samples).size, samples.length, 'generated passwords must be unique');
  // If the guaranteed classes were never shuffled, position 0 would always be
  // uppercase and position 3 always a special character.
  assert.ok(samples.some((s) => !/[A-Z]/.test(s[0])), 'first character is always uppercase');
  assert.ok(samples.some((s) => !'!@#$%'.includes(s[3])), 'fourth character is always special');
});

test('the admin user dialogs use the shared generator, not their own', async () => {
  for (const relative of [
    '../components/settings/access-control/InviteUserDialog.tsx',
    '../components/settings/access-control/EditUserDialog.tsx',
  ]) {
    const source = await readFile(fileURLToPath(new URL(relative, import.meta.url)), 'utf8');
    assert.match(source, /generateSecurePassword/);
    assert.match(source, /from '@\/lib\/password'/);
    assert.doesNotMatch(source, /getRandomValues/, `${relative} must not roll its own generator`);
  }
});
