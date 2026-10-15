// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * The one client-side mirror of the server's password policy, plus the
 * admin-issued password generator that must satisfy it.
 *
 * Source of truth: `PasswordRequirements::default()` and `MAX_PASSWORD_BYTES`
 * in `nanosiem-core/src/auth/password.rs`. Every server entry point that
 * accepts a new plaintext funnels through `validate_password` there — first-run
 * setup, admin user create/update, password reset, password change, and both
 * enterprise-shared activation paths — so there is exactly one policy to
 * mirror, and it belongs in exactly one module here.
 *
 * Before this existed, `Setup.tsx` carried its own narrower special-character
 * class (`[!@#$%^&*(),.?":{}|<>]`) and rejected passwords the server accepts.
 * `password.test.ts` asserts the lockstep against the Rust source and that no
 * page re-derives the rules.
 */

/** `validate_password_complexity` measures `str::len()` — bytes, not UTF-16 units. */
export const PASSWORD_MIN_BYTES = 12;

/** `MAX_PASSWORD_BYTES` in nanosiem-core/src/auth/password.rs. */
export const PASSWORD_MAX_BYTES = 1024;

/** Exactly the set accepted by `is_special_char` in nanosiem-core/src/auth/password.rs. */
export const PASSWORD_SPECIAL_CHARACTERS = '!@#$%^&*()-_=+[]{}|\\;:\'",.<>/?`~';

/** Rendered as a field hint so the requirements are visible before submitting. */
export const PASSWORD_HINT =
  `At least ${PASSWORD_MIN_BYTES} characters, with an uppercase letter, `
  + 'a lowercase letter, a digit, and a special character.';

/** The server measures bytes (`str::len`), not UTF-16 units, so match it. */
function byteLength(value: string): number {
  return new TextEncoder().encode(value).length;
}

interface PasswordRule {
  /** Short checklist label, for a "requirements" list next to the field. */
  label: string;
  /** Full sentence, for an inline error summary. */
  message: string;
  satisfied: (password: string) => boolean;
}

/**
 * The rules, declared once. Both `validatePassword` (sentences) and
 * `unmetPasswordRequirements` (checklist labels) are derived from this list, so
 * a surface cannot drift by restating a rule in its own words.
 *
 * Order mirrors `validate_password_complexity`: length, then upper, lower,
 * digit, special.
 */
/**
 * The server's upper bound. It is a transport/hashing cap rather than
 * something a person chooses toward, so it is validated like every other rule
 * but left out of `PASSWORD_REQUIREMENT_LABELS`.
 */
const MAX_LENGTH_RULE: PasswordRule = {
  label: `At most ${PASSWORD_MAX_BYTES} characters`,
  message: `Password must be at most ${PASSWORD_MAX_BYTES} characters long.`,
  satisfied: (password) => byteLength(password) <= PASSWORD_MAX_BYTES,
};

const PASSWORD_RULES: readonly PasswordRule[] = [
  {
    label: `At least ${PASSWORD_MIN_BYTES} characters`,
    message: `Password must be at least ${PASSWORD_MIN_BYTES} characters long.`,
    satisfied: (password) => byteLength(password) >= PASSWORD_MIN_BYTES,
  },
  MAX_LENGTH_RULE,
  {
    label: 'At least one uppercase letter',
    message: 'Password must contain at least one uppercase letter.',
    satisfied: (password) => /[A-Z]/.test(password),
  },
  {
    label: 'At least one lowercase letter',
    message: 'Password must contain at least one lowercase letter.',
    satisfied: (password) => /[a-z]/.test(password),
  },
  {
    label: 'At least one digit',
    message: 'Password must contain at least one digit.',
    satisfied: (password) => /[0-9]/.test(password),
  },
  {
    label: 'At least one special character',
    message: 'Password must contain at least one special character.',
    satisfied: (password) => [...password].some(
      (character) => PASSWORD_SPECIAL_CHARACTERS.includes(character),
    ),
  },
];

/**
 * Every requirement as a short label, in policy order — for surfaces that
 * advertise the policy before anything has been typed (the first-run setup
 * page's inspector). Derived from `PASSWORD_RULES` so a surface never restates
 * a rule in its own words.
 */
export const PASSWORD_REQUIREMENT_LABELS: readonly string[] = PASSWORD_RULES.filter(
  (rule) => rule !== MAX_LENGTH_RULE,
).map((rule) => rule.label);

/**
 * The policy as a live checklist: one short chip label per rule, ticked as the
 * password satisfies it. Derived from `PASSWORD_RULES` like the labels above;
 * the max-length rule is omitted because it cannot be "unmet by not typing".
 */
export function passwordChecklist(password: string): { label: string; ok: boolean }[] {
  const short: Record<string, string> = {
    [PASSWORD_RULES[0]!.label]: `${PASSWORD_MIN_BYTES}+ chars`,
    'At least one uppercase letter': 'uppercase',
    'At least one lowercase letter': 'lowercase',
    'At least one digit': 'digit',
    'At least one special character': 'special',
  };
  return PASSWORD_RULES.filter((rule) => rule !== MAX_LENGTH_RULE).map((rule) => ({
    label: short[rule.label] ?? rule.label,
    ok: rule.satisfied(password),
  }));
}

/** Mirrors `validate_password`; returns a sentence per unmet requirement. */
export function validatePassword(password: string): string[] {
  if (password.length === 0) return ['Enter a password.'];
  return PASSWORD_RULES.filter((rule) => !rule.satisfied(password)).map((rule) => rule.message);
}

/**
 * The same unmet requirements as short checklist labels, for forms that render
 * a requirements list under the field rather than an error summary.
 */
export function unmetPasswordRequirements(password: string): string[] {
  return PASSWORD_RULES.filter((rule) => !rule.satisfied(password)).map((rule) => rule.label);
}

// ---------------------------------------------------------------------------
// Admin-issued password generation (invite + edit flows)
// ---------------------------------------------------------------------------

/**
 * Character classes for generated passwords. Ambiguous glyphs (`0/O`, `1/l/I`)
 * are excluded so an admin can read the password aloud or paste-and-confirm
 * without confusion. Concatenated in this order they form the original
 * `PASSWORD_CHARSET`.
 */
const GENERATOR_UPPERCASE = 'ABCDEFGHJKMNPQRSTUVWXYZ';
const GENERATOR_LOWERCASE = 'abcdefghjkmnpqrstuvwxyz';
const GENERATOR_DIGITS = '23456789';
const GENERATOR_SPECIALS = '!@#$%';

const PASSWORD_CHARSET =
  GENERATOR_UPPERCASE + GENERATOR_LOWERCASE + GENERATOR_DIGITS + GENERATOR_SPECIALS;

/**
 * Cryptographically random bytes; falls back to `Math.random` only when the Web
 * Crypto API is unavailable (test harnesses, SSR — should never hit in a real
 * browser).
 */
function randomBytes(count: number): Uint8Array {
  const bytes = new Uint8Array(count);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
    return bytes;
  }
  for (let i = 0; i < count; i += 1) {
    bytes[i] = Math.floor(Math.random() * 256);
  }
  return bytes;
}

/**
 * Generate a password for an admin-issued credential.
 *
 * It is guaranteed to satisfy `validatePassword` — one character is drawn from
 * each required class and the result is shuffled, so the classes are not
 * clustered at the front. Drawing every character uniformly from the full
 * charset (the previous behaviour) left roughly a one-in-three chance of no
 * special character at length 16, which the server now rejects: the admin
 * create/update endpoints used to skip password validation entirely, so those
 * generated credentials were silently accepted.
 *
 * `length` is floored at `PASSWORD_MIN_BYTES`; the charset is ASCII, so
 * characters and bytes coincide.
 */
export function generateSecurePassword(length = 16): string {
  const size = Math.max(length, PASSWORD_MIN_BYTES);
  const classes = [
    GENERATOR_UPPERCASE,
    GENERATOR_LOWERCASE,
    GENERATOR_DIGITS,
    GENERATOR_SPECIALS,
  ];
  // `size` draws plus `size` shuffle decisions.
  const bytes = randomBytes(size * 2);

  const characters = classes.map((set, index) => set[bytes[index] % set.length]);
  for (let i = classes.length; i < size; i += 1) {
    characters.push(PASSWORD_CHARSET[bytes[i] % PASSWORD_CHARSET.length]);
  }

  // Fisher-Yates, so the guaranteed classes are not always in the first slots.
  for (let i = characters.length - 1; i > 0; i -= 1) {
    const j = bytes[size + i] % (i + 1);
    [characters[i], characters[j]] = [characters[j], characters[i]];
  }

  return characters.join('');
}
