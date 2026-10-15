// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Theme identities, in one place.
 *
 * The app has three concrete themes plus `system`. Two of them — `dark` and
 * `matte` — are DARK-APPEARANCE: black window, light text. Several components
 * ask "is this dark?" to pick an icon, a logo asset, or the other end of a
 * binary toggle, and every one of them used to spell it `resolvedTheme ===
 * 'dark'`. That comparison is now wrong for matte (it would serve the
 * dark-on-light logo on a black window), so the question gets one answer here
 * instead of five copies.
 *
 * `THEMES` must be handed to next-themes' `themes` prop: it only writes classes
 * for themes it has been told about, so a theme missing from this list is
 * selectable in the UI and simply never applied.
 */
export const THEMES = [
  'light',
  'paper',
  'dark',
  'matte',
  'mono',
  'dark-pink',
  'dark-violet',
  'dark-emerald',
  'dark-amber',
] as const;

export type Theme = (typeof THEMES)[number];

/** Themes whose surfaces are dark and whose text is light. */
const DARK_APPEARANCE = new Set<string>([
  'dark',
  'matte',
  'mono',
  'dark-pink',
  'dark-violet',
  'dark-emerald',
  'dark-amber',
]);

/**
 * Is the resolved theme a dark-appearance one?
 *
 * Takes `resolvedTheme` (never `theme` — that can be the literal `'system'`,
 * which has no appearance of its own). `undefined` before mount reads as dark,
 * matching the app's `defaultTheme`.
 */
export function isDarkAppearance(resolvedTheme: string | undefined): boolean {
  return resolvedTheme === undefined || DARK_APPEARANCE.has(resolvedTheme);
}

/**
 * The `theme` prop for sonner's <Toaster>.
 *
 * Sonner only knows `light` / `dark`: it writes the prop to
 * `data-sonner-theme` and keys all of its surface tokens on those two values.
 * Handing it an app theme name (`matte`, `dark-pink`, ...) left every token
 * undefined and the toast background transparent (NAN-2788). The colours
 * themselves come from the app tokens in `index.css` (`TOASTS (sonner)`).
 */
export function sonnerAppearance(resolvedTheme: string | undefined): 'light' | 'dark' {
  return isDarkAppearance(resolvedTheme) ? 'dark' : 'light';
}

/** Human labels for the theme picker. */
export const THEME_LABELS: Record<Theme, string> = {
  light: 'Light',
  dark: 'Dark',
  matte: 'Matte Black',
  mono: 'Matte Mono',
  'dark-pink': 'Dark · Pink',
  'dark-violet': 'Dark · Violet',
  'dark-emerald': 'Dark · Emerald',
  'dark-amber': 'Dark · Amber',
  paper: 'Matte White',
};

/**
 * Swatch colours for the theme picker: each theme's own window surface paired
 * with its own brand accent, so a swatch previews the theme rather than being
 * an arbitrary dot. Kept in sync by hand with the token blocks in `index.css`
 * (`--background` and `--primary` of each theme) — a swatch cannot read those,
 * because every theme's tokens are only live when that theme is applied.
 */
export const THEME_SWATCH: Record<Theme, { surface: string; accent: string }> = {
  light: { surface: '#F1F5F9', accent: '#0891B2' },
  dark: { surface: '#0B0E12', accent: '#5EE7F0' },
  matte: { surface: '#121212', accent: '#E68E0D' },
  mono: { surface: '#121212', accent: '#EAEAEA' },
  'dark-pink': { surface: '#0B0E12', accent: '#FF5CA8' },
  'dark-violet': { surface: '#0B0E12', accent: '#B58CFF' },
  'dark-emerald': { surface: '#0B0E12', accent: '#4FD6A0' },
  'dark-amber': { surface: '#0B0E12', accent: '#FFB454' },
  paper: { surface: '#FFFFFF', accent: '#111111' },
};
