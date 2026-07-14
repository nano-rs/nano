// Timestamp formatting. Range presets and their resolution live in the shared
// @/lib/time-range module, so both apps agree on what each range means.

const TIME_ONLY = new Intl.DateTimeFormat(undefined, {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
});

const DATE_TIME = new Intl.DateTimeFormat(undefined, {
  month: 'short',
  day: 'numeric',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  hour12: false,
});

/** Long windows need the date; short ones would just repeat it on every row. */
export function formatTimestamp(value: unknown, withDate: boolean): string {
  if (value == null) return '—';
  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) return String(value);
  return withDate ? DATE_TIME.format(date) : TIME_ONLY.format(date);
}

export function formatBucketLabel(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return DATE_TIME.format(date);
}
