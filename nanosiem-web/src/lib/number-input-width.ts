/**
 * NAN-5329: a fixed 80px number input clipped 7–8 digit limits
 * ("100000(" for 1000000). Size the input to the widest allowed value
 * (digits of `max`) plus room for padding and the native spinner.
 */
export function numberInputWidth(max: number): string {
  const digits = Math.max(3, String(Math.trunc(Math.abs(max))).length);
  return `calc(${digits}ch + 2.75rem)`;
}
