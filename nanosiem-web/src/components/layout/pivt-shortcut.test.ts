// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, test } from 'vitest';
import { pivtShortcutFor } from './pivt-shortcut';

const ev = (o: Partial<KeyboardEvent>) =>
  ({ metaKey: false, ctrlKey: false, altKey: false, shiftKey: false, key: '', code: '', ...o }) as KeyboardEvent;

describe('pivtShortcutFor (NAN-5864)', () => {
  test('Cmd/Ctrl+. toggles', () => {
    expect(pivtShortcutFor(ev({ metaKey: true, key: '.', code: 'Period' }))).toBe('toggle');
    expect(pivtShortcutFor(ev({ ctrlKey: true, key: '.', code: 'Period' }))).toBe('toggle');
  });
  test('Cmd/Ctrl+Shift+. switches, as a real keyboard reports it (key ">")', () => {
    expect(pivtShortcutFor(ev({ metaKey: true, shiftKey: true, key: '>', code: 'Period' }))).toBe('switch');
    expect(pivtShortcutFor(ev({ ctrlKey: true, shiftKey: true, key: '>', code: 'Period' }))).toBe('switch');
    expect(pivtShortcutFor(ev({ ctrlKey: true, shiftKey: true, key: '.' }))).toBe('switch');
  });
  test('Dvorak: the physical Period key is "v", so Cmd/Ctrl+V stays paste', () => {
    expect(pivtShortcutFor(ev({ ctrlKey: true, key: 'v', code: 'Period' }))).toBeNull();
    expect(pivtShortcutFor(ev({ metaKey: true, key: 'v', code: 'Period' }))).toBeNull();
    expect(pivtShortcutFor(ev({ ctrlKey: true, shiftKey: true, key: 'V', code: 'Period' }))).toBeNull();
  });
  test('AZERTY: the physical Period key is ":" or "/", so Cmd/Ctrl+/ is left alone', () => {
    expect(pivtShortcutFor(ev({ ctrlKey: true, key: ':', code: 'Period' }))).toBeNull();
    expect(pivtShortcutFor(ev({ metaKey: true, shiftKey: true, key: '/', code: 'Period' }))).toBeNull();
    // AZERTY's "." is Shift+";": the character still opens pivt.
    expect(pivtShortcutFor(ev({ ctrlKey: true, shiftKey: true, key: '.', code: 'Comma' }))).toBe('switch');
  });
  test('AltGr (Ctrl+Alt) and Cmd+Option chords never fire', () => {
    expect(pivtShortcutFor(ev({ ctrlKey: true, altKey: true, key: '.', code: 'Period' }))).toBeNull();
    expect(pivtShortcutFor(ev({ metaKey: true, altKey: true, key: '.', code: 'Period' }))).toBeNull();
    expect(pivtShortcutFor(ev({ ctrlKey: true, altKey: true, shiftKey: true, key: '>', code: 'Period' }))).toBeNull();
  });
  test('exactly one of Cmd / Ctrl', () => {
    expect(pivtShortcutFor(ev({ metaKey: true, ctrlKey: true, key: '.', code: 'Period' }))).toBeNull();
  });
  test('the physical key is a fallback only when the browser cannot name the character', () => {
    expect(pivtShortcutFor(ev({ ctrlKey: true, key: 'Dead', code: 'Period' }))).toBe('toggle');
    expect(pivtShortcutFor(ev({ metaKey: true, shiftKey: true, key: 'Unidentified', code: 'Period' }))).toBe('switch');
    expect(pivtShortcutFor(ev({ ctrlKey: true, key: 'Dead', code: 'Comma' }))).toBeNull();
  });
  test('anything else is not a pivt shortcut', () => {
    expect(pivtShortcutFor(ev({ key: '.', code: 'Period' }))).toBeNull();
    expect(pivtShortcutFor(ev({ ctrlKey: true, key: ',', code: 'Comma' }))).toBeNull();
    expect(pivtShortcutFor(ev({ ctrlKey: true, shiftKey: true, key: '<', code: 'Comma' }))).toBeNull();
  });
});
