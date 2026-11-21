// SPDX-License-Identifier: AGPL-3.0-or-later
// @vitest-environment jsdom
//
// NAN-5683 — `EditorState.readOnly` only stops CodeMirror's built-in input;
// the YAML helper plugins dispatch their own changes. On a read-only buffer
// (an archived rule) they must offer no clickable value hint and clear no
// placeholder.
import { afterEach, describe, expect, test } from 'vitest';
import { EditorState } from '@codemirror/state';
import { EditorView } from '@codemirror/view';
import { createClickableFieldPlugin, createEmptyFieldHintsPlugin } from './yaml-helper-plugins';

const DOC = '---\ntitle: r\nseverity:\ntags: tag1, tag2\n---\nprocess_name="x"';
let view: EditorView | null = null;

function mount(readOnly: boolean) {
  const parent = document.createElement('div');
  document.body.appendChild(parent);
  view = new EditorView({
    parent,
    state: EditorState.create({
      doc: DOC,
      selection: { anchor: DOC.length },
      extensions: [EditorState.readOnly.of(readOnly), createEmptyFieldHintsPlugin(), createClickableFieldPlugin()],
    }),
  });
  return view;
}

function clickTagsLine(v: EditorView) {
  const line = v.state.doc.line(4);
  v.posAtCoords = () => line.from + 8;
  v.contentDOM.dispatchEvent(new MouseEvent('click', { bubbles: true, clientX: 1, clientY: 1 }));
}

afterEach(() => {
  view?.destroy();
  view = null;
  document.body.innerHTML = '';
});

describe('YAML helper plugins honor readOnly', () => {
  test('read-only: no empty-field hint options to click', () => {
    const v = mount(true);
    expect(v.dom.querySelectorAll('.cm-hint-option').length).toBe(0);
  });

  test('control: editable shows the severity options', () => {
    const v = mount(false);
    expect(v.dom.querySelectorAll('.cm-hint-option').length).toBeGreaterThan(0);
  });

  test('read-only: a click on the tags placeholder does not clear it', () => {
    const v = mount(true);
    clickTagsLine(v);
    expect(v.state.doc.toString()).toBe(DOC);
  });

  test('control: editable, the same click clears the placeholder', () => {
    const v = mount(false);
    clickTagsLine(v);
    expect(v.state.doc.line(4).text).toBe('tags: ');
  });
});
