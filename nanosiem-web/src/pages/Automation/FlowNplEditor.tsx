// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-4586 — the Search page's nPL editor plus binding chips (easy mode).
 * Lazy-loaded by FlowSearchQuery so CodeMirror stays out of the route chunk.
 */
import { useMemo } from 'react';
import { SearchQueryEditor } from '@/components/editor/SearchQueryEditor';
import type { FieldDef } from './soar-fields';
import { bindingChips } from './npl-binding-chips';

export default function FlowNplEditor({ value, onChange, fields, chips, onCursor }: {
  value: string;
  onChange: (v: string) => void;
  fields: FieldDef[];
  /** Easy mode: render `{{path}}` bindings as atomic chips. */
  chips: boolean;
  onCursor: (pos: number) => void;
}) {
  // Field arrays are rebuilt on every edit; key the extension on their content.
  const sig = fields.map((f) => `${f.path}\u0000${f.label}`).join('\u0001');
  const extensions = useMemo(() => (chips ? [bindingChips(fields)] : []), [chips, sig]); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <SearchQueryEditor
      value={value}
      onChange={onChange}
      placeholder="process_name=powershell.exe | stats count by host"
      autocomplete="auto"
      extensions={extensions}
      onCursorChange={(p) => onCursor(p)}
    />
  );
}
