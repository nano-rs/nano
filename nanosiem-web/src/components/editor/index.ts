// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Detection Rule Editor - CodeMirror 6 Integration
 *
 * Exports the main CodeMirrorEditor component and supporting utilities
 */

// Main editor component
export { CodeMirrorEditor, type CodeMirrorEditorRef, type CodeMirrorEditorProps } from './CodeMirrorEditor';

// TypeScript editor (for enrichment code)
export { TypeScriptEditor, type TypeScriptEditorRef, type TypeScriptEditorProps } from './TypeScriptEditor';

// VRL editor (for parser code)
export { VrlEditor, type VrlEditorRef, type VrlEditorProps } from './VrlEditor';

// Lightweight code input (for JSON samples, curl examples, docs)
export { CodeInput, type CodeInputProps } from './CodeInput';

// Query editor (minimal, for dashboard panels)
export { QueryEditor, type QueryEditorRef, type QueryEditorProps } from './QueryEditor';

// Search query editor (for search bar input)
export { SearchQueryEditor, type SearchQueryEditorRef, type SearchQueryEditorProps, type CursorCoords } from './SearchQueryEditor';

// Query language mode
export { queryLanguage, registerDynamicFields } from './query-language';

// Theme
export { detectionTheme, editorTheme, syntaxTheme } from './codemirror-theme';

// Language mode
export {
  detectionLanguage,
  isInYamlSection,
  getYamlFieldAtPosition,
  hasYamlAutocomplete,
} from './detection-language';

// Autocomplete
export { detectionAutocomplete } from './detection-autocomplete';

// Linter
export {
  detectionLinter,
  clientLinter,
  backendLinter,
  resetValidationCache,
  getValidationState,
  type ValidationState,
} from './detection-linter';
