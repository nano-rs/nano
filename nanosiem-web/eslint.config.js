import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist'] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': [
        'warn',
        { allowConstantExport: true },
      ],
    },
  },
  {
    // NAN-3591: a bare <input type="checkbox"> renders the OS-native widget,
    // which clashes with the dense design system. Use
    // `@/components/ui/checkbox` instead. A deliberately styled custom
    // checkbox (visually hidden input + styled sibling) may opt out with an
    // inline `eslint-disable-next-line no-restricted-syntax` and a reason.
    files: ['src/**/*.tsx'],
    ignores: ['src/components/ui/**'],
    rules: {
      'no-restricted-syntax': [
        'error',
        {
          selector:
            "JSXOpeningElement[name.name='input']:has(JSXAttribute[name.name='type']:matches([value.value='checkbox'], [value.expression.value='checkbox']))",
          message:
            'Native checkboxes render with the OS style. Use <Checkbox> from @/components/ui/checkbox.',
        },
      ],
    },
  }
);
