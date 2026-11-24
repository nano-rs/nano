// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-5796: lint guards for the shared <InfoTip> (src/components/ui/info-tip.tsx).
//
// `nano/no-hand-built-info-tip` reports
//  1. a lucide Info / HelpCircle / CircleHelp icon rendered inside a tooltip
//     trigger (the hand-built pattern InfoTip replaced). Imports are tracked,
//     so aliases (`Info as HelpIcon`, `TooltipTrigger as Trig`) and namespaces
//     (`Icons.Info`, `TooltipPrimitive.Trigger`) are caught. An Info icon in a
//     tooltip BODY is fine (a severity legend, say) and is not reported.
//  2. an <InfoTip> inside a heading or a label: a button inside <h1> joins the
//     heading's accessible name, and inside <label> it steals the label's
//     control. Place it next to the heading or label instead.

const HELP_ICONS = new Set([
  'Info',
  'InfoIcon',
  'LucideInfo',
  'HelpCircle',
  'HelpCircleIcon',
  'LucideHelpCircle',
  'CircleHelp',
  'CircleHelpIcon',
  'LucideCircleHelp',
  'CircleQuestionMark',
  'CircleQuestionMarkIcon',
  'LucideCircleQuestionMark',
]);

const isUiModule = (source, name) => source === `@/components/ui/${name}` || source.endsWith(`/ui/${name}`) || source === `./${name}`;
const HEADING_TAGS = new Set(['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'label', 'legend']);

function importedName(spec) {
  return spec.imported.type === 'Identifier' ? spec.imported.name : spec.imported.value;
}

const rule = {
  meta: {
    type: 'problem',
    docs: { description: 'Use the shared <InfoTip> for help tips, and keep it out of headings and labels.' },
    schema: [],
    messages: {
      handBuilt: 'Use <InfoTip> from @/components/ui/info-tip instead of a tooltip trigger around an Info / HelpCircle icon.',
      insideHeading:
        'Place <InfoTip> next to the {{tag}}, not inside it: a button inside a heading joins its name, and inside a label it steals the label control.',
    },
  },
  create(context) {
    const iconLocals = new Set();
    const lucideNamespaces = new Set();
    const triggerLocals = new Set();
    // namespace local -> property names that are a trigger
    const triggerNamespaces = new Map();
    const infoTipLocals = new Set();
    const labelLocals = new Set();

    function isIcon(name) {
      if (name.type === 'JSXIdentifier') return iconLocals.has(name.name);
      if (name.type === 'JSXMemberExpression' && name.object.type === 'JSXIdentifier') {
        return lucideNamespaces.has(name.object.name) && HELP_ICONS.has(name.property.name);
      }
      return false;
    }

    function isTrigger(name) {
      if (name.type === 'JSXIdentifier') return triggerLocals.has(name.name);
      if (name.type === 'JSXMemberExpression' && name.object.type === 'JSXIdentifier') {
        const props = triggerNamespaces.get(name.object.name);
        return Boolean(props && props.has(name.property.name));
      }
      return false;
    }

    function headingTag(opening) {
      const { name } = opening;
      if (name.type === 'JSXIdentifier') {
        if (HEADING_TAGS.has(name.name)) return name.name === 'label' || name.name === 'legend' ? 'label' : 'heading';
        if (labelLocals.has(name.name)) return 'label';
      }
      const role = opening.attributes.find(
        (a) => a.type === 'JSXAttribute' && a.name.name === 'role' && a.value && a.value.type === 'Literal',
      );
      if (role && role.value.value === 'heading') return 'heading';
      return null;
    }

    function* jsxAncestors(node) {
      for (let p = node.parent && node.parent.parent; p; p = p.parent) {
        if (p.type === 'JSXElement') yield p;
      }
    }

    return {
      ImportDeclaration(node) {
        const source = String(node.source.value);
        const lucide = source === 'lucide-react' || source.startsWith('lucide-react/');
        const uiTooltip = isUiModule(source, 'tooltip');
        const radixTooltip = source === '@radix-ui/react-tooltip';
        const infoTip = isUiModule(source, 'info-tip');
        const uiLabel = isUiModule(source, 'label');
        for (const spec of node.specifiers) {
          if (spec.type === 'ImportNamespaceSpecifier') {
            if (lucide) lucideNamespaces.add(spec.local.name);
            if (uiTooltip) triggerNamespaces.set(spec.local.name, new Set(['TooltipTrigger']));
            if (radixTooltip) triggerNamespaces.set(spec.local.name, new Set(['Trigger', 'TooltipTrigger']));
            continue;
          }
          if (spec.type !== 'ImportSpecifier') continue;
          const imported = importedName(spec);
          if (lucide && HELP_ICONS.has(imported)) iconLocals.add(spec.local.name);
          if (uiTooltip && imported === 'TooltipTrigger') triggerLocals.add(spec.local.name);
          if (radixTooltip && (imported === 'Trigger' || imported === 'TooltipTrigger')) triggerLocals.add(spec.local.name);
          if (infoTip && imported === 'InfoTip') infoTipLocals.add(spec.local.name);
          if (uiLabel && imported === 'Label') labelLocals.add(spec.local.name);
        }
      },
      JSXOpeningElement(node) {
        const { name } = node;
        if (isIcon(name)) {
          for (const el of jsxAncestors(node)) {
            if (isTrigger(el.openingElement.name)) {
              context.report({ node, messageId: 'handBuilt' });
              return;
            }
          }
          return;
        }
        if (name.type === 'JSXIdentifier' && infoTipLocals.has(name.name)) {
          for (const el of jsxAncestors(node)) {
            const tag = headingTag(el.openingElement);
            if (tag) {
              context.report({ node, messageId: 'insideHeading', data: { tag } });
              return;
            }
          }
        }
      },
    };
  },
};

export default { rules: { 'no-hand-built-info-tip': rule } };
