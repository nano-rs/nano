// SPDX-License-Identifier: AGPL-3.0-or-later

// NAN-5796: cases for nano/no-hand-built-info-tip (eslint-rules/info-tip.mjs).

import { afterAll, describe, it } from 'vitest';
import { RuleTester } from 'eslint';
import plugin from './info-tip.mjs';

RuleTester.describe = describe;
RuleTester.it = it;
RuleTester.afterAll = afterAll;

const tester = new RuleTester({
  languageOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
    parserOptions: { ecmaFeatures: { jsx: true } },
  },
});

const UI = "import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';\n";
const TIP = "import { InfoTip } from '@/components/ui/info-tip';\n";
const hand = { messageId: 'handBuilt' };
const inside = (tag) => ({ messageId: 'insideHeading', data: { tag } });

tester.run('no-hand-built-info-tip', plugin.rules['no-hand-built-info-tip'], {
  valid: [
    // The shared component.
    { code: TIP + 'const A = () => <InfoTip label="About x">Body</InfoTip>;' },
    // A bare icon outside any tooltip.
    { code: "import { Info } from 'lucide-react';\nconst A = () => <Info />;" },
    // An Info icon in a tooltip BODY (a severity legend), not the trigger.
    {
      code:
        "import { Info } from 'lucide-react';\n" +
        UI +
        'const A = () => <Tooltip><TooltipTrigger>info</TooltipTrigger><TooltipContent><Info /> informational</TooltipContent></Tooltip>;',
    },
    // A non-help icon in a trigger.
    { code: "import { Copy } from 'lucide-react';\n" + UI + 'const A = () => <TooltipTrigger><Copy /></TooltipTrigger>;' },
    // A local component that happens to be called Info, not from lucide.
    { code: UI + 'const Info = () => null;\nconst A = () => <TooltipTrigger><Info /></TooltipTrigger>;' },
    // InfoTip next to a heading and next to a label.
    { code: TIP + 'const A = () => <div><h1>Title</h1><InfoTip label="About">Body</InfoTip></div>;' },
    { code: TIP + 'const A = () => <div><label htmlFor="x">Days</label><InfoTip label="About">Body</InfoTip><input id="x" /></div>;' },
  ],
  invalid: [
    {
      code: "import { Info } from 'lucide-react';\n" + UI + 'const A = () => <Tooltip><TooltipTrigger asChild><button><Info /></button></TooltipTrigger></Tooltip>;',
      errors: [hand],
    },
    // Aliased icon and aliased trigger.
    {
      code:
        "import { HelpCircle as HelpIcon } from 'lucide-react';\n" +
        "import { TooltipTrigger as Trig } from '@/components/ui/tooltip';\n" +
        'const A = () => <Trig><HelpIcon /></Trig>;',
      errors: [hand],
    },
    // Namespace icon import.
    {
      code: "import * as Icons from 'lucide-react';\n" + UI + 'const A = () => <TooltipTrigger><Icons.CircleHelp /></TooltipTrigger>;',
      errors: [hand],
    },
    // Radix namespace trigger.
    {
      code:
        "import { Info } from 'lucide-react';\n" +
        "import * as TooltipPrimitive from '@radix-ui/react-tooltip';\n" +
        'const A = () => <TooltipPrimitive.Trigger><Info /></TooltipPrimitive.Trigger>;',
      errors: [hand],
    },
    // Radix named trigger.
    {
      code: "import { Info } from 'lucide-react';\nimport { Trigger } from '@radix-ui/react-tooltip';\nconst A = () => <Trigger><Info /></Trigger>;",
      errors: [hand],
    },
    // InfoTip inside a heading, a role=heading element, a label and the ui Label.
    { code: TIP + 'const A = () => <h1>Title <InfoTip label="About">Body</InfoTip></h1>;', errors: [inside('heading')] },
    { code: TIP + 'const A = () => <div role="heading">Title <InfoTip label="About">Body</InfoTip></div>;', errors: [inside('heading')] },
    {
      code: TIP + 'const A = () => <label><span>Days <InfoTip label="About">Body</InfoTip></span><input /></label>;',
      errors: [inside('label')],
    },
    {
      code: TIP + "import { Label } from '@/components/ui/label';\nconst A = () => <Label>Days <InfoTip label=\"About\">Body</InfoTip></Label>;",
      errors: [inside('label')],
    },
    // Aliased InfoTip import.
    {
      code: "import { InfoTip as Tip } from '@/components/ui/info-tip';\nconst A = () => <h2>Title <Tip label=\"About\">Body</Tip></h2>;",
      errors: [inside('heading')],
    },
  ],
});
