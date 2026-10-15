// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub. NewRuleAiPanel is the meloD-backed AI panel embedded
// in RuleEditorRedesign for generating detection rule scaffolds. Renders
// nothing in open builds; RuleEditorRedesign drops the import in Task #15.

import type { GeneratedDetection } from '@/lib/api';

interface NewRuleAiPanelProps {
  /** Apply a single candidate → write YAML into the editor body. */
  onApply: (detection: GeneratedDetection) => void;
  /** Batch-create N candidates as new draft rules. Returns IDs of created rules. */
  onBatchCreate: (detections: GeneratedDetection[]) => Promise<void>;
  /** Seed the textarea when the user lands with a prefilled narrative. */
  initialNarrative?: string;
  disabled?: boolean;
  onClose?: () => void;
}

export function NewRuleAiPanel(_props: NewRuleAiPanelProps) {
  return null;
}
export default NewRuleAiPanel;
