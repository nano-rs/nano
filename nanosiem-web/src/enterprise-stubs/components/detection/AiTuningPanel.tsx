// SPDX-License-Identifier: AGPL-3.0-or-later

// Open-edition stub. AiTuningPanel is the meloD-backed rule tuning wizard the
// rule editor opens on `pivt:open-tuning-wizard` (NAN-3208). Renders nothing
// in open builds; the editor only mounts it when meloD is available.

interface AiTuningPanelProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  ruleId: string;
  ruleName: string;
  onApplySuggestion: (modifiedQuery: string) => void;
  initialFeedback?: string;
}

export function AiTuningPanel(props: AiTuningPanelProps) {
  void props;
  return null;
}
export default AiTuningPanel;
