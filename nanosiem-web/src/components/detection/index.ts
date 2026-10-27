// SPDX-License-Identifier: AGPL-3.0-or-later

// Editor components
export { DetectionEditorHeader } from './editor/DetectionEditorHeader';
export { YamlAutocompleteDropdown } from './editor/YamlAutocompleteDropdown';
export { ValidationTestModal } from './editor/ValidationTestModal';
// RuleTuningPanel lifted to @/enterprise/components/detection/editor/RuleTuningPanel (NAN-745).
export { SigmaConverter, convertSigmaRule } from './editor/SigmaConverter';
// CasePermissionsEditor lifted to @/enterprise/components/detection/editor/CasePermissionsEditor (NAN-745).
// RulePlaybookSelector lifted to @/enterprise/components/detection/editor/RulePlaybookSelector (NAN-745).
// LinkedPlaybooksPreview lifted to @/enterprise/components/detection/editor/LinkedPlaybooksPreview (NAN-745).

// Panel components
export { RightPanel } from './panels/RightPanel';
export { RulesListPanel } from './panels/RulesListPanel';
// AiGenerationPanel (lifted to enterprise in NAN-745) was removed in NAN-4595: drafting runs in pivt (`@detection`).

// Dialog components
export { SaveConfirmDialog, DeleteConfirmDialog, ArchiveConfirmDialog } from './dialogs';
