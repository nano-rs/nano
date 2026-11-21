// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-5683 — which rule-editor controls a viewer gets, from their permissions
 * and the rule's state. One place, so the top bar, banner, tray, code lens,
 * inspector and pivt bridge agree, and each flag mirrors the exact server
 * check of the endpoint the control calls:
 *
 * | control       | endpoint                                  | server requires                                   |
 * |---------------|-------------------------------------------|---------------------------------------------------|
 * | write (new)   | POST /api/rules                           | detections:create                                 |
 * | write (saved) | PUT /api/rules/{id}                       | detections:edit                                   |
 * | format        | POST /api/rules/format (+ writes buffer)  | detections:view (+ write)                         |
 * | test (saved)  | POST /api/rules/{id}/test                 | detections:view + search:execute                  |
 * | test (buffer) | POST /api/rules/test                      | detections:create + search:execute                |
 * | tune          | POST /api/melod/detection/tune (+ apply)  | melod:detection + detections:view + alerts:view + search:execute (+ edit to apply) |
 * | tune settings | PUT /api/tuning/settings/{id}             | detections:edit                                   |
 * | lifecycle     | /pause /resume /promote /demote           | detections:promote                                |
 * | archive       | PUT /api/rules/{id} {archived:true}       | detections:edit + detections:delete               |
 * | unarchive     | PUT /api/rules/{id} {archived:false}      | detections:edit + detections:promote              |
 * | delete        | DELETE /api/rules/{id}                    | detections:delete                                 |
 *
 * An archived rule is a deleted rule (NAN-3816 / NAN-5672): it doesn't run,
 * and the API answers 404 to every rule action on it except unarchive. Its
 * page is read-only; Unarchive is the one action. Viewing its match history
 * stays available.
 */
export interface RuleEditorActionInput {
  isNewMode: boolean;
  /** A saved rule is open (there is a rule id). */
  hasRule: boolean;
  archived: boolean;
  /** The buffer differs from the saved rule (a test then runs the buffer). */
  unsavedEdits: boolean;
  canView: boolean;
  canCreate: boolean;
  canEdit: boolean;
  canDelete: boolean;
  canPromote: boolean;
  canSearch: boolean;
  canViewAlerts: boolean;
  canMelodDetection: boolean;
}

export interface RuleEditorActionAccess {
  /** The buffer, form, folder, inspector and pivt edits are writable. */
  write: boolean;
  save: boolean;
  discard: boolean;
  format: boolean;
  test: boolean;
  viewMatches: boolean;
  duplicate: boolean;
  /** Pause / resume / promote / demote. */
  lifecycle: boolean;
  /** AI tune (pivt `@tune`). */
  tune: boolean;
  /** The bottom tray's Tune settings popover. */
  tuneSettings: boolean;
  archive: boolean;
  unarchive: boolean;
  delete: boolean;
}

export function ruleEditorActionAccess(input: RuleEditorActionInput): RuleEditorActionAccess {
  const { isNewMode, archived, canView, canCreate, canEdit, canDelete, canPromote, canSearch } = input;
  const saved = !isNewMode && input.hasRule;
  const live = !archived;
  const write = live && (isNewMode ? canCreate : saved && canEdit);
  const testsBuffer = isNewMode || input.unsavedEdits;
  return {
    write,
    save: write,
    discard: write && saved,
    format: write && canView,
    test: live && canSearch && (testsBuffer ? canCreate : saved && canView),
    viewMatches: saved,
    duplicate: live && saved && canCreate,
    lifecycle: live && saved && canPromote,
    tune: write && saved && canView && canSearch && input.canViewAlerts && input.canMelodDetection,
    tuneSettings: write && saved,
    archive: live && saved && canEdit && canDelete,
    unarchive: archived && saved && canEdit && canPromote,
    delete: live && saved && canDelete,
  };
}
