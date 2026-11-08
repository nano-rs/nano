// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * NAN-4970: `identity_allow_shrink` is a config key the connector engine reads
 * as a boolean (nano-connector `ALLOW_SHRINK_CONFIG`, the identity shrink-guard
 * override). It shows up in an identity spec's `config_fields`, but it is not
 * free text: the admin API refuses any non-boolean value. Every feed-create
 * form renders it with this checkbox and builds the key with
 * `withAllowShrink`: left out unless checked, `true` when checked.
 */

import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import type { CreateConnectorFeedRequest } from '@/lib/api/connector-feeds';

export const ALLOW_SHRINK = 'identity_allow_shrink';

/** The spec's config fields that are entered as text (everything but the flag). */
export function textConfigFields(configFields: readonly string[]): string[] {
  return configFields.filter((f) => f !== ALLOW_SHRINK);
}

export function hasAllowShrink(configFields: readonly string[]): boolean {
  return configFields.includes(ALLOW_SHRINK);
}

/** Adds the flag to a request config: omitted (engine default, guard on) unless checked. */
export function withAllowShrink(
  config: CreateConnectorFeedRequest['config'],
  configFields: readonly string[],
  allowShrink: boolean,
): CreateConnectorFeedRequest['config'] {
  return hasAllowShrink(configFields) && allowShrink ? { ...config, [ALLOW_SHRINK]: true } : config;
}

export function AllowShrinkField({
  id,
  checked,
  onCheckedChange,
  disabled,
}: {
  id: string;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <div className="flex items-start gap-2.5 rounded-md border border-border px-3 py-2.5">
      <Checkbox
        id={id}
        checked={checked}
        disabled={disabled}
        onCheckedChange={(v) => onCheckedChange(v === true)}
        className="mt-0.5"
      />
      <div className="space-y-0.5">
        <Label htmlFor={id} className="text-[12px] font-medium leading-snug cursor-pointer">
          Allow a full sync to drop more than half the directory
        </Label>
        <p className="text-[10.5px] text-muted-foreground leading-relaxed">
          Off by default: a full run that would leave fewer than half the previous users, or none, is refused and
          the directory stays unchanged. Sent as <span className="font-mono">{ALLOW_SHRINK}</span>.
        </p>
      </div>
    </div>
  );
}
