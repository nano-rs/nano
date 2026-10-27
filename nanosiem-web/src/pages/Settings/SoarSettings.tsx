// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import type { SoarSettings as SoarSettingsValue } from '@/lib/api/soar';
import { browserTenantRuntime } from '@/lib/tenant-runtime';
import { useAuth } from '@/contexts/AuthContext';
import { useCapabilities } from '@/hooks/use-capabilities';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { SettingsSection } from '@/components/settings/SettingsSection';
import { SoarMailSettings } from './SoarMailSettings';
import { DemoSoarSettings } from './DemoSoarSettings';
import { SoarPackUpdates } from './SoarPackUpdates';

const SOAR_REASON_MAX_BYTES = 2048;
const SOAR_DISABLE_WARNING =
  'New runs stop, active runs are canceled and pending approvals expire with reason “soar disabled”. A request already sent to a vendor cannot be undone. History, connections and installed packs stay stored until removed.';
function errorStatus(error: unknown): number | undefined {
  const status = (error as { status?: unknown } | null)?.status;
  return typeof status === 'number' ? status : undefined;
}
function saveErrorMessage(error: unknown): string {
  switch (errorStatus(error)) {
    case 409:
      return 'The SOAR setting changed since you loaded it. It has been refreshed. Review it and save again.';
    case 503:
      return 'Another change to this setting is in progress. Try again in a moment.';
    case 403:
      return 'Only a tenant admin signed in to the web app can change SOAR. API keys cannot change it.';
    default:
      return error instanceof Error && error.message
        ? error.message
        : 'Unable to save the SOAR setting.';
  }
}
export function SoarSettings() {
  useDocumentTitle('SOAR');
  const { capabilities } = useCapabilities();
  const { user } = useAuth();
  if (!capabilities.soar)
    return (
      <p className="px-6 py-5 text-xs text-muted-foreground">
        SOAR is not available for this tenant.
      </p>
    );
  if (
    user?.demo ||
    user?.roles?.some((role) => role.trim().toLowerCase() === 'demo_analyst')
  )
    return <DemoSoarSettings />;
  return <SoarSettingsPanel />;
}

function SoarSettingsPanel() {
  const { hasPermission } = useAuth();
  const canEdit = hasPermission('settings:system');
  const client = useQueryClient();
  const tenant = browserTenantRuntime.current().key;
  const queryKey = ['soar-settings', tenant];
  const settings = useQuery({
    queryKey,
    queryFn: () => api.soar.getSettings(),
    staleTime: 0,
  });
  const [reason, setReason] = useState('');
  // Freeze the intended action. A 409 refresh must never reverse Enable/Disable.
  const [intent, setIntent] = useState<{ enabled: boolean } | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: (next: {
      enabled: boolean;
      revision: number;
      reason: string;
    }) =>
      api.soar.updateSettings({
        soar_enabled: next.enabled,
        expected_revision: next.revision,
        reason: next.reason,
      }),
    onMutate: () => setSaved(null),
    onSuccess: (value: SoarSettingsValue) => {
      client.setQueryData(queryKey, value);
      void client.invalidateQueries({ queryKey: ['soar-recipients', tenant] });
      setReason('');
      setIntent(null);
      setSaved(value.soar_enabled ? 'SOAR enabled.' : 'SOAR disabled.');
    },
    onError: (error) => {
      if (errorStatus(error) === 409)
        void client.invalidateQueries({ queryKey });
    },
  });
  const current = settings.data;
  const bytes = new TextEncoder().encode(reason.trim()).length;
  const valid = reason.trim().length > 0 && bytes <= SOAR_REASON_MAX_BYTES;
  const busy = save.isPending || settings.isFetching;
  const changed = !!(
    intent &&
    current &&
    current.soar_enabled === intent.enabled
  );

  return (
    <div className="max-w-[1160px] space-y-6 px-6 py-5 text-xs">
      <header className="space-y-2">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="text-[18px] font-semibold tracking-tight text-foreground">
              SOAR
            </h1>
            <p className="mt-1 text-[11.5px] leading-relaxed text-muted-foreground">
              Automated response for this tenant. Off by default; every change
              is audited with your reason.
            </p>
          </div>
          {hasPermission('audit:view') && (
            <Button
              asChild
              variant="link"
              size="sm"
              className="h-7 px-0 text-[11.5px] shadow-none"
            >
              <Link to="/settings/audit?action=soar.settings.updated">
                View audit history
              </Link>
            </Button>
          )}
        </div>
        <p className="font-mono text-[10.5px] text-muted-foreground">
          {current
            ? (current.soar_enabled ? 'enabled' : 'disabled') +
              ' · revision ' +
              current.revision
            : 'Loading settings…'}
        </p>
      </header>
      {settings.isError && (
        <p role="alert" className="text-destructive">
          {settings.error instanceof Error
            ? settings.error.message
            : 'Unable to load the SOAR setting.'}
        </p>
      )}
      <div className="space-y-5">
        <SettingsSection
          title="Status"
          description="Controls whether this tenant can run automated response actions. Only a tenant admin can change this setting."
        >
          {current ? (
            <>
              <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
                <div className="flex min-w-0 items-center gap-3">
                  <span
                    aria-hidden="true"
                    className={
                      'size-2 shrink-0 rounded-full ' +
                      (current.soar_enabled
                        ? 'bg-primary'
                        : 'bg-muted-foreground')
                    }
                  />
                  <div>
                    <p className="text-[12.5px] font-semibold">
                      {current.soar_enabled ? 'Enabled' : 'Disabled'}
                      <span className="font-normal text-muted-foreground">
                        {' '}
                        ·{' '}
                        {current.soar_enabled
                          ? 'response actions can run'
                          : 'automation is off'}
                      </span>
                    </p>
                    <p className="mt-1 font-mono text-[10.5px] text-muted-foreground">
                      revision {current.revision}
                    </p>
                  </div>
                </div>
                {canEdit && !intent && (
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-7 px-2.5 text-[11.5px] shadow-none"
                    disabled={busy}
                    onClick={() => {
                      save.reset();
                      setSaved(null);
                      setReason('');
                      setIntent({ enabled: !current.soar_enabled });
                    }}
                  >
                    {current.soar_enabled ? 'Disable SOAR…' : 'Enable SOAR…'}
                  </Button>
                )}
              </div>
              {!canEdit && (
                <p className="border-t border-border px-4 py-3 text-[11px] text-muted-foreground">
                  Read-only. Changing SOAR requires the{' '}
                  <span className="font-mono">settings:system</span> permission.
                </p>
              )}
              {canEdit && intent && (
                <form
                  className="space-y-3 border-t border-border bg-muted/20 p-4"
                  onSubmit={(event) => {
                    event.preventDefault();
                    if (!busy && valid && !changed)
                      save.mutate({
                        enabled: intent.enabled,
                        revision: current.revision,
                        reason: reason.trim(),
                      });
                  }}
                >
                  {!intent.enabled && (
                    <p className="text-[11.5px] leading-relaxed text-destructive">
                      {SOAR_DISABLE_WARNING}
                    </p>
                  )}
                  <div className="flex items-center justify-between gap-2">
                    <label
                      htmlFor="soar-change-reason"
                      className="text-[11.5px] font-medium"
                    >
                      {intent.enabled
                        ? 'Why are you enabling SOAR?'
                        : 'Why are you disabling SOAR?'}
                    </label>
                    <span
                      className={
                        'font-mono text-[10.5px] ' +
                        (bytes > SOAR_REASON_MAX_BYTES
                          ? 'text-destructive'
                          : 'text-muted-foreground')
                      }
                    >
                      {bytes} / {SOAR_REASON_MAX_BYTES} bytes
                    </span>
                  </div>
                  <Textarea
                    id="soar-change-reason"
                    aria-label="Reason"
                    autoFocus
                    className="min-h-[64px] text-xs shadow-none"
                    value={reason}
                    onChange={(event) => setReason(event.target.value)}
                    disabled={save.isPending}
                    placeholder="Describe why this setting is changing"
                  />
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <p className="text-[11px] text-muted-foreground">
                      {changed
                        ? 'Another admin already made this change. Cancel to review the current setting.'
                        : 'Required. Saved in the audit log with this change.'}
                    </p>
                    <div className="flex gap-2">
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className="h-7 px-2.5 text-[11.5px] shadow-none"
                        disabled={save.isPending}
                        onClick={() => {
                          setIntent(null);
                          setReason('');
                          save.reset();
                        }}
                      >
                        Cancel
                      </Button>
                      <Button
                        type="submit"
                        variant={intent.enabled ? 'default' : 'destructive'}
                        size="sm"
                        className="h-7 px-2.5 text-[11.5px] shadow-none"
                        disabled={busy || !valid || changed}
                      >
                        {save.isPending
                          ? 'Saving…'
                          : intent.enabled
                            ? 'Enable SOAR'
                            : 'Disable SOAR'}
                      </Button>
                    </div>
                  </div>
                </form>
              )}
            </>
          ) : (
            <p className="p-4 text-muted-foreground">
              {settings.isError
                ? 'SOAR status is unavailable.'
                : 'Loading SOAR status…'}
            </p>
          )}
          {save.isError && (
            <p
              role="alert"
              className="border-t border-border px-4 py-3 text-destructive"
            >
              {saveErrorMessage(save.error)}
            </p>
          )}
          {saved && !save.isError && (
            <p
              role="status"
              className="border-t border-border px-4 py-3 text-muted-foreground"
            >
              {saved}
            </p>
          )}
        </SettingsSection>
        <SoarPackUpdates key={tenant} enabled={current?.soar_enabled ?? false} />
        <SoarMailSettings
          canEdit={canEdit}
          enabled={current?.soar_enabled ?? false}
        />
      </div>
    </div>
  );
}
