// SPDX-License-Identifier: AGPL-3.0-or-later
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';
import type {
  EmailRecipient,
  MailTransport,
  SmtpConfig,
  UpdateMailTransportRequest,
} from '@/lib/api/soar';
import { browserTenantRuntime } from '@/lib/tenant-runtime';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { SettingsSection } from '@/components/settings/SettingsSection';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { ConfirmDialog } from '@/components/ui/confirm-dialog';
import { FormSheet } from '@/components/ui/detail-sheet';

const reasonValid = (s: string) =>
  s.trim().length > 0 && new TextEncoder().encode(s.trim()).length <= 2048;
const message = (e: unknown) => {
  if ((e as { status?: number })?.status === 409)
    return 'The setting changed. It has been refreshed; review it before saving again.';
  return e instanceof Error
    ? e.message
    : 'Unable to save notification settings.';
};
const emptySmtp: SmtpConfig = {
  host: '',
  port: 587,
  tls: 'starttls',
  username: null,
  from: '',
};

export function SoarMailSettings({
  canEdit,
  enabled,
}: {
  canEdit: boolean;
  enabled: boolean;
}) {
  const client = useQueryClient();
  const tenant = browserTenantRuntime.current().key;
  const recipientsKey = ['soar-recipients', tenant];
  const transportKey = ['soar-mail-transport', tenant];
  const recipients = useQuery({
    queryKey: recipientsKey,
    queryFn: () => api.soar.getRecipients(),
  });
  const transport = useQuery({
    queryKey: transportKey,
    queryFn: () => api.soar.getMailTransport(),
  });
  const [newName, setNewName] = useState('');
  const [newAddress, setNewAddress] = useState('');
  const [editRecipient, setEditRecipient] = useState<{
    previous?: string;
    name: string;
    address: string;
    reason: string;
  } | null>(null);
  const [remove, setRemove] = useState<EmailRecipient | null>(null);
  const [editTransport, setEditTransport] = useState(false);
  const [testTo, setTestTo] = useState('');
  const refreshConflict = (e: unknown, queryKey: string[]) => {
    if ((e as { status?: number })?.status === 409)
      void client.invalidateQueries({ queryKey });
  };
  const saveRecipients = useMutation({
    mutationFn: ({
      list,
      reason,
    }: {
      list: EmailRecipient[];
      reason: string;
    }) =>
      api.soar.updateRecipients({
        recipients: list,
        expected_revision: recipients.data!.revision,
        reason,
      }),
    onSuccess: (value) => {
      client.setQueryData(recipientsKey, value);
      void client.invalidateQueries({ queryKey: ['soar-settings', tenant] });
      if (!editRecipient?.previous) {
        setNewName('');
        setNewAddress('');
      }
      setEditRecipient(null);
      setRemove(null);
    },
    onError: (e) => {
      refreshConflict(e, recipientsKey);
      if ((e as { status?: number })?.status === 409) {
        setEditRecipient(null);
        setRemove(null);
      }
    },
  });
  const test = useMutation({
    mutationFn: () => api.soar.sendTestEmail(testTo),
  });
  const list = recipients.data?.recipients ?? [];
  const selectedTest = list.some((r) => r.name === testTo) ? testTo : '';

  return (
    <>
      <SettingsSection
        title="Email recipients"
        description={
          <>
            Flows address recipients by name, such as{' '}
            <span className="font-mono">oncall</span>. Change an address here
            without editing each flow. Only tenant admins can edit destinations.
          </>
        }
      >
        {recipients.isError && (
          <p role="alert" className="p-4 text-destructive">
            {message(recipients.error)}
          </p>
        )}
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-4 py-2">
          <span className="font-mono text-[10.5px] text-muted-foreground">
            {recipients.data
              ? list.length +
                (list.length === 1 ? ' recipient' : ' recipients') +
                ' · revision ' +
                recipients.data.revision
              : recipients.isError
                ? 'Recipients unavailable'
                : 'Loading recipients…'}
          </span>
          {recipients.data && (
            <span className="font-mono text-[10.5px] text-muted-foreground">
              {recipients.data.daily_send_cap} emails / UTC day, including tests
            </span>
          )}
        </div>
        {list.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[400px] text-left text-[11.5px]">
              <thead className="sr-only">
                <tr>
                  <th>Name</th>
                  <th>Email address</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {list.map((r) => (
                  <tr
                    key={r.name}
                    className="h-7 border-b border-border last:border-b-0"
                  >
                    <td
                      className="max-w-[160px] truncate px-4 py-0 font-mono"
                      title={r.name}
                    >
                      {r.name}
                    </td>
                    <td
                      className="max-w-[220px] truncate py-0 font-mono text-muted-foreground"
                      title={r.address}
                    >
                      {r.address}
                    </td>
                    <td className="whitespace-nowrap px-2 py-0 text-right">
                      {canEdit && (
                        <>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 px-1.5 text-[11px] text-muted-foreground shadow-none"
                            onClick={() => {
                              saveRecipients.reset();
                              setEditRecipient({
                                previous: r.name,
                                ...r,
                                reason: '',
                              });
                            }}
                            disabled={saveRecipients.isPending}
                            aria-label={'Edit ' + r.name}
                          >
                            Edit
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-7 px-1.5 text-[11px] text-muted-foreground hover:text-destructive shadow-none"
                            onClick={() => {
                              saveRecipients.reset();
                              setRemove(r);
                            }}
                            disabled={saveRecipients.isPending}
                            aria-label={'Remove ' + r.name}
                          >
                            Remove
                          </Button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          recipients.data && (
            <div className="px-4 py-5 text-[11.5px] text-muted-foreground">
              <p className="font-medium text-foreground">
                No recipients configured
              </p>
              <p className="mt-1">
                Add a named destination such as{' '}
                <span className="font-mono">oncall</span> before a flow can send
                email.
              </p>
            </div>
          )
        )}
        {canEdit ? (
          <form
            className="grid gap-2 border-t border-border p-3 sm:grid-cols-[minmax(80px,0.7fr)_minmax(120px,1.5fr)_auto]"
            onSubmit={(event) => {
              event.preventDefault();
              saveRecipients.reset();
              setEditRecipient({
                name: newName,
                address: newAddress,
                reason: '',
              });
            }}
          >
            <Input
              aria-label="New recipient name"
              value={newName}
              onChange={(event) => setNewName(event.target.value)}
              placeholder="oncall"
              maxLength={64}
              className="h-7 min-w-0 font-mono text-[11.5px] shadow-none"
              disabled={
                !recipients.data ||
                saveRecipients.isPending ||
                list.length >= 50
              }
            />
            <Input
              aria-label="New recipient email address"
              value={newAddress}
              onChange={(event) => setNewAddress(event.target.value)}
              type="email"
              placeholder="oncall@example.com"
              maxLength={254}
              className="h-7 min-w-0 font-mono text-[11.5px] shadow-none"
              disabled={
                !recipients.data ||
                saveRecipients.isPending ||
                list.length >= 50
              }
            />
            <Button
              type="submit"
              variant="outline"
              size="sm"
              className="h-7 px-2.5 text-[11.5px] shadow-none"
              disabled={
                !recipients.data ||
                saveRecipients.isPending ||
                list.length >= 50
              }
            >
              Add recipient
            </Button>
            <p className="text-[10.5px] text-muted-foreground sm:col-span-3">
              {list.length >= 50
                ? 'The 50-recipient limit has been reached.'
                : 'Review the destination and provide an audit reason before saving.'}
            </p>
          </form>
        ) : (
          <p className="border-t border-border px-4 py-2 text-[11px] text-muted-foreground">
            Read-only. A tenant admin manages recipients.
          </p>
        )}
      </SettingsSection>

      <SettingsSection
        title="Mail transport"
        description="Use the nano mailer or your own SMTP relay. Send a test to a named recipient to check delivery. Tests count toward the daily limit."
      >
        <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
          <div className="min-w-0 space-y-1">
            <div className="flex items-center gap-2">
              <p className="text-[12.5px] font-semibold">
                {transport.data
                  ? transport.data.transport === 'smtp'
                    ? 'Your SMTP server'
                    : 'nano mailer'
                  : 'Mail transport'}
              </p>
              {transport.data?.transport === 'nano' && (
                <Badge
                  variant="secondary"
                  className="rounded-sm font-mono text-[10.5px] font-normal"
                >
                  DEFAULT
                </Badge>
              )}
            </div>
            <p className="font-mono text-[10.5px] text-muted-foreground">
              {transport.data
                ? transport.data.transport === 'smtp' && transport.data.smtp
                  ? transport.data.smtp.host +
                    ':' +
                    transport.data.smtp.port +
                    ' · ' +
                    transport.data.smtp.tls +
                    ' · revision ' +
                    transport.data.revision
                  : 'revision ' + transport.data.revision
                : transport.isError
                  ? 'Transport unavailable'
                  : 'Loading transport…'}
            </p>
            {transport.data?.transport === 'smtp' && transport.data.smtp && (
              <p className="font-mono text-[10.5px] text-muted-foreground">
                from {transport.data.smtp.from}
              </p>
            )}
            {transport.data?.transport === 'nano' &&
              !transport.data.nano_mailer_available && (
                <p className="text-[11.5px] text-muted-foreground">
                  No transport configured. Configure your SMTP server.
                </p>
              )}
          </div>
          {canEdit && (
            <Button
              variant="outline"
              size="sm"
              className="h-7 px-2.5 text-[11.5px] shadow-none"
              disabled={!transport.data}
              onClick={() => setEditTransport(true)}
            >
              Configure transport
            </Button>
          )}
        </div>
        {transport.isError && (
          <p
            role="alert"
            className="border-t border-border px-4 py-3 text-destructive"
          >
            {message(transport.error)}
          </p>
        )}
        {canEdit && (
          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border bg-muted/20 px-4 py-3">
            <p className="text-[11px] text-muted-foreground">
              {!enabled
                ? 'Enable SOAR to send a test email.'
                : list.length === 0
                  ? 'Add a recipient to send a test email.'
                  : 'Send a test to confirm delivery.'}
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <Select
                value={selectedTest}
                onValueChange={(value) => {
                  setTestTo(value);
                  test.reset();
                }}
                disabled={!enabled || list.length === 0 || test.isPending}
              >
                <SelectTrigger
                  aria-label="Test email recipient"
                  className="h-7 w-[150px] font-mono text-[11px] shadow-none"
                >
                  <SelectValue placeholder="Select recipient" />
                </SelectTrigger>
                <SelectContent className="rounded-md shadow-none">
                  {list.map((r) => (
                    <SelectItem
                      key={r.name}
                      value={r.name}
                      className="font-mono text-[11.5px]"
                    >
                      {r.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button
                variant="outline"
                size="sm"
                className="h-7 px-2.5 text-[11.5px] shadow-none"
                disabled={
                  !enabled ||
                  !selectedTest ||
                  test.isPending ||
                  !transport.data ||
                  (transport.data.transport === 'smtp' &&
                    !transport.data.smtp) ||
                  (transport.data.transport === 'nano' &&
                    !transport.data.nano_mailer_available)
                }
                onClick={() => test.mutate()}
              >
                Send test email
              </Button>
            </div>
          </div>
        )}
        {test.isError && (
          <p
            role="alert"
            className="border-t border-border px-4 py-3 text-destructive"
          >
            {message(test.error)}
          </p>
        )}
        {test.data && (
          <p
            role={
              ['sent', 'queued'].includes(test.data.status) ? 'status' : 'alert'
            }
            className={
              'border-t border-border px-4 py-3 ' +
              (['sent', 'queued'].includes(test.data.status)
                ? 'text-muted-foreground'
                : 'text-destructive')
            }
          >
            {test.data.status === 'sent'
              ? 'Test email sent.'
              : test.data.status === 'queued'
                ? 'Test email queued for delivery.'
                : test.data.status === 'ambiguous'
                  ? 'Delivery could not be confirmed. Check the mailbox before sending another test.'
                  : 'Test email failed. Review the transport settings.'}
          </p>
        )}
      </SettingsSection>
      <Dialog
        open={canEdit && !!editRecipient}
        onOpenChange={(open) => {
          if (!open && !saveRecipients.isPending) setEditRecipient(null);
        }}
      >
        <DialogContent className="shadow-none sm:max-w-[420px]">
          <DialogHeader>
            <DialogTitle>
              {editRecipient?.previous ? 'Edit recipient' : 'Add recipient'}
            </DialogTitle>
            <DialogDescription>
              Flows use the name to send email to this address.
            </DialogDescription>
          </DialogHeader>
          {editRecipient && (
            <form
              className="space-y-3"
              onSubmit={(e) => {
                e.preventDefault();
                saveRecipients.mutate({
                  list: [
                    ...list.filter((r) => r.name !== editRecipient.previous),
                    {
                      name: editRecipient.name.trim(),
                      address: editRecipient.address.trim(),
                    },
                  ],
                  reason: editRecipient.reason.trim(),
                });
              }}
            >
              <label className="block space-y-1 text-xs">
                Name
                <Input
                  aria-label="Recipient name"
                  pattern="[a-z][a-z0-9_]{0,63}"
                  required
                  maxLength={64}
                  value={editRecipient.name}
                  onChange={(e) =>
                    setEditRecipient({ ...editRecipient, name: e.target.value })
                  }
                  className="h-7 font-mono text-xs"
                  placeholder="oncall"
                />
              </label>
              <label className="block space-y-1 text-xs">
                Email address
                <Input
                  aria-label="Recipient email address"
                  type="email"
                  required
                  maxLength={254}
                  value={editRecipient.address}
                  onChange={(e) =>
                    setEditRecipient({
                      ...editRecipient,
                      address: e.target.value,
                    })
                  }
                  className="h-7 font-mono text-xs"
                />
              </label>
              <label className="block space-y-1 text-xs">
                Reason
                <Textarea
                  aria-label="Recipient change reason"
                  required
                  value={editRecipient.reason}
                  onChange={(e) =>
                    setEditRecipient({
                      ...editRecipient,
                      reason: e.target.value,
                    })
                  }
                  className="min-h-[56px] text-xs"
                />
              </label>
              {saveRecipients.isError && (
                <p role="alert" className="text-xs text-destructive">
                  {message(saveRecipients.error)}
                </p>
              )}
              <DialogFooter>
                <Button
                  type="submit"
                  size="sm"
                  className="h-7 text-[11.5px] shadow-none"
                  disabled={
                    saveRecipients.isPending ||
                    !reasonValid(editRecipient.reason)
                  }
                >
                  Save recipient
                </Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={canEdit && !!remove}
        className="rounded-md shadow-none [&_button]:h-7"
        confirmClassName="bg-destructive text-destructive-foreground hover:bg-destructive/90"
        onOpenChange={(open) => {
          if (!open && !saveRecipients.isPending) setRemove(null);
        }}
        title="Remove notification recipient?"
        description={`Flows using “${remove?.name ?? ''}” will fail validation and stop sending to this recipient.`}
        confirmLabel="Remove recipient"
        variant="danger"
        onConfirm={() => {
          if (remove)
            saveRecipients.mutate({
              list: list.filter((r) => r.name !== remove.name),
              reason: `Removed notification recipient ${remove.name}`,
            });
        }}
      />
      {saveRecipients.isError && !editRecipient && (
        <p role="alert" className="text-destructive">
          {message(saveRecipients.error)}
        </p>
      )}
      {canEdit && transport.data && editTransport && (
        <TransportEditor
          key={transport.data.revision}
          open={editTransport}
          onOpenChange={setEditTransport}
          current={transport.data}
          onSaved={(value) => client.setQueryData(transportKey, value)}
          onConflict={() =>
            void client.invalidateQueries({ queryKey: transportKey })
          }
        />
      )}
    </>
  );
}

function TransportEditor({
  open,
  onOpenChange,
  current,
  onSaved,
  onConflict,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  current: MailTransport;
  onSaved: (value: MailTransport) => void;
  onConflict: () => void;
}) {
  const [kind, setKind] = useState(
    current.transport === 'nano' && !current.nano_mailer_available
      ? 'smtp'
      : current.transport,
  );
  const [smtp, setSmtp] = useState<SmtpConfig>(current.smtp ?? emptySmtp);
  const [password, setPassword] = useState('');
  const [clearPassword, setClearPassword] = useState(false);
  const [reason, setReason] = useState('');
  const save = useMutation({
    mutationFn: (body: UpdateMailTransportRequest) =>
      api.soar.updateMailTransport(body),
    onSuccess: (value) => {
      onSaved(value);
      setPassword('');
      setReason('');
      onOpenChange(false);
    },
    onError: (e) => {
      if ((e as { status?: number })?.status === 409) onConflict();
    },
  });
  const field = (key: keyof SmtpConfig, value: string | number | null) =>
    setSmtp((old) => ({ ...old, [key]: value }));
  return (
    <FormSheet
      open={open}
      onOpenChange={(value) => {
        if (!save.isPending) onOpenChange(value);
      }}
      size="md"
      className="shadow-none"
      breadcrumb={['Settings', 'SOAR']}
      title="Mail transport"
      description="Use the nano mailer or your own SMTP server. TLS is required."
      pending={save.isPending}
      submitDisabled={!reasonValid(reason)}
      onSubmit={() =>
        save.mutate({
          transport: kind,
          smtp: kind === 'smtp' ? smtp : null,
          ...(kind === 'smtp' && (password || clearPassword)
            ? { password: clearPassword ? '' : password }
            : {}),
          expected_revision: current.revision,
          reason: reason.trim(),
        })
      }
    >
      <div className="space-y-3 text-xs">
        <label className="block space-y-1">
          Transport
          <Select
            value={kind}
            onValueChange={(value) => setKind(value as 'nano' | 'smtp')}
          >
            <SelectTrigger
              aria-label="Mail transport"
              className="h-7 text-xs shadow-none"
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="rounded-md shadow-none">
              <SelectItem
                value="nano"
                disabled={!current.nano_mailer_available}
              >
                nano mailer
                {!current.nano_mailer_available ? ' (unavailable)' : ''}
              </SelectItem>
              <SelectItem value="smtp">Your SMTP server</SelectItem>
            </SelectContent>
          </Select>
        </label>
        {kind === 'smtp' && (
          <>
            <label className="block space-y-1">
              Host
              <Input
                aria-label="SMTP host"
                value={smtp.host}
                onChange={(e) =>
                  field('host', e.target.value.trim().toLowerCase())
                }
                required
                maxLength={253}
                className="h-7 font-mono text-xs"
              />
            </label>
            <label className="block space-y-1">
              Port
              <Input
                aria-label="SMTP port"
                type="number"
                min={1}
                max={65535}
                value={smtp.port}
                onChange={(e) => field('port', Number(e.target.value))}
                required
                className="h-7 font-mono text-xs"
              />
            </label>
            <p className="text-xs text-muted-foreground">
              Hosted deployments: allow a few minutes after changing the port
              before sending a test email.
            </p>
            <label className="block space-y-1">
              TLS mode
              <Select
                value={smtp.tls}
                onValueChange={(value) => field('tls', value)}
              >
                <SelectTrigger
                  aria-label="SMTP TLS mode"
                  className="h-7 text-xs shadow-none"
                >
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="rounded-md shadow-none">
                  <SelectItem value="starttls">STARTTLS (required)</SelectItem>
                  <SelectItem value="implicit_tls">Implicit TLS</SelectItem>
                </SelectContent>
              </Select>
            </label>
            <label className="block space-y-1">
              From address
              <Input
                aria-label="SMTP From address"
                type="email"
                required
                value={smtp.from}
                onChange={(e) => field('from', e.target.value)}
                className="h-7 font-mono text-xs"
              />
            </label>
            <label className="block space-y-1">
              Username (optional)
              <Input
                aria-label="SMTP username"
                autoComplete="off"
                value={smtp.username ?? ''}
                onChange={(e) => field('username', e.target.value || null)}
                className="h-7 font-mono text-xs"
              />
            </label>
            <label className="block space-y-1">
              Password
              <Input
                aria-label="SMTP password"
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  setClearPassword(false);
                }}
                placeholder={
                  current.has_password
                    ? 'Stored password retained when blank'
                    : 'Optional'
                }
                className="h-7 text-xs"
              />
            </label>
            {current.has_password && (
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={clearPassword}
                  onChange={(e) => {
                    setClearPassword(e.target.checked);
                    setPassword('');
                  }}
                />
                Remove stored password
              </label>
            )}
            <p className="text-[11px] text-muted-foreground">
              Hosted delivery permits only this host and port through the tenant
              egress policy.
            </p>
          </>
        )}
        <label className="block space-y-1">
          Reason
          <Textarea
            aria-label="Transport change reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            required
            className="min-h-[56px] text-xs"
          />
        </label>
        {save.isError && (
          <p role="alert" className="text-destructive">
            {message(save.error)}
          </p>
        )}
      </div>
    </FormSheet>
  );
}
