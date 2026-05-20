// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react';
import { X, Plus, Radio, Zap } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { IpAllowlistInput } from './IpAllowlistInput';
import { TlsConfigSection } from './TlsConfigSection';
import { CredentialPicker } from './CredentialPicker';
import type { TlsSourceConfig } from '@/lib/api/types';

const FIELD_LABEL =
  'text-[10.5px] font-mono uppercase tracking-[0.12em] text-muted-foreground';
const HELP_TEXT = 'text-[10.5px] text-muted-foreground leading-relaxed';
const INPUT_BASE = 'h-8 text-[12px] bg-card';
const INPUT_MONO = 'h-8 text-[12px] font-mono bg-card';
const SELECT_TRIGGER = 'h-8 text-[12px] bg-card';
const SELECT_ITEM = 'text-[12px]';

interface SourceConfigFormProps {
  sourceType: string;
  config: Record<string, unknown>;
  onConfigChange: (config: Record<string, unknown>) => void;
  credentialId: string | undefined;
  onCredentialChange: (id: string | undefined) => void;
  disabled?: boolean;
}

export function SourceConfigForm({
  sourceType,
  config,
  onConfigChange,
  credentialId,
  onCredentialChange,
  disabled,
}: SourceConfigFormProps) {
  switch (sourceType) {
    case 'kafka':
      return (
        <KafkaConfigForm
          config={config}
          onChange={onConfigChange}
          credentialId={credentialId}
          onCredentialChange={onCredentialChange}
          disabled={disabled}
        />
      );

    case 'aws_s3':
      return (
        <S3ConfigForm
          config={config}
          onChange={onConfigChange}
          credentialId={credentialId}
          onCredentialChange={onCredentialChange}
          disabled={disabled}
        />
      );

    case 'gcp_pubsub':
      return (
        <GcpPubSubConfigForm
          config={config}
          onChange={onConfigChange}
          credentialId={credentialId}
          onCredentialChange={onCredentialChange}
          disabled={disabled}
        />
      );

    case 'splunk_hec':
      return <SplunkHecConfigForm />;

    case 'vector':
      return (
        <VectorConfigForm
          config={config}
          onChange={onConfigChange}
          disabled={disabled}
        />
      );

    case 'routed':
    default:
      return (
        <div className="p-4 bg-muted/30 rounded-md text-center text-muted-foreground">
          <Radio className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p className="text-[12px]">
            HTTP sources receive logs via the ingestion endpoint.
          </p>
          <p className="text-[10.5px] mt-2">
            No additional configuration required. Logs are routed by the{' '}
            <code className="font-mono bg-muted px-1 rounded">X-Source-Type</code> header.
          </p>
        </div>
      );
  }
}

// ============================================================================
// Individual Source Config Forms
// ============================================================================

interface FormProps {
  config: Record<string, unknown>;
  onChange: (config: Record<string, unknown>) => void;
  disabled?: boolean;
}

interface FormWithCredentialsProps extends FormProps {
  credentialId: string | undefined;
  onCredentialChange: (id: string | undefined) => void;
}

function KafkaConfigForm({ config, onChange, credentialId, onCredentialChange, disabled }: FormWithCredentialsProps) {
  const [topicInput, setTopicInput] = useState('');

  const topics = (config.topics as string[]) || [];

  const addTopic = () => {
    const trimmed = topicInput.trim();
    if (trimmed && !topics.includes(trimmed)) {
      onChange({ ...config, topics: [...topics, trimmed] });
      setTopicInput('');
    }
  };

  const removeTopic = (topic: string) => {
    onChange({ ...config, topics: topics.filter(t => t !== topic) });
  };

  return (
    <div className="space-y-3">
      <div className="space-y-1.5">
        <Label className={FIELD_LABEL}>Bootstrap Servers</Label>
        <Input
          value={(config.bootstrap_servers as string) || ''}
          onChange={(e) => onChange({ ...config, bootstrap_servers: e.target.value })}
          placeholder="kafka-1:9092,kafka-2:9092"
          disabled={disabled}
          className={INPUT_MONO}
        />
        <p className={HELP_TEXT}>Comma-separated list of Kafka brokers</p>
      </div>

      <div className="space-y-1.5">
        <Label className={FIELD_LABEL}>Topics</Label>
        <div className="flex gap-2">
          <Input
            value={topicInput}
            onChange={(e) => setTopicInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addTopic())}
            placeholder="logs, events"
            disabled={disabled}
            className={`flex-1 ${INPUT_MONO}`}
          />
          <Button
            type="button"
            variant="outline"
            size="icon"
            onClick={addTopic}
            disabled={disabled}
            className="h-8 w-8"
          >
            <Plus className="w-3.5 h-3.5" />
          </Button>
        </div>
        {topics.length > 0 && (
          <div className="flex flex-wrap gap-1.5 pt-1">
            {topics.map((topic) => (
              <div
                key={topic}
                className="flex items-center gap-1 px-1.5 py-0.5 bg-muted rounded-[4px] text-[11px] font-mono"
              >
                {topic}
                <button type="button" onClick={() => removeTopic(topic)} disabled={disabled}>
                  <X className="w-3 h-3 hover:text-red-400" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1.5">
          <Label className={FIELD_LABEL}>Consumer Group ID</Label>
          <Input
            value={(config.group_id as string) || ''}
            onChange={(e) => onChange({ ...config, group_id: e.target.value })}
            placeholder="nano"
            disabled={disabled}
            className={INPUT_MONO}
          />
        </div>

        <div className="space-y-1.5">
          <Label className={FIELD_LABEL}>Auto Offset Reset</Label>
          <Select
            value={(config.auto_offset_reset as string) || 'latest'}
            onValueChange={(v) => onChange({ ...config, auto_offset_reset: v })}
            disabled={disabled}
          >
            <SelectTrigger className={SELECT_TRIGGER}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="latest" className={SELECT_ITEM}>
                Latest (new messages only)
              </SelectItem>
              <SelectItem value="earliest" className={SELECT_ITEM}>
                Earliest (all messages)
              </SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <CredentialPicker
        provider="kafka"
        value={credentialId}
        onChange={onCredentialChange}
        disabled={disabled}
      />
    </div>
  );
}

function S3ConfigForm({ config, onChange, credentialId, onCredentialChange, disabled }: FormWithCredentialsProps) {
  const AWS_REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
    'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-south-1',
    'sa-east-1', 'ca-central-1',
  ];

  return (
    <div className="space-y-3">
      <div className="space-y-1.5">
        <Label className={FIELD_LABEL}>SQS Queue URL *</Label>
        <Input
          value={(config.sqs_queue_url as string) || ''}
          onChange={(e) => onChange({ ...config, sqs_queue_url: e.target.value })}
          placeholder="https://sqs.us-east-1.amazonaws.com/123456789/my-queue"
          disabled={disabled}
          className={INPUT_MONO}
        />
        <p className={HELP_TEXT}>SQS queue that receives S3 bucket notifications</p>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1.5">
          <Label className={FIELD_LABEL}>AWS Region</Label>
          <Select
            value={(config.region as string) || 'us-east-1'}
            onValueChange={(v) => onChange({ ...config, region: v })}
            disabled={disabled}
          >
            <SelectTrigger className={SELECT_TRIGGER}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="max-h-64">
              {AWS_REGIONS.map((region) => (
                <SelectItem key={region} value={region} className={SELECT_ITEM}>
                  {region}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-1.5">
          <Label className={FIELD_LABEL}>Compression</Label>
          <Select
            value={(config.compression as string) || 'auto'}
            onValueChange={(v) => onChange({ ...config, compression: v === 'auto' ? undefined : v })}
            disabled={disabled}
          >
            <SelectTrigger className={SELECT_TRIGGER}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="auto" className={SELECT_ITEM}>
                Auto-detect
              </SelectItem>
              <SelectItem value="gzip" className={SELECT_ITEM}>
                Gzip
              </SelectItem>
              <SelectItem value="zstd" className={SELECT_ITEM}>
                Zstd
              </SelectItem>
              <SelectItem value="none" className={SELECT_ITEM}>
                None
              </SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="space-y-1.5">
        <Label className={FIELD_LABEL}>Custom Endpoint (optional)</Label>
        <Input
          value={(config.endpoint as string) || ''}
          onChange={(e) => onChange({ ...config, endpoint: e.target.value || undefined })}
          placeholder="https://minio.example.com:9000"
          disabled={disabled}
          className={INPUT_MONO}
        />
        <p className={HELP_TEXT}>For S3-compatible storage like MinIO</p>
      </div>

      <CredentialPicker
        provider="aws_s3"
        value={credentialId}
        onChange={onCredentialChange}
        disabled={disabled}
      />
    </div>
  );
}

const PUBSUB_PATH_RE = /^projects\/([^/]+)\/subscriptions\/([^/]+)$/;

function GcpPubSubConfigForm({ config, onChange, credentialId, onCredentialChange, disabled }: FormWithCredentialsProps) {
  const splitFullPath = (raw: string): { project: string; subscription: string } | null => {
    const match = PUBSUB_PATH_RE.exec(raw.trim());
    return match ? { project: match[1], subscription: match[2] } : null;
  };

  return (
    <div className="space-y-3">
      <div className="space-y-1.5">
        <Label className={FIELD_LABEL}>GCP Project ID *</Label>
        <Input
          value={(config.project as string) || ''}
          onChange={(e) => onChange({ ...config, project: e.target.value })}
          placeholder="my-gcp-project"
          disabled={disabled}
          className={INPUT_MONO}
        />
      </div>

      <div className="space-y-1.5">
        <Label className={FIELD_LABEL}>Subscription Name *</Label>
        <Input
          value={(config.subscription as string) || ''}
          onChange={(e) => onChange({ ...config, subscription: e.target.value })}
          onPaste={(e) => {
            const pasted = e.clipboardData.getData('text');
            const parts = splitFullPath(pasted);
            if (parts) {
              e.preventDefault();
              onChange({ ...config, project: parts.project, subscription: parts.subscription });
            }
          }}
          onBlur={(e) => {
            const parts = splitFullPath(e.target.value);
            if (parts) {
              onChange({ ...config, project: parts.project, subscription: parts.subscription });
            }
          }}
          placeholder="my-subscription"
          disabled={disabled}
          className={INPUT_MONO}
        />
        <p className={HELP_TEXT}>
          Short name only (e.g. <span className="font-mono">my-subscription</span>). Pasting a full{' '}
          <span className="font-mono">projects/.../subscriptions/...</span> path will split it into the two fields.
        </p>
      </div>

      <div className="space-y-1.5">
        <Label className={FIELD_LABEL}>ACK Deadline (seconds)</Label>
        <Input
          type="number"
          value={(config.ack_deadline_secs as number) || 600}
          onChange={(e) => onChange({ ...config, ack_deadline_secs: parseInt(e.target.value) || 600 })}
          placeholder="600"
          disabled={disabled}
          className={INPUT_BASE}
        />
      </div>

      <CredentialPicker
        provider="gcp_pubsub"
        value={credentialId}
        onChange={onCredentialChange}
        disabled={disabled}
      />
    </div>
  );
}

// NAN-883 / NAN-855: HEC is served by the OOTB `splunk_hec_ingest` listener
// (config/vector/02-hec-source.toml, :8088, shared `${VECTOR_AUTH_TOKEN}`).
// A user HEC source config is a routing profile only — `address`,
// `valid_tokens`, `permit_origin`, and `tls` no longer have any effect at
// deploy time, so the form has nothing per-config to ask for.
function SplunkHecConfigForm() {
  return (
    <div className="p-4 bg-muted/30 rounded-md text-center text-muted-foreground">
      <Zap className="w-8 h-8 mx-auto mb-2 opacity-50" />
      <p className="text-[12px]">
        Splunk HEC events arrive on the platform-managed listener.
      </p>
      <p className="text-[10.5px] mt-2 leading-relaxed">
        No per-config connection settings. Events are accepted on{' '}
        <code className="font-mono bg-muted px-1 rounded">:8088</code> with the shared{' '}
        <code className="font-mono bg-muted px-1 rounded">VECTOR_AUTH_TOKEN</code> and routed
        by the rules on this page based on the in-band{' '}
        <code className="font-mono bg-muted px-1 rounded">sourcetype</code> field.
      </p>
    </div>
  );
}

function VectorConfigForm({ config, onChange, disabled }: FormProps) {
  return (
    <div className="space-y-3">
      <div className="p-2.5 bg-blue-500/10 border border-blue-500/30 rounded-md text-[11px] text-blue-300 leading-relaxed">
        Receive logs from upstream Vector instances using Vector&rsquo;s native protocol.
        Ideal for on-premise aggregators forwarding to cloud SIEM.
      </div>

      <div className="space-y-1.5">
        <Label className={FIELD_LABEL}>Listen Address</Label>
        <Input
          value={(config.address as string) || ''}
          onChange={(e) => onChange({ ...config, address: e.target.value })}
          placeholder="0.0.0.0:6000"
          disabled={disabled}
          className={INPUT_MONO}
        />
        <p className={HELP_TEXT}>Standard Vector native port is 6000</p>
      </div>

      <div className="space-y-1.5">
        <Label className={FIELD_LABEL}>Protocol Version</Label>
        <Select
          value={(config.version as string) || '2'}
          onValueChange={(v) => onChange({ ...config, version: v })}
          disabled={disabled}
        >
          <SelectTrigger className={SELECT_TRIGGER}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="2" className={SELECT_ITEM}>
              Version 2 (recommended)
            </SelectItem>
            <SelectItem value="1" className={SELECT_ITEM}>
              Version 1 (legacy)
            </SelectItem>
          </SelectContent>
        </Select>
        <p className={HELP_TEXT}>
          Match the version used by your upstream Vector instances
        </p>
      </div>

      <IpAllowlistInput
        value={(config.permit_origin as string[]) || []}
        onChange={(ips) => onChange({ ...config, permit_origin: ips.length > 0 ? ips : undefined })}
        disabled={disabled}
      />

      <TlsConfigSection
        value={config.tls as TlsSourceConfig | undefined}
        onChange={(tls) => onChange({ ...config, tls })}
        disabled={disabled}
      />
    </div>
  );
}
