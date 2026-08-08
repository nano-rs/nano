// SPDX-License-Identifier: AGPL-3.0-or-later

import { ChevronDown, ChevronRight, Lock, Upload, X, FileText } from 'lucide-react';
import { useState, useRef } from 'react';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import type { TlsSourceConfig } from '@/lib/api/types';

interface TlsConfigSectionProps {
  value: TlsSourceConfig | undefined;
  onChange: (config: TlsSourceConfig | undefined) => void;
  disabled?: boolean;
}

export function TlsConfigSection({ value, onChange, disabled }: TlsConfigSectionProps) {
  const [expanded, setExpanded] = useState(value?.enabled ?? false);

  const handleToggle = (enabled: boolean) => {
    if (enabled) {
      onChange({ enabled: true });
      setExpanded(true);
    } else {
      onChange(undefined);
      setExpanded(false);
    }
  };

  const handleChange = (field: keyof TlsSourceConfig, fieldValue: string | undefined) => {
    onChange({
      ...(value ?? { enabled: true }),
      [field]: fieldValue || undefined,
    });
  };

  return (
    <div className="border border-border rounded-xl overflow-hidden">
      <button
        type="button"
        onClick={() => setExpanded(!expanded)}
        disabled={disabled}
        className="w-full flex items-center justify-between p-3 bg-muted/30 hover:bg-muted/50 transition-colors disabled:opacity-50"
      >
        <div className="flex items-center gap-2">
          {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          <Lock className="w-4 h-4 text-muted-foreground" />
          <span className="text-sm font-medium">TLS Configuration</span>
          {value?.enabled && (
            <span className="text-xs text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded">Enabled</span>
          )}
        </div>
        <Switch
          checked={value?.enabled ?? false}
          onCheckedChange={handleToggle}
          disabled={disabled}
          onClick={(e) => e.stopPropagation()}
        />
      </button>

      {expanded && value?.enabled && (
        <div className="p-4 space-y-4 border-t border-border">
          <p className="text-xs text-muted-foreground">
            Upload or paste certificate contents. Certificates will be securely stored and deployed to the Vector server.
          </p>

          <CertificateInput
            label="CA Certificate"
            description="Certificate Authority certificate for verifying client certificates (optional)"
            value={value.ca_content}
            onChange={(content) => handleChange('ca_content', content)}
            disabled={disabled}
            placeholder="-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----"
          />

          <CertificateInput
            label="Server Certificate"
            description="Server certificate for TLS encryption (required for TLS)"
            value={value.crt_content}
            onChange={(content) => handleChange('crt_content', content)}
            disabled={disabled}
            placeholder="-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----"
          />

          <CertificateInput
            label="Private Key"
            description="Private key for the server certificate (required for TLS)"
            value={value.key_content}
            onChange={(content) => handleChange('key_content', content)}
            disabled={disabled}
            placeholder="-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----"
            sensitive
          />
        </div>
      )}
    </div>
  );
}

interface CertificateInputProps {
  label: string;
  description: string;
  value: string | undefined;
  onChange: (value: string | undefined) => void;
  disabled?: boolean;
  placeholder?: string;
  sensitive?: boolean;
}

function CertificateInput({
  label,
  description,
  value,
  onChange,
  disabled,
  placeholder,
  sensitive,
}: CertificateInputProps) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [showContent, setShowContent] = useState(!sensitive);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      onChange(content);
    };
    reader.readAsText(file);

    // Reset input so same file can be re-uploaded
    e.target.value = '';
  };

  const handleClear = () => {
    onChange(undefined);
  };

  const hasContent = !!value?.trim();

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <Label className="text-muted-foreground text-sm">{label}</Label>
        <div className="flex items-center gap-2">
          {hasContent && sensitive && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => setShowContent(!showContent)}
              className="h-6 text-xs"
            >
              {showContent ? 'Hide' : 'Show'}
            </Button>
          )}
          {hasContent && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={handleClear}
              disabled={disabled}
              className="h-6 text-xs text-red-400 hover:text-red-300"
            >
              <X className="w-3 h-3" />
              Clear
            </Button>
          )}
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => fileInputRef.current?.click()}
            disabled={disabled}
            className="h-6 text-xs"
          >
            <Upload className="w-3 h-3" />
            Upload
          </Button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".pem,.crt,.cer,.key,.txt"
            onChange={handleFileUpload}
            className="hidden"
          />
        </div>
      </div>

      {hasContent ? (
        <div className="relative">
          {showContent ? (
            <Textarea
              value={value}
              onChange={(e) => onChange(e.target.value || undefined)}
              disabled={disabled}
              className="font-mono text-xs h-24 border-border rounded-lg resize-none"
              placeholder={placeholder}
            />
          ) : (
            <div className="flex items-center gap-2 p-3 bg-muted/30 rounded-lg border border-border">
              <FileText className="w-4 h-4 text-emerald-400" />
              <span className="text-sm text-muted-foreground">
                {label} loaded ({value?.length ?? 0} characters)
              </span>
            </div>
          )}
        </div>
      ) : (
        <Textarea
          value={value ?? ''}
          onChange={(e) => onChange(e.target.value || undefined)}
          disabled={disabled}
          className="font-mono text-xs h-24 border-border rounded-lg resize-none"
          placeholder={placeholder}
        />
      )}

      <p className="text-xs text-muted-foreground">{description}</p>
    </div>
  );
}
