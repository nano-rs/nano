// SPDX-License-Identifier: AGPL-3.0-or-later

import { useState } from 'react';
import { X, Plus, Shield } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';

interface IpAllowlistInputProps {
  value: string[];
  onChange: (ips: string[]) => void;
  disabled?: boolean;
  placeholder?: string;
}

// Simple CIDR/IP validation
function isValidCidrOrIp(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) return false;

  // IPv4 with optional CIDR
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
  // IPv6 with optional CIDR (simplified)
  const ipv6Regex = /^([a-fA-F0-9:]+)(\/\d{1,3})?$/;

  if (ipv4Regex.test(trimmed)) {
    const [ip, cidr] = trimmed.split('/');
    const octets = ip.split('.').map(Number);
    if (octets.some(o => o > 255)) return false;
    if (cidr && (parseInt(cidr) > 32 || parseInt(cidr) < 0)) return false;
    return true;
  }

  if (ipv6Regex.test(trimmed)) {
    const [, cidr] = trimmed.split('/');
    if (cidr && (parseInt(cidr) > 128 || parseInt(cidr) < 0)) return false;
    return true;
  }

  return false;
}

export function IpAllowlistInput({ value, onChange, disabled, placeholder }: IpAllowlistInputProps) {
  const [inputValue, setInputValue] = useState('');
  const [error, setError] = useState<string | null>(null);

  const handleAdd = () => {
    const trimmed = inputValue.trim();
    if (!trimmed) return;

    // Split by comma or newline for bulk entry
    const entries = trimmed.split(/[,\n]/).map(s => s.trim()).filter(Boolean);

    const validEntries: string[] = [];
    const invalidEntries: string[] = [];

    for (const entry of entries) {
      if (isValidCidrOrIp(entry)) {
        if (!value.includes(entry)) {
          validEntries.push(entry);
        }
      } else {
        invalidEntries.push(entry);
      }
    }

    if (invalidEntries.length > 0) {
      setError(`Invalid: ${invalidEntries.join(', ')}`);
    } else {
      setError(null);
    }

    if (validEntries.length > 0) {
      onChange([...value, ...validEntries]);
      setInputValue('');
    }
  };

  const handleRemove = (ip: string) => {
    onChange(value.filter(v => v !== ip));
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleAdd();
    }
  };

  // Auto-add on blur if there's a valid value in the input
  const handleBlur = () => {
    if (inputValue.trim()) {
      handleAdd();
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Shield className="w-4 h-4 text-muted-foreground" />
        <Label className="text-muted-foreground text-sm">IP Allowlist (CIDR)</Label>
      </div>

      <div className="flex gap-2">
        <Input
          value={inputValue}
          onChange={(e) => {
            setInputValue(e.target.value);
            setError(null);
          }}
          onKeyDown={handleKeyDown}
          onBlur={handleBlur}
          placeholder={placeholder ?? '192.168.1.0/24 or 10.0.0.1'}
          disabled={disabled}
          className="flex-1 border-border rounded-lg font-mono text-sm"
        />
        <Button
          type="button"
          variant="outline"
          size="icon"
          onClick={handleAdd}
          disabled={disabled || !inputValue.trim()}
          className="border-border rounded-lg"
        >
          <Plus className="w-4 h-4" />
        </Button>
      </div>

      {error && (
        <p className="text-xs text-red-400">{error}</p>
      )}

      <p className="text-xs text-muted-foreground">
        Enter IP addresses or CIDR ranges. Separate multiple with commas.
      </p>

      {value.length > 0 && (
        <div className="flex flex-wrap gap-2 pt-2">
          {value.map((ip) => (
            <div
              key={ip}
              className="flex items-center gap-1 px-2 py-1 bg-muted rounded-lg text-sm font-mono"
            >
              {ip}
              <button
                type="button"
                onClick={() => handleRemove(ip)}
                disabled={disabled}
                className="ml-1 hover:text-red-400 transition-colors disabled:opacity-50"
              >
                <X className="w-3 h-3" />
              </button>
            </div>
          ))}
        </div>
      )}

      {value.length === 0 && (
        <div className="text-xs text-muted-foreground italic">
          No IP restrictions configured. All IPs will be accepted.
        </div>
      )}
    </div>
  );
}
