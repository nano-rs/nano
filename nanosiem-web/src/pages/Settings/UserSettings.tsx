// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * User Settings — ported to Wave 18+ aesthetic from
 * `design-ref/user-settings.html` + `design-ref/shadcn/user-settings.jsx`
 * (zip 16). Three sections in a 2-column grid + full-width MFA card:
 *   - General (landing / time range / auto-collapse / auto-suggest / theme)
 *   - Query mode (Standard nPL / Advanced SQL + live sample preview)
 *   - Account security (TOTP wizard with QR / verify / backup-codes)
 *
 * All real backend wiring preserved: `useUserPreferences`, `next-themes`,
 * localStorage for sidebar/autosuggest, and the full MFA flow via
 * `api.auth.{getMfaStatus, setupMfa, verifyMfaSetup, disableMfa,
 * regenerateBackupCodes}`.
 *
 * Konami code (↑↑↓↓←→←→ba) unlocks an ops-mode panel with three
 * developer-leaning prefs (query.profiler, kbd.vim, ui.density). Pure
 * flair — not persisted, not shipped. Bypassed when typing into inputs.
 */

import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { Link as RouterLink, useNavigate } from 'react-router-dom';
import { useResetOnboarding } from '@/hooks/use-api';
import { useDocumentTitle } from '@/hooks/useDocumentTitle';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import {
  Loader2,
  Code,
  Terminal,
  Sun,
  Moon,
  Monitor,
  Lock,
  Shield,
  ShieldCheck,
  ShieldOff,
  KeyRound,
  ChevronRight,
  Copy,
  Download,
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  Check,
  Database,
  Filter,
  Hash,
  List,
  Zap,
  X,
  RotateCcw,
} from 'lucide-react';
import { useTheme } from 'next-themes';
import { useToast } from '@/hooks/use-toast';
import { useAuth } from '@/contexts/AuthContext';
import {
  useUserPreferences,
  QueryMode,
  TimeRangePreset,
  LandingPage,
} from '@/contexts/UserPreferencesContext';
import { api } from '@/lib/api';
import type { MfaStatusResponse, MfaSetupResponse } from '@/lib/api/types';
import { cn } from '@/lib/utils';

type MfaStep = 'idle' | 'scan' | 'verify' | 'backup';

// ── Display labels (match real persisted enum values) ───────────────
const timeRangeLabels: Record<TimeRangePreset, string> = {
  last_15_minutes: 'Last 15 minutes',
  last_hour: 'Last hour',
  last_4_hours: 'Last 4 hours',
  last_24_hours: 'Last 24 hours',
  last_7_days: 'Last 7 days',
  last_30_days: 'Last 30 days',
};

const landingPageLabels: Record<LandingPage, string> = {
  search: 'Search',
  home: 'Home',
  cases: 'Cases',
  dashboards: 'Dashboards',
  rules: 'Rules',
};

// ── Atoms ───────────────────────────────────────────────────────────

function Eyebrow({
  icon,
  children,
}: {
  icon?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase tracking-[0.18em] text-muted-foreground">
      {icon}
      <span>{children}</span>
    </div>
  );
}

function SectionCard({
  children,
  className = '',
  glow = false,
}: {
  children: React.ReactNode;
  className?: string;
  glow?: boolean;
}) {
  return (
    <div
      className={cn(
        'rounded-[10px] border border-border bg-card relative',
        glow && 'shadow-[0_24px_60px_-30px_color-mix(in_srgb,var(--primary)_18%,transparent)]',
        className,
      )}
    >
      {children}
    </div>
  );
}

function CardHeader({
  eyebrow,
  eyebrowIcon,
  icon,
  title,
  desc,
  id,
}: {
  eyebrow: string;
  eyebrowIcon?: React.ReactNode;
  icon: React.ReactNode;
  title: string;
  desc: React.ReactNode;
  id?: string;
}) {
  return (
    <div id={id} className="px-5 pt-4 pb-3 border-b border-[var(--rule)]">
      <Eyebrow icon={eyebrowIcon}>{eyebrow}</Eyebrow>
      <div className="flex items-center gap-2 mt-1.5">
        <span className="text-foreground">{icon}</span>
        <h2 className="text-[16px] font-semibold tracking-[-0.01em] text-foreground">{title}</h2>
      </div>
      <div className="text-[12px] text-foreground/85 mt-0.5">{desc}</div>
    </div>
  );
}

function Row({
  label,
  desc,
  children,
  last,
}: {
  label: string;
  desc?: React.ReactNode;
  children: React.ReactNode;
  last?: boolean;
}) {
  return (
    <div className={cn('flex items-start gap-6 py-4 px-5', !last && 'border-b border-[var(--rule)]')}>
      <div className="flex-1 min-w-0">
        <div className="text-[10px] font-mono uppercase tracking-[0.16em] text-muted-foreground">
          {label}
        </div>
        {desc && (
          <div className="text-[12px] text-foreground/85 mt-1 leading-snug max-w-[420px]">{desc}</div>
        )}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

function Chip({
  tone,
  children,
}: {
  tone: 'good' | 'brand' | 'warn' | 'fg';
  children: React.ReactNode;
}) {
  return (
    <span
      className={cn(
        'h-[20px] px-1.5 inline-flex items-center rounded-[3px] text-[10.5px] font-mono tracking-[0.02em]',
        tone === 'good' &&
          'bg-[color-mix(in_srgb,var(--success)_15%,transparent)] text-[var(--success)]',
        tone === 'brand' && 'bg-primary/15 text-primary',
        tone === 'warn' &&
          'bg-[color-mix(in_srgb,var(--warning)_15%,transparent)] text-[var(--warning)]',
        tone === 'fg' && 'bg-foreground/8 text-foreground/85',
      )}
    >
      {children}
    </span>
  );
}

function QueryModeOption({
  active,
  onSelect,
  icon,
  title,
  desc,
  chips,
  badge,
  disabled,
}: {
  active: boolean;
  onSelect: () => void;
  icon: React.ReactNode;
  title: string;
  desc: React.ReactNode;
  chips: { label: string; tone: 'good' | 'brand' | 'warn' | 'fg' }[];
  badge?: React.ReactNode;
  disabled?: boolean;
}) {
  return (
    <button
      onClick={disabled ? undefined : onSelect}
      disabled={disabled}
      className={cn(
        'w-full text-left px-4 py-3.5 rounded-[8px] border transition-colors flex gap-3',
        active
          ? 'border-primary/50 bg-primary/[0.06]'
          : 'border-border hover:border-[var(--border-2)] bg-[var(--card-2)]/40',
        disabled && 'opacity-60 cursor-not-allowed hover:border-border',
      )}
    >
      <div className="pt-0.5">
        <div
          className={cn(
            'w-[18px] h-[18px] rounded-full border flex items-center justify-center transition-colors',
            active ? 'border-primary bg-primary/20' : 'border-foreground/25',
          )}
        >
          {active && <span className="w-2 h-2 rounded-full bg-primary" />}
        </div>
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className={cn('w-[14px] h-[14px]', active ? 'text-primary' : 'text-foreground/85')}>
            {icon}
          </span>
          <span className="text-[13.5px] font-semibold tracking-[-0.005em] text-foreground">
            {title}
          </span>
          {badge}
        </div>
        <div className="text-[12px] text-foreground/85 mt-1 leading-snug">{desc}</div>
        <div className="flex flex-wrap gap-1.5 mt-2.5">
          {chips.map((c) => (
            <Chip key={c.label} tone={c.tone}>
              {c.label}
            </Chip>
          ))}
        </div>
      </div>
    </button>
  );
}

// ── Konami sequence (easter egg) ────────────────────────────────────
const KONAMI = [
  'ArrowUp',
  'ArrowUp',
  'ArrowDown',
  'ArrowDown',
  'ArrowLeft',
  'ArrowRight',
  'ArrowLeft',
  'ArrowRight',
  'b',
  'a',
];

function useKonamiCode(onUnlock: () => void): { hinted: boolean } {
  const [idx, setIdx] = useState(0);
  const [hinted, setHinted] = useState(false);
  const idxRef = useRef(0);
  idxRef.current = idx;

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const tag = target?.tagName ?? '';
      if (tag === 'INPUT' || tag === 'TEXTAREA' || target?.isContentEditable) return;
      const want = KONAMI[idxRef.current];
      const got = e.key.length === 1 ? e.key.toLowerCase() : e.key;
      if (got === want) {
        if (got.startsWith('Arrow')) e.preventDefault();
        const next = idxRef.current + 1;
        if (next === KONAMI.length) {
          onUnlock();
          setIdx(0);
        } else {
          setIdx(next);
          if (next >= 3) setHinted(true);
        }
      } else if (idxRef.current > 0) {
        setIdx(0);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onUnlock]);

  return { hinted };
}

// ── Page ────────────────────────────────────────────────────────────
export function UserSettings() {
  useDocumentTitle('User Settings');

  const { toast } = useToast();
  const { setTheme, theme } = useTheme();
  const { user, hasPermission } = useAuth();
  const navigate = useNavigate();
  const { mutate: resetOnboarding } = useResetOnboarding();
  const handleReopenSetup = useCallback(async () => {
    try {
      await resetOnboarding();
      navigate('/getting-started');
    } catch (err) {
      console.error('Failed to reopen onboarding:', err);
      toast({
        title: "Couldn't reopen Getting Started",
        description: 'Setup wizard reset failed. Try refreshing the page.',
        variant: 'destructive',
      });
    }
  }, [resetOnboarding, navigate, toast]);
  const canSql = hasPermission('search:sql');
  const {
    queryMode,
    setQueryMode,
    defaultTimeRange,
    setDefaultTimeRange,
    landingPage,
    setLandingPage,
    isLoading,
  } = useUserPreferences();

  const [saving, setSaving] = useState(false);
  const [smartSidebar, setSmartSidebar] = useState(
    () => localStorage.getItem('nanosiem-smart-sidebar') !== 'false',
  );
  const [autoAutocomplete, setAutoAutocomplete] = useState(
    () => localStorage.getItem('nanosiem-auto-autocomplete') !== 'false',
  );

  // ── MFA state ────────────────────────────────────────────────────
  const [mfaStatus, setMfaStatus] = useState<MfaStatusResponse | null>(null);
  const [mfaLoading, setMfaLoading] = useState(true);
  const [mfaStep, setMfaStep] = useState<MfaStep>('idle');
  const [setupData, setSetupData] = useState<MfaSetupResponse | null>(null);
  const [showManualKey, setShowManualKey] = useState(false);
  const [verifyCode, setVerifyCode] = useState('');
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [mfaActionLoading, setMfaActionLoading] = useState(false);
  const [mfaError, setMfaError] = useState<string | null>(null);
  const [savedConfirmed, setSavedConfirmed] = useState(false);
  const [showDisableConfirm, setShowDisableConfirm] = useState(false);
  const [disablePassword, setDisablePassword] = useState('');
  const [disabling, setDisabling] = useState(false);
  const [showRegen, setShowRegen] = useState(false);
  const [regenPassword, setRegenPassword] = useState('');
  const [regenLoading, setRegenLoading] = useState(false);
  const [regenCodes, setRegenCodes] = useState<string[] | null>(null);
  const verifyInputRef = useRef<HTMLInputElement>(null);

  // ── Konami / ops mode ────────────────────────────────────────────
  const [opsMode, setOpsMode] = useState(false);
  const [opsLines, setOpsLines] = useState<{ t: string; cls: string }[]>([]);
  const [profiler, setProfiler] = useState(false);
  const [vimKeys, setVimKeys] = useState(false);
  const [density, setDensity] = useState<'comfy' | 'compact' | 'dense'>('comfy');

  const unlockOps = useCallback(() => {
    setOpsMode(true);
    setOpsLines([]);
    const lines: { t: string; cls: string }[] = [
      { t: '$ nano user --ops-mode --enable', cls: 'text-foreground/85' },
      { t: '› unlocking developer preferences', cls: 'text-muted-foreground' },
      { t: '› injecting query.profiler, kbd.vim, ui.density', cls: 'text-muted-foreground' },
      { t: 'ok · ops mode active. welcome back, operator.', cls: 'text-[var(--success)]' },
    ];
    let i = 0;
    const tick = () => {
      const ln = lines[i];
      if (!ln) return;
      setOpsLines((curr) => [...curr, ln]);
      i++;
      if (i < lines.length) setTimeout(tick, 220);
    };
    tick();
    setTimeout(() => {
      const el = document.getElementById('ops');
      el?.scrollIntoView({ behavior: 'smooth', block: 'end' });
    }, 80);
  }, []);
  const { hinted: opsHinted } = useKonamiCode(unlockOps);

  // ── Effects ──────────────────────────────────────────────────────
  useEffect(() => {
    api.auth
      .getMfaStatus()
      .then(setMfaStatus)
      .catch(() => setMfaStatus(null))
      .finally(() => setMfaLoading(false));
  }, []);

  useEffect(() => {
    if (mfaStep === 'verify' && verifyInputRef.current) {
      verifyInputRef.current.focus();
    }
  }, [mfaStep]);

  // ── Handlers ─────────────────────────────────────────────────────
  const startMfaSetup = useCallback(async () => {
    setMfaActionLoading(true);
    setMfaError(null);
    try {
      const data = await api.auth.setupMfa();
      setSetupData(data);
      setMfaStep('scan');
    } catch (err: unknown) {
      setMfaError(err instanceof Error ? err.message : 'Failed to start MFA setup');
    } finally {
      setMfaActionLoading(false);
    }
  }, []);

  const handleMfaVerify = useCallback(async () => {
    if (!verifyCode.trim()) return;
    setMfaActionLoading(true);
    setMfaError(null);
    try {
      const result = await api.auth.verifyMfaSetup(verifyCode);
      setBackupCodes(result.backup_codes);
      setMfaStep('backup');
    } catch (err: unknown) {
      setMfaError(err instanceof Error ? err.message : 'Invalid code');
      setVerifyCode('');
    } finally {
      setMfaActionLoading(false);
    }
  }, [verifyCode]);

  useEffect(() => {
    if (verifyCode.length === 6 && /^\d{6}$/.test(verifyCode) && mfaStep === 'verify') {
      handleMfaVerify();
    }
  }, [verifyCode, mfaStep, handleMfaVerify]);

  const completeMfaSetup = useCallback(() => {
    setMfaStatus((prev) => (prev ? { ...prev, mfa_enabled: true, mfa_setup_pending: false } : null));
    setMfaStep('idle');
    setSetupData(null);
    setVerifyCode('');
    setBackupCodes([]);
    setSavedConfirmed(false);
    setShowManualKey(false);
    toast({
      title: 'MFA enabled',
      description: 'Two-factor authentication is now active on your account.',
    });
  }, [toast]);

  const copyBackupCodes = (codes: string[]) => {
    navigator.clipboard.writeText(codes.join('\n'));
    toast({ title: 'Copied', description: 'Backup codes copied to clipboard' });
  };

  const downloadBackupCodes = (codes: string[]) => {
    const text = `nano Backup Codes\n${'='.repeat(30)}\n\nStore these codes in a safe place.\nEach code can only be used once.\n\n${codes
      .map((c, i) => `${i + 1}. ${c}`)
      .join('\n')}\n`;
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'nanosiem-backup-codes.txt';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleQueryModeChange = async (mode: QueryMode) => {
    setSaving(true);
    try {
      await setQueryMode(mode);
      toast({
        title: 'Preference saved',
        description:
          mode === 'standard' ? 'Query mode set to Standard (nPL)' : 'Query mode set to Advanced (SQL)',
      });
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to save preference',
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleLandingChange = async (v: LandingPage) => {
    try {
      await setLandingPage(v);
      toast({ title: 'Preference saved', description: `Landing page set to ${landingPageLabels[v]}` });
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to save preference',
        variant: 'destructive',
      });
    }
  };

  const handleTimeRangeChange = async (v: TimeRangePreset) => {
    try {
      await setDefaultTimeRange(v);
      toast({
        title: 'Preference saved',
        description: `Default time range set to ${timeRangeLabels[v]}`,
      });
    } catch (err) {
      toast({
        title: 'Error',
        description: err instanceof Error ? err.message : 'Failed to save preference',
        variant: 'destructive',
      });
    }
  };

  // Tiny stable QR-ish bitmap fallback if the backend hasn't returned a
  // qr_code_base64 by the time the user reaches the scan step. Pure
  // visual; the real QR is an `<img>` from `setupData.qr_code_base64`
  // when present.
  const fallbackQrCells = useMemo(() => {
    const seed = 1337;
    const r = (i: number) => Math.abs(Math.sin(seed * i + i * 7)) > 0.5;
    const N = 21;
    const arr: number[][] = [];
    for (let y = 0; y < N; y++) {
      const row: number[] = [];
      for (let x = 0; x < N; x++) {
        const inFinder =
          (x < 7 && y < 7) || (x >= N - 7 && y < 7) || (x < 7 && y >= N - 7);
        if (inFinder) {
          const fx = x < 7 ? x : x - (N - 7);
          const fy = y < 7 ? y : y - (N - 7);
          const onRing = fx === 0 || fx === 6 || fy === 0 || fy === 6;
          const inner = fx >= 2 && fx <= 4 && fy >= 2 && fy <= 4;
          row.push(onRing || inner ? 1 : 0);
        } else {
          row.push(r(y * N + x) ? 1 : 0);
        }
      }
      arr.push(row);
    }
    return arr;
  }, []);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  const firstName = user?.name?.split(' ')[0] || 'You';

  return (
    <div className="max-w-[1180px] mx-auto px-2 py-2">
      {/* Page header */}
      <div className="flex items-end gap-6 mb-7">
        <div className="flex-1 min-w-0">
          <Eyebrow>User · settings</Eyebrow>
          <div className="flex items-baseline gap-3 mt-1.5">
            <h1 className="text-[26px] font-semibold tracking-[-0.018em] text-foreground">
              {firstName}
            </h1>
            {user?.email && (
              <span className="font-mono text-[12px] text-muted-foreground truncate">
                @ {user.email}
              </span>
            )}
          </div>
          <p className="text-[12.5px] text-foreground/85 mt-1.5 max-w-[640px] leading-relaxed">
            Personal defaults, search preferences and account security. Workspace-wide policy
            lives in
            <RouterLink to="/settings" className="text-primary hover:underline ml-1">
              Workspace settings
            </RouterLink>
            .
          </p>
        </div>
        <nav className="hidden lg:flex items-center gap-1 font-mono text-[10.5px] uppercase tracking-[0.14em] text-muted-foreground">
          {[
            ['general', 'general'],
            ['query', 'query mode'],
            ['security', 'account security'],
          ].map(([id, label]) => (
            <a
              key={id}
              href={`#${id}`}
              className="px-2 py-1 rounded hover:text-foreground hover:bg-foreground/5 transition-colors"
            >
              {label}
            </a>
          ))}
        </nav>
      </div>

      {/* General + Query Mode */}
      <div className="grid grid-cols-1 lg:grid-cols-[1.05fr_1fr] gap-5 items-start">
        {/* GENERAL */}
        <SectionCard>
          <CardHeader
            id="general"
            eyebrowIcon={<Filter className="w-[11px] h-[11px]" />}
            eyebrow="General"
            icon={<Filter className="w-[15px] h-[15px]" />}
            title="General"
            desc="Defaults for navigation and search."
          />

          <Row label="Landing page" desc="Page shown when you log in or navigate to /.">
            <Select value={landingPage} onValueChange={(v) => handleLandingChange(v as LandingPage)}>
              <SelectTrigger className="w-[170px] h-8 text-[12.5px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(Object.keys(landingPageLabels) as LandingPage[]).map((p) => (
                  <SelectItem key={p} value={p} className="text-[12.5px]">
                    {landingPageLabels[p]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Row>

          <Row
            label="Default time range"
            desc="Applied when opening Search without a time range in the URL."
          >
            <Select
              value={defaultTimeRange}
              onValueChange={(v) => handleTimeRangeChange(v as TimeRangePreset)}
            >
              <SelectTrigger className="w-[170px] h-8 text-[12.5px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(Object.keys(timeRangeLabels) as TimeRangePreset[]).map((p) => (
                  <SelectItem key={p} value={p} className="text-[12.5px]">
                    {timeRangeLabels[p]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Row>

          <Row
            label="Auto-collapse sidebar"
            desc="Collapse navigation when the notebook is open."
          >
            <Switch
              checked={smartSidebar}
              onCheckedChange={(checked) => {
                setSmartSidebar(checked);
                localStorage.setItem('nanosiem-smart-sidebar', String(checked));
                toast({
                  title: 'Preference saved',
                  description: checked
                    ? 'Sidebar will auto-collapse when notebook opens'
                    : 'Sidebar will stay as-is when notebook opens',
                });
              }}
              className="h-4 w-7"
              aria-label="Auto-collapse sidebar"
            />
          </Row>

          <Row
            label="Auto-suggest in search"
            desc={
              <>
                Show completions as you type after pipe commands. When off, press{' '}
                <kbd className="font-mono text-[10.5px] px-1 py-px rounded-sm bg-foreground/8 border border-border text-foreground/85 mx-px">
                  Tab
                </kbd>{' '}
                to trigger.
              </>
            }
          >
            <Switch
              checked={autoAutocomplete}
              onCheckedChange={(checked) => {
                setAutoAutocomplete(checked);
                localStorage.setItem('nanosiem-auto-autocomplete', String(checked));
                toast({
                  title: 'Preference saved',
                  description: checked
                    ? 'Autocomplete will show as you type'
                    : 'Autocomplete will only show on Tab',
                });
              }}
              className="h-4 w-7"
              aria-label="Auto-suggest in search"
            />
          </Row>

          <Row label="Theme" desc="Choose light, dark, or follow your system setting.">
            <Select
              value={theme || 'system'}
              onValueChange={(v) => {
                setTheme(v);
                const root = document.documentElement;
                root.classList.remove('light', 'dark');
                if (v === 'system') {
                  const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches
                    ? 'dark'
                    : 'light';
                  root.classList.add(systemTheme);
                } else {
                  root.classList.add(v);
                }
                toast({
                  title: 'Theme updated',
                  description: `Theme set to ${v.charAt(0).toUpperCase() + v.slice(1)}`,
                });
              }}
            >
              <SelectTrigger className="w-[150px] h-8 text-[12.5px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="light" className="text-[12.5px]">
                  <span className="flex items-center gap-2">
                    <Sun className="w-3 h-3" /> Light
                  </span>
                </SelectItem>
                <SelectItem value="dark" className="text-[12.5px]">
                  <span className="flex items-center gap-2">
                    <Moon className="w-3 h-3" /> Dark
                  </span>
                </SelectItem>
                <SelectItem value="system" className="text-[12.5px]">
                  <span className="flex items-center gap-2">
                    <Monitor className="w-3 h-3" /> System
                  </span>
                </SelectItem>
              </SelectContent>
            </Select>
          </Row>

          <Row
            label="Getting Started"
            desc="Reopen the setup wizard from the top — useful after dismissing or finishing it."
            last
          >
            <Button
              variant="outline"
              size="sm"
              onClick={handleReopenSetup}
              className="h-8 text-[12.5px] gap-1.5"
            >
              <RotateCcw className="w-3 h-3" />
              Reopen Getting Started
            </Button>
          </Row>
        </SectionCard>

        {/* QUERY MODE */}
        <SectionCard>
          <CardHeader
            id="query"
            eyebrowIcon={<Code className="w-[11px] h-[11px]" />}
            eyebrow="Query mode"
            icon={<Code className="w-[15px] h-[15px]" />}
            title="Query mode"
            desc="Choose how queries are generated when using the AI assistant."
          />

          <div className="p-4 space-y-3">
            <QueryModeOption
              active={queryMode === 'standard'}
              onSelect={() => handleQueryModeChange('standard')}
              icon={<Terminal className="w-[14px] h-[14px]" />}
              title="Standard (nPL)"
              badge={
                <span className="inline-flex items-center gap-1 text-[10px] font-mono text-[var(--success)]">
                  <Check className="w-[10px] h-[10px]" />
                  recommended
                </span>
              }
              desc="Human-readable pipe syntax with full validation. Detection-ready queries that can be saved as rules."
              chips={[
                { label: 'Full validation', tone: 'good' },
                { label: 'Detection-ready', tone: 'brand' },
                { label: 'Field suggestions', tone: 'brand' },
              ]}
            />
            <QueryModeOption
              active={queryMode === 'advanced'}
              onSelect={() => handleQueryModeChange('advanced')}
              disabled={!canSql}
              icon={<Database className="w-[14px] h-[14px]" />}
              title="Advanced (SQL)"
              badge={
                !canSql ? (
                  <span className="inline-flex items-center gap-1 text-[10px] font-mono text-muted-foreground">
                    <Lock className="w-[10px] h-[10px]" />
                    locked
                  </span>
                ) : undefined
              }
              desc={
                canSql
                  ? 'Full ClickHouse SQL power including window functions, CTEs, and complex JOINs.'
                  : 'Requires the search:sql permission. Contact your administrator.'
              }
              chips={[
                { label: 'Window functions', tone: 'brand' },
                { label: 'CTEs', tone: 'brand' },
                { label: 'Complex JOINs', tone: 'brand' },
                { label: 'Not for detectors', tone: 'warn' },
              ]}
            />

            {/* Sample query preview */}
            <div className="rounded-md border border-border bg-background/60 px-3 py-2.5 mt-2">
              <div className="flex items-center gap-2 mb-1.5">
                <span className="text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">
                  Preview
                </span>
                <span className="font-mono text-[10px] text-muted-foreground/60">
                  — same intent, your syntax
                </span>
              </div>
              {queryMode === 'standard' ? (
                <code className="block font-mono text-[12px] text-[var(--str)] leading-relaxed">
                  <span className="text-muted-foreground">source_type</span>=
                  <span className="text-foreground">aws_cloudtrail</span> |{' '}
                  <span className="text-primary">stats</span> count(){' '}
                  <span className="text-muted-foreground">by</span> user
                </code>
              ) : (
                <code className="block font-mono text-[12px] text-[var(--str)] leading-relaxed">
                  <span className="text-primary">SELECT</span> user,{' '}
                  <span className="text-primary">count()</span>{' '}
                  <span className="text-primary">FROM</span> events{' '}
                  <span className="text-primary">WHERE</span> source_type=
                  <span className="text-foreground">'aws_cloudtrail'</span>{' '}
                  <span className="text-primary">GROUP BY</span> user
                </code>
              )}
            </div>

            {saving && (
              <div className="flex items-center gap-2 text-[11.5px] text-muted-foreground">
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                Saving preference…
              </div>
            )}
          </div>
        </SectionCard>
      </div>

      {/* ACCOUNT SECURITY */}
      {!mfaLoading && mfaStatus && (
        <div id="security" className="mt-5">
          <SectionCard>
            <CardHeader
              eyebrowIcon={<Lock className="w-[11px] h-[11px]" />}
              eyebrow="Account security"
              icon={<Shield className="w-[15px] h-[15px]" />}
              title="Two-factor authentication"
              desc="Add an extra layer of security to your account with a TOTP authenticator app."
            />

            {mfaError && (
              <div className="mx-5 mt-4 text-[12px] text-destructive bg-destructive/10 border border-destructive/20 rounded-md px-3 py-2">
                {mfaError}
              </div>
            )}

            {/* Idle: enabled — management actions */}
            {mfaStep === 'idle' && mfaStatus.mfa_enabled && (
              <div className="px-5 py-4">
                <div className="flex items-center gap-3">
                  <span className="inline-flex items-center gap-1.5 text-[11.5px] font-mono text-[var(--success)]">
                    <span className="w-1.5 h-1.5 rounded-full bg-[var(--success)]" />
                    Enabled
                  </span>
                  {mfaStatus.mfa_required_globally && (
                    <span className="text-[10.5px] font-mono text-[var(--warning)]">
                      required by admin
                    </span>
                  )}
                  <span className="flex-1" />
                  {!showRegen && !showDisableConfirm && !regenCodes && (
                    <>
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-8 text-[11.5px]"
                        onClick={() => setShowRegen(true)}
                      >
                        <KeyRound className="w-3 h-3" />
                        Regenerate backup codes
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-8 text-[11.5px] text-destructive hover:text-destructive"
                        onClick={() => setShowDisableConfirm(true)}
                      >
                        <ShieldOff className="w-3 h-3" />
                        Disable MFA
                      </Button>
                    </>
                  )}
                </div>

                {showRegen && !regenCodes && (
                  <div className="mt-4 space-y-3 p-4 rounded-md border border-border bg-[var(--card-2)]">
                    <p className="text-[12px] text-foreground/85">
                      Enter your password to generate new backup codes. This will invalidate your
                      existing codes.
                    </p>
                    <Input
                      type="password"
                      placeholder="Current password"
                      value={regenPassword}
                      onChange={(e) => setRegenPassword(e.target.value)}
                      disabled={regenLoading}
                      className="h-8 text-[12.5px]"
                    />
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        className="h-8 text-[11.5px]"
                        disabled={regenLoading || !regenPassword}
                        onClick={async () => {
                          setRegenLoading(true);
                          try {
                            const result = await api.auth.regenerateBackupCodes(regenPassword);
                            setRegenCodes(result.backup_codes);
                            setShowRegen(false);
                            setRegenPassword('');
                          } catch {
                            toast({
                              title: 'Error',
                              description: 'Invalid password',
                              variant: 'destructive',
                            });
                          } finally {
                            setRegenLoading(false);
                          }
                        }}
                      >
                        {regenLoading && <Loader2 className="w-3 h-3 animate-spin" />}
                        Generate new codes
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-8 text-[11.5px]"
                        onClick={() => {
                          setShowRegen(false);
                          setRegenPassword('');
                        }}
                      >
                        Cancel
                      </Button>
                    </div>
                  </div>
                )}

                {regenCodes && (
                  <div className="mt-4 space-y-4 p-4 rounded-md border border-border bg-[var(--card-2)]">
                    <div className="flex items-start gap-3">
                      <KeyRound className="w-4 h-4 text-[var(--warning)] mt-0.5 shrink-0" />
                      <div>
                        <p className="text-[12.5px] font-medium text-foreground">
                          New backup codes
                        </p>
                        <p className="text-[11.5px] text-muted-foreground mt-1">
                          Your old codes are now invalid. Save these somewhere safe.
                        </p>
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      {regenCodes.map((code, i) => (
                        <div
                          key={i}
                          className="bg-card border border-border rounded-md px-3 py-2 font-mono text-[12px] text-center text-foreground"
                        >
                          {code}
                        </div>
                      ))}
                    </div>
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-8 text-[11.5px]"
                        onClick={() => copyBackupCodes(regenCodes)}
                      >
                        <Copy className="w-3 h-3" />
                        Copy
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-8 text-[11.5px]"
                        onClick={() => downloadBackupCodes(regenCodes)}
                      >
                        <Download className="w-3 h-3" />
                        Download
                      </Button>
                      <Button
                        size="sm"
                        className="h-8 text-[11.5px] ml-auto"
                        onClick={() => setRegenCodes(null)}
                      >
                        Done
                      </Button>
                    </div>
                  </div>
                )}

                {showDisableConfirm && (
                  <div className="mt-4 space-y-3 p-4 rounded-md border border-destructive/20 bg-destructive/5">
                    <p className="text-[12px] text-foreground/85">
                      Enter your password to confirm disabling MFA.
                    </p>
                    <Input
                      type="password"
                      placeholder="Current password"
                      value={disablePassword}
                      onChange={(e) => setDisablePassword(e.target.value)}
                      disabled={disabling}
                      className="h-8 text-[12.5px]"
                    />
                    <div className="flex gap-2">
                      <Button
                        variant="destructive"
                        size="sm"
                        className="h-8 text-[11.5px]"
                        disabled={disabling || !disablePassword}
                        onClick={async () => {
                          setDisabling(true);
                          try {
                            await api.auth.disableMfa(disablePassword);
                            setMfaStatus((prev) => (prev ? { ...prev, mfa_enabled: false } : null));
                            setShowDisableConfirm(false);
                            setDisablePassword('');
                            toast({
                              title: 'MFA disabled',
                              description: 'Two-factor authentication has been removed.',
                            });
                          } catch {
                            toast({
                              title: 'Error',
                              description: 'Invalid password or failed to disable MFA',
                              variant: 'destructive',
                            });
                          } finally {
                            setDisabling(false);
                          }
                        }}
                      >
                        {disabling && <Loader2 className="w-3 h-3 animate-spin" />}
                        Confirm disable
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-8 text-[11.5px]"
                        onClick={() => {
                          setShowDisableConfirm(false);
                          setDisablePassword('');
                        }}
                      >
                        Cancel
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Idle: not enabled */}
            {mfaStep === 'idle' && !mfaStatus.mfa_enabled && (
              <div className="px-5 py-4 flex items-center gap-3">
                <span className="inline-flex items-center gap-1.5 text-[11.5px] font-mono text-muted-foreground">
                  <span className="w-1.5 h-1.5 rounded-full bg-foreground/35" />
                  Not enabled
                </span>
                {mfaStatus.mfa_required_globally && (
                  <span className="text-[10.5px] font-mono text-[var(--warning)]">
                    required by admin
                  </span>
                )}
                <span className="flex-1" />
                <Button
                  size="sm"
                  className="h-8 text-[12.5px] font-semibold"
                  onClick={startMfaSetup}
                  disabled={mfaActionLoading}
                >
                  {mfaActionLoading ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <ShieldCheck className="w-3.5 h-3.5" />
                  )}
                  Enable two-factor authentication
                </Button>
              </div>
            )}

            {/* Step 1: Scan QR */}
            {mfaStep === 'scan' && setupData && (
              <div className="px-5 py-5 space-y-4">
                <div className="rounded-md border border-border bg-background/40 px-5 py-6 flex flex-col items-center">
                  <div className="text-[13px] text-foreground">
                    Scan this QR code with your authenticator app
                  </div>
                  <div className="text-[11.5px] text-muted-foreground mt-0.5">
                    (Google Authenticator, Authy, 1Password, etc.)
                  </div>

                  <div className="mt-5 p-4 rounded-md bg-white shadow-[0_8px_24px_rgba(0,0,0,0.4)]">
                    {setupData.qr_code_base64 ? (
                      <img
                        src={`data:image/png;base64,${setupData.qr_code_base64}`}
                        alt="TOTP QR Code"
                        className="w-[180px] h-[180px]"
                      />
                    ) : (
                      <svg width="180" height="180" viewBox="0 0 21 21" shapeRendering="crispEdges">
                        <rect width="21" height="21" fill="#fff" />
                        {fallbackQrCells.map((row, y) =>
                          row.map((c, x) =>
                            c ? <rect key={`${x}-${y}`} x={x} y={y} width="1" height="1" fill="#0B0E12" /> : null,
                          ),
                        )}
                      </svg>
                    )}
                  </div>

                  <button
                    type="button"
                    onClick={() => setShowManualKey((s) => !s)}
                    className="mt-4 inline-flex items-center gap-1.5 text-[12px] text-foreground/85 hover:text-foreground"
                  >
                    <ChevronRight
                      className={cn(
                        'w-3 h-3 transition-transform',
                        showManualKey && 'rotate-90',
                      )}
                    />
                    Can't scan? Enter key manually
                  </button>

                  {showManualKey && (
                    <div className="mt-3 w-full max-w-[420px] rounded-md border border-border bg-[var(--card-2)] px-3 py-2 flex items-center gap-2">
                      <span className="text-[10px] font-mono uppercase tracking-[0.14em] text-muted-foreground">
                        secret
                      </span>
                      <code className="font-mono text-[12px] text-[var(--str)] flex-1 truncate select-all">
                        {setupData.secret}
                      </code>
                    </div>
                  )}
                </div>

                <div className="flex gap-3">
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-9 text-[12.5px]"
                    onClick={() => {
                      setMfaStep('idle');
                      setSetupData(null);
                      setShowManualKey(false);
                    }}
                  >
                    Cancel
                  </Button>
                  <Button
                    size="sm"
                    className="h-9 text-[12.5px] font-semibold flex-1"
                    onClick={() => setMfaStep('verify')}
                  >
                    Continue
                    <ArrowRight className="w-3.5 h-3.5 ml-2" />
                  </Button>
                </div>
              </div>
            )}

            {/* Step 2: Verify */}
            {mfaStep === 'verify' && (
              <div className="px-5 py-5 space-y-4">
                <p className="text-[12px] text-foreground/85">
                  Enter the 6-digit code from your authenticator app to verify setup.
                </p>
                <div className="relative">
                  <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                  <Input
                    ref={verifyInputRef}
                    type="text"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    placeholder="000000"
                    value={verifyCode}
                    onChange={(e) => setVerifyCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    disabled={mfaActionLoading}
                    className="pl-9 h-10 text-[16px] tracking-widest font-mono"
                    maxLength={6}
                  />
                </div>
                <div className="flex gap-3">
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-9 text-[12.5px]"
                    onClick={() => setMfaStep('scan')}
                  >
                    <ArrowLeft className="w-3.5 h-3.5" />
                    Back
                  </Button>
                  <Button
                    size="sm"
                    className="h-9 text-[12.5px] font-semibold flex-1"
                    onClick={handleMfaVerify}
                    disabled={mfaActionLoading || verifyCode.length < 6}
                  >
                    {mfaActionLoading ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <ShieldCheck className="w-3.5 h-3.5" />
                    )}
                    Verify
                  </Button>
                </div>
              </div>
            )}

            {/* Step 3: Backup */}
            {mfaStep === 'backup' && (
              <div className="px-5 py-5 space-y-4">
                <div className="flex items-start gap-3">
                  <KeyRound className="w-4 h-4 text-[var(--warning)] mt-0.5 shrink-0" />
                  <div>
                    <p className="text-[12.5px] font-medium text-foreground">
                      Save your backup codes
                    </p>
                    <p className="text-[11.5px] text-muted-foreground mt-1">
                      If you lose access to your authenticator app, use these one-time codes to
                      sign in. Each code can only be used once.
                    </p>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  {backupCodes.map((code, i) => (
                    <div
                      key={i}
                      className="bg-[var(--card-2)] border border-border rounded-md px-3 py-2 font-mono text-[12px] text-center text-foreground"
                    >
                      {code}
                    </div>
                  ))}
                </div>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-8 text-[11.5px]"
                    onClick={() => copyBackupCodes(backupCodes)}
                  >
                    <Copy className="w-3 h-3" />
                    Copy
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-8 text-[11.5px]"
                    onClick={() => downloadBackupCodes(backupCodes)}
                  >
                    <Download className="w-3 h-3" />
                    Download
                  </Button>
                </div>
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={savedConfirmed}
                    onChange={(e) => setSavedConfirmed(e.target.checked)}
                    className="mt-1 rounded border-border"
                  />
                  <span className="text-[12px] text-foreground/85">
                    I have saved these backup codes in a secure location
                  </span>
                </label>
                <Button
                  size="sm"
                  className="h-9 text-[12.5px] font-semibold w-full"
                  onClick={completeMfaSetup}
                  disabled={!savedConfirmed}
                >
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  Done
                </Button>
              </div>
            )}
          </SectionCard>
        </div>
      )}

      {/* OPS MODE (easter egg) */}
      {opsMode && (
        <div id="ops" className="mt-5">
          <SectionCard glow>
            <div className="px-5 pt-4 pb-3 border-b border-[var(--rule)] flex items-center gap-3">
              <div>
                <Eyebrow icon={<Zap className="w-[11px] h-[11px]" />}>Ops mode · unlocked</Eyebrow>
                <div className="flex items-center gap-2 mt-1.5">
                  <Terminal className="w-[15px] h-[15px] text-primary" />
                  <h2 className="text-[16px] font-semibold tracking-[-0.01em] text-foreground">
                    Developer preferences
                  </h2>
                  <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-primary bg-primary/15 px-1.5 py-px rounded-sm">
                    ↑↑↓↓←→←→ba
                  </span>
                </div>
                <div className="text-[12px] text-foreground/85 mt-0.5">
                  You found it. These knobs aren't shipped — just for the curious.
                </div>
              </div>
              <span className="flex-1" />
              <button
                onClick={() => {
                  setOpsMode(false);
                  setOpsLines([]);
                }}
                className="h-7 px-2.5 rounded-md text-[11.5px] text-muted-foreground hover:text-foreground hover:bg-foreground/5 inline-flex items-center gap-1.5"
              >
                <X className="w-3 h-3" />
                Hide
              </button>
            </div>

            <div className="mx-5 mt-4 rounded-md border border-border bg-background/70 px-3 py-2.5 font-mono text-[11.5px] leading-[1.7] min-h-[88px]">
              {opsLines.map((l, i) => (
                <div key={i} className={l.cls}>
                  {l.t}
                </div>
              ))}
              <span className="inline-block w-[7px] h-[12px] bg-primary align-[-1px] ml-px animate-pulse" />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-[var(--rule)] mt-4">
              <div className="bg-card px-5 py-4">
                <Eyebrow icon={<Zap className="w-[11px] h-[11px]" />}>query.profiler</Eyebrow>
                <div className="flex items-center justify-between mt-2 gap-2">
                  <div className="text-[12px] text-foreground/85 leading-snug max-w-[180px]">
                    Show row-scan, time, and bloom hits inline next to each query.
                  </div>
                  <Switch
                    checked={profiler}
                    onCheckedChange={setProfiler}
                    className="h-4 w-7"
                    aria-label="Profiler"
                  />
                </div>
              </div>
              <div className="bg-card px-5 py-4">
                <Eyebrow icon={<Hash className="w-[11px] h-[11px]" />}>kbd.vim</Eyebrow>
                <div className="flex items-center justify-between mt-2 gap-2">
                  <div className="text-[12px] text-foreground/85 leading-snug max-w-[180px]">
                    Vim keybindings in the query editor and code views.
                  </div>
                  <Switch
                    checked={vimKeys}
                    onCheckedChange={setVimKeys}
                    className="h-4 w-7"
                    aria-label="Vim mode"
                  />
                </div>
              </div>
              <div className="bg-card px-5 py-4">
                <Eyebrow icon={<List className="w-[11px] h-[11px]" />}>ui.density</Eyebrow>
                <div className="flex items-center justify-between mt-2 gap-2">
                  <div className="text-[12px] text-foreground/85 leading-snug">
                    Row height across tables.
                  </div>
                  <Select value={density} onValueChange={(v) => setDensity(v as typeof density)}>
                    <SelectTrigger className="w-[120px] h-8 text-[12.5px]">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="comfy" className="text-[12.5px]">
                        Comfy
                      </SelectItem>
                      <SelectItem value="compact" className="text-[12.5px]">
                        Compact
                      </SelectItem>
                      <SelectItem value="dense" className="text-[12.5px]">
                        Dense
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </div>
          </SectionCard>
        </div>
      )}

      {/* Footer save bar */}
      <div className="mt-6 flex items-center gap-3 text-[11.5px] text-muted-foreground font-mono">
        <span className="text-[var(--success)]">●</span>
        <span>
          changes saved · <span className="text-foreground/85">just now</span>
        </span>
        <span className="text-muted-foreground/60">·</span>
        <span>autosave on</span>
        <span className="flex-1" />
        {opsHinted && !opsMode && (
          <span className="text-muted-foreground/60 italic font-sans">try ↑↑↓↓…</span>
        )}
        <RouterLink
          to="/settings"
          className="text-muted-foreground hover:text-foreground inline-flex items-center gap-1"
        >
          workspace settings →
        </RouterLink>
      </div>

    </div>
  );
}
