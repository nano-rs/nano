// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Shared pre-auth terminal chrome.
 *
 * Extracted verbatim from `Login.tsx` (the terminal-aesthetic port of
 * `design-ref/login-terminal.html`) so every pre-auth surface renders inside
 * the same frame: collapsed rail, breadcrumb topbar, tabbed terminal card,
 * optional right inspector, bottom status bar.
 *
 * Both `Login.tsx` and `EnterpriseSharedActivation.tsx` use it, so activation →
 * MFA setup → login reads as one product rather than three pages. The markup
 * here is the login page's markup; it was parameterised (breadcrumb trail, tab
 * label, status line, inspector) but not redesigned.
 */

import React, { useEffect, useState } from 'react';
import { Terminal, RefreshCw } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { Logo } from '@/components/ui/logo';
import { cn } from '@/lib/utils';

export type TermLineKind = 'sys' | 'err' | 'warn' | 'good' | 'hint';

/**
 * Inline terminal-line renderer. Tone follows the mockup:
 *   sys = muted, err = destructive, warn = warning, good = success,
 *   hint = italic muted.
 */
export function TermLine({
  kind,
  children,
  ...rest
}: {
  kind: TermLineKind;
  children: React.ReactNode;
} & React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      {...rest}
      className={cn(
        'font-mono text-[12.5px] leading-[1.6] min-w-0 break-words',
        kind === 'sys' && 'text-foreground/85',
        kind === 'err' && 'text-destructive',
        kind === 'warn' && 'text-[var(--warning)]',
        kind === 'good' && 'text-[var(--success)]',
        kind === 'hint' && 'text-muted-foreground/60 italic',
        rest.className,
      )}
    >
      {children}
    </div>
  );
}

/** Indents content to the terminal prompt's gutter. */
export function TermGroup({ children }: { children: React.ReactNode }) {
  return <div style={{ paddingLeft: '9ch' }}>{children}</div>;
}

function useClock(): Date {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  return now;
}

function fmtClock(d: Date): string {
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const mm = String(d.getUTCMinutes()).padStart(2, '0');
  const ss = String(d.getUTCSeconds()).padStart(2, '0');
  return `${hh}:${mm}:${ss} UTC`;
}

/** Brand block + release line above the first prompt. `children` is the blurb. */
export function WelcomeBanner({
  version,
  children,
}: {
  version: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="mb-4">
      <Logo className="h-6 select-none" size="normal" />
      <div className="mt-3 font-mono text-[11.5px] text-muted-foreground leading-[1.65]">
        <div>
          <span className="text-muted-foreground/60">release</span>{' '}
          <span className="text-foreground/85">v{version}</span>{'   '}
        </div>
      </div>
      <div
        className="mt-3 font-mono text-[11px] text-muted-foreground/60 leading-[1.55] max-w-[78ch]"
        style={{ textWrap: 'pretty' as React.CSSProperties['textWrap'] }}
      >
        {children}
      </div>
    </div>
  );
}

function Rail() {
  // Collapsed/locked rail per mockup — visual only, matches the rest of the
  // app's left-rail width so the chrome reads as continuous post-login.
  // Uses the real nano Logo so brand identity stays consistent post-login;
  // the mockup's `n + dot` letter-mark was a placeholder.
  return (
    <div
      className="hidden md:flex flex-col border-r border-border shrink-0 w-[44px]"
      style={{ background: 'var(--background)' }}
    >
      <div className="h-[42px] flex items-center justify-center">
        <Logo className="w-5 h-5" size="small" />
      </div>
      <div className="flex-1" />
      <div className="py-2 flex justify-center border-t border-border">
        <button
          className="w-8 h-8 rounded-md flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-foreground/5"
          title="Switch tenant"
          type="button"
          disabled
        >
          <RefreshCw className="w-[14px] h-[14px]" />
        </button>
      </div>
    </div>
  );
}

export interface BreadcrumbSegment {
  label: string;
  mono?: boolean;
}

function Topbar({ trail, version }: { trail: BreadcrumbSegment[]; version: string }) {
  return (
    <div
      className="h-[42px] px-3 flex items-center gap-3 border-b border-border shrink-0"
      style={{ background: 'var(--panel)' }}
    >
      <div className="flex items-center gap-1.5 text-[12px] min-w-0 shrink-0">
        {trail.map((t, i) => (
          <div key={i} className="flex items-center gap-1.5 shrink-0">
            {i > 0 && <span className="text-muted-foreground/60 shrink-0">/</span>}
            <span
              className={cn(
                'whitespace-nowrap shrink-0',
                t.mono && 'font-mono',
                i === trail.length - 1 ? 'text-foreground/85' : 'text-muted-foreground',
              )}
            >
              {t.label}
            </span>
          </div>
        ))}
      </div>
      <span className="flex-1" />
      <div className="hidden sm:flex items-center gap-1.5 text-[11px] shrink-0">
        <span className="h-[22px] inline-flex items-center gap-1.5 px-2 rounded-md border border-border text-muted-foreground font-mono whitespace-nowrap">
          v{version}
        </span>
      </div>
    </div>
  );
}

/** `active` pulses in brand colour, `done` is success, `error` is destructive. */
export type StatusTone = 'active' | 'done' | 'error';

export interface StatusLine {
  label: string;
  tone: StatusTone;
}

function StatusBar({
  status,
  version,
  clock,
}: {
  status: StatusLine;
  version: string;
  clock: Date;
}) {
  return (
    <div
      className="h-[26px] px-3 flex items-center gap-3 border-t border-border font-mono text-[10.5px] text-muted-foreground tracking-[0.02em] shrink-0 whitespace-nowrap overflow-hidden"
      style={{ background: 'var(--panel)' }}
    >
      <span
        className={cn(
          'flex items-center gap-1.5 shrink-0 whitespace-nowrap',
          status.tone === 'done' ? 'text-[var(--success)]' : 'text-primary',
          status.tone === 'error' && 'text-destructive',
        )}
      >
        <span
          className={cn(
            'w-1.5 h-1.5 rounded-full',
            status.tone === 'done' ? 'bg-[var(--success)]' : 'bg-primary animate-pulse',
            status.tone === 'error' && 'bg-destructive',
          )}
        />
        {status.label}
      </span>
      <span className="flex-1" />
      <span className="shrink-0 whitespace-nowrap tabular-nums">{fmtClock(clock)}</span>
      <span className="text-muted-foreground/60 shrink-0">·</span>
      <span className="shrink-0 whitespace-nowrap">
        <span className="text-muted-foreground/60">build</span>{' '}
        <span className="text-foreground/85">v{version}</span>
      </span>
    </div>
  );
}

export function InspectorSection({
  title,
  rightSlot,
  children,
}: {
  title: string;
  rightSlot?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="border-b border-border">
      <div className="px-3 py-2 flex items-center gap-2 whitespace-nowrap">
        <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-[0.14em] whitespace-nowrap">
          {title}
        </span>
        <span className="flex-1" />
        {rightSlot}
      </div>
      <div className="px-3 pb-3">{children}</div>
    </div>
  );
}

/**
 * Right inspector shell. `hidden lg:flex` — nothing actionable may live only
 * in here (NAN-2179); it is reference material at wide viewports.
 */
export function InspectorPanel({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="hidden lg:flex w-[300px] shrink-0 border-l border-border flex-col"
      style={{ background: 'var(--panel)' }}
    >
      {children}
    </div>
  );
}

/**
 * The `tenant` inspector section, identical on every pre-auth surface.
 *
 * `title` exists only for first-run setup, where no tenant exists yet and the
 * block describes the instance being initialised; it defaults to `tenant` so
 * every other surface renders exactly as before.
 */
export function TenantInspectorSection({
  name = 'nano',
  detail = 'control-plane',
  title = 'tenant',
}: {
  name?: string;
  detail?: string;
  title?: string;
}) {
  return (
    <InspectorSection title={title}>
      <div
        className="rounded-md border border-border p-2.5 space-y-1.5"
        style={{ background: 'var(--card)' }}
      >
        <div className="flex items-center gap-2">
          <Logo className="w-7 h-7" size="small" />
          <div className="min-w-0">
            <div className="text-[12.5px] font-semibold text-foreground truncate">{name}</div>
            <div className="text-[10.5px] font-mono text-muted-foreground whitespace-nowrap">
              {detail}
            </div>
          </div>
        </div>
      </div>
    </InspectorSection>
  );
}

/** Keyed rows for the inspector's `keyboard` section. */
export function KeyboardInspectorSection({ rows }: { rows: [string, string][] }) {
  return (
    <InspectorSection title="keyboard">
      <div className="space-y-1 font-mono text-[10.5px]">
        {rows.map(([k, v]) => (
          <div key={k} className="flex items-center justify-between gap-2 whitespace-nowrap">
            <kbd className="px-1.5 py-px rounded bg-foreground/[0.06] text-foreground text-[10px] border border-border shrink-0">
              {k}
            </kbd>
            <span className="text-muted-foreground shrink-0">{v}</span>
          </div>
        ))}
      </div>
    </InspectorSection>
  );
}

/**
 * Header strip of the anchored prompt card: pulse + state caption + the shell
 * prompt path + an optional `[n/m] STEP` indicator.
 */
export function PromptCardHeader({
  caption,
  prompt,
  stepIndicator,
}: {
  caption: string;
  prompt: string;
  stepIndicator?: { num: string; label: string } | null;
}) {
  return (
    <div
      className="h-[22px] px-2.5 flex items-center gap-2 border-b border-border"
      style={{
        backgroundColor: 'color-mix(in srgb, var(--primary) 7%, var(--card))',
      }}
    >
      <span className="w-1 h-1 rounded-full bg-primary animate-pulse shrink-0" />
      <span className="font-mono text-[9.5px] uppercase tracking-[0.14em] text-muted-foreground shrink-0 whitespace-nowrap">
        {caption}
      </span>
      <span className="text-muted-foreground/50 text-[10px] shrink-0">·</span>
      <span className="font-mono text-[9.5px] text-muted-foreground truncate">{prompt}</span>
      <div className="flex-1" />
      {stepIndicator && (
        <div className="h-[18px] px-1.5 rounded-sm border border-border inline-flex items-center gap-1 font-mono text-[10px] text-muted-foreground shrink-0">
          <span className="text-primary tabular-nums">{stepIndicator.num}</span>
          <span className="uppercase tracking-[0.12em]">{stepIndicator.label}</span>
        </div>
      )}
    </div>
  );
}

/**
 * One prompt row inside a `PromptCard`: `> label:` then the field. The login
 * wizard renders its rows inline; the multi-field pages (activation, setup)
 * share this so their rows are byte-identical to the wizard's.
 */
export function PromptRow({
  label,
  children,
  bordered,
  htmlFor,
}: {
  label: string;
  children: React.ReactNode;
  bordered?: boolean;
  htmlFor?: string;
}) {
  return (
    <div
      className={cn(
        'px-2.5 h-[30px] flex items-center gap-2 font-mono text-[12.5px] leading-none',
        bordered && 'border-t border-border',
      )}
    >
      <span className="text-primary select-none shrink-0">&gt;</span>
      <label htmlFor={htmlFor} className="text-muted-foreground select-none shrink-0 whitespace-nowrap">
        {label}
      </label>
      {children}
    </div>
  );
}

/**
 * A masked field drawn the way the login wizard draws its password prompt:
 * one `•` per typed character and a pulsing block cursor while focused, a
 * dim placeholder while empty, and the real `<input>` laid invisibly over the
 * row so focus, paste, password managers and screen readers all behave. A
 * bare transparent input with no placeholder reads as an inert line -- that
 * is what the first activation page shipped with.
 */
export const MaskedPromptInput = React.forwardRef<
  HTMLInputElement,
  Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type' | 'value' | 'className'> & {
    value: string;
    placeholder: string;
  }
>(function MaskedPromptInput({ value, placeholder, disabled, onFocus, onBlur, ...rest }, ref) {
  const [focused, setFocused] = React.useState(false);
  return (
    <div className="relative flex-1 min-w-0 h-full flex items-center">
      {value.length === 0 ? (
        <span className="text-muted-foreground/50 select-none truncate">{placeholder}</span>
      ) : (
        <span className="text-foreground tracking-[0.08em] truncate">{'•'.repeat(value.length)}</span>
      )}
      {focused && !disabled && <span className="text-primary animate-pulse select-none">▍</span>}
      <input
        ref={ref}
        type="password"
        value={value}
        disabled={disabled}
        onFocus={(event) => {
          setFocused(true);
          onFocus?.(event);
        }}
        onBlur={(event) => {
          setFocused(false);
          onBlur?.(event);
        }}
        className="absolute inset-0 w-full h-full bg-transparent text-transparent caret-transparent outline-none disabled:cursor-not-allowed"
        {...rest}
      />
    </div>
  );
});

/**
 * The compact submit chip a multi-field prompt card ends with. Enter submits
 * from any field, exactly as the wizard's `↵`; this is the pointer / screen
 * reader affordance for the same action, styled like the wizard's `retry`
 * chip rather than a form button.
 */
export function PromptSubmitRow({
  label,
  busy,
  hint,
}: {
  label: string;
  busy?: boolean;
  hint?: string;
}) {
  return (
    <div className="px-2.5 h-[30px] flex items-center gap-2 border-t border-border">
      <button
        type="submit"
        disabled={busy}
        aria-busy={busy}
        className="inline-flex items-center gap-1.5 h-[20px] px-2 rounded-sm border font-mono text-[11px] text-foreground hover:bg-foreground/[0.06] focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--primary)] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        style={{ borderColor: 'color-mix(in srgb, var(--primary) 45%, var(--border))' }}
      >
        {busy ? (
          <LoadingIcon className="w-3 h-3 text-muted-foreground" />
        ) : (
          <span className="text-primary">→</span>
        )}
        {label}
      </button>
      {hint && (
        <span className="font-mono text-[10.5px] text-muted-foreground/60 truncate">{hint}</span>
      )}
      <span className="flex-1" />
      <kbd className="hidden sm:inline-flex items-center h-[16px] px-1 rounded-sm border border-border bg-foreground/[0.06] font-mono text-[9.5px] text-muted-foreground shrink-0">
        ↵
      </kbd>
    </div>
  );
}

/** Brand-tinted bordered card that anchors the active prompt. */
export function PromptCard({ children }: { children: React.ReactNode }) {
  return (
    <div
      className="max-w-[78ch] rounded-md overflow-hidden border bg-card"
      style={{
        borderColor: 'color-mix(in srgb, var(--primary) 45%, var(--border))',
        backgroundColor: 'color-mix(in srgb, var(--primary) 4%, var(--card))',
      }}
    >
      {children}
    </div>
  );
}

/**
 * Full pre-auth page frame. `children` are the terminal scrollback contents.
 *
 * `scrollRef` / `onScrollClick` exist for the login wizard, which scrolls to
 * the newest line and refocuses its prompt when the scroll area is clicked.
 */
export function AuthTerminalFrame({
  version,
  trail,
  tab,
  status,
  inspector,
  scrollRef,
  onScrollClick,
  children,
}: {
  version: string;
  trail: BreadcrumbSegment[];
  tab: { label: string; sublabel: string };
  status: StatusLine;
  inspector?: React.ReactNode;
  scrollRef?: React.Ref<HTMLDivElement>;
  onScrollClick?: () => void;
  children: React.ReactNode;
}) {
  const clock = useClock();
  return (
    <div className="flex min-h-screen" style={{ background: 'var(--background)' }}>
      <Rail />
      <div className="flex-1 flex flex-col min-w-0">
        <Topbar trail={trail} version={version} />
        <div className="flex-1 flex min-h-0">
          <div
            className="flex-1 flex flex-col min-w-0 p-3 md:p-5"
            style={{ background: 'var(--background)' }}
          >
            <div
              className="flex-1 flex flex-col min-h-0 rounded-[10px] border border-border overflow-hidden"
              style={{ background: 'var(--card)' }}
            >
              {/* Tab strip */}
              <div
                className="h-[34px] px-1 flex items-end gap-0 border-b border-border shrink-0 whitespace-nowrap"
                style={{ background: 'var(--card-2)' }}
              >
                <div
                  className="h-full px-3 flex items-center gap-2 rounded-t-md border-t border-l border-r border-border text-[11.5px] -mb-px shrink-0 whitespace-nowrap"
                  style={{ background: 'var(--card)' }}
                >
                  <Terminal className="w-[12px] h-[12px] text-primary shrink-0" />
                  <span className="font-mono text-foreground whitespace-nowrap">{tab.label}</span>
                  <span className="text-muted-foreground/60">·</span>
                  <span className="font-mono text-muted-foreground text-[10.5px] whitespace-nowrap">
                    {tab.sublabel}
                  </span>
                </div>
                <div className="flex-1" />
                <div className="h-full px-2 flex items-center gap-2 font-mono text-[10px] text-muted-foreground/60 shrink-0 whitespace-nowrap">
                  <span>ansi · 256</span>
                  <span>·</span>
                  <span>utf-8</span>
                </div>
              </div>

              {/* Terminal scroll */}
              <div
                ref={scrollRef}
                className="flex-1 min-h-0 overflow-y-auto scrollbar-thin px-5 py-4 font-mono"
                onClick={onScrollClick}
              >
                {children}
              </div>
            </div>
          </div>
          {inspector}
        </div>
        <StatusBar status={status} version={version} clock={clock} />
      </div>
    </div>
  );
}
