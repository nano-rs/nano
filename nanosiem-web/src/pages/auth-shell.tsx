// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Pre-auth page shell, ported from the design kit's "Activate (nano tokens)"
 * artboard (2026-09-16): a centered 400px task column under a slim top bar
 * (wordmark · mono breadcrumb · version chip) over a scanline backdrop with a
 * brand glow, and a status footer. Every color is a product token
 * (`--background`, `--card`, `--border-2`, `--primary`, `--fg-4`, …), which the
 * kit was cut from, so the pages stay in step with the rest of the app.
 *
 * The earlier terminal-emulator treatment (`auth-terminal-chrome.tsx`) is the
 * login wizard's; first-run pages — activation, authenticator enrollment,
 * initial admin setup — read better as a plain guided form: a numbered step
 * rail, labeled fields, a live policy checklist, one primary action.
 */
import React, { useId, useState } from 'react';
import { Eye, EyeOff } from 'lucide-react';
import { LoadingIcon } from '@/components/icons/LoadingIcon';
import { Logo } from '@/components/ui/logo';
import { cn } from '@/lib/utils';

/* ------------------------------------------------------------------ shell */

export function AuthShell({
  crumb,
  version,
  status,
  children,
  width = 400,
}: {
  /** Mono breadcrumb beside the wordmark, e.g. `auth / activate`. */
  crumb: string;
  version: string;
  /** Footer status line; `good` colors the dot. */
  status: { text: string; good?: boolean };
  children: React.ReactNode;
  /** Task column width. The kit uses 400; setup's four fields fit the same. */
  width?: number;
}) {
  return (
    <div
      className="relative min-h-screen flex flex-col bg-background text-foreground antialiased"
      style={{ fontSize: 13, fontWeight: 500, letterSpacing: '-0.005em' }}
    >
      {/* scanline texture + brand glow, both purely decorative */}
      <div
        aria-hidden
        className="absolute inset-0 pointer-events-none"
        style={{
          backgroundImage:
            'repeating-linear-gradient(90deg, color-mix(in srgb, var(--primary) 3.5%, transparent) 0 1px, transparent 1px 3px)',
        }}
      />
      <div
        aria-hidden
        className="absolute left-1/2 -translate-x-1/2 pointer-events-none"
        style={{
          top: -160,
          width: 640,
          height: 520,
          borderRadius: '50%',
          background:
            'radial-gradient(circle, color-mix(in srgb, var(--primary) 10%, transparent), transparent 66%)',
        }}
      />

      <header className="relative flex items-center justify-between px-6 py-[18px]">
        <div className="flex items-center gap-3">
          <Logo className="h-[18px] w-auto" />
          <span className="font-mono text-[11px] text-muted-foreground">{crumb}</span>
        </div>
        <span className="font-mono text-[11px] text-muted-foreground px-[9px] py-1 rounded border border-[var(--border-2)]">
          {version}
        </span>
      </header>

      <main className="relative flex-1 flex items-center justify-center p-6">
        <div className="w-full" style={{ maxWidth: width }}>
          {children}
        </div>
      </main>

      <footer className="relative flex items-center justify-between px-6 py-[14px] border-t border-border font-mono text-[11px] text-muted-foreground">
        <span className="flex items-center gap-2">
          <span
            className={cn(
              'w-1.5 h-1.5 rounded-full',
              status.good ? 'bg-[var(--good)]' : 'bg-[var(--fg-4)]',
            )}
          />
          {status.text}
        </span>
        <span>build {version}</span>
      </footer>
    </div>
  );
}

/* -------------------------------------------------------------- step rail */

export function StepRail({ steps, current }: { steps: string[]; current: number }) {
  return (
    <ol className="flex items-center gap-[10px] mb-[26px] font-mono text-[11px] list-none p-0 m-0">
      {steps.map((label, i) => {
        const n = i + 1;
        const state = n < current ? 'done' : n === current ? 'current' : 'todo';
        return (
          <React.Fragment key={label}>
            {i > 0 && <span aria-hidden className="flex-1 h-px bg-[var(--border-2)]" />}
            <li
              className={cn(
                'flex items-center gap-[7px]',
                state === 'current' ? 'text-primary' : state === 'done' ? 'text-[var(--good)]' : 'text-[var(--fg-4)]',
              )}
              aria-current={state === 'current' ? 'step' : undefined}
            >
              <span
                className={cn(
                  'inline-flex items-center justify-center w-[18px] h-[18px] rounded text-[10px] border',
                  state === 'current' && 'border-[color-mix(in_srgb,var(--primary)_30%,transparent)] bg-[color-mix(in_srgb,var(--primary)_14%,transparent)]',
                  state === 'done' && 'border-[color-mix(in_srgb,var(--good)_30%,transparent)]',
                  state === 'todo' && 'border-[var(--border-2)]',
                )}
              >
                {state === 'done' ? '✓' : n}
              </span>
              {label}
            </li>
          </React.Fragment>
        );
      })}
    </ol>
  );
}

/* ---------------------------------------------------------------- heading */

export function AuthHeading({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <>
      <h1 className="m-0 text-[22px] font-semibold tracking-[-0.02em] text-foreground">{title}</h1>
      {children && (
        <p className="mt-1.5 mb-[26px] text-[13px] leading-[1.55] text-muted-foreground">{children}</p>
      )}
    </>
  );
}

/* ------------------------------------------------------------------ field */

const inputBase =
  'w-full h-[38px] px-3 rounded-[5px] bg-card border text-foreground font-mono text-[13px] outline-none placeholder:text-[var(--fg-4)] focus:border-primary disabled:opacity-50 transition-colors';

/**
 * Labeled input. `password` adds the show/hide eye; `tone` colors the border
 * for match / mismatch feedback the way the kit does on the confirm field.
 */
export const Field = React.forwardRef<
  HTMLInputElement,
  Omit<React.InputHTMLAttributes<HTMLInputElement>, 'className'> & {
    label: string;
    password?: boolean;
    tone?: 'neutral' | 'good' | 'bad';
    /** Rendered under the input; reserves height so the layout never jumps. */
    note?: React.ReactNode;
    noteTone?: 'muted' | 'good' | 'bad';
  }
>(function Field({ label, password, tone = 'neutral', note, noteTone = 'muted', id, ...rest }, ref) {
  const generated = useId();
  const inputId = id ?? generated;
  const [show, setShow] = useState(false);
  const border =
    tone === 'bad' ? 'border-destructive' : tone === 'good' ? 'border-[color-mix(in_srgb,var(--primary)_30%,var(--border-2))]' : 'border-[var(--border-2)]';
  return (
    <div className="mb-2">
      <label htmlFor={inputId} className="block text-[12px] font-medium text-[var(--fg-2)] mb-[7px]">
        {label}
      </label>
      <div className="relative">
        <input
          ref={ref}
          id={inputId}
          type={password ? (show ? 'text' : 'password') : rest.type ?? 'text'}
          className={cn(inputBase, border, password && 'pr-[42px]')}
          {...rest}
        />
        {password && (
          <button
            type="button"
            onClick={() => setShow((s) => !s)}
            aria-label={show ? 'Hide password' : 'Show password'}
            aria-pressed={show}
            className="absolute top-0 right-0 h-[38px] w-[38px] flex items-center justify-center text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:text-foreground"
          >
            {show ? <EyeOff className="w-[15px] h-[15px]" strokeWidth={2} /> : <Eye className="w-[15px] h-[15px]" strokeWidth={2} />}
          </button>
        )}
      </div>
      <div className="min-h-[22px] pt-[5px] font-mono text-[11px]">
        {note && (
          <span
            role={noteTone === 'bad' ? 'alert' : undefined}
            className={cn(
              noteTone === 'bad' && 'text-destructive',
              noteTone === 'good' && 'text-[var(--good)]',
              noteTone === 'muted' && 'text-[var(--fg-4)]',
            )}
          >
            {note}
          </span>
        )}
      </div>
    </div>
  );
});

/* ------------------------------------------------------- policy checklist */

export interface PolicyCheck {
  label: string;
  ok: boolean;
}

/** Inline chips, one per rule, ticking live as the password is typed. */
export function PolicyChecklist({ checks, id }: { checks: PolicyCheck[]; id?: string }) {
  return (
    <div id={id} className="flex flex-wrap gap-x-[14px] gap-y-1.5 mb-[18px]" aria-live="polite">
      {checks.map((c) => (
        <span
          key={c.label}
          className={cn(
            'inline-flex items-center gap-[5px] font-mono text-[11px]',
            c.ok ? 'text-[var(--good)]' : 'text-[var(--fg-4)]',
          )}
        >
          <span className="text-[10px]" aria-hidden>
            {c.ok ? '✓' : '·'}
          </span>
          {c.label}
          <span className="sr-only">{c.ok ? ' met' : ' not met'}</span>
        </span>
      ))}
    </div>
  );
}

/* ---------------------------------------------------------------- buttons */

export function PrimaryButton({
  children,
  busy,
  disabled,
  ...rest
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { busy?: boolean }) {
  const inert = disabled || busy;
  return (
    <button
      {...rest}
      disabled={inert}
      aria-busy={busy}
      className={cn(
        'w-full h-10 mt-1.5 rounded-[5px] border-0 text-[13.5px] font-semibold tracking-[0.01em] inline-flex items-center justify-center gap-2 transition-[filter,background-color,color]',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40',
        inert
          ? 'bg-[var(--card-2)] text-[var(--fg-4)] cursor-default'
          : 'bg-primary text-[var(--primary-foreground,#06080B)] hover:brightness-[1.06] cursor-pointer',
      )}
    >
      {busy && <LoadingIcon className="w-4 h-4" />}
      {children}
    </button>
  );
}

export function SecondaryButton({
  children,
  ...rest
}: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...rest}
      className={cn(
        'h-10 px-4 rounded-[5px] bg-card border border-[var(--border-2)] text-foreground text-[13px] font-medium inline-flex items-center justify-center gap-[9px] hover:bg-[var(--card-2)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40 disabled:opacity-50 disabled:cursor-not-allowed transition-colors',
        rest.className,
      )}
    >
      {children}
    </button>
  );
}

/** Centered footnote under the primary action. */
export function AuthFootnote({ children }: { children: React.ReactNode }) {
  return <p className="mt-4 mb-0 text-center text-[12px] leading-[1.5] text-[var(--fg-4)]">{children}</p>;
}

/** Inline error banner above the form, for request-level failures. */
export function AuthError({ children }: { children: React.ReactNode }) {
  return (
    <div
      role="alert"
      className="mb-4 px-3 py-2.5 rounded-[5px] border border-destructive/40 bg-destructive/10 text-[12.5px] text-destructive leading-snug"
    >
      {children}
    </div>
  );
}
