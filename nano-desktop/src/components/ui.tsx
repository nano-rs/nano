import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from 'react';

/** macOS draws the traffic lights over our content; reserve their gutter. */
export const TRAFFIC_LIGHT_GUTTER = 78;

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'accent' | 'ghost';
}

export function Button({ variant = 'accent', className = '', ...props }: ButtonProps) {
  const base =
    'rounded-[8px] px-4 py-2 text-[12px] font-semibold transition-opacity disabled:opacity-40 disabled:cursor-default';
  const variants = {
    accent: 'bg-accent text-accent-ink hover:opacity-90',
    ghost: 'bg-raised border border-line-strong text-t2 hover:text-t1',
  };
  return <button className={`${base} ${variants[variant]} ${className}`} {...props} />;
}

interface FieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  mono?: boolean;
  hint?: ReactNode;
}

export function Field({ label, mono, hint, className = '', ...props }: FieldProps) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-[10.5px] font-bold tracking-[0.06em] text-t4 uppercase">{label}</span>
      <input
        className={`w-full rounded-[9px] border border-line-strong bg-input px-3.5 py-2.5 text-[13px] text-t1 outline-none placeholder:text-t4 focus:border-accent ${
          mono ? 'font-mono' : ''
        } ${className}`}
        {...props}
      />
      {hint}
    </label>
  );
}

/** Inline failure. Never a toast — the user needs it next to what they typed. */
export function ErrorNote({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-[9px] border border-danger/40 bg-danger-soft px-3.5 py-2.5 text-[12px] leading-[1.5] text-danger">
      {children}
    </div>
  );
}

export function Spinner({ className = '' }: { className?: string }) {
  return (
    <span
      className={`inline-block size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent ${className}`}
    />
  );
}
