import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { getCurrentWindow } from '@tauri-apps/api/window';

import { Spinner } from '../components/ui';
import { api, errorMessage } from '../lib/ipc';
import {
  classifyIndicator,
  indicatorLabel,
  indicatorQuery,
  type Indicator,
} from '../lib/indicator';
import type { IocPeek } from '../lib/types';

/** The window the peek searches; also the range handed to "Open in nano". */
const PEEK_RANGE = 'Last 30 days';

/**
 * The ⌥Space spotlight. A launcher first: type an nPL query and Enter hands it to
 * the main window. Its one inline feature is the indicator peek — drop an IP,
 * hash, or domain and it shows what nano actually knows (prevalence, and geo/ASN
 * for IPs), fetched live and labelled as such. Deliberately NOT a fake "offline
 * verdict": there is no local index, so we never imply one.
 */
type Peek =
  | { status: 'idle' }
  | { status: 'loading'; indicator: Indicator }
  | { status: 'ready'; indicator: Indicator; data: IocPeek; ms: number }
  | { status: 'error'; indicator: Indicator; message: string };

export function QuickSearch() {
  const [input, setInput] = useState('');
  const [authed, setAuthed] = useState<boolean | null>(null);
  const [peek, setPeek] = useState<Peek>({ status: 'idle' });
  const inputRef = useRef<HTMLInputElement>(null);
  const reqToken = useRef(0);

  const indicator = useMemo(() => classifyIndicator(input), [input]);

  const checkAuth = useCallback(() => {
    api.isAuthenticated().then(setAuthed).catch(() => setAuthed(false));
  }, []);

  // On first mount.
  useEffect(() => {
    checkAuth();
    inputRef.current?.focus();
  }, [checkAuth]);

  // Each time the hotkey re-shows the window: pre-fill from whatever the analyst
  // had selected in the frontmost app (if anything), refocus, select-all (so a
  // retype replaces it), and recheck auth in case the session changed while hidden.
  useEffect(() => {
    const unlisten = getCurrentWindow().listen<{
      selection: string | null;
      clipboard: string | null;
    }>('quick-show', (event) => {
      checkAuth();
      const selection = event.payload?.selection?.trim();
      const clipboard = event.payload?.clipboard?.trim();
      // An explicit selection (⌘C capture) always wins. Otherwise fall back to the
      // clipboard, but only when it's indicator-shaped — so "⌘C an IOC then ⌥Space"
      // pre-fills, while a stale clipboard doesn't hijack a fresh query.
      const prefill = selection || (clipboard && classifyIndicator(clipboard) ? clipboard : '');
      if (prefill) setInput(prefill); // → the peek effect runs on the change
      // After the value settles, focus and select-all so a retype replaces it.
      requestAnimationFrame(() => {
        const el = inputRef.current;
        if (el) {
          el.focus();
          el.select();
        }
      });
    });
    return () => {
      void unlisten.then((off) => off());
    };
  }, [checkAuth]);

  // Esc hides the spotlight.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        void api.hideQuick();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // Click away and it dismisses, like Spotlight. Clicking inside keeps the window
  // focused (webview focus stays within it), so this only fires on a real switch
  // to another app — it won't fight the user mid-interaction.
  useEffect(() => {
    const unlisten = getCurrentWindow().onFocusChanged(({ payload: focused }) => {
      if (!focused) void api.hideQuick();
    });
    return () => {
      void unlisten.then((off) => off());
    };
  }, []);

  // Debounced indicator peek. A race token drops any response that a newer
  // keystroke has superseded, so a slow lookup can't overwrite a fresh one.
  useEffect(() => {
    // Only once we know there's a session — skip the pre-resolve (null) and
    // signed-out (false) cases so we don't flicker an error before auth settles.
    if (!indicator || authed !== true) {
      setPeek({ status: 'idle' });
      return;
    }
    const token = ++reqToken.current;
    setPeek({ status: 'loading', indicator });
    const timer = setTimeout(() => {
      // Clock the request itself, not the debounce — the chip claims query time.
      const started = performance.now();
      api
        .iocPeek(indicator.value)
        .then((data) => {
          if (token !== reqToken.current) return;
          setPeek({ status: 'ready', indicator, data, ms: Math.round(performance.now() - started) });
        })
        .catch((caught) => {
          if (token !== reqToken.current) return;
          setPeek({ status: 'error', indicator, message: errorMessage(caught) });
        });
    }, 350);
    return () => clearTimeout(timer);
  }, [indicator?.kind, indicator?.value, authed]);

  const submit = () => {
    // Nothing to hand over if there's no session — the main window is on the
    // login screen and would drop the query.
    if (authed === false) return;
    const query = indicator ? indicatorQuery(indicator) : input.trim();
    if (!query) return;
    // Open an indicator search over the same window the peek used, so the main
    // window shows the events the peek counted; free-text uses the tab default.
    void api.openInMain(query, indicator ? PEEK_RANGE : undefined);
  };

  const askPivt = () => {
    if (authed === false) return;
    const value = input.trim();
    if (!value) return;
    // An indicator becomes an investigation prompt; free text is asked as-is.
    const prompt = indicator
      ? `What can you tell me about the ${indicatorLabel(indicator.kind).toLowerCase()} ${indicator.value}? Investigate where it's been seen in our environment and whether it's a concern.`
      : value;
    void api.askPivt(prompt);
  };

  return (
    <div className="flex h-full flex-col overflow-hidden rounded-[16px] border border-line-strong bg-window">
      <div className="flex items-center gap-3 px-4.5 py-4">
        <SearchIcon />
        <input
          ref={inputRef}
          value={input}
          onChange={(event) => setInput(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') {
              event.preventDefault();
              if (event.metaKey) askPivt();
              else submit();
            }
          }}
          placeholder="Search logs, or drop an IP, hash, or domain"
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          className="min-w-0 flex-1 bg-transparent text-[17px] text-t1 outline-none placeholder:text-t4"
        />
        {peek.status === 'loading' && <Spinner className="text-t3" />}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto border-t border-line px-4.5 py-3.5">
        <Body authed={authed} input={input} indicator={indicator} peek={peek} />
      </div>

      <Footer indicator={indicator} hasInput={input.trim().length > 0} />
    </div>
  );
}

function Body({
  authed,
  input,
  indicator,
  peek,
}: {
  authed: boolean | null;
  input: string;
  indicator: Indicator | null;
  peek: Peek;
}) {
  if (authed === false) {
    return (
      <Hint>
        Sign in from the main nano window to search. <Kbd>⌥Space</Kbd> reopens this any time.
      </Hint>
    );
  }
  if (!input.trim()) {
    return (
      <Hint>
        Type an nPL query and press <Kbd>↵</Kbd> to open it in nano — or drop an IP, hash, or
        domain for a live context peek.
      </Hint>
    );
  }
  if (indicator) {
    return <PeekView peek={peek} indicator={indicator} />;
  }
  return (
    <div className="flex items-baseline gap-2 text-[13px] text-t2">
      <Kbd>↵</Kbd>
      <span>
        Search <span className="font-mono text-t1">{input.trim()}</span> in nano
      </span>
    </div>
  );
}

function PeekView({ peek, indicator }: { peek: Peek; indicator: Indicator }) {
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-2.5">
        <span className="text-[10.5px] font-bold tracking-[0.06em] text-t4 uppercase">
          {indicatorLabel(indicator.kind)}
        </span>
        <span className="font-mono text-[13px] text-t1">{indicator.value}</span>
        {peek.status === 'ready' && <LiveChip ms={peek.ms} />}
        {peek.status === 'loading' && <Spinner className="text-t3" />}
      </div>

      {peek.status === 'error' && (
        <p className="text-[12.5px] leading-[1.5] text-danger">{peek.message}</p>
      )}

      {peek.status === 'ready' && <PeekResult data={peek.data} />}
    </div>
  );
}

function PeekResult({ data }: { data: IocPeek }) {
  if (!data.seen) {
    return <p className="text-[13px] text-t3">Not seen in the last {data.window_days} days.</p>;
  }
  return (
    <div className="flex flex-col gap-2.5">
      <div className="flex flex-wrap items-center gap-1.5">
        <Chip tone="accent">{plural(data.events, 'event')}</Chip>
        <Chip tone="muted">{plural(data.assets, 'asset')}</Chip>
        <span className="self-center text-[11px] text-t4">last {data.window_days}d</span>
      </div>

      {(data.first_seen || data.last_seen) && (
        <p className="text-[12px] text-t3">
          {data.first_seen && `First seen ${ago(data.first_seen)}`}
          {data.first_seen && data.last_seen && ' · '}
          {data.last_seen && `last seen ${ago(data.last_seen)}`}
        </p>
      )}

      {data.top_assets.length > 0 && (
        <div className="flex flex-col gap-1">
          <span className="text-[10.5px] font-bold tracking-[0.06em] text-t4 uppercase">
            Top assets
          </span>
          {data.top_assets.map((entry) => (
            <div key={entry.asset} className="flex items-center justify-between text-[12px]">
              <span className="font-mono text-t1">{entry.asset}</span>
              <span className="text-t3">{plural(entry.hits, 'hit')}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Footer({ indicator, hasInput }: { indicator: Indicator | null; hasInput: boolean }) {
  return (
    <div className="flex items-center justify-between border-t border-line px-4.5 py-2.5 text-[11px] text-t4">
      {hasInput ? (
        <span className="flex items-center gap-3">
          <span>
            <Kbd>↵</Kbd> {indicator ? 'Search' : 'Open in nano'}
          </span>
          <span>
            <Kbd>⌘↵</Kbd> Ask pivt
          </span>
        </span>
      ) : (
        <span>nano Quick Search</span>
      )}
      <span>
        <Kbd>esc</Kbd> Close
      </span>
    </div>
  );
}

function LiveChip({ ms }: { ms: number }) {
  // Honest: this was just fetched from nano, not read from a local cache.
  return (
    <span className="flex items-center gap-1.5 text-[10.5px] text-t4">
      <span className="size-1.5 rounded-full bg-accent" />
      queried nano · {ms} ms
    </span>
  );
}

function Chip({ tone, children }: { tone: 'muted' | 'accent'; children: React.ReactNode }) {
  const tones = {
    muted: 'border-line-strong text-t2',
    accent: 'border-accent-line bg-accent-soft text-accent',
  };
  return (
    <span
      className={`rounded-[6px] border px-2 py-0.5 text-[11px] font-medium ${tones[tone]}`}
    >
      {children}
    </span>
  );
}

function Hint({ children }: { children: React.ReactNode }) {
  return <p className="text-[13px] leading-[1.6] text-t3">{children}</p>;
}

function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="rounded-[5px] border border-line-strong bg-raised px-1.5 py-0.5 font-mono text-[10.5px] text-t2">
      {children}
    </kbd>
  );
}

function SearchIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" className="shrink-0 text-t3">
      <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="1.5" />
      <path d="m20 20-3.5-3.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}

function plural(n: number, noun: string): string {
  return `${n.toLocaleString()} ${noun}${n === 1 ? '' : 's'}`;
}

function ago(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '—';
  const secs = Math.max(0, (Date.now() - then) / 1000);
  if (secs < 60) return 'just now';
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}
