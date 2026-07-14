import { useEffect, useRef, useState } from 'react';
import { Channel, invoke } from '@tauri-apps/api/core';
import { FitAddon } from '@xterm/addon-fit';
import { Terminal as Xterm } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';

import { api, errorMessage } from '../lib/ipc';
import type { AgentStatus } from '../lib/types';

export interface QueryHistoryEntry {
  /** Which run this was, so a concurrent tab's result can't be stamped onto it. */
  runId: string;
  query: string;
  at: number;
  events: number | null;
}

type Tab = 'terminal' | 'history';

interface Props {
  history: QueryHistoryEntry[];
  onPickQuery: (query: string) => void;
  onClose: () => void;
}

export function TerminalDrawer({ history, onPickQuery, onClose }: Props) {
  const [tab, setTab] = useState<Tab>('terminal');
  const [agent, setAgent] = useState<AgentStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [agentError, setAgentError] = useState<string | null>(null);

  useEffect(() => {
    void api
      .agentStatus()
      .then(setAgent)
      .catch(() => setAgent(null));
  }, []);

  async function provision() {
    setBusy(true);
    setAgentError(null);
    try {
      setAgent(await api.provisionAgent());
    } catch (caught) {
      setAgentError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex h-[260px] shrink-0 flex-col border-t border-line-strong bg-black/45 font-mono text-[12px]">
      <div className="flex shrink-0 items-center gap-4.5 border-b border-white/5 px-[18px] py-2 text-[11px]">
        <TabButton active={tab === 'terminal'} onClick={() => setTab('terminal')}>
          Terminal
        </TabButton>
        <TabButton active={tab === 'history'} onClick={() => setTab('history')}>
          Query history
        </TabButton>
        <span className="flex-1" />
        {/* The real state, not the mock's hardcoded "connected". */}
        <AgentBadge agent={agent} busy={busy} error={agentError} onProvision={provision} />
        <button onClick={onClose} className="text-t4 hover:text-t1" title="Hide drawer (⌘J)">
          ✕
        </button>
      </div>

      {/* The pty is mounted once and hidden rather than unmounted, so switching
          tabs doesn't kill a running shell (or whatever agent is mid-answer). */}
      <div className={`min-h-0 flex-1 ${tab === 'terminal' ? '' : 'hidden'}`}>
        <Shell />
      </div>
      {tab === 'history' && <QueryHistory history={history} onPick={onPickQuery} />}
    </div>
  );
}

/**
 * The mock shows a static `claude-code connected · mcp://nano.local`. This says
 * what is actually true: whether an agent CLI is installed, and whether nano's
 * tools have been wired to it.
 */
function AgentBadge({
  agent,
  busy,
  error,
  onProvision,
}: {
  agent: AgentStatus | null;
  busy: boolean;
  error: string | null;
  onProvision: () => void;
}) {
  if (error) {
    return <span className="text-danger">{error}</span>;
  }
  if (!agent) return null;

  const clis = [
    agent.claude_installed && 'claude-code',
    agent.codex_installed && 'codex',
  ].filter(Boolean) as string[];

  if (clis.length === 0) {
    return (
      <span className="text-t4" title="Install Claude Code or Codex to use nano's agent tools">
        no agent CLI found
      </span>
    );
  }

  if (agent.provisioned) {
    return (
      <span className="flex items-center gap-1.5 text-accent">
        <span className="size-1.5 rounded-full bg-accent pulse" />
        {clis.join(' · ')} connected · nano MCP
        {agent.key_prefix && <span className="text-t4">· key {agent.key_prefix}…</span>}
      </span>
    );
  }

  return (
    <button
      onClick={onProvision}
      disabled={busy}
      title="Mints a read-only API key and configures nano's MCP tools for these CLIs"
      className="rounded-[5px] border border-accent-line bg-accent-soft px-2 py-0.5 text-accent disabled:opacity-50"
    >
      {busy ? 'Connecting…' : `Connect ${clis.join(' + ')} to nano`}
    </button>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={active ? 'font-semibold text-t1' : 'text-t4 hover:text-t2'}
    >
      {children}
    </button>
  );
}

function Shell() {
  const host = useRef<HTMLDivElement>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const element = host.current;
    if (!element) return;

    const term = new Xterm({
      fontFamily: "ui-monospace, 'SF Mono', Menlo, monospace",
      fontSize: 12,
      lineHeight: 1.35,
      cursorBlink: true,
      allowTransparency: true,
      theme: {
        background: 'rgba(0,0,0,0)',
        foreground: '#F2F4F7',
        cursor: '#FF5CA8',
        selectionBackground: 'rgba(255,92,168,0.28)',
        black: '#1A1D24',
        red: '#FF7A76',
        green: '#4FD6A0',
        yellow: '#FFB454',
        blue: '#7FB8FF',
        magenta: '#FF5CA8',
        cyan: '#5EE7F0',
        white: '#F2F4F7',
      },
    });

    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(element);
    fit.fit();

    const output = new Channel<string>();
    output.onmessage = (encoded) => {
      // Raw shell bytes arrive base64'd: a read can split a multi-byte character,
      // and not every byte a terminal emits is valid UTF-8. xterm decodes.
      const binary = atob(encoded);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
      term.write(bytes);
    };

    let disposed = false;
    void invoke('pty_open', { rows: term.rows, cols: term.cols, onOutput: output }).catch(
      (caught) => {
        if (!disposed) setError(errorMessage(caught));
      }
    );

    const input = term.onData((data) => {
      void invoke('pty_write', { data });
    });

    // Refit on drawer/window resize, and tell the shell its new size — otherwise
    // full-screen programs wrap at the wrong column.
    const observer = new ResizeObserver(() => {
      fit.fit();
      void invoke('pty_resize', { rows: term.rows, cols: term.cols });
    });
    observer.observe(element);

    return () => {
      disposed = true;
      observer.disconnect();
      input.dispose();
      term.dispose();
      void invoke('pty_close');
    };
  }, []);

  return (
    <div className="relative h-full">
      <div ref={host} className="h-full px-[18px] py-2" />
      {error && (
        <div className="absolute inset-0 flex items-center justify-center px-6 text-center text-[12px] text-danger">
          {error}
        </div>
      )}
    </div>
  );
}

function QueryHistory({
  history,
  onPick,
}: {
  history: QueryHistoryEntry[];
  onPick: (query: string) => void;
}) {
  if (history.length === 0) {
    return (
      <div className="flex flex-1 items-center justify-center text-[11.5px] text-t4">
        Queries you run this session appear here.
      </div>
    );
  }

  return (
    <div className="min-h-0 flex-1 overflow-auto px-[18px] py-2">
      {history.map((entry) => (
        <button
          key={entry.runId}
          onClick={() => onPick(entry.query)}
          className="flex w-full items-baseline gap-3 rounded-[6px] px-2 py-1.5 text-left hover:bg-white/5"
        >
          <span className="shrink-0 text-[10.5px] text-t4">
            {new Date(entry.at).toLocaleTimeString(undefined, { hour12: false })}
          </span>
          <span className="min-w-0 flex-1 truncate text-t2">{entry.query || '*'}</span>
          {entry.events !== null && (
            <span className="shrink-0 text-[10.5px] text-t4">
              {entry.events.toLocaleString()} events
            </span>
          )}
        </button>
      ))}
    </div>
  );
}
