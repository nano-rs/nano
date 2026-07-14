import { useEffect, useRef, useState, type KeyboardEvent } from 'react';
import { Channel, invoke } from '@tauri-apps/api/core';

import { errorMessage } from '../lib/ipc';
import { Markdown } from '../lib/markdown';
import type { ScreenContext } from '../lib/screen';
import { Spinner } from './ui';

/**
 * pivt — the ambient assistant.
 *
 * It is handed what the analyst is currently looking at (query, window, the rows
 * on screen, the expanded event), so "why did this spike?" is answerable without
 * a single tool call. nano's MCP tools are its reach for what ISN'T on screen —
 * a wider window, another source, an entity's history.
 *
 * The engine is the local `claude` CLI in headless mode: already authenticated,
 * and pointed at the same MCP config the terminal uses.
 */

/** One tool pivt ran, and how it went. */
export interface ToolCall {
  /** Claude's `tool_use` block id — what a later `tool_result` refers back to. */
  id: string;
  /** The wire name (`mcp__nano__search`) — what the tool router matches on. */
  raw: string;
  /** `nano.search`, not `mcp__nano__search`. For humans. */
  name: string;
  /** The raw arguments, kept whole: the mirrored tab is driven off them. */
  input: Record<string, unknown>;
  /** The one-line gist for the collapsed card. */
  detail: string;
  failed?: boolean;
  /**
   * What actually went wrong, in the server's words.
   *
   * This used to be rendered as "denied" for ANY error, which invented a security
   * story out of an ordinary mistake: a query naming a field that doesn't exist on
   * this schema profile came back "Unknown field 'event_code'", and the panel told
   * the analyst their agent had been DENIED. In a security console, that sends
   * someone hunting a permissions bug that was never there.
   */
  error?: string;
}

/**
 * The conversation, as exchanges rather than a flat list of turns.
 *
 * A tool call belongs to the question that provoked it. Keeping the two together
 * — instead of one global tool block pinned under the chat — is what lets the
 * panel show "here is what pivt did to answer THIS" and fold it away once read.
 * `items` stays in arrival order, so "I'll check the auth logs" → search →
 * "here's what I found" reads the way it happened.
 */
export type Item =
  | { kind: 'text'; text: string }
  | { kind: 'tool'; tool: ToolCall };

export interface Exchange {
  question: string;
  items: Item[];
}

interface Props {
  /**
   * Rebuilt on every render so the assistant always gets the CURRENT screen.
   * `null` when the analyst has no search open — pivt is then told nothing about
   * the screen rather than the panel being torn down to avoid the question.
   */
  screen: ScreenContext | null;
  onClose: () => void;
  /** A question routed in from Quick Search (⌘↵). Asked when `nonce` changes. */
  pendingAsk?: { text: string; nonce: number };
  /**
   * Hidden rather than unmounted. Toggling ⌘I used to destroy the panel, taking
   * the conversation, the Claude session id and the notebook with it — an
   * investigation you could lose by pressing the button that opened it.
   */
  hidden?: boolean;

  /**
   * pivt using the product for real. Every tool call is handed to the workspace,
   * which opens it as a tab the analyst can read and build on. See lib/agent-tools.
   */
  onToolCall?: (call: ToolCall) => void;
  /** What the tool came back with, matched to its call by id. */
  onToolResult?: (callId: string, result: string, failed: boolean) => void;
  /** The investigation's notebook — its title names the tab group. */
  onNotebook?: (notebook: { id: string; title: string }) => void;
  /** Whether pivt is working — the rail pulses while it is, even when hidden. */
  onRunningChange?: (running: boolean) => void;
  /**
   * An unfinished investigation, picked back up.
   *
   * The whole conversation is rehydrated from the notebook, and the Claude session
   * id goes back to `--resume`, so pivt continues the SAME conversation rather than
   * starting a new one that merely looks like it. Keyed on `nonce` so resuming the
   * same session twice still fires.
   */
  resume?: {
    nonce: number;
    notebook: { id: string; title: string };
    sessionId: string | null;
    exchanges: Exchange[];
  };
}

export function AgentPanel({
  screen,
  onClose,
  pendingAsk,
  hidden,
  onToolCall,
  onToolResult,
  onNotebook,
  onRunningChange,
  resume,
}: Props) {
  const [exchanges, setExchanges] = useState<Exchange[]>([]);
  const [input, setInput] = useState('');
  const [running, setRunning] = useState(false);
  const runningRef = useRef(false);
  /** A question waiting for the current turn to finish. */
  const queued = useRef<string | null>(null);
  const [queuedPreview, setQueuedPreview] = useState<string | null>(null);

  useEffect(() => {
    onRunningChange?.(running);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running]);
  const [error, setError] = useState<string | null>(null);
  /**
   * Claude Code's session id and the notebook — held in REFS as well as state.
   *
   * The state is for rendering; the refs are what `ask` reads. A queued question
   * is run from inside the previous turn's `finally`, i.e. from that turn's
   * closure — which still holds the session and notebook as they were BEFORE the
   * turn set them. Reading state there would launch the follow-up with
   * `resume: null`, starting a second Claude conversation and a second notebook:
   * the investigation would silently fork, and its audit trail with it.
   */
  // The session id is never rendered, only sent back to resume — so it is a ref
  // and nothing else. The notebook IS rendered, so it needs both.
  const sessionRef = useRef<string | null>(null);
  const [notebook, setNotebook] = useState<{ id: string; title: string } | null>(null);
  const notebookRef = useRef<{ id: string; title: string } | null>(null);
  const [notRecorded, setNotRecorded] = useState<string | null>(null);

  // Same reason as the session/notebook refs: a queued question runs from the
  // previous turn's closure, and must be handed the screen as it is NOW.
  const screenRef = useRef(screen);
  screenRef.current = screen;

  const scroller = useRef<HTMLDivElement>(null);
  useEffect(() => {
    scroller.current?.scrollTo({ top: scroller.current.scrollHeight });
  }, [exchanges, running]);

  // A question handed over from Quick Search (⌘↵ Ask pivt) auto-asks here. Keyed
  // on `nonce` so asking about the same thing twice still fires.
  useEffect(() => {
    if (pendingAsk?.text) void ask(pendingAsk.text);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pendingAsk?.nonce]);

  // Picking an unfinished investigation back up: the conversation comes back, and
  // so does the session it belongs to, so the next question CONTINUES it.
  useEffect(() => {
    if (!resume) return;
    // Never rehydrate on TOP of a live turn — the streaming handler would append
    // the running answer onto the replayed transcript, and the queued-question
    // flush would record it into the wrong notebook and --resume the wrong
    // conversation. If pivt is mid-answer, resuming is simply refused here (the
    // Sessions button is also disabled while running).
    if (runningRef.current) return;
    setExchanges(resume.exchanges);
    setNotebook(resume.notebook);
    notebookRef.current = resume.notebook;
    onNotebook?.(resume.notebook);
    sessionRef.current = resume.sessionId;
    setError(null);
    setNotRecorded(
      resume.sessionId
        ? null
        : 'This session was recorded before pivt kept its session id, so it cannot be continued — a new question starts a fresh conversation.'
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resume?.nonce]);

  /** Append to the exchange in flight — the last one, always. */
  function appendItem(item: Item) {
    setExchanges((current) => {
      if (current.length === 0) return current;
      const last = current[current.length - 1];
      return [...current.slice(0, -1), { ...last, items: [...last.items, item] }];
    });
  }

  async function ask(promptText?: string) {
    const prompt = (promptText ?? input).trim();
    if (!prompt) return;

    // A question arriving while pivt is mid-answer used to be dropped on the
    // floor — no error, no queue, no sign it had happened. "Investigate these 3
    // matches with pivt" from the bulk lookup, or ⌘↵ from Quick Search, could
    // simply evaporate. Queue it and say so.
    if (runningRef.current) {
      queued.current = prompt;
      setInput('');
      setQueuedPreview(prompt);
      return;
    }

    setInput('');
    setError(null);
    setExchanges((current) => [...current, { question: prompt, items: [] }]);
    setRunning(true);
    // A ref, not the state: `ask` can be re-entered from the `finally` below
    // before React has re-rendered, and the state value would still read `false`.
    runningRef.current = true;

    const channel = new Channel<AgentEvent>();
    channel.onmessage = (event) => {
      if (event.event === 'notebook') {
        const opened = event.data as { id: string; title: string };
        notebookRef.current = opened;
        setNotebook(opened);
        onNotebook?.(opened);
        return;
      }
      // If the trail failed to open, say so. A record the analyst believes
      // exists and doesn't is worse than no record at all.
      if (event.event === 'notebook_error') {
        setNotRecorded((event.data as { message: string }).message);
        return;
      }

      if (event.type === 'system' && event.subtype === 'init') {
        sessionRef.current = event.session_id ?? null;
        return;
      }

      if (event.type === 'assistant') {
        for (const block of event.message?.content ?? []) {
          if (block.type === 'text' && block.text?.trim()) {
            appendItem({ kind: 'text', text: block.text });
          } else if (block.type === 'tool_use') {
            const input = isObject(block.input) ? block.input : {};
            const call: ToolCall = {
              id: block.id ?? '',
              raw: block.name ?? '',
              name: prettyTool(block.name ?? ''),
              input,
              detail: summarize(input),
            };
            appendItem({ kind: 'tool', tool: call });
            // The workspace mirrors it into a real tab. This is the whole point:
            // pivt uses the product, it doesn't just describe having used it.
            onToolCall?.(call);
          }
        }
        return;
      }

      // A failed tool must be visible, not silently swallowed — it explains why
      // the answer took another route. What it must NOT be is described as a
      // denial: most failures are pivt naming a field this schema doesn't have.
      // Matched by `tool_use_id`, not by position: pivt fires tools in parallel,
      // so "the most recent one" is regularly the wrong one to blame.
      if (event.type === 'user') {
        for (const block of event.message?.content ?? []) {
          if (block.type !== 'tool_result' || !block.tool_use_id) continue;
          const failed = Boolean(block.is_error);
          const text = resultText(block.content);
          if (failed) markFailed(block.tool_use_id, text);
          onToolResult?.(block.tool_use_id, text, failed);
        }
      }
    };

    try {
      await invoke('agent_ask', {
        prompt,
        screen: screenRef.current,
        // From the REFS, not the state: a queued follow-up runs inside the
        // previous turn's closure, where the state still reads null. See the
        // declarations above — getting this wrong forks the investigation.
        resume: sessionRef.current,
        // Reuse this session's notebook, so a conversation is one investigation
        // rather than a notebook per question.
        notebook: notebookRef.current?.id ?? null,
        onEvent: channel,
      });
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setRunning(false);
      runningRef.current = false;

      // Flush whatever arrived while this turn was in flight.
      const next = queued.current;
      queued.current = null;
      setQueuedPreview(null);
      if (next) void ask(next);
    }
  }

  function markFailed(toolUseId: string, message: string) {
    setExchanges((current) =>
      current.map((exchange) => ({
        ...exchange,
        items: exchange.items.map((item) =>
          item.kind === 'tool' && item.tool.id === toolUseId
            ? { ...item, tool: { ...item.tool, failed: true, error: summarizeError(message) } }
            : item
        ),
      }))
    );
  }

  function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      void ask();
    }
  }

  return (
    <div
      className={`w-[420px] shrink-0 flex-col border-l border-line bg-panel ${hidden ? 'hidden' : 'flex'}`}
    >
      <div className="flex items-center gap-2.5 border-b border-line px-4 py-3">
        <span className={`size-2 shrink-0 rounded-full ${running ? 'bg-accent pulse' : 'bg-accent/40'}`} />
        <span className="shrink-0 text-[13px] font-semibold text-t1">pivt</span>
        <span className="ml-auto truncate font-mono text-[10.5px] text-t4">
          {notebook ? `notebook · ${notebook.id.slice(0, 12)}` : 'claude-code · MCP'}
        </span>
        <button onClick={onClose} className="shrink-0 text-t4 hover:text-t1" title="Hide pivt (⌘I)">
          ✕
        </button>
      </div>

      {/* overflow-x-hidden, not auto: nothing in a 330px panel earns a sideways
          scrollbar. Long tokens wrap or clip inside their own card instead. */}
      <div
        ref={scroller}
        className="flex-1 space-y-3 overflow-x-hidden overflow-y-auto p-4 text-[12.5px] leading-[1.55]"
      >
        {exchanges.length === 0 && !running && (
          <div className="text-[12px] text-t4">
            pivt can see your query, time range, and the rows on screen. Ask about them
            directly — "why the spike?", "anything odd here?" — or have it dig further with
            nano's tools.
          </div>
        )}

        {exchanges.map((exchange, index) => (
          <ExchangeView key={index} exchange={exchange} />
        ))}

        {running && (
          <div className="flex items-center gap-2 text-[11.5px] text-t3">
            <Spinner className="text-accent" /> thinking…
          </div>
        )}

        {/* Asked while pivt was busy. It WILL run — saying so beats the old
            behaviour, which was to drop it without a trace. */}
        {queuedPreview && (
          <div className="ml-auto max-w-[85%] rounded-[11px_11px_3px_11px] border border-line-strong bg-white/5 px-3 py-2 text-[12px] break-words text-t3">
            {queuedPreview}
            <span className="mt-0.5 block font-mono text-[10.5px] text-t4">queued</span>
          </div>
        )}

        {notRecorded && (
          <div className="rounded-[8px] border border-warn/40 bg-warn-soft px-3 py-2 text-[11.5px] break-words text-warn">
            Not being recorded to a notebook: {notRecorded}
          </div>
        )}

        {error && (
          <div className="rounded-[8px] border border-danger/40 bg-danger-soft px-3 py-2 text-[11.5px] break-words text-danger">
            {error}
          </div>
        )}
      </div>

      <div className="border-t border-line p-3">
        <textarea
          rows={2}
          value={input}
          onChange={(event) => setInput(event.target.value)}
          onKeyDown={onKeyDown}
          placeholder="Ask about what's on screen…"
          className="w-full resize-none rounded-[9px] border border-line-strong bg-input px-3 py-2 text-[12.5px] text-t1 outline-none placeholder:text-t4 focus:border-accent"
        />
      </div>
    </div>
  );
}

/** One question and everything pivt did and said in answer to it. */
function ExchangeView({ exchange }: { exchange: Exchange }) {
  return (
    <div className="space-y-3">
      <div className="ml-auto max-w-[85%] rounded-[11px_11px_3px_11px] border border-accent-line bg-accent-soft px-3 py-2 break-words text-t1">
        {exchange.question}
      </div>

      {groupItems(exchange.items).map((group, index) =>
        group.kind === 'text' ? (
          <div
            key={index}
            className="max-w-[92%] min-w-0 rounded-[11px_11px_11px_3px] border border-line-strong bg-white/5 px-3 py-2.5 text-t2"
          >
            <Markdown text={group.text} />
          </div>
        ) : (
          <ActivityCard key={index} tools={group.tools} />
        )
      )}
    </div>
  );
}

/**
 * A run of tool calls, collapsed to one line. Expanded, it is the audit trail:
 * what pivt asked nano for, in full, and whether nano answered.
 *
 * Collapsed by default — the answer is what the analyst came for; how it was
 * reached is one click away.
 */
function ActivityCard({ tools }: { tools: ToolCall[] }) {
  const [open, setOpen] = useState(false);
  const failed = tools.filter((tool) => tool.failed).length;

  return (
    <div className="min-w-0 overflow-hidden rounded-[8px] border border-line-strong bg-black/25">
      <button
        onClick={() => setOpen((current) => !current)}
        className="flex w-full items-center gap-1.5 px-3 py-1.5 text-left font-mono text-[11px] text-t3 hover:text-t1"
      >
        {/* inline-block is load-bearing: a transform is ignored on an inline
            element, so an inline span would never actually rotate. */}
        <span
          className={`inline-block shrink-0 text-[9px] transition-transform ${open ? 'rotate-90' : ''}`}
        >
          ▶
        </span>
        <span className={`shrink-0 ${failed ? 'text-danger' : 'text-accent'}`}>⏺</span>
        <span className="truncate">
          {tools.length === 1 ? tools[0].name : `${tools.length} tool calls`}
        </span>
        {failed > 0 && (
          <span className="ml-auto shrink-0 text-danger">
            {failed} failed
          </span>
        )}
      </button>

      {open && (
        <div className="space-y-1.5 border-t border-line px-3 py-2">
          {tools.map((tool, index) => (
            <div key={index} className="min-w-0 font-mono text-[11px] leading-[1.5]">
              <div className={tool.failed ? 'text-danger' : 'text-accent'}>
                {tool.name}
              </div>
              {/* break-all, not break-words: an nPL query or a sha256 has no
                  spaces to break on, and is exactly what bled out of the panel. */}
              {tool.detail && <div className="break-all text-t4">{tool.detail}</div>}
              {/* The real reason, not a guess at it. Most failures are pivt getting
                  a field name wrong and fixing it on the next call. */}
              {tool.failed && tool.error && (
                <div className="break-words text-danger">{tool.error}</div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

type Group = { kind: 'text'; text: string } | { kind: 'tools'; tools: ToolCall[] };

/** Consecutive tool calls collapse into one card; text stays as it came. */
function groupItems(items: Item[]): Group[] {
  const groups: Group[] = [];
  for (const item of items) {
    if (item.kind === 'text') {
      groups.push({ kind: 'text', text: item.text });
      continue;
    }
    const last = groups[groups.length - 1];
    if (last?.kind === 'tools') last.tools.push(item.tool);
    else groups.push({ kind: 'tools', tools: [item.tool] });
  }
  return groups;
}

/**
 * The failure, in one readable line.
 *
 * A tool error is usually a plain sentence ("Unknown field 'event_code' in query.
 * Did you mean: event_type…"), sometimes a JSON blob. Either way the analyst wants
 * the first sentence of it, not the word "denied".
 */
function summarizeError(message: string): string {
  const text = message.replace(/^Error:\s*/i, '').trim();
  if (!text) return 'failed';

  // A JSON error body: pull the message out rather than showing braces.
  try {
    const parsed = JSON.parse(text) as { error?: { message?: string }; message?: string };
    const inner = parsed.error?.message ?? parsed.message;
    if (inner) return clip(inner);
  } catch {
    // Not JSON. Good — it's already prose.
  }
  return clip(text.split('\n')[0]);
}

function clip(text: string): string {
  return text.length > 160 ? `${text.slice(0, 160)}…` : text;
}

/** `mcp__nano__search` reads as noise; `nano.search` reads as a tool. */
function prettyTool(name: string): string {
  return name.startsWith('mcp__nano__') ? `nano.${name.slice('mcp__nano__'.length)}` : name;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function summarize(input: Record<string, unknown>): string {
  const interesting = input.query ?? input.sql ?? input.entity ?? input.value ?? input.id;
  if (typeof interesting !== 'string') return '';
  return interesting.length > 120 ? `${interesting.slice(0, 120)}…` : interesting;
}

/**
 * A tool result is `[{type:'text', text}]` or a bare string, depending on the
 * tool. Clipped: the tool tab is a RECORD of what pivt got, not a second copy of
 * the result set — a `search_sql` result can be a hundred kilobytes of JSON.
 */
const MAX_RESULT_CHARS = 20_000;

function resultText(content: unknown): string {
  const text = extractText(content);
  return text.length > MAX_RESULT_CHARS
    ? `${text.slice(0, MAX_RESULT_CHARS)}\n…[truncated — see the notebook for the full record]`
    : text;
}

function extractText(content: unknown): string {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content
      .map((block) =>
        isObject(block) && typeof block.text === 'string' ? block.text : ''
      )
      .filter(Boolean)
      .join('\n');
  }
  return '';
}

/** The subset of Claude Code's stream-json events the panel renders. */
interface AgentEvent {
  /** Our own frames (notebook lifecycle), distinct from Claude's stream events. */
  event?: 'notebook' | 'notebook_error';
  data?: unknown;
  type?: 'system' | 'assistant' | 'user' | 'result';
  subtype?: string;
  session_id?: string;
  message?: {
    content?: {
      type: string;
      text?: string;
      /** On `tool_use`: the id a later `tool_result` refers back to. */
      id?: string;
      name?: string;
      input?: unknown;
      /** On `tool_result`: which `tool_use` it answers, and what it returned. */
      tool_use_id?: string;
      content?: unknown;
      is_error?: boolean;
    }[];
  };
}
