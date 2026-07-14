import { Suspense, lazy, useCallback, useEffect, useReducer, useRef, useState } from 'react';
import { listen } from '@tauri-apps/api/event';

import { setAutocompleteTimeRange } from '@/lib/query-autocomplete';
import { toApiTimeRange, type TimeRangeValue } from '@/lib/time-range';

import { AgentPanel, type Exchange, type ToolCall } from '../components/AgentPanel';
import { BulkPane } from '../components/BulkPane';
import { DashboardPane } from '../components/DashboardPane';
import { DashboardsPane } from '../components/DashboardsPane';
import { McpToolsPane } from '../components/McpToolsPane';
import { SearchPane } from '../components/SearchPane';
import { SessionsPane } from '../components/SessionsPane';
import { Sidebar } from '../components/Sidebar';
import { ToolPane } from '../components/ToolPane';
import { buildScreenContext } from '../lib/screen';
import { TabStrip } from '../components/TabStrip';
import { UserMenu } from '../components/UserMenu';
import type { QueryHistoryEntry } from '../components/TerminalDrawer';
import { baseName, mirrorFor } from '../lib/agent-tools';
import {
  addDraftPanel,
  emptyDraft,
  panelDataFromToolResult,
  panelFromToolInput,
  savedDashboardId,
} from '../lib/dashboard-draft';
import { extractIndicators, indicatorQuery } from '../lib/indicator';
import { replaySession } from '../lib/session';
import { api, errorMessage } from '../lib/ipc';
import { useSchemaProfile } from '../lib/schema';
import type {
  DashboardDetail,
  NotebookEntry,
  PivtSession,
  ServerConfig,
  StreamEvent,
  User,
} from '../lib/types';
import {
  FULL_LIMIT,
  MAX_GROUP_TABS,
  initialTabs,
  newAgentSearchTab,
  newDashboardTab,
  newSingletonTab,
  newAgentToolTab,
  newBulkTab,
  newTab,
  tabsReducer,
  type BulkState,
  type DraftPanelState,
  type SingletonKind,
  type Tab,
} from '../state/tabs';

// xterm is a big dependency and the drawer starts closed — don't pay for it at launch.
const TerminalDrawer = lazy(() =>
  import('../components/TerminalDrawer').then((m) => ({ default: m.TerminalDrawer }))
);

interface Props {
  server: ServerConfig;
  user: User;
  onLock: () => void;
  onSignOut: () => void;
}

export function Search({ server, user, onLock, onSignOut }: Props) {
  const profile = useSchemaProfile();
  const [state, dispatch] = useReducer(tabsReducer, undefined, initialTabs);

  const [showTerminal, setShowTerminal] = useState(false);
  // Open by default. The desktop client is agent-driven — pivt is the workflow, not
  // a panel you go and find. ⌘I still hides it.
  const [showAgent, setShowAgent] = useState(true);
  /** pivt is working. Surfaced in the rail, so it's visible with the panel hidden. */
  const [agentRunning, setAgentRunning] = useState(false);
  /** A question routed from Quick Search (⌘↵) for pivt to pick up. */
  const [pivtAsk, setPivtAsk] = useState<{ text: string; nonce: number } | null>(null);
  /** An unfinished investigation being picked back up. */
  const [pivtResume, setPivtResume] = useState<{
    nonce: number;
    notebook: { id: string; title: string };
    sessionId: string | null;
    exchanges: Exchange[];
  } | null>(null);
  /** Whatever event the analyst has open — part of what pivt can see. */
  const [expandedEvent, setExpandedEvent] = useState<Record<string, unknown> | null>(null);
  // Workspace-level: the history is the analyst's, not a single tab's.
  const [history, setHistory] = useState<QueryHistoryEntry[]>([]);

  const activeTab = state.tabs.find((tab) => tab.id === state.activeId) ?? state.tabs[0];

  // Once opened, the panel stays mounted (hidden) for the rest of the session.
  const agentEverOpened = useRef(false);
  if (showAgent) agentEverOpened.current = true;

  // What pivt is shown. A tool tab is a record of pivt's OWN work — handing it
  // back as "the analyst's screen" would have pivt reasoning about its own
  // exhaust. Fall back to the search the analyst was last actually looking at.
  const contextTab =
    activeTab?.kind === 'search'
      ? activeTab
      : [...state.tabs].reverse().find((tab) => tab.kind === 'search');

  // `run` is called from event handlers and keyboard shortcuts; reading tabs
  // from a ref keeps it from capturing a stale snapshot of them.
  const stateRef = useRef(state);
  stateRef.current = state;

  // Rows arrive in batches, per tab. Coalescing them into one state update per
  // frame keeps a fast stream from re-rendering hundreds of times.
  const pending = useRef(new Map<string, Record<string, unknown>[]>());
  const flushHandles = useRef(new Map<string, number>());
  // The run currently owning each tab. Re-running (or the Rust side superseding)
  // doesn't unregister the previous run's event listener, so its late frames
  // still arrive; onEvent drops any whose runId is no longer the tab's current
  // one, keeping a stale query's rows/count/status off a fresh run.
  const currentRun = useRef(new Map<string, string>());

  // Tabs whose run is waiting for them to land in state. A tab opened by Quick
  // Search or by pivt can't be run in the same tick it was dispatched — `run`
  // reads the tab (for its time range) out of state, and the reducer update
  // isn't visible until the next render. A queue, not one slot: several opens
  // before a render must not drop any of them.
  const pendingRuns = useRef<string[]>([]);

  const flush = useCallback((tabId: string) => {
    flushHandles.current.delete(tabId);
    const batch = pending.current.get(tabId);
    if (!batch?.length) return;
    pending.current.set(tabId, []);
    dispatch({ type: 'appendRows', id: tabId, rows: batch });
  }, []);

  const run = useCallback(
    /**
     * `overrideQuery` lets the empty state run a starter query in one click, and
     * `overrideLimit` lets a preview tab be promoted to a full run. Both are read
     * from the argument rather than tab state, because the reducer update that
     * would carry them isn't visible until the next render.
     */
    (tabId: string, bypass = false, overrideQuery?: string, overrideLimit?: number) => {
      const tab = stateRef.current.tabs.find((candidate) => candidate.id === tabId);
      // A tool tab is a record of something pivt did, not a query — there is
      // nothing to run.
      if (!tab || tab.kind !== 'search') return;

      const query = (overrideQuery ?? tab.query).trim();
      const limit = overrideLimit ?? tab.limit;
      // Resolved at run time, not render time — a relative range means "now
      // minus N", and "now" moves.
      const timeRange = toApiTimeRange(tab.range);

      pending.current.set(tabId, []);
      dispatch({
        type: 'patch',
        id: tabId,
        patch: {
          // Keep the bar in step when the query came from a starter.
          query,
          rows: [],
          metadata: null,
          cache: null,
          error: null,
          status: 'running',
          ranQuery: query,
          ranRange: timeRange,
          // Promoting a preview to a full run makes it a normal tab: the cap is
          // lifted for good, not just for this one run.
          limit,
          preview: overrideLimit ? false : tab.preview,
        },
      });

      // Identify THIS run. Tabs stream concurrently, so stamping the event count
      // onto "the newest history entry" would credit it to whichever tab last
      // hit Run — not the tab whose results actually arrived.
      const runId = `${tabId}:${Date.now()}`;
      currentRun.current.set(tabId, runId);
      setHistory((current) => [{ runId, query, at: Date.now(), events: null }, ...current]);

      const onEvent = (event: StreamEvent) => {
        // A superseded run's in-flight frames (Rust drains what it already
        // buffered) must not touch the tab that has moved on to a newer run.
        if (currentRun.current.get(tabId) !== runId) return;
        switch (event.event) {
          case 'cache_meta':
            dispatch({ type: 'patch', id: tabId, patch: { cache: event.data } });
            break;

          case 'rows': {
            const buffer = pending.current.get(tabId) ?? [];
            buffer.push(...event.data.rows);
            pending.current.set(tabId, buffer);
            if (!flushHandles.current.has(tabId)) {
              flushHandles.current.set(
                tabId,
                requestAnimationFrame(() => flush(tabId))
              );
            }
            break;
          }

          case 'metadata':
            dispatch({ type: 'patch', id: tabId, patch: { metadata: event.data } });
            // Stamp the count onto the run it belongs to, by id.
            setHistory((current) =>
              current.map((entry) =>
                entry.runId === runId ? { ...entry, events: event.data.total_count } : entry
              )
            );
            break;

          case 'completed':
            flush(tabId);
            dispatch({ type: 'patch', id: tabId, patch: { status: 'done' } });
            break;

          case 'error':
            flush(tabId);
            dispatch({
              type: 'patch',
              id: tabId,
              patch: { status: 'error', error: event.data.message },
            });
            break;

          default:
            break;
        }
      };

      api
        .searchStream(tabId, { query, time_range: timeRange, limit, table_view: false }, onEvent, bypass)
        .catch((caught) => {
          // Same guard the stream events get. A superseded run failing LATE would
          // otherwise stamp its error onto the tab that has already moved on —
          // the analyst reads "error" over a healthy result set that came from a
          // different query.
          if (currentRun.current.get(tabId) !== runId) return;
          dispatch({
            type: 'patch',
            id: tabId,
            patch: { status: 'error', error: errorMessage(caught) },
          });
        });
    },
    [flush]
  );

  const closeTab = useCallback((id: string) => {
    // The tab is going away; its stream should not keep running in Rust.
    void api.cancelSearch(id);
    // Forget it in the agent's bookkeeping, or a later identical tool call would
    // "focus the existing tab" — one the analyst closed and which no longer
    // exists — instead of opening a fresh one.
    for (const [key, tabId] of agentTabs.current) {
      if (tabId === id) {
        agentTabs.current.delete(key);
        agentTabCount.current = Math.max(0, agentTabCount.current - 1);
      }
    }
    // The analyst closed pivt's draft mid-build. Forget it, or every later panel
    // is patched into a tab that no longer exists and simply vanishes.
    if (draft.current?.tabId === id) {
      draft.current = null;
      draftStates.current = {};
      draftPanelByCall.current.clear();
    }
    // Drop the tab's per-run bookkeeping so a long session doesn't accumulate
    // dead entries, and cancel any flush still queued for it.
    const handle = flushHandles.current.get(id);
    if (handle !== undefined) cancelAnimationFrame(handle);
    flushHandles.current.delete(id);
    pending.current.delete(id);
    currentRun.current.delete(id);
    dispatch({ type: 'close', id });
  }, []);

  /**
   * The bulk lookup: one search per pasted indicator, run in Rust. Its answer
   * lands on the tab, so the analyst can leave it and come back.
   */
  /**
   * Sessions and MCP tools are single destinations, not documents — opening one
   * that's already open should take you to it, not stack a second identical tab.
   */
  const openSingleton = useCallback((kind: SingletonKind) => {
    const existing = stateRef.current.tabs.find(
      (tab) =>
        tab.kind === kind &&
        // A dashboard tab showing a dashboard (or pivt's draft) is NOT the list.
        // Matching on kind alone let a draft swallow the Dashboards button, and
        // the list became unreachable for the rest of the session.
        (kind !== 'dashboard' || (!tab.dashboardId && !tab.draft))
    );
    if (existing) {
      dispatch({ type: 'select', id: existing.id });
      return;
    }
    dispatch({ type: 'add', tab: newSingletonTab(kind) });
  }, []);

  /**
   * Merge into the tab's bulk state as it is NOW, not as it was when the lookup
   * started. Capturing the snapshot instead would mean a result landing after the
   * analyst edited their paste would put the OLD text back — quietly undoing what
   * they just typed.
   */
  const patchBulk = useCallback((tabId: string, patch: Partial<BulkState>) => {
    const tab = stateRef.current.tabs.find((candidate) => candidate.id === tabId);
    if (!tab?.bulk) return;
    dispatch({ type: 'patch', id: tabId, patch: { bulk: { ...tab.bulk, ...patch } } });
  }, []);

  const runBulk = useCallback(
    (tabId: string) => {
      const tab = stateRef.current.tabs.find((candidate) => candidate.id === tabId);
      if (!tab?.bulk) return;

      const indicators = extractIndicators(tab.bulk.text);
      if (indicators.length === 0) return;
      const windowDays = tab.bulk.windowDays;

      patchBulk(tabId, { status: 'running', error: null, hits: [], indicators });

      api
        .bulkIocPeek(
          indicators.map((indicator) => indicator.value),
          windowDays
        )
        .then((hits) => patchBulk(tabId, { status: 'done', hits }))
        .catch((caught) => patchBulk(tabId, { status: 'error', error: errorMessage(caught) }));
    },
    [patchBulk]
  );

  const closeGroup = useCallback(
    (groupId: string) => {
      for (const tab of stateRef.current.tabs) {
        if (tab.groupId === groupId) void api.cancelSearch(tab.id);
      }
      // The session's tabs are gone; the next tool call starts a fresh group
      // rather than re-populating one the analyst just dismissed.
      if (agentGroup.current === groupId) {
        agentGroup.current = null;
        agentTabs.current.clear();
        agentTabCount.current = 0;
      }
      dispatch({ type: 'closeGroup', id: groupId });
    },
    []
  );

  /**
   * pivt using the product.
   *
   * Every tool call it makes is mirrored into the workspace as a tab the analyst
   * can open, read, re-run and pivot off — a search becomes a real (preview-capped)
   * search tab; anything else becomes an inspectable record of the call. They
   * cluster under one group named after the investigation, so the agent's work
   * never gets mixed up with the analyst's own.
   */
  const agentGroup = useRef<string | null>(null);
  /** Tabs the current group has already opened, keyed by what produced them. */
  const agentTabs = useRef(new Map<string, string>());
  /**
   * How many tabs this group holds, counted in a REF rather than read off
   * `state.tabs`.
   *
   * Claude can emit several `tool_use` blocks in ONE assistant message, and the
   * panel forwards them in a synchronous loop — so every call in that loop sees
   * the same pre-dispatch snapshot of state. Counting from state let nine tool
   * calls each observe "7 tabs open, room for one more" and all nine get added,
   * sailing straight past the cap that exists to stop pivt burying the analyst.
   */
  const agentTabCount = useRef(0);

  const startGroup = useCallback((id: string, label: string) => {
    agentGroup.current = id;
    agentTabs.current.clear();
    agentTabCount.current = 0;
    dispatch({ type: 'openGroup', group: { id, label, overflow: 0 } });
  }, []);

  const ensureGroup = useCallback((): string => {
    const existing = agentGroup.current;
    // The analyst may have closed the group while pivt was still working.
    if (existing && stateRef.current.groups.some((group) => group.id === existing)) {
      return existing;
    }
    const id = `pivt-${Date.now()}`;
    startGroup(id, 'pivt');
    return id;
  }, [startGroup]);

  /**
   * pivt building a dashboard, drawn as it goes.
   *
   * Each `dashboard_panel_query` it runs carries the panel it belongs to, so the
   * panel can be placed the MOMENT it is proven to return rows — the analyst
   * watches the dashboard assemble itself rather than a spinner, and sees an empty
   * panel before it gets saved rather than after.
   */
  /**
   * The draft lives in a REF, not in tab state — and this is load-bearing.
   *
   * `onToolCall` runs synchronously inside the stream handler, and Claude routinely
   * emits several `tool_use` blocks in ONE message. `stateRef` is only refreshed on
   * render, so reading the tab back out of it inside that loop sees the state as it
   * was BEFORE any of them: the first panel's patch found no tab and was thrown away
   * (the draft opened, and then said "pivt hasn't added a panel yet" forever), and
   * two panels in one message each opened their own dashboard. The ref is the truth;
   * the tab is a projection of it.
   */
  const draft = useRef<{ tabId: string; board: DashboardDetail } | null>(null);
  /** Which draft panel a tool call is going to answer for. */
  const draftPanelByCall = useRef(new Map<string, { tabId: string; panelId: string }>());
  /** Calls whose result carries a SAVED dashboard id (create/update only). */
  const savingCalls = useRef(new Set<string>());
  /** Panel results, held here for the same reason the board is. */
  const draftStates = useRef<Record<string, DraftPanelState>>({});

  /** Push the ref's truth into the tab. */
  const syncDraft = useCallback(() => {
    const current = draft.current;
    if (!current) return;
    dispatch({
      type: 'patch',
      id: current.tabId,
      patch: { draft: current.board, draftStates: { ...draftStates.current } },
    });
  }, []);

  const onDraftPanel = useCallback(
    (call: ToolCall, groupId: string) => {
      const panel = panelFromToolInput(call.input);
      if (!panel) return;

      // One draft per investigation, opened on the first panel that arrives.
      if (!draft.current) {
        const tab = newDashboardTab(undefined, emptyDraft());
        tab.groupId = groupId;
        tab.origin = 'pivt';

        draft.current = { tabId: tab.id, board: emptyDraft() };
        draftStates.current = {};

        dispatch({ type: 'add', tab });
        // Worth looking at while it builds — unlike a mirrored search tab, which
        // must not yank the analyst out of what they were reading.
        dispatch({ type: 'select', id: tab.id });
      }

      const current = draft.current;
      current.board = addDraftPanel(current.board, panel);
      draftStates.current[panel.id] = { status: 'running' };
      draftPanelByCall.current.set(call.id, { tabId: current.tabId, panelId: panel.id });

      syncDraft();
    },
    [syncDraft]
  );

  const onToolCall = useCallback(
    (call: ToolCall) => {
      const mirror = mirrorFor(call.raw, call.input);
      if (mirror.as === 'skip') return;

      const groupId = ensureGroup();

      if (mirror.as === 'draft-panel') {
        onDraftPanel(call, groupId);
        return;
      }
      if (mirror.as === 'dashboard') {
        // The id only exists once the call comes BACK. Remember it and wait.
        savingCalls.current.add(call.id);
        return;
      }

      const state = stateRef.current;

      // pivt often runs the same search twice in one investigation (a follow-up
      // that re-derives it). Focus the tab that already holds it rather than
      // stacking duplicates — but the WINDOW is part of the identity: the same
      // query over 24h and over 7d are two different searches, and collapsing
      // them would show the analyst a window pivt didn't use.
      const key =
        mirror.as === 'search'
          ? `search:${mirror.query} ${rangeKey(mirror.range)}`
          : `tool:${call.id}`;
      // The MAP, not state: a tab added earlier in this same message's loop has
      // not reached state yet, and checking state would open it a second time.
      const existing = agentTabs.current.get(key);
      if (existing) {
        dispatch({ type: 'select', id: existing });
        return;
      }

      // The COUNT ref, for the same reason: nine tool calls in one message would
      // each read "7 open, room for one more" off the same stale snapshot and all
      // nine would be added, sailing past the cap.
      if (agentTabCount.current >= MAX_GROUP_TABS) {
        // A long autonomous run must not bury the analyst's own tabs. The call is
        // still in the panel's activity card; the strip just counts it.
        dispatch({ type: 'countOverflow', id: groupId });
        return;
      }

      const tab =
        mirror.as === 'search'
          ? newAgentSearchTab(groupId, mirror.query, mirror.range)
          : newAgentToolTab(groupId, {
              callId: call.id,
              name: baseName(call.raw),
              input: call.input,
            });

      agentTabs.current.set(key, tab.id);
      agentTabCount.current += 1;
      dispatch({ type: 'add', tab });

      // Opening pivt's tab must not yank the analyst out of what they were
      // reading — the tab appears, the focus stays.
      dispatch({ type: 'select', id: state.activeId });

      if (mirror.as === 'search' && mirror.run) pendingRuns.current.push(tab.id);
    },
    [ensureGroup]
  );

  const onToolResult = useCallback(
    (callId: string, result: string, failed: boolean) => {
      dispatch({ type: 'toolResult', callId, result, failed });

      // A panel pivt just validated: draw it with the rows the agent already got.
      // Re-running the query here would double the load on the analyst's own
      // cluster to show them the same rows a second later.
      const pending = draftPanelByCall.current.get(callId);
      if (pending) {
        draftPanelByCall.current.delete(callId);
        const data = failed ? null : panelDataFromToolResult(result);

        draftStates.current[pending.panelId] = data
          ? { status: 'done', data }
          : { status: 'error', message: failed ? result : 'pivt could not run this panel.' };
        syncDraft();
        return;
      }

      // It saved. Turn the draft into the real, saved dashboard — same tab, so the
      // thing the analyst has been watching is the thing that now exists.
      if (savingCalls.current.has(callId)) {
        savingCalls.current.delete(callId);
        if (failed) return;

        const id = savedDashboardId(result);
        if (!id) return;

        const current = draft.current;
        // The analyst may have closed the draft while pivt was still saving.
        const alive =
          current && stateRef.current.tabs.some((tab) => tab.id === current.tabId);

        if (current && alive) {
          draft.current = null;
          draftStates.current = {};
          dispatch({
            type: 'patch',
            id: current.tabId,
            patch: { dashboardId: id, draft: undefined, draftStates: undefined },
          });
        } else {
          // pivt edited a dashboard it never drafted here (an existing one), or the
          // draft is gone. Open the saved thing.
          draft.current = null;
          dispatch({ type: 'add', tab: newDashboardTab(id) });
        }
      }
    },
    [syncDraft]
  );

  const onNotebook = useCallback(
    (notebook: { id: string; title: string }) => {
      // The notebook titles the investigation. It arrives before the first tool
      // call, so the group is usually named from the start; if a call somehow
      // beat it, rename the group we already opened rather than opening a second.
      const label = shortLabel(notebook.title);
      const existing = agentGroup.current;
      if (existing && stateRef.current.groups.some((group) => group.id === existing)) {
        dispatch({ type: 'renameGroup', id: existing, label });
        return;
      }
      startGroup(`pivt-${notebook.id}`, label);
    },
    [startGroup]
  );

  // Source-type suggestions are only meaningful for the window being searched —
  // a source that stopped logging last month shouldn't be offered for "last 15m".
  useEffect(() => {
    if (activeTab) setAutocompleteTimeRange(toApiTimeRange(activeTab.range));
  }, [activeTab]);

  useEffect(() => {
    function onKeyDown(event: globalThis.KeyboardEvent) {
      if (!event.metaKey) return;
      const key = event.key.toLowerCase();

      if (key === 'j') {
        event.preventDefault();
        setShowTerminal((open) => !open);
      } else if (key === 'i') {
        event.preventDefault();
        setShowAgent((open) => !open);
      } else if (key === 't') {
        event.preventDefault();
        dispatch({ type: 'add', tab: newTab() });
      } else if (key === 'b') {
        event.preventDefault();
        dispatch({ type: 'add', tab: newBulkTab() });
      } else if (key === 'w') {
        event.preventDefault();
        closeTab(stateRef.current.activeId);
      }
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [closeTab]);

  // Leaving the screen (sign-out, quit) must not leave streams running server-side.
  useEffect(
    () => () => {
      for (const handle of flushHandles.current.values()) cancelAnimationFrame(handle);
      for (const tab of stateRef.current.tabs) void api.cancelSearch(tab.id);
    },
    []
  );

  // A query handed over from the ⌥Space Quick Search opens as a fresh tab here.
  useEffect(() => {
    const unlisten = listen<{ query: string; range: string | null }>(
      'quick-search-open',
      (event) => {
        const query = event.payload?.query?.trim();
        if (!query) return;
        // An indicator peek hands over its window (e.g. "Last 30 days") so the
        // opened search matches what the peek showed, not the tab default.
        const preset = event.payload.range;
        const range = preset ? { type: 'preset' as const, preset } : undefined;
        const tab = newTab(query, range);
        dispatch({ type: 'add', tab });
        pendingRuns.current.push(tab.id);
      }
    );
    return () => {
      void unlisten.then((off) => off());
    };
  }, []);
  useEffect(() => {
    if (pendingRuns.current.length === 0) return;
    pendingRuns.current = pendingRuns.current.filter((id) => {
      const present = stateRef.current.tabs.some((tab) => tab.id === id);
      if (present) run(id);
      return !present; // keep ids whose tab hasn't landed in state yet
    });
  }, [state.tabs, run]);

  // ⌘↵ in Quick Search hands a question to pivt: open the panel and ask it.
  useEffect(() => {
    const unlisten = listen<string>('quick-ask-pivt', (event) => {
      const prompt = event.payload?.trim();
      if (!prompt) return;
      setShowAgent(true);
      setPivtAsk({ text: prompt, nonce: Date.now() });
    });
    return () => {
      void unlisten.then((off) => off());
    };
  }, []);

  const patchTab = (id: string, patch: Partial<Tab>) => dispatch({ type: 'patch', id, patch });

  /**
   * Pick an unfinished investigation back up.
   *
   * The conversation is rebuilt from the notebook and the Claude session id goes
   * back to `--resume`, so the next question CONTINUES the same conversation rather
   * than starting a new one that merely looks like it.
   */
  const continueSession = useCallback((session: PivtSession, entries: NotebookEntry[]) => {
    const replay = replaySession(entries);

    setShowAgent(true);
    setPivtResume({
      nonce: Date.now(),
      // The notebook title keeps its "pivt · " prefix in storage; the panel adds
      // its own branding, so hand it the bare title.
      notebook: { id: session.id, title: session.title.replace(/^pivt\s*·\s*/, '') },
      sessionId: replay.sessionId,
      exchanges: replay.exchanges.map((exchange) => ({
        question: exchange.question,
        items: exchange.items.map((item) =>
          item.kind === 'text'
            ? { kind: 'text' as const, text: item.text ?? '' }
            : {
                kind: 'tool' as const,
                tool: {
                  // A replayed call has no live id — it is a record, not something
                  // awaiting a result.
                  id: '',
                  raw: item.tool?.name ?? '',
                  // Match the live panel: `mcp__nano__search` reads as `nano.search`.
                  name: prettyToolName(item.tool?.name ?? 'tool'),
                  input: item.tool?.input ?? {},
                  detail: describeToolInput(item.tool?.input ?? {}),
                },
              }
        ),
      })),
    });
  }, []);

  /** Open any query as a real search tab — a panel is a lead, not just a picture. */
  const drillToSearch = useCallback((query: string) => {
    const tab = newTab(query, { type: 'preset', preset: 'Last 24 hours' });
    dispatch({ type: 'add', tab });
    pendingRuns.current.push(tab.id);
  }, []);

  return (
    <div className="flex h-full overflow-hidden rounded-[14px] border border-line-strong bg-window">
      <Sidebar
        onOpenBulk={() => dispatch({ type: 'add', tab: newBulkTab() })}
        onOpenAgent={openSingleton}
        onOpenDashboard={() => openSingleton('dashboard')}
        onOpenOverview={() => openSingleton('overview')}
        agentRunning={agentRunning}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        {/* Titlebar. macOS paints the traffic lights over it, hence the gutter. */}
        {/* No fixed height: the row is sized by the dock plus its breathing room,
            so the well isn't jammed against the titlebar edges. */}
        <div
          data-tauri-drag-region
          className="flex shrink-0 items-center gap-2.5 border-b border-line py-2.5 pr-3.5 pl-2.5"
        >
          <TabStrip
            tabs={state.tabs}
            groups={state.groups}
            activeId={state.activeId}
            onSelect={(id) => dispatch({ type: 'select', id })}
            onClose={closeTab}
            onCloseGroup={closeGroup}
            onAdd={() => dispatch({ type: 'add', tab: newTab() })}
          />

          <span className="flex-1" />

          <button
            onClick={() => setShowAgent((open) => !open)}
            title="pivt (⌘I)"
            className={`shrink-0 rounded-[7px] border px-2 py-1 text-[11px] font-semibold ${
              showAgent
                ? 'border-accent-line bg-accent-soft text-accent'
                : 'border-line-strong text-t3 hover:text-t1'
            }`}
          >
            ✳ pivt
          </button>
          <button
            onClick={() => setShowTerminal((open) => !open)}
            title="Terminal (⌘J)"
            className={`shrink-0 rounded-[7px] border px-2 py-1 font-mono text-[11px] ${
              showTerminal
                ? 'border-accent-line bg-accent-soft text-accent'
                : 'border-line-strong text-t3 hover:text-t1'
            }`}
          >
            ➜_
          </button>
          <div className="shrink-0 rounded-[20px] border border-accent-line bg-accent-soft px-2.5 py-1 font-mono text-[11px] text-accent">
            ● {hostOf(server.base_url)}
          </div>
          <UserMenu server={server} user={user} onLock={onLock} onSignOut={onSignOut} />
        </div>

        <div className="flex min-h-0 flex-1">
          <div className="flex min-w-0 flex-1 flex-col">
            {activeTab?.kind === 'tool' ? (
              <ToolPane tab={activeTab} />
            ) : activeTab?.kind === 'sessions' ? (
              <SessionsPane onContinue={continueSession} disabled={agentRunning} />
            ) : activeTab?.kind === 'mcp' ? (
              <McpToolsPane />
            ) : activeTab?.kind === 'overview' ? (
              <DashboardPane onDrill={drillToSearch} />
            ) : activeTab?.kind === 'dashboard' ? (
              <DashboardsPane
                dashboardId={activeTab.dashboardId}
                draft={activeTab.draft}
                draftStates={activeTab.draftStates}
                onOpen={(id) => dispatch({ type: 'add', tab: newDashboardTab(id) })}
                onDrill={drillToSearch}
              />
            ) : activeTab?.kind === 'bulk' ? (
              <BulkPane
                tab={activeTab}
                // Indicators are re-extracted as they type, so the TAB says how
                // many are in the paste before the lookup is ever run.
                onTextChange={(text) =>
                  patchBulk(activeTab.id, { text, indicators: extractIndicators(text) })
                }
                onRun={() => runBulk(activeTab.id)}
                // A matched indicator is a lead. Clicking it opens the search
                // that produced the number, so the analyst can read the events
                // rather than take the count on faith.
                onOpenIndicator={(indicator) => {
                  const tab = newTab(indicatorQuery(indicator), {
                    type: 'preset',
                    preset: 'Last 30 days',
                  });
                  dispatch({ type: 'add', tab });
                  pendingRuns.current.push(tab.id);
                }}
                onInvestigate={(hits) => {
                  setShowAgent(true);
                  setPivtAsk({
                    text:
                      `These indicators from a report were seen in our data: ` +
                      `${hits.map((hit) => `${hit.indicator} (${hit.events} events)`).join(', ')}. ` +
                      `Investigate them: what are they doing, which hosts are involved, ` +
                      `and is this worth escalating?`,
                    nonce: Date.now(),
                  });
                }}
              />
            ) : (
              activeTab && (
                <SearchPane
                  tab={activeTab}
                  profile={profile}
                  onQueryChange={(query) => patchTab(activeTab.id, { query })}
                  onRangeChange={(range: TimeRangeValue) => patchTab(activeTab.id, { range })}
                  onRun={(bypass) => run(activeTab.id, bypass)}
                  onRunQuery={(query) => run(activeTab.id, false, query)}
                  onRunFull={() => run(activeTab.id, false, undefined, FULL_LIMIT)}
                  onCancel={() => {
                    void api.cancelSearch(activeTab.id);
                    patchTab(activeTab.id, { status: 'done' });
                  }}
                  onExpandedChange={setExpandedEvent}
                />
              )
            )}
          </div>

          {/* Mounted once opened and thereafter only HIDDEN. Unmounting it on ⌘I
              would throw away the conversation, the Claude session and the
              notebook — an investigation lost to the key that opened it.
              `screen` is rebuilt each render, so pivt always sees the CURRENT
              screen rather than whatever it showed when the panel opened. */}
          {/* NOT gated on there being a search tab. Gating it there reintroduced
              exactly the bug the `hidden` prop exists to prevent: close your last
              search tab mid-investigation (leaving, say, a bulk tab) and the panel
              would unmount, taking the conversation, the Claude session and the
              notebook with it. pivt simply gets no screen context in that case —
              which is true, and which `agent_ask` already accepts. */}
          {(showAgent || agentEverOpened.current) && (
            <AgentPanel
              hidden={!showAgent}
              screen={contextTab ? buildScreenContext(contextTab, profile, expandedEvent) : null}
              onClose={() => setShowAgent(false)}
              pendingAsk={pivtAsk ?? undefined}
              onToolCall={onToolCall}
              onToolResult={onToolResult}
              onNotebook={onNotebook}
              onRunningChange={setAgentRunning}
              resume={pivtResume ?? undefined}
            />
          )}
        </div>

        {showTerminal && (
          <Suspense
            fallback={<div className="h-[260px] shrink-0 border-t border-line-strong bg-black/45" />}
          >
            <TerminalDrawer
              history={history}
              onPickQuery={(query) => activeTab && patchTab(activeTab.id, { query })}
              onClose={() => setShowTerminal(false)}
            />
          </Suspense>
        )}
      </div>
    </div>
  );
}

/** `mcp__nano__search` → `nano.search`, matching the live panel. */
function prettyToolName(name: string): string {
  return name.startsWith('mcp__nano__') ? `nano.${name.slice('mcp__nano__'.length)}` : name;
}

/** The gist of a replayed tool call, for its collapsed card. */
function describeToolInput(input: Record<string, unknown>): string {
  const interesting = input.query ?? input.sql ?? input.value ?? input.id;
  if (typeof interesting !== 'string') return '';
  return interesting.length > 120 ? `${interesting.slice(0, 120)}…` : interesting;
}

/** Two mirrored searches are the same tab only if the window matches too. */
function rangeKey(range: TimeRangeValue): string {
  if (range.type === 'preset') return range.preset ?? '';
  return `${range.start?.toISOString() ?? ''}..${range.end?.toISOString() ?? ''}`;
}

/**
 * The notebook is titled "pivt · <the question>". The group chip already carries
 * the ✳, so the prefix is redundant there — and the chip is 110px wide, so the
 * question itself has to be cut to fit.
 */
function shortLabel(title: string): string {
  const question = title.replace(/^pivt\s*·\s*/, '').trim();
  if (!question) return 'pivt';
  return question.length > 28 ? `${question.slice(0, 28)}…` : question;
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
