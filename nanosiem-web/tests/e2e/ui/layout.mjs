// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Layout invariants for the e2e UI suite (NAN-5762). The Python page wrapper
// (e2e/nano_e2e/ui.py, UiPage.op) runs `layout_check` after every op, so every
// page, route change, flyout and drawer a scenario reaches is measured without
// the scenario asking for it. Three invariants, per visible container:
//
//   overflow   a scroll container, the main pane, a flyout / drawer / dialog
//              must not scroll or spill sideways (scrollWidth > clientWidth + 1
//              for scrollers; element boxes past the right edge for the main
//              pane and panels, which CLIP horizontal overflow: the app shell
//              clips at the document, so document.scrollWidth says nothing,
//              NAN-5756).
//   escape     a visible descendant must stay inside its nearest card or panel
//              (beyond a small tolerance). `clipped` is the same thing inside a
//              card that hides overflow: the part past the edge is cut off.
//   overdrawn  a sampled link / button must be what is painted at its centre
//              (elementFromPoint), not a sibling drawn over it.
//
// Cards: `data-layout-card` (the shared <Card> sets it; `data-layout-card="off"`
// opts a box out) or, for the many hand-rolled cards, any box with a border on
// all four sides, rounded corners and at least 120x32 px that is not itself a
// control. Panels: `data-layout-panel` (sheets, dialogs, drawers) and
// `data-detail-sheet`. There is deliberately no in-page opt-out: every
// exception goes through the allowlist, which carries its reason.
//
// Intentional exceptions live in e2e/coverage/layout-allowlist.json, each with
// a reason; the driver loads it at start (E2E_LAYOUT_ALLOWLIST).

import fs from 'node:fs';

export const LAYOUT_CHECKS = ['overflow', 'escape', 'clipped', 'overdrawn'];

// Manifest route keys (`/automation/flows/:id`) as an anchored pathname regex.
export function routeRegex(route) {
  if (route === '*') return '.*';
  const esc = route.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/:[A-Za-z_]+/g, '[^/]+').replace(/\*/g, '.*');
  return `^${esc}/?$`;
}

export function loadAllowlist(file) {
  if (!file || !fs.existsSync(file)) return [];
  const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  return (doc.entries || []).map((e) => ({
    id: e.id,
    checks: e.checks || [],
    routes: (e.surfaces || []).map(routeRegex),
    selector: e.selector || null,
    within: e.within || null,
    container: e.container || null,
  }));
}

// Cheap per-op fingerprint: the full scan runs only when it changes. It
// carries in-page UI state, not just the route: the query string (?tab=),
// the theme, open panels, every selected / active / open / expanded control
// (tabs, accordions, expanded rows, menus) and a fine DOM size bucket.
export function layoutSignature() {
  const label = (e) => e.getAttribute('data-testid') || e.getAttribute('aria-label') || e.id
    || (e.textContent || '').trim().slice(0, 24) || e.tagName;
  const overlays = [...document.querySelectorAll('[role=dialog],[role=alertdialog],[data-layout-panel],[data-detail-sheet]')]
    .filter((e) => e.getClientRects().length)
    .map(label)
    .join(',');
  const state = [...document.querySelectorAll('[aria-selected=true],[data-state=active],[data-state=open],[aria-expanded=true],[aria-pressed=true],details[open]')]
    .filter((e) => e.getClientRects().length)
    .map(label)
    .join(',');
  const n = document.body ? document.body.getElementsByTagName('*').length : 0;
  const busy = document.querySelectorAll('[aria-busy=true],.animate-pulse,.animate-spin').length > 0;
  return [location.pathname, location.search, innerWidth, document.documentElement.className, overlays, state,
    Math.round(n / 25), busy ? 'busy' : ''].join('|');
}

// Fail-closed secret guard for layout artifacts (NAN-5762): true when the page
// may be showing a secret, so no screenshot is taken and no element text goes
// into layout.jsonl. Any password field (even empty), any known reveal-once
// element, any field a secret was typed into, or any registered secret in the
// DOM, the rendered text or a field value.
export const SECRET_REVEAL = [
  // Password-shaped fields, also the masked type=text ones (the terminal login).
  'input[type=password]', 'input[autocomplete=current-password]', 'input[autocomplete=new-password]',
  'input[autocomplete=one-time-code]', '[data-testid=one-time-token]', '[data-testid=issued-ingest-token]',
  '[data-testid=rotated-ingest-token]', '[data-testid=rotated-ingest-token-dialog]', '[data-testid=issue-ingest-token-dialog]',
  '[data-testid=api-key-reveal]', '[data-testid=invite-temp-password]', '[data-testid=mfa-secret]',
  '[data-testid=public-install-token-alert]', '[data-testid=token-delivery-alert]', 'img[alt="TOTP QR Code"]',
].join(',');
export function pageMayShowSecret({ vals, fields, reveal }) {
  if (document.querySelector(reveal)) return true;
  if ([...document.querySelectorAll('[role=dialog],[role=alertdialog]')].some((d) => /backup codes|recovery codes/i.test(d.textContent || ''))) return true;
  if (fields.length && window.__e2e) {
    for (const f of fields) for (const e of window.__e2e.all({ ...f, visible: false })) if ('value' in e && e.value) return true;
  }
  if (!vals.length) return false;
  const t = [document.documentElement.outerHTML, document.body ? document.body.innerText : '',
    ...[...document.querySelectorAll('input,textarea')].map((e) => e.value)].join('\n');
  return vals.some((v) => t.includes(v));
}

// Token- or key-shaped strings (a JWT, a known key prefix, or a long
// mixed-case base64-like run) in text that goes into layout.jsonl.
export function redactTokens(text) {
  return String(text)
    .replace(/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(\.[A-Za-z0-9_-]+)?/g, '<token>')
    .replace(/\b(?:nano|nsk|sk|pk|ghp|gho|xox[abp]|AKIA|ASIA|AIza)[_-]?[A-Za-z0-9_-]{12,}/g, '<token>')
    // 32+ chars, no '-' or '/': hostnames, paths and ATT&CK labels stay readable.
    .replace(/[A-Za-z0-9+_=]{32,}/g, (m) => (/[a-z]/.test(m) && /[A-Z]/.test(m) && /[0-9]/.test(m) ? '<token>' : m));
}

// The in-page scan. Self-contained (puppeteer serializes it into the page).
export function layoutScan(opts) {
  const { tol = 2, absTol = 8, maxControls = 300, allow = [], noText = false } = opts || {};
  const route = location.pathname;
  const vw = innerWidth;
  const vh = innerHeight;
  const styleCache = new Map();
  const cs = (e) => {
    let s = styleCache.get(e);
    if (!s) { s = getComputedStyle(e); styleCache.set(e, s); }
    return s;
  };
  const shown = (e) => (e.checkVisibility
    ? e.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })
    : !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length));
  const SKIP_TAGS = new Set(['SCRIPT', 'STYLE', 'TEMPLATE', 'BR', 'OPTION', 'NOSCRIPT', 'HEAD', 'LINK', 'META']);
  const CONTROL = 'a[href],button,[role=button],[role=link],input,select,textarea,[role=tab],[role=menuitem],'
    + '[role=option],[role=switch],[role=checkbox],[role=radio],[role=combobox],summary,label';
  const FORM = 'input,textarea,select,[contenteditable=""],[contenteditable=true]';
  const PANEL = '[data-layout-panel],[data-detail-sheet]';
  const scrolls = (v) => v === 'auto' || v === 'scroll';
  const clips = (v) => v === 'hidden' || v === 'clip';
  const isSvgInner = (e) => e instanceof SVGElement && !(e instanceof SVGSVGElement);
  // A dropdown / popover / palette rendered in place (not portaled): it floats
  // over the layout on purpose, so it may leave its card and cover controls.
  const floating = (e) => {
    const s = cs(e);
    return ((s.position === 'absolute' || s.position === 'fixed') && (parseInt(s.zIndex, 10) || 0) >= 20)
      || e.matches('[role=listbox],[role=menu],[role=tooltip]');
  };

  const stable = (e) => {
    const id = e.getAttribute('data-testid');
    const cls = (typeof e.className === 'string' ? e.className : '').split(/\s+/).filter((c) => c && !/[[\]:]/.test(c)).slice(0, 3);
    return `${e.tagName.toLowerCase()}${id ? `[data-testid="${id}"]` : ''}${cls.length ? `.${cls.join('.')}` : ''}`;
  };
  const anchor = (e) => {
    const a = e.parentElement && e.parentElement.closest('[data-testid]');
    return a ? `[data-testid="${a.getAttribute('data-testid')}"] ` : '';
  };
  const text = (e) => (noText ? '' : (e.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 50));
  const describe = (e) => `${anchor(e)}${stable(e)}${text(e) ? ` "${text(e)}"` : ''}`;
  const keyOf = (e) => `${anchor(e)}${stable(e)}`;

  const cardMemo = new Map();
  const isCard = (e) => {
    if (cardMemo.has(e)) return cardMemo.get(e);
    let v;
    const a = e.getAttribute('data-layout-card');
    if (a != null) v = a !== 'off';
    else if (e.matches(PANEL)) v = true;
    else if (e.matches(CONTROL)) v = false;
    else {
      const s = cs(e);
      const sides = ['Top', 'Right', 'Bottom', 'Left'];
      v = sides.every((k) => parseFloat(s[`border${k}Width`]) > 0 && s[`border${k}Style`] !== 'none' && s[`border${k}Style`] !== 'hidden')
        && parseFloat(s.borderTopLeftRadius) > 0;
      if (v) { const r = e.getBoundingClientRect(); v = r.width >= 120 && r.height >= 32; }
    }
    cardMemo.set(e, v);
    return v;
  };

  const allowErrors = [];
  const safe = (fn, sel) => {
    try { return fn(); } catch (err) { allowErrors.push(`${sel}: ${err.message}`); return false; }
  };
  const matchesSafe = (e, sel) => safe(() => e.matches(sel), sel);
  const closestSafe = (e, sel) => safe(() => !!e.closest(sel), sel);
  const allowedBy = (kind, el, cont) => {
    for (const a of allow) {
      if (!a.checks.includes(kind) && !a.checks.includes('any')) continue;
      if (a.routes.length && !a.routes.some((rx) => new RegExp(rx).test(route))) continue;
      if (a.selector && !matchesSafe(el, a.selector)) continue;
      if (a.within && !closestSafe(el, a.within)) continue;
      if (a.container && !(cont && matchesSafe(cont, a.container))) continue;
      return a.id;
    }
    return null;
  };

  const violations = [];
  let mark = 0;
  const add = (kind, el, cont, detail) => {
    const key = `${kind}|${keyOf(el)}${cont ? ` in ${keyOf(cont)}` : ''}`;
    if (violations.some((v) => v.key === key)) return;
    const allowed = allowedBy(kind, el, cont);
    const v = { kind, key, route, element: describe(el), container: cont ? describe(cont) : null, detail, allowed };
    if (!allowed) { mark += 1; el.setAttribute('data-e2e-layout-offender', String(mark)); v.mark = mark; }
    violations.push(v);
  };

  const body = document.body;
  if (!body) return { route, violations, errors: [] };
  const all = [...body.querySelectorAll('*')].filter((e) => !SKIP_TAGS.has(e.tagName) && !isSvgInner(e));
  const visible = new Set();
  for (const e of all) {
    const r = e.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) continue;
    if (!shown(e)) continue;
    visible.add(e);
  }

  // ---- overflow: scroll containers, the main pane, panels
  const pastRight = (root, rr) => {
    // Outermost visible elements whose box ends past root's right edge (not
    // inside a nested scroller / clipper, which are roots of their own), then
    // the deepest one inside the worst of them.
    const out = [];
    const walk = (el) => {
      for (const c of el.children) {
        if (out.length >= 3) return;
        if (!visible.has(c)) continue;
        const s = cs(c);
        if (s.position === 'fixed') continue;
        const r = c.getBoundingClientRect();
        if (r.right > rr.right + 1 && r.left < rr.right) { out.push(c); continue; }
        if (s.overflowX !== 'visible') continue;
        walk(c);
      }
    };
    walk(root);
    return out.map((o) => {
      let leaf = o;
      for (;;) {
        const next = [...leaf.children].filter((c) => visible.has(c) && c.getBoundingClientRect().right > rr.right + 1)
          .sort((a, b) => b.getBoundingClientRect().right - a.getBoundingClientRect().right)[0];
        if (!next) break;
        leaf = next;
      }
      const px = Math.round(o.getBoundingClientRect().right - rr.right);
      return `${describe(o)} +${px}px${leaf !== o ? ` (deepest: ${describe(leaf)})` : ''}`;
    });
  };
  const main = document.querySelector('main');
  const mainWidth = main ? main.getBoundingClientRect().width : vw;
  for (const e of visible) {
    if (e.matches(FORM) || e.closest('.cm-editor .cm-content')) continue;
    const s = cs(e);
    const r = e.getBoundingClientRect();
    const isPanel = e.matches(`${PANEL},[role=dialog],[role=alertdialog],[data-vaul-drawer]`);
    const isMain = e === main || (main && main.contains(e) && clips(s.overflowX) && r.width >= mainWidth * 0.6 && scrolls(s.overflowY));
    if (scrolls(s.overflowX) && e.clientWidth > 0 && e.scrollWidth > e.clientWidth + 1) {
      add('overflow', e, null, { scroll_width: e.scrollWidth, client_width: e.clientWidth, past_edge: pastRight(e, r) });
    } else if (isMain || isPanel) {
      const past = pastRight(e, r);
      if (past.length) add('overflow', e, null, { client_width: Math.round(r.width), past_edge: past, clipped: clips(s.overflowX) });
    }
    if (isPanel && s.position === 'fixed' && (r.right > vw + 1 || r.left < -1)) {
      add('overflow', e, null, { offscreen: { left: Math.round(r.left), right: Math.round(r.right), viewport: vw } });
    }
  }

  // ---- escape / clipped: descendants vs their nearest card or panel
  const containerOf = (e) => {
    for (let p = e.parentElement; p && p !== body; p = p.parentElement) {
      const s = cs(p);
      if (isCard(p)) {
        if (scrolls(s.overflowX) || scrolls(s.overflowY)) return null; // a scroller: the overflow check owns it
        return { el: p, clipX: clips(s.overflowX), clipY: clips(s.overflowY) };
      }
      if (floating(p) || s.position === 'fixed') return null;
      if (s.overflowX !== 'visible' || s.overflowY !== 'visible') return null; // clipped / scrolled below the card
      if (s.display === 'contents') continue;
    }
    return null;
  };
  const flagged = new Map(); // element -> its container, to report only the outermost escapee
  for (const e of visible) {
    const s = cs(e);
    if (s.position === 'fixed' || floating(e)) continue;
    const c = containerOf(e);
    if (!c) continue;
    if (flagged.get(e.parentElement) === c.el) { flagged.set(e, c.el); continue; }
    const r = e.getBoundingClientRect();
    const cr = c.el.getBoundingClientRect();
    let right = r.right;
    // Text that spills out of its own (block) box: the box fits, the glyphs do
    // not. Leaf elements only: a parent's scrollWidth also counts children that
    // are measured on their own (and absolutely positioned ones).
    if (!e.firstElementChild && s.overflowX === 'visible' && s.display !== 'inline' && e.clientWidth > 0 && e.scrollWidth > e.clientWidth + 1) {
      right = Math.max(right, r.left + e.scrollWidth);
    }
    const t = s.position === 'absolute' ? absTol : tol;
    const h = Math.max(cr.left - r.left, right - cr.right);
    const v = c.clipY ? 0 : Math.max(cr.top - r.top, r.bottom - cr.bottom);
    if (h <= t && v <= t) continue;
    flagged.set(e, c.el);
    const kind = c.clipX && h > t ? 'clipped' : 'escape';
    add(kind, e, c.el, {
      past: { left: Math.round(cr.left - r.left), right: Math.round(right - cr.right), top: Math.round(cr.top - r.top), bottom: Math.round(r.bottom - cr.bottom) },
    });
  }

  // ---- overdrawn: a hit-test sample of links and buttons in the top layer
  // A modal covers the page behind it (its backdrop is what is hit there):
  // only its own controls are sampled. Radix modals also mark the rest
  // aria-hidden / pointer-events:none, which the filter below drops.
  const modals = [...document.querySelectorAll('[aria-modal=true],[role=alertdialog]')].filter((e) => visible.has(e));
  // Open poppers, menus and tooltips do not narrow the sample: a hit that lands
  // in one is skipped below, so only the area they actually cover is exempt.
  const scope = modals.length ? modals[modals.length - 1] : body;
  const TRANSIENT = '[data-sonner-toaster],[data-sonner-toast],[role=tooltip],[role=status],[data-radix-popper-content-wrapper]';
  const controls = [...scope.querySelectorAll('a[href],button,[role=button],[role=link]')].filter((e) => visible.has(e)
    && !e.disabled && e.getAttribute('aria-disabled') !== 'true' && cs(e).pointerEvents !== 'none'
    && !e.closest('[aria-hidden=true],[inert]'));
  const step = Math.max(1, Math.ceil(controls.length / maxControls));
  for (let i = 0; i < controls.length; i += step) {
    const e = controls[i];
    const rect = [...e.getClientRects()].find((q) => q.width >= 2 && q.height >= 2);
    if (!rect) continue;
    let x0 = Math.max(rect.left, 0);
    let x1 = Math.min(rect.right, vw);
    let y0 = Math.max(rect.top, 0);
    let y1 = Math.min(rect.bottom, vh);
    for (let p = e.parentElement; p && p !== body; p = p.parentElement) {
      const s = cs(p);
      if (s.overflowX !== 'visible' || s.overflowY !== 'visible') {
        const q = p.getBoundingClientRect();
        x0 = Math.max(x0, q.left); x1 = Math.min(x1, q.right); y0 = Math.max(y0, q.top); y1 = Math.min(y1, q.bottom);
      }
      if (s.position === 'fixed') break;
    }
    if (x1 - x0 < 2 || y1 - y0 < 2) continue; // scrolled or clipped out of view
    const cx = (Math.max(rect.left, x0) + Math.min(rect.right, x1)) / 2;
    const cy = (Math.max(rect.top, y0) + Math.min(rect.bottom, y1)) / 2;
    const hit = document.elementFromPoint(cx, cy);
    if (!hit || hit === e || e.contains(hit) || hit.contains(e)) continue;
    if (hit.closest(TRANSIENT) && !e.closest(TRANSIENT)) continue;
    const label = hit.closest('label');
    if (label && label.control === e) continue;
    let overlay = false;
    for (let p = hit; p && p !== body; p = p.parentElement) {
      const pos = cs(p).position;
      if (pos === 'fixed' || pos === 'sticky' || floating(p)) { overlay = !p.contains(e); break; }
    }
    if (overlay) continue; // content scrolled under a sticky header / floating button
    add('overdrawn', e, null, { at: [Math.round(cx), Math.round(cy)], painted_over_by: describe(hit) });
  }

  const cards = [...visible].filter((e) => isCard(e)).length;
  return { route, violations, errors: allowErrors, stats: { visible: visible.size, cards, controls: controls.length } };
}

export function clearMarks() {
  for (const e of document.querySelectorAll('[data-e2e-layout-offender]')) e.removeAttribute('data-e2e-layout-offender');
  document.getElementById('__e2e-layout-style')?.remove();
}

export function showMarks() {
  const st = document.createElement('style');
  st.id = '__e2e-layout-style';
  st.textContent = '[data-e2e-layout-offender]{outline:2px solid #ff00d4 !important;outline-offset:-1px !important}';
  document.head.appendChild(st);
}
