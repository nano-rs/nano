// SPDX-License-Identifier: AGPL-3.0-or-later
const selector = 'meta[name="nano-build-id"]';

// The loaded document is the baseline: never adopt a fetched ID without reloading.
export function watchForNewBuild(notify: () => void, intervalMs = 60_000) {
  const current = document.querySelector<HTMLMetaElement>(selector)?.content;
  if (!current) return () => {};
  let stopped = false;
  let notified = false;
  let pending = false;
  let controller: AbortController | undefined;
  const check = async () => {
    if (stopped || notified || pending || document.visibilityState === 'hidden') return;
    pending = true;
    controller = new AbortController();
    const timeout = window.setTimeout(() => controller?.abort(), 10_000);
    try {
      const response = await fetch('/index.html', { cache: 'no-cache', signal: controller.signal });
      if (!response.ok || !response.headers.get('content-type')?.includes('text/html')) return;
      const html = new DOMParser().parseFromString(await response.text(), 'text/html');
      const next = html.querySelector<HTMLMetaElement>(selector)?.content;
      if (!stopped && next && next !== current) {
        notified = true;
        notify();
      }
    } catch {
      // Offline, timeout, or a rolling deployment: try again on the next tick.
    } finally {
      window.clearTimeout(timeout);
      pending = false;
    }
  };
  const timer = window.setInterval(() => { void check(); }, intervalMs);
  const onVisible = () => { void check(); };
  document.addEventListener('visibilitychange', onVisible);
  return () => {
    stopped = true;
    controller?.abort();
    window.clearInterval(timer);
    document.removeEventListener('visibilitychange', onVisible);
  };
}
