// SPDX-License-Identifier: AGPL-3.0-or-later

/** One mounted investigation owns this bounded cache and all of its requests. */
export class EventPayloadCache {
  private entries = new Map<string, { value: Record<string, unknown>; at: number; bytes: number }>();
  private pending = new Map<string, Promise<Record<string, unknown> | null>>();
  private controller = new AbortController();
  private bytes = 0;

  constructor(private maxBytes = 4 * 1024 * 1024, private staleMs = 120_000) {}

  peek(key: string): Record<string, unknown> | null {
    return this.entries.get(key)?.value ?? null;
  }

  load(key: string, fetcher: (signal: AbortSignal) => Promise<Record<string, unknown> | null>, speculative = false) {
    if (this.controller.signal.aborted) return Promise.reject(new DOMException('Aborted', 'AbortError'));
    const entry = this.entries.get(key);
    if (entry && Date.now() - entry.at < this.staleMs) return Promise.resolve(entry.value);
    const existing = this.pending.get(key);
    if (existing) return existing;
    if (speculative && this.pending.size >= 2) return Promise.resolve(null);
    const request = fetcher(this.controller.signal).then((value) => {
      if (value && !this.controller.signal.aborted) {
        const bytes = JSON.stringify(value).length * 2;
        if (entry) { this.entries.delete(key); this.bytes -= entry.bytes; }
        if (bytes <= this.maxBytes) {
          while (this.bytes + bytes > this.maxBytes && this.entries.size) {
            const oldest = this.entries.keys().next().value!;
            this.bytes -= this.entries.get(oldest)!.bytes;
            this.entries.delete(oldest);
          }
          this.entries.set(key, { value, bytes, at: Date.now() });
          this.bytes += bytes;
        }
      }
      return value;
    }).finally(() => this.pending.delete(key));
    this.pending.set(key, request);
    return request;
  }

  dispose() {
    this.controller.abort();
    this.entries.clear();
    this.pending.clear();
    this.bytes = 0;
  }
}

export const eventPayloadKey = (id: string, timestamp: string, source: string) => JSON.stringify([id, timestamp, source]);
