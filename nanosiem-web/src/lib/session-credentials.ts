// SPDX-License-Identifier: AGPL-3.0-or-later
import { getAccessToken } from './auth-token.ts';

export const SESSION_EXPIRED_MESSAGE = 'Session expired — sign in again';

/** A protected request could not obtain a bearer. AuthContext has already
 * been told once; callers should not show their own error for it. */
export class SessionExpiredError extends Error {
  readonly code = 'SESSION_EXPIRED';
  readonly status = 401;
  constructor() {
    super(SESSION_EXPIRED_MESSAGE);
    this.name = 'SessionExpiredError';
  }
}

/** One refresh queue and one failure notification per tab, shared by JSON,
 * raw downloads, scheduled refreshes and streaming requests (NAN-2453).
 *
 * - While a refresh is in flight every protected request waits for it rather
 *   than going out with no bearer (or a bearer that is about to be replaced).
 * - A refresh failure rejects every waiter with the SAME error and invokes
 *   the expiry callback exactly once, instead of N "session expired" toasts.
 * - A rejected bearer is replayed at most once, with the replacement. */
export class SessionCredentials {
  private pending: Promise<boolean> | null = null;
  private failure: SessionExpiredError | null = null;
  private refresh: (() => Promise<boolean>) | null = null;
  private onExpired: (() => void) | null = null;
  private failedToken: string | null = null;

  private readonly token: () => string | null;

  constructor(token: () => string | null = getAccessToken) { this.token = token; }

  configure(refresh: (() => Promise<boolean>) | null, onExpired: (() => void) | null): void {
    this.refresh = refresh;
    this.onExpired = onExpired;
  }

  /** Latch the failure for the current bearer. `notify` is false only for
   * the silent page-load refresh of a visitor who was never signed in: the
   * latch still stops protected requests, but no "session expired" prompt. */
  expire(notify = true): SessionExpiredError {
    if (!this.failure) {
      this.failedToken = this.token();
      this.failure = new SessionExpiredError();
      if (notify) this.onExpired?.();
    }
    return this.failure;
  }

  /** Run `operation` as THE refresh for this tab; concurrent callers share it. */
  runRefresh(operation: () => Promise<boolean>, notify = true): Promise<boolean> {
    if (this.pending) return this.pending;
    this.pending = Promise.resolve().then(operation).then(ok => {
      if (!ok) throw this.expire(notify);
      this.failure = null;
      return true;
    }, () => { throw this.expire(notify); }).finally(() => { this.pending = null; });
    return this.pending;
  }

  /** A bearer for a protected request. `rejectedToken` is the bearer a 401
   * just refused: if another caller already replaced it, reuse the
   * replacement without rotating the refresh token again. */
  async credential(rejectedToken?: string): Promise<string> {
    if (this.pending) await this.pending.catch(() => false);
    let token = this.token();
    // A new login resets the failure latch; a rejected bearer does not.
    if (this.failure && token && token !== this.failedToken) this.failure = null;
    if (this.failure) throw this.failure;
    if (!token || token === rejectedToken) {
      if (!this.refresh) throw this.expire();
      const ok = await this.refresh().catch(() => false);
      if (!ok) throw this.expire();
      token = this.token();
    }
    if (!token) throw this.expire();
    return token;
  }
}

export const sessionCredentials = new SessionCredentials();
