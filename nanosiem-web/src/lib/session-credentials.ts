// SPDX-License-Identifier: AGPL-3.0-or-later
import { getAccessToken } from './auth-token.ts';
import { SessionExpiredError } from './request-credentials.ts';

/** One queue and one failure notification per tab/session, shared by JSON,
 * raw downloads, scheduled refreshes and streaming requests. */
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

  expire(): SessionExpiredError {
    if (!this.failure) {
      this.failedToken = this.token();
      this.failure = new SessionExpiredError();
      this.onExpired?.();
    }
    return this.failure;
  }

  runRefresh(operation: () => Promise<boolean>): Promise<boolean> {
    if (this.pending) return this.pending;
    this.pending = Promise.resolve().then(operation).then(ok => {
      if (!ok) throw this.expire();
      this.failure = null;
      return true;
    }, () => { throw this.expire(); }).finally(() => { this.pending = null; });
    return this.pending;
  }

  async credential(rejectedToken?: string): Promise<string> {
    if (this.pending) await this.pending;
    let token = this.token();
    // A new login resets the failure latch; a rejected bearer does not.
    if (this.failure && token && token !== this.failedToken) this.failure = null;
    if (this.failure) throw this.failure;
    if (!token || token === rejectedToken) {
      if (!this.refresh) throw this.expire();
      if (!await this.refresh()) throw this.expire();
      token = this.token();
    }
    if (!token) throw this.expire();
    return token;
  }
}

export const sessionCredentials = new SessionCredentials();
