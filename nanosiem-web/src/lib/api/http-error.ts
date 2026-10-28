/**
 * NAN-4753: turn a failed HTTP response into a short, safe message.
 *
 * An edge or proxy error (Cloudflare 524, an NGINX 502, a load balancer page)
 * answers with an HTML document, not our JSON error shape. That HTML used to
 * reach the UI verbatim: the AU parser wizard rendered Cloudflare's whole 524
 * page (scripts, footer, IP-reveal button) in the pivt panel. Every error body
 * that is not our JSON goes through here instead. The UI gets one sentence and
 * a reference id; the console keeps the details for support.
 */

export interface HttpFailure {
  /** Short, user-facing sentence. Never contains markup. */
  message: string;
  /** Cloudflare Ray or our request id, when the response carried one. */
  requestId?: string;
}

const EDGE_TIMEOUT_STATUSES = new Set([504, 522, 523, 524]);
const EDGE_UNAVAILABLE_STATUSES = new Set([502, 503, 520, 521, 525, 526, 527, 530]);

/** True when `text` is (or contains) an HTML document or tag soup. */
export function looksLikeHtml(text: string): boolean {
  const head = text.trimStart().slice(0, 512).toLowerCase();
  return head.startsWith('<!doctype') || head.startsWith('<html') || /<(head|body|script|div|title|meta)[\s>]/.test(head);
}

/** Pull a reference id from the response headers or a Cloudflare error page. */
export function failureRequestId(headers: Headers | undefined, body: string): string | undefined {
  const fromHeader = headers?.get('cf-ray') || headers?.get('x-request-id') || undefined;
  if (fromHeader && /^[a-z0-9._:-]{1,64}$/i.test(fromHeader.trim())) return fromHeader.trim();
  const ray = /Ray ID:?\s*(?:<[^>]*>\s*)*([0-9a-f]{16})/i.exec(body);
  return ray?.[1];
}

/**
 * A message that is safe to show. Plain-text bodies up to 300 chars pass
 * through; HTML, empty and oversized bodies become a status-based sentence.
 */
export function describeHttpFailure(input: {
  status: number;
  body?: string;
  headers?: Headers;
}): HttpFailure {
  const body = input.body ?? '';
  const requestId = failureRequestId(input.headers, body);
  const ref = requestId ? ` Reference ${requestId}.` : '';
  const plain = body.trim();

  let message: string;
  if (EDGE_TIMEOUT_STATUSES.has(input.status)) {
    message = `The server took too long to answer (HTTP ${input.status}). Retry in a moment.`;
  } else if (EDGE_UNAVAILABLE_STATUSES.has(input.status)) {
    message = `The server is unreachable right now (HTTP ${input.status}). Retry in a moment.`;
  } else if (plain && !looksLikeHtml(plain) && plain.length <= 300 && !/[<>]/.test(plain)) {
    message = plain;
  } else {
    message = `Request failed (HTTP ${input.status}).`;
  }

  if (looksLikeHtml(body) || !plain || requestId) {
    console.warn('[api] non-JSON error response', { status: input.status, requestId });
  }
  return { message: `${message}${ref}`, requestId };
}

/** Our JSON error envelope (nested `{ error: { code, message } }` or flat). */
export interface ApiErrorBody {
  error?: string | { code?: string; message?: string; details?: unknown };
  code?: string;
  message?: string;
  details?: unknown;
}

/** One normalized API error: code, message and details from any envelope. */
export interface NormalizedApiError {
  code?: string;
  message?: string;
  details?: unknown;
}

/**
 * Read a failed response's body into one error. Our JSON envelopes pass
 * through (nested `{ error: { code, message } }`, flat `{ error: "<code>",
 * message }`, or bare `{ code, message }`); anything else (an edge HTML page,
 * an empty body) becomes a short sentence with the reference id.
 */
export function normalizeErrorBody(status: number, text: string, headers?: Headers): NormalizedApiError {
  const parsed = parseJsonBody(text);
  if (parsed && typeof parsed === 'object') {
    const body = parsed as ApiErrorBody;
    // Flat `{ error: "<code>", message }` bodies (the shared auth-lifecycle
    // and step-up admin APIs) carry the code as a string.
    const error = typeof body.error === 'string'
      ? { code: body.error, message: body.message }
      : (body.error ?? { code: body.code, message: body.message, details: body.details });
    return { ...error, message: safeErrorMessage(error.message, `Request failed (HTTP ${status}). Retry in a moment.`) };
  }
  const failure = describeHttpFailure({ status, body: text, headers });
  return {
    code: 'UNKNOWN_ERROR',
    message: failure.message,
    details: failure.requestId ? { request_id: failure.requestId } : undefined,
  };
}

/** Parse a JSON error body; `null` when the body is not JSON. */
export function parseJsonBody(text: string): unknown {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/**
 * Last line of defence for strings that reach a toast or panel: strips any
 * markup-bearing message down to a generic sentence.
 */
export function safeErrorMessage(message: string | undefined | null, fallback = 'Something went wrong. Retry in a moment.'): string {
  if (typeof message !== 'string' || !message) return fallback;
  if (looksLikeHtml(message) || /<\/?[a-z][^>]*>/i.test(message)) {
    const requestId = failureRequestId(undefined, message);
    return requestId ? `${fallback} Reference ${requestId}.` : fallback;
  }
  return message.length > 500 ? `${message.slice(0, 497)}…` : message;
}
