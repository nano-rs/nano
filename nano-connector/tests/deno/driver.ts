// Deno baseline for the G1 diff (NAN-3490). Runs a shipped script UNMODIFIED
// the way production does today: the auth wrapper from the enterprise
// custom-enrichment sandbox (`generate_auth_setup`)
// monkey-patches fetch, then enrich()/collect() is called with the same
// arguments as `create_wrapper` / the collector `build_wrapper`.
//
// The only harness change: fetch to the vendor is routed to the local TLS
// mock (127.0.0.1:<port>) with the original host in `x-mock-host`.
//
// usage: deno run --allow-net=127.0.0.1 --allow-read driver.ts <input.json>

const input = JSON.parse(await Deno.readTextFile(Deno.args[0]));
const port: number = input.mock_port;

const realFetch = globalThis.fetch;
globalThis.fetch = (u: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
  const url = new URL(typeof u === "string" ? u : u instanceof URL ? u.href : u.url);
  const host = url.host;
  url.host = `127.0.0.1:${port}`;
  const headers = new Headers(init?.headers);
  headers.set("x-mock-host", host);
  return realFetch(url, { ...init, headers });
};

// ---- generate_auth_setup (sandbox.rs), ported verbatim to JS ----
const authHeaders: Record<string, string> = {};
const originalFetch = globalThis.fetch;
const auth = input.auth ?? { type: "none" };
let initAuth = async () => {};
if (auth.type === "bearer") {
  initAuth = async () => { authHeaders["Authorization"] = "Bearer " + auth.token; };
} else if (auth.type === "api_key_header") {
  initAuth = async () => { authHeaders[auth.header_name] = auth.api_key; };
} else if (auth.type === "basic") {
  initAuth = async () => { authHeaders["Authorization"] = `Basic ${btoa(auth.username + ":" + auth.password)}`; };
} else if (auth.type === "service_account_jwt") {
  let saToken: string | null = null;
  let saExpiry = 0;
  const b64url = (bytes: Uint8Array) => {
    let binary = "";
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const b64urlStr = (s: string) => b64url(new TextEncoder().encode(s));
  const pemToDer = (pem: string) => {
    const body = pem.replace(/-----BEGIN [^-]+-----/g, "").replace(/-----END [^-]+-----/g, "")
      .replace(/\\n/g, "").replace(/\s+/g, "");
    const raw = atob(body);
    const buf = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
    return buf.buffer;
  };
  initAuth = async () => {
    if (saToken && Date.now() < saExpiry) { authHeaders["Authorization"] = `Bearer ${saToken}`; return; }
    const now = Math.floor(Date.now() / 1000);
    const claims: Record<string, unknown> = { iss: auth.client_email, scope: auth.scope, aud: auth.token_url, iat: now, exp: now + 3600 };
    if (auth.subject) claims.sub = auth.subject;
    const signingInput = b64urlStr(JSON.stringify({ alg: "RS256", typ: "JWT" })) + "." + b64urlStr(JSON.stringify(claims));
    const key = await crypto.subtle.importKey("pkcs8", pemToDer(auth.private_key), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(signingInput)));
    const body = new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: signingInput + "." + b64url(sig) });
    const response = await originalFetch(auth.token_url, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: body.toString() });
    if (!response.ok) throw new Error(`Service-account token exchange failed: ${response.status} ${await response.text()}`);
    const data = await response.json();
    saToken = data.access_token;
    saExpiry = Date.now() + ((data.expires_in || 3600) - 60) * 1000;
    authHeaders["Authorization"] = `Bearer ${saToken}`;
  };
}
globalThis.fetch = async (u: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
  const url = typeof u === "string" ? u : u instanceof URL ? u.href : u.url;
  if (auth.token_url && url === auth.token_url) return originalFetch(u, init);
  const headers = new Headers(init?.headers);
  for (const [k, v] of Object.entries(authHeaders)) if (!headers.has(k)) headers.set(k, v);
  return originalFetch(u, { ...init, headers });
};

// ---- run ----
const mod = await import(input.script);
const out: Record<string, unknown> = {};
try {
  await initAuth();
  if (input.kind === "agent") {
    out.result = await mod.enrich(input.artifact, input.artifact_type, input.credentials);
  } else if (input.kind === "data") {
    out.result = await mod.enrich({ credentials: input.credentials, lastWatermark: input.last_watermark ?? undefined });
  } else {
    const emits: unknown[] = [];
    const checkpoints: unknown[] = [];
    await mod.collect({
      credentials: input.credentials,
      config: input.config ?? {},
      streams: input.streams ?? [],
      cursors: input.cursors ?? {},
      // The host's point-forward start (NAN-3697); backfillFrom is its
      // deprecated same-valued alias.
      initialCursor: input.initial_cursor ?? undefined,
      backfillFrom: input.initial_cursor ?? undefined,
      emit: async (stream: string, events: unknown[]) => { emits.push([stream, events]); },
      checkpoint: async (stream: string, cursor: string) => { checkpoints.push([stream, cursor]); },
      shouldStop: () => false,
      log: (_m: string, _f?: unknown) => {},
    });
    out.emits = emits;
    out.checkpoints = checkpoints;
  }
} catch (e) {
  out.error = e instanceof Error ? e.message : String(e);
}
console.log(JSON.stringify(out));
