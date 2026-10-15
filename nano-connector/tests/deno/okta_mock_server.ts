// Serves the NAN-3483 MockOkta (unmodified) over TLS for the G1 diff, so the
// Deno collector and the engine read the same synthetic System Log.
// usage: deno run --allow-net=127.0.0.1 --allow-read okta_mock_server.ts <cfg.json>
// cfg: {mock_module, cert_pem, key_pem, events, users, page_max, shift_ms}
// Prints {"port": N} once listening. POST /__mock/mode {"append": N} adds events.

const cfg = JSON.parse(await Deno.readTextFile(Deno.args[0]));
const { MockOkta } = await import(cfg.mock_module);
const mock = new MockOkta({
  token: "mock-token",
  events: cfg.events,
  users: cfg.users,
  pageMax: cfg.page_max,
  now: () => Date.now() - cfg.shift_ms,
  origin: "https://acme.okta.com",
});
const server = Deno.serve(
  {
    port: 0,
    hostname: "127.0.0.1",
    cert: cfg.cert_pem,
    key: cfg.key_pem,
    onListen: ({ port }) => console.log(JSON.stringify({ port })),
  },
  async (req: Request) => {
    const url = new URL(req.url);
    if (url.pathname === "/__mock/mode" && req.method === "POST") {
      const body = await req.json().catch(() => ({}));
      if (typeof body.append === "number") mock.append(body.append);
      return new Response(JSON.stringify({ events: mock.eventCount }), { status: 200 });
    }
    return mock.handle(req);
  },
);
await server.finished;
