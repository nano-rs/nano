// SPDX-License-Identifier: AGPL-3.0-or-later
// Mock Okta System Log vendor for the connector runner's loopback transport.
import http from 'node:http';
const port = Number(process.argv[2] ?? 18990);
let hits = 0;
http.createServer((req, res) => {
  hits += 1;
  const url = new URL(req.url, 'http://x');
  console.log(new Date().toISOString(), req.method, req.url, 'auth=', (req.headers.authorization ?? '').slice(0, 10));
  if (!url.pathname.startsWith('/api/v1/logs')) { res.writeHead(404); res.end(); return; }
  if (req.headers.authorization !== 'SSWS mock-okta-token') { res.writeHead(401, { 'content-type': 'application/json' }); res.end('{"errorCode":"E0000011"}'); return; }
  const since = url.searchParams.get('since') ?? new Date(Date.now() - 60000).toISOString();
  const t = new Date(new Date(since).getTime() + 1000).toISOString();
  const ev = (i) => ({ uuid: `mock-${since}-${i}`, published: t, eventType: 'user.session.start', displayMessage: 'User login to Okta', severity: 'INFO',
    actor: { id: '00u1', type: 'User', alternateId: 'alice@example.com', displayName: 'Alice' },
    client: { ipAddress: '203.0.113.7', userAgent: { rawUserAgent: 'mock' } }, outcome: { result: 'SUCCESS' } });
  res.writeHead(200, { 'content-type': 'application/json', 'X-Rate-Limit-Remaining': '100', 'X-Rate-Limit-Reset': String(Math.floor(Date.now() / 1000) + 60) });
  res.end(JSON.stringify([ev(1), ev(2)]));
}).listen(port, '127.0.0.1', () => console.log('okta mock on', port));
