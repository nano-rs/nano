// SPDX-License-Identifier: AGPL-3.0-or-later
// Serve a built SPA and proxy /api like nginx: node serve.mjs <dist> <port> <apiPort> <searchPort>
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
const [dist, port, apiPort, searchPort] = process.argv.slice(2);
const types = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.json': 'application/json', '.woff2': 'font/woff2', '.png': 'image/png' };
const toSearch = p => p.startsWith('/api/search') && !/^\/api\/search\/(history|share|shared|explanation)/.test(p);
http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname.startsWith('/api') || url.pathname === '/health') {
    const target = toSearch(url.pathname) ? searchPort : apiPort;
    const p = http.request({ host: '127.0.0.1', port: target, path: req.url, method: req.method, headers: req.headers }, r => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
    p.on('error', e => { res.writeHead(502); res.end(String(e)); });
    req.pipe(p);
    return;
  }
  let file = path.join(dist, decodeURIComponent(url.pathname));
  if (!file.startsWith(dist) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) file = path.join(dist, 'index.html');
  res.writeHead(200, { 'content-type': types[path.extname(file)] ?? 'application/octet-stream' });
  fs.createReadStream(file).pipe(res);
}).listen(Number(port), '127.0.0.1', () => console.log(`serving ${dist} on ${port}`));
