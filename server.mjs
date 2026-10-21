import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { encryptLink, maxInputBytes } from './index.mjs';

export function createAPI({ token, limit = 120, windowMs = 60000 }) {
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{32,256}$/.test(token)) throw new Error('A random API token (32+ base64url characters) is required');
  const credential = Buffer.from('Bearer ' + token);
  let started = Date.now(), count = 0;
  const server = http.createServer(async (req, res) => {
    const reply = (status, value) => {
      res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Connection': 'close' });
      res.end(JSON.stringify(value));
    };
    // No CORS, access logs, URL fetching, or forwarded-IP trust.
    const auth = Buffer.from(req.headers.authorization || '');
    if (auth.length !== credential.length || !timingSafeEqual(auth, credential)) return reply(401, { error: 'unauthorized' });
    if (req.method !== 'POST' || req.url !== '/v1/links') return reply(404, { error: 'not_found' });
    if (Date.now() - started >= windowMs) { started = Date.now(); count = 0; }
    if (++count > limit) return reply(429, { error: 'rate_limited' });
    if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(req.headers['content-type'] || '')) return reply(415, { error: 'json_required' });
    if (req.headers['content-encoding'] || Number(req.headers['content-length']) > maxInputBytes) return reply(413, { error: 'body_too_large' });
    let bytes = 0;
    const chunks = [];
    try {
      for await (const chunk of req) {
        bytes += chunk.length;
        if (bytes > maxInputBytes) { reply(413, { error: 'body_too_large' }); return; }
        chunks.push(chunk);
      }
      reply(200, { link: encryptLink(JSON.parse(Buffer.concat(chunks).toString('utf8'))) });
    } catch {
      if (!res.headersSent) reply(400, { error: 'invalid_input' });
    }
  });
  server.headersTimeout = 10000;
  server.requestTimeout = 15000;
  server.setTimeout(15000, socket => socket.destroy());
  server.maxHeadersCount = 32;
  server.on('clientError', (_error, socket) => socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'));
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const token = readFileSync(process.env.ALIENMODE_API_TOKEN_FILE, 'utf8').trim();
    const port = Number(process.env.PORT || 8787);
    if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('invalid_port');
    const server = createAPI({ token });
    server.on('error', () => { process.stderr.write('API could not start.\n'); process.exitCode = 1; });
    server.listen(port, '127.0.0.1', () => process.stdout.write('AlienMode provider API listening on loopback. Use an HTTPS reverse proxy for remote access.\n'));
    for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { server.close(); server.closeAllConnections(); });
  } catch {
    process.stderr.write('Set ALIENMODE_API_TOKEN_FILE to a private file containing a random API token (32+ base64url characters).\n');
    process.exitCode = 1;
  }
}
