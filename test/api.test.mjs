import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { spawnSync } from 'node:child_process';
import { encryptLink, prefix, recipient } from '../index.mjs';
import { createAPI } from '../server.mjs';

test('randomized canonical envelopes, public key only', () => {
  const input = { url: 'https://example.com/sub/token%2Btest#Name', title: 'Alien VPN 🛸' };
  const a = encryptLink(input), b = encryptLink(input);
  assert.notEqual(a, b);
  assert.match(a, /^alienmode:\/\/crypt5\/am-2026-01\.[A-Za-z0-9_-]+$/);
  assert.equal(Buffer.from(recipient.publicKey, 'base64url').length, 32);
  assert.deepEqual(Object.keys(recipient).sort(), ['kid', 'publicKey']);
  const wire = Buffer.from(a.slice((prefix + recipient.kid + '.').length), 'base64url');
  assert.ok(wire.length > 60);
});

test('reject unsafe URLs and ambiguous/oversized payloads', () => {
  for (const url of ['http://example.com/token', 'file:///etc/passwd', 'https://user:pw@example.com/', 'https://example.com:0/', 'https://example.com/\nprivate', 'https://example.com\\@evil.test/']) {
    assert.throws(() => encryptLink({ url }));
  }
  for (const input of [null, [], { url: 'https://example.com/', title: 1 }, { url: 'https://example.com/', title: 'a'.repeat(201) }, { url: 'https://example.com/', unknown: true }, { url: 'https://example.com/' + 'a'.repeat(16384) }]) assert.throws(() => encryptLink(input));
});

test('CLI accepts stdin and does not echo invalid secret', () => {
  const file = new URL('../cli.mjs', import.meta.url);
  const good = spawnSync(process.execPath, [file.pathname], { input: JSON.stringify({ url: 'https://example.com/test', title: 'CLI' }), encoding: 'utf8' });
  assert.equal(good.status, 0);
  assert.ok(JSON.parse(good.stdout).link.startsWith(prefix));
  const bad = spawnSync(process.execPath, [file.pathname], { input: '{SECRET_SUBSCRIPTION', encoding: 'utf8' });
  assert.equal(bad.status, 1);
  assert.equal(bad.stdout, '');
  assert.ok(!bad.stderr.includes('SECRET_SUBSCRIPTION'));
});

test('API authentication, limits, methods, validation and encryption', async t => {
  const token = 'synthetic_test_token_'.repeat(3);
  const server = createAPI({ token, limit: 20 });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => { server.closeAllConnections(); server.close(); });
  const url = `http://127.0.0.1:${server.address().port}/v1/links`;
  const headers = { authorization: 'Bearer ' + token, 'content-type': 'application/json' };
  let res = await fetch(url, { method: 'POST', body: '{}' }); assert.equal(res.status, 401);
  res = await fetch(url, { headers }); assert.equal(res.status, 404);
  res = await fetch(url, { method: 'POST', headers: { ...headers, 'content-type': 'text/plain' }, body: '{}' }); assert.equal(res.status, 415);
  res = await fetch(url, { method: 'POST', headers, body: 'a'.repeat(24577) }); assert.equal(res.status, 413);
  res = await fetch(url, { method: 'POST', headers, body: JSON.stringify({ url: 'http://example.com/SECRET' }) });
  assert.equal(res.status, 400); assert.ok(!(await res.text()).includes('SECRET'));
  res = await fetch(url, { method: 'POST', headers, body: JSON.stringify({ url: 'https://example.com/sub/demo', title: 'API' }) });
  assert.equal(res.status, 200); assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.equal(res.headers.get('access-control-allow-origin'), null);
  assert.ok((await res.json()).link.startsWith(prefix));
});

test('API refuses missing credentials and caps request rate', async t => {
  assert.throws(() => createAPI({ token: '' }));
  const token = 'x'.repeat(40), server = createAPI({ token, limit: 1 });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => { server.closeAllConnections(); server.close(); });
  const url = `http://127.0.0.1:${server.address().port}/v1/links`;
  const options = { method: 'POST', headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' }, body: '{"url":"https://example.com/"}' };
  assert.equal((await fetch(url, options)).status, 200);
  assert.equal((await fetch(url, options)).status, 429);
});
