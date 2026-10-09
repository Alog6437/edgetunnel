import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import test from 'node:test';

async function loadWorker() {
  let source = await readFile(new URL('../_worker.js', import.meta.url), 'utf8');
  source = source
    .replace("import { connect } from 'cloudflare:sockets';", 'const connect = () => { throw new Error("socket unavailable in unit test"); };')
    .replace('export default {', 'const __worker = {');
  source += '\n__worker.checkDestination = (...args) => createRequestWorker().checkDestination(...args); globalThis.__edgeTunnelWorker = __worker;';
  source = source.replace('return requestWorker;', 'requestWorker.checkDestination = (env, host, port) => { tunnelEnv = env; assertDestinationAllowed(host, port); }; return requestWorker;');

  const subtle = {
    ...webcrypto.subtle,
    async digest(algorithm, data) {
      if (String(algorithm).toUpperCase() === 'MD5') {
        const digest = createHash('md5').update(Buffer.from(data)).digest();
        return digest.buffer.slice(digest.byteOffset, digest.byteOffset + digest.byteLength);
      }
      return webcrypto.subtle.digest(algorithm, data);
    },
  };

  const context = {
    AbortController,
    ArrayBuffer,
    Blob,
    Buffer,
    DataView,
    Date,
    Headers,
    Math,
    ReadableStream,
    Request,
    Response,
    Set,
    TextDecoder,
    TextEncoder,
    TransformStream,
    URL,
    Uint8Array,
    WritableStream,
    atob,
    btoa,
    clearTimeout,
    console,
    crypto: { subtle },
    fetch,
    setTimeout,
  };
  context.globalThis = context;
  vm.runInNewContext(source, context, { filename: '_worker.js' });
  return context.__edgeTunnelWorker;
}

const UUID = '90cd4a77-141a-43c9-991b-08263cfe9c10';
const executionContext = { waitUntil() {} };

test('tunnel guard rejects disabled service, client relays and excess connections before upgrade', async () => {
  const worker = await loadWorker();
  const request = (path = '/') => new Request(`https://example.com${path}`, { headers: { Upgrade: 'WebSocket' } });
  assert.equal((await worker.fetch(request(), { TUNNEL_ENABLED: 'false' }, executionContext)).status, 503);
  for (const path of ['/?proxyip=other.test', '/socks5=other.test', '/http://other.test']) {
    assert.equal((await worker.fetch(request(path), {}, executionContext)).status, 403);
  }
  assert.equal((await worker.fetch(request(), { TUNNEL_RATE_LIMITER: { limit: async ({ key }) => {
    assert.equal(key, 'tunnel'); return { success: false };
  } } }, executionContext)).status, 429);
});

test('destination policy limits ports and matches normalized hosts at domain boundaries', async () => {
  const worker = await loadWorker();
  assert.doesNotThrow(() => worker.checkDestination({}, 'example.com', 443));
  for (const port of [22, 25, 465, 587, 8080]) assert.throws(() => worker.checkDestination({}, 'example.com', port));
  assert.throws(() => worker.checkDestination({ ALLOWED_PORTS: '25' }, 'example.com', 25));
  const env = { ALLOWED_HOSTS: 'example.com,*.example.org' };
  assert.doesNotThrow(() => worker.checkDestination(env, 'EXAMPLE.COM.', 443));
  assert.doesNotThrow(() => worker.checkDestination(env, 'a.example.org', 443));
  for (const host of ['example.org', 'badexample.org', 'example.com.evil.test']) {
    assert.throws(() => worker.checkDestination(env, host, 443));
  }
  assert.throws(() => worker.checkDestination({}, 'SPEED.CLOUDFLARE.COM.', 443));
});

test('root endpoint is a minimal health response', async () => {
  const worker = await loadWorker();
  const request = new Request('https://example.com/', {
    headers: { 'User-Agent': 'test' },
  });
  Object.defineProperty(request, 'cf', { value: { country: 'CN', colo: 'TEST' } });
  const response = await worker.fetch(request, { UUID }, executionContext);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.service, 'edgetunnel');
  assert.equal(body.status, 'ok');
  assert.equal('country' in body, false);
});

test('admin endpoints require a separately configured token', async () => {
  const worker = await loadWorker();
  const response = await worker.fetch(
    new Request(`https://example.com/${UUID}/edit`),
    { UUID },
    executionContext,
  );
  assert.equal(response.status, 503);
});

test('admin endpoints challenge invalid credentials and accept HTTP Basic', async () => {
  const worker = await loadWorker();
  const url = `https://example.com/${UUID}/edit`;
  const unauthorized = await worker.fetch(
    new Request(url, { headers: { Authorization: 'Bearer wrong' } }),
    { UUID, ADMIN_TOKEN: 'correct horse battery staple' },
    executionContext,
  );
  assert.equal(unauthorized.status, 401);
  assert.match(unauthorized.headers.get('WWW-Authenticate'), /^Basic /);

  const authorized = await worker.fetch(
    new Request(url, {
      headers: { Authorization: `Basic ${btoa('admin:correct horse battery staple')}` },
    }),
    { UUID, ADMIN_TOKEN: 'correct horse battery staple' },
    executionContext,
  );
  assert.equal(authorized.status, 200);
  assert.match(authorized.headers.get('Content-Security-Policy'), /frame-ancestors 'none'/);
});

test('subscription generation still returns usable VLESS content', async () => {
  const worker = await loadWorker();
  const response = await worker.fetch(
    new Request(`https://example.com/${UUID}`, {
      headers: { 'User-Agent': 'CF-Workers-SUB' },
    }),
    { UUID },
    executionContext,
  );
  assert.equal(response.status, 200);
  const encoded = await response.text();
  const decoded = Buffer.from(encoded, 'base64').toString('utf8');
  assert.match(decoded, new RegExp(UUID));
  assert.match(decoded, /vless:\/\//);
});

test('KV editor escapes stored content before embedding it in HTML', async () => {
  const worker = await loadWorker();
  const payload = '</textarea><script>globalThis.pwned=true</script>';
  const response = await worker.fetch(
    new Request(`https://example.com/${UUID}/edit`, {
      headers: { Authorization: `Bearer admin-secret` },
    }),
    {
      UUID,
      ADMIN_TOKEN: 'admin-secret',
      KV: { get: async () => payload },
    },
    executionContext,
  );
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.equal(html.includes(payload), false);
  assert.match(html, /&lt;\/textarea&gt;&lt;script&gt;/);
});
