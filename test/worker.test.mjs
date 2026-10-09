import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash, createCipheriv, hkdfSync, webcrypto } from 'node:crypto';
import vm from 'node:vm';

const UUID = '90cd4a77-141a-43c9-991b-08263cfe9c10';
const ctx = { waitUntil() {} };
const environment = { UUID, ALLOWED_HOSTS: 'example.com' };

async function loadWorker(options = {}) {
  let code = await readFile(new URL('../_worker.js', import.meta.url), 'utf8');
  code = code.replace("import { connect } from 'cloudflare:sockets';", 'const connect = mockedConnect;')
    .replace('export default {', 'const worker = {')
    .replace('return requestWorker;', `requestWorker.testTCP = forwardataTCP;
      requestWorker.testDNS = forwardataudp;
      requestWorker.testTrojanUDP = 转发木马UDP数据;
      requestWorker.testRelay = 反代参数获取;
      requestWorker.testConnector = 创建请求TCP连接器;
      requestWorker.testTrojanHash = sha224;
      requestWorker.testHash = MD5MD5;
      requestWorker.testFetch = fetch;
      return requestWorker;`);
  code += '\nglobalThis.api = { worker, createRequestWorker, makeTunnelPolicy, assertPublicTarget, normalizeTarget };';
  const sockets = [], websocketServers = [], timers = new Set();
  const connect = options => {
    let resolve;
    const closed = new Promise(r => resolve = r);
    const socket = {
      readable: new ReadableStream({ start(controller) { socketController = controller; } }),
      writable: new WritableStream({ write(chunk) { socket.writes.push(new Uint8Array(chunk)); } }),
      opened: Promise.resolve(), closed, writes: [],
      close() { resolve(); try { socketController.close(); } catch (_) {} },
    };
    sockets.push({ options, socket });
    return socket;
    var socketController;
  };
  class FakeSocket extends EventTarget {
    static OPEN = 1; static CLOSED = 3; static CLOSING = 2;
    readyState = 1; sent = [];
    accept() {}
    send(value) { this.sent.push(value); }
    close() { if (this.readyState !== 3) { this.readyState = 3; this.dispatchEvent(new Event('close')); } }
  }
  class WorkerResponse extends Response {
    constructor(body, init = {}) {
      if (init.status === 101) { super(null); this.webSocket = init.webSocket; this.upgraded = true; }
      else super(body, init);
    }
  }
  const context = {
    mockedConnect: connect, URL, URLSearchParams, Request, Headers, Response: WorkerResponse,
    TextEncoder, TextDecoder, Uint8Array, ArrayBuffer, DataView, ReadableStream, WritableStream, TransformStream,
    Buffer, atob, btoa, console, AbortController, queueMicrotask, Event, EventTarget, performance,
    WebSocket: FakeSocket,
    WebSocketPair: class { constructor() { this[0] = new FakeSocket(); this[1] = new FakeSocket(); websocketServers.push(this[1]); } },
    crypto: { getRandomValues: webcrypto.getRandomValues.bind(webcrypto), subtle: {
      importKey: webcrypto.subtle.importKey.bind(webcrypto.subtle),
      encrypt: webcrypto.subtle.encrypt.bind(webcrypto.subtle),
      decrypt: webcrypto.subtle.decrypt.bind(webcrypto.subtle),
      sign: webcrypto.subtle.sign.bind(webcrypto.subtle),
      digest(algorithm, data) {
        if (String(algorithm).toUpperCase() === 'MD5') {
          const bytes = createHash('md5').update(Buffer.from(data)).digest();
          return Promise.resolve(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length));
        }
        return webcrypto.subtle.digest(algorithm, data);
      }
    } },
    fetch: options.fetch || (() => { throw Error('Unexpected external fetch'); }),
    setTimeout(fn, ms) { const timer = setTimeout(fn, ms); timer.unref(); timers.add(timer); return timer; },
    clearTimeout(timer) { clearTimeout(timer); timers.delete(timer); },
  };
  context.globalThis = context;
  vm.runInNewContext(code, context);
  return { ...context.api, sockets, websocketServers, cleanup() { for (const timer of timers) clearTimeout(timer); } };
}

function request(path = '/', init = {}) {
  const req = new Request('https://tunnel.example.com' + path, init);
  Object.defineProperty(req, 'cf', { value: { colo: 'HKG' } });
  return req;
}
function vless(host = 'example.com', port = 443, cmd = 1) {
  const name = Buffer.from(host);
  return Uint8Array.from([0, ...Buffer.from(UUID.replaceAll('-', ''), 'hex'), 0, cmd, port >> 8, port & 255, 2, name.length, ...name, 1, 2, 3]);
}
const flush = () => new Promise(resolve => setTimeout(resolve, 40));

test('private addresses, alternate IPv4 notation and restricted IPv6 cannot pass the public target guard', async t => {
  const api = await loadWorker(); t.after(api.cleanup);
  for (const host of ['127.0.0.1', '2130706433', '0x7f000001', '10.0.0.1', '169.254.169.254', '172.16.0.1', '192.168.1.1', '100.64.0.1', '224.0.0.1', 'localhost', 'foo.local', '[::1]', '[::ffff:127.0.0.1]', 'fc00::1', 'fe80::1', 'ff02::1', '2001:db8::1', '2002:7f00:1::', 'a.com@127.0.0.1']) {
    assert.throws(() => api.assertPublicTarget(host), undefined, host);
  }
  assert.equal(api.assertPublicTarget('EXAMPLE.COM.'), 'example.com');
  assert.equal(api.assertPublicTarget('2606:4700:4700::1111'), '2606:4700:4700::1111');
});

test('allowlist domain boundaries, mandatory configuration and permanent mail-port ban', async t => {
  const api = await loadWorker(); t.after(api.cleanup);
  const policy = api.makeTunnelPolicy({ ALLOWED_HOSTS: 'example.com,*.example.org', ALLOWED_PORTS: '443,25,587' });
  assert.doesNotThrow(() => policy.assertTCP('EXAMPLE.COM.', 443));
  assert.doesNotThrow(() => policy.assertTCP('a.example.org', 443));
  for (const host of ['example.org', 'badexample.org', 'example.com.evil.com', '10.0.0.1']) assert.throws(() => policy.assertTCP(host, 443));
  for (const port of [25, 587, 465, 22]) assert.throws(() => policy.assertTCP('example.com', port));
  assert.equal(api.makeTunnelPolicy({}).ready, false);
  assert.throws(() => api.makeTunnelPolicy({ ALLOWED_HOSTS: '*' }));
});

test('all tunnel transports respect disabled service, missing allowlist, fixed path and rate limiter', async t => {
  const api = await loadWorker(); t.after(api.cleanup);
  for (const init of [{ headers: { Upgrade: 'websocket' } }, { method: 'POST', body: vless(), headers: { 'Content-Type': 'application/grpc' } }, { method: 'POST', body: vless() }]) {
    assert.equal((await api.worker.fetch(request('/', init), { ...environment, TUNNEL_ENABLED: 'false' }, ctx)).status, 503);
    assert.equal((await api.worker.fetch(request('/', init), { UUID }, ctx)).status, 503);
    assert.equal((await api.worker.fetch(request('/', init), { ...environment, TUNNEL_PATH: '/private-tunnel' }, ctx)).status, 404);
    assert.equal((await api.worker.fetch(request('/', init), { ...environment, TUNNEL_RATE_LIMITER: { limit: async () => ({ success: false }) } }, ctx)).status, 429);
  }
  assert.equal(api.sockets.length, 0);
});

test('client relay parameters ignored by default and request configuration does not leak', async t => {
  const api = await loadWorker(); t.after(api.cleanup);
  const instance = api.createRequestWorker();
  await instance.fetch(request('/version'), environment, ctx);
  for (const path of ['/?proxyip=evil.com', '/video/socks5://evil.com:1080', '/trojan=evil.com', '/ghttp=evil.com:80']) {
    const relay = await instance.testRelay(new URL('https://tunnel.example.com' + path), UUID, 'operator.example.com', false);
    assert.equal(relay.反代IP, 'operator.example.com');
    assert.equal(relay.代理类型, null);
    assert.equal(relay.木马反代地址, null);
  }
  const other = api.createRequestWorker();
  await other.fetch(request('/version'), { UUID }, ctx);
  await assert.rejects(other.testTCP('example.com', 443), /outside ALLOWED_HOSTS/);
});

test('WebSocket VLESS blocks denied target before connecting; accepted target uses one official socket', async t => {
  const api = await loadWorker(); t.after(api.cleanup);
  const response = await api.worker.fetch(request('/?proxyip=evil.com', { headers: { Upgrade: 'websocket' } }), environment, ctx);
  assert.equal(response.upgraded, true);
  const deniedWS = api.websocketServers[0];
  deniedWS.dispatchEvent(new MessageEvent('message', { data: vless('evil.com').buffer }));
  await flush();
  assert.equal(api.sockets.length, 0);
  assert.equal(deniedWS.readyState, 3);
  await api.worker.fetch(request('/', { headers: { Upgrade: 'websocket' } }), environment, ctx);
  api.websocketServers[1].dispatchEvent(new MessageEvent('message', { data: vless().buffer }));
  await flush();
  assert.equal(api.sockets.length, 1);
  assert.equal(api.sockets[0].options.hostname, 'example.com');
  api.sockets[0].socket.close();
});

test('xHTTP rejects oversized unauthenticated first packets without sockets', async t => {
  const api = await loadWorker(); t.after(api.cleanup);
  const response = await api.worker.fetch(request('/', { method: 'POST', body: new Uint8Array(70000) }), environment, ctx);
  assert.equal(response.status, 400);
  assert.equal(api.sockets.length, 0);
});

test('xHTTP accepts an authorized VLESS destination and rejects a mail port before dialing', async t => {
  const api = await loadWorker(); t.after(api.cleanup);
  const denied = await api.worker.fetch(request('/', { method: 'POST', body: vless('example.com', 25) }), environment, ctx);
  assert.equal(denied.status, 502);
  assert.equal(api.sockets.length, 0);
  const response = await api.worker.fetch(request('/', { method: 'POST', body: vless() }), environment, ctx);
  assert.equal(response.status, 200);
  assert.equal(api.sockets.length, 1);
  assert.equal(api.sockets[0].options.hostname, 'example.com');
  await response.body.cancel();
});

test('authenticated Trojan TCP and gRPC VLESS cannot bypass the target allowlist', async t => {
  const api = await loadWorker(); t.after(api.cleanup);
  const name = Buffer.from('evil.com');
  const trojan = Buffer.concat([Buffer.from(api.createRequestWorker().testTrojanHash(UUID) + '\r\n'), Buffer.from([1, 3, name.length]), name, Buffer.from([1, 187, 13, 10, 1, 2])]);
  const denied = await api.worker.fetch(request('/', { method: 'POST', body: trojan }), environment, ctx);
  assert.equal(denied.status, 502);
  const payload = vless('evil.com');
  const frame = Buffer.alloc(5 + 2 + payload.length);
  frame.writeUInt32BE(2 + payload.length, 1);
  frame[5] = 10; frame[6] = payload.length; frame.set(payload, 7);
  const response = await api.worker.fetch(request('/', { method: 'POST', headers: { 'Content-Type': 'application/grpc' }, body: frame }), environment, ctx);
  await response.arrayBuffer();
  assert.equal(api.sockets.length, 0);
});

test('authenticated Shadowsocks AEAD applies the same destination policy', async t => {
  const api = await loadWorker(); t.after(api.cleanup);
  const salt = Buffer.alloc(16, 7);
  const master = createHash('md5').update(UUID).digest();
  const key = Buffer.from(hkdfSync('sha1', master, salt, 'ss-subkey', 16));
  const name = Buffer.from('evil.com');
  const payload = Buffer.concat([Buffer.from([3, name.length]), name, Buffer.from([1, 187, 1, 2])]);
  const encrypt = (plaintext, counter) => {
    const nonce = Buffer.alloc(12); nonce[0] = counter;
    const cipher = createCipheriv('aes-128-gcm', key, nonce);
    return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  };
  const length = Buffer.alloc(2); length.writeUInt16BE(payload.length);
  const packet = Buffer.concat([salt, encrypt(length, 0), encrypt(payload, 1)]);
  await api.worker.fetch(request('/?enc=aes-128-gcm', { headers: { Upgrade: 'websocket' } }), environment, ctx);
  api.websocketServers[0].dispatchEvent(new MessageEvent('message', { data: Uint8Array.from(packet).buffer }));
  await flush();
  assert.equal(api.sockets.length, 0);
  assert.equal(api.websocketServers[0].readyState, 3);
});

test('gRPC rejects oversized frame lengths before any outbound connection', async t => {
  const api = await loadWorker(); t.after(api.cleanup);
  const response = await api.worker.fetch(request('/', { method: 'POST', headers: { 'Content-Type': 'application/grpc' }, body: Uint8Array.of(0, 0x7f, 0xff, 0xff, 0xff) }), environment, ctx);
  await response.arrayBuffer();
  assert.equal(api.sockets.length, 0);
});

test('DNS and Trojan UDP are disabled by default and fail before sockets', async t => {
  const api = await loadWorker(); t.after(api.cleanup);
  const instance = api.createRequestWorker();
  await instance.fetch(request('/version'), environment, ctx);
  await assert.rejects(instance.testDNS(new Uint8Array(0)), /DNS tunnel disabled/);
  await assert.rejects(instance.testTrojanUDP(new Uint8Array(0), null, { 反代地址: 'evil.com' }), /DNS tunnel disabled/);
  assert.equal(api.sockets.length, 0);
});

test('socket attempts and total bytes are bounded, including direct connector calls', async t => {
  const api = await loadWorker(); t.after(api.cleanup);
  const instance = api.createRequestWorker();
  await instance.fetch(request('/version'), { ...environment, MAX_TUNNEL_MB: '1' }, ctx);
  const connect = instance.testConnector();
  assert.throws(() => connect({ hostname: '127.0.0.1', port: 443 }));
  const socket = connect({ hostname: 'example.com', port: 443 });
  await assert.rejects(socket.writable.getWriter().write(new Uint8Array(1024 * 1024 + 1)), /byte budget/);
  for (let i = 0; i < 3; i++) connect({ hostname: 'example.com', port: 443 }).close();
  assert.throws(() => connect({ hostname: 'example.com', port: 443 }), /attempt budget/);
});

test('version requires the whole UUID and admin mutations reject cross-origin requests', async t => {
  const api = await loadWorker(); t.after(api.cleanup);
  assert.equal((await api.worker.fetch(request('/version?uuid=' + UUID), environment, ctx)).status, 200);
  const changed = '90cd4a77-241a-43c9-991b-08263cfe9c10';
  assert.notEqual((await api.worker.fetch(request('/version?uuid=' + changed), environment, ctx)).headers.get('Content-Type'), 'application/json;charset=utf-8');
  assert.equal((await api.worker.fetch(request('/admin', { method: 'POST', headers: { Origin: 'https://evil.com' }, body: '{}' }), environment, ctx)).status, 403);
  const adminEnv = { ...environment, ADMIN: 'admin-secret', KEY: 'private-key', KV: { get: async () => null } };
  const cookie = await api.createRequestWorker().testHash('testprivate-keyadmin-secret');
  const response = await api.worker.fetch(request('/admin/getCloudflareUsage?APIToken=secret', { headers: { 'User-Agent': 'test', Cookie: 'auth=' + cookie } }), adminEnv, ctx);
  assert.equal(response.status, 400);
});

test('remote configuration fetches reject HTTP, private IPs, redirects and oversized bodies', async t => {
  const api = await loadWorker({ fetch: async url => String(url).includes('redirect')
    ? new Response(null, { status: 302, headers: { Location: 'http://127.0.0.1' } })
    : new Response(new Uint8Array(2 * 1024 * 1024 + 1)) });
  t.after(api.cleanup);
  const fetch = api.createRequestWorker().testFetch;
  await assert.rejects(fetch('http://example.com'), /HTTPS/);
  await assert.rejects(fetch('https://127.0.0.1'), /Non-public/);
  await assert.rejects(fetch('https://example.com/redirect'), /redirect/);
  await assert.rejects((await fetch('https://example.com/large')).arrayBuffer(), /too large/);
});

test('login, authenticated admin and setup pages use final static URLs without redirects', async t => {
  const requested = [];
  const api = await loadWorker({ fetch: async resource => {
    const url = new URL(String(resource)); requested.push(url);
    if (!url.pathname.endsWith('/')) return new Response(null, { status: 301, headers: { Location: url.href + '/' } });
    return new Response('<html>page loaded</html>', { headers: { 'Content-Type': 'text/html' } });
  } });
  t.after(api.cleanup);
  const store = new Map();
  const env = { ...environment, ADMIN: 'admin-secret', KEY: 'private-key', KV: {
    get: async key => store.get(key) || null,
    put: async (key, value) => store.set(key, value),
  } };
  const login = await api.worker.fetch(request('/login'), env, ctx);
  assert.equal(login.status, 200);
  assert.match(await login.text(), /page loaded/);
  const cookie = await api.createRequestWorker().testHash('testprivate-keyadmin-secret');
  const admin = await api.worker.fetch(request('/admin', { headers: { 'User-Agent': 'test', Cookie: 'auth=' + cookie } }), env, ctx);
  assert.equal(admin.status, 200);
  assert.match(await admin.text(), /page loaded/);
  const missingAdmin = await api.worker.fetch(request('/'), {}, ctx);
  assert.equal(missingAdmin.status, 404);
  assert.match(await missingAdmin.text(), /page loaded/);
  const missingKV = await api.worker.fetch(request('/'), { ADMIN: 'admin-secret' }, ctx);
  assert.equal(missingKV.status, 404);
  assert.match(await missingKV.text(), /page loaded/);
  assert.deepEqual(requested.map(url => url.pathname), ['/login/', '/admin/', '/noADMIN/', '/noKV/']);
});
