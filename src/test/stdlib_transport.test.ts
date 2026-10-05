import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import { Logger } from '../util/logger.js';
import { HttpClient, HttpError, type HttpClientOptions } from '../http/client.js';
import { SiteState } from '../site/state.js';

function stdlibClient(baseUrl: string, overrides: Partial<HttpClientOptions> = {}) {
  return new HttpClient({
    baseUrl,
    timeoutMs: 5000,
    logger: new Logger('silent'),
    auth: { type: 'user_api_key', key: 'user-key', client_id: 'discourse-mcp' },
    cookie: 'cf_clearance=abc',
    extraHeaders: { 'User-Agent': 'TestAgent/1.0' },
    httpProfile: 'stdlib',
    ...overrides,
  });
}

async function captureWire() {
  const seen: { lines: string[]; body: string }[] = [];
  const server = net.createServer((sock) => {
    let buf = Buffer.alloc(0);
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      const text = buf.toString('latin1');
      const headEnd = text.indexOf('\r\n\r\n');
      if (headEnd === -1) return;
      const head = text.slice(0, headEnd);
      const lengthMatch = head.match(/\r\ncontent-length:\s*(\d+)/i);
      const want = lengthMatch ? parseInt(lengthMatch[1], 10) : 0;
      const bodyStart = headEnd + 4;
      if (buf.length < bodyStart + want) return;
      seen.push({
        lines: head.split('\r\n'),
        body: buf.subarray(bodyStart, bodyStart + want).toString('utf8'),
      });
      sock.end('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 12\r\nConnection: close\r\n\r\n{"ok": true}');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, port: (server.address() as AddressInfo).port, seen };
}

test('stdlib profile emits conservative header order without fetch auto headers', async () => {
  const { server, port, seen } = await captureWire();
  try {
    const client = stdlibClient(`http://127.0.0.1:${port}`);
    const data = await client.get('/about.json');
    assert.deepEqual(data, { ok: true });
    assert.equal(seen.length, 1);
    const [requestLine, ...headers] = seen[0].lines;
    assert.equal(requestLine, 'GET /about.json HTTP/1.1');
    const names = headers.map((h) => h.split(':')[0]);
    assert.deepEqual(names, [
      'Accept-Encoding',
      'Host',
      'User-Agent',
      'Accept',
      'User-Api-Key',
      'User-Api-Client-Id',
      'Cookie',
      'Connection',
    ]);
    const values = Object.fromEntries(headers.map((h) => {
      const i = h.indexOf(':');
      return [h.slice(0, i), h.slice(i + 1).trim()];
    }));
    assert.equal(values['Accept-Encoding'], 'identity');
    assert.equal(values.Host, `127.0.0.1:${port}`);
    assert.equal(values.Cookie, 'cf_clearance=abc');
    assert.equal(values.Connection, 'close');
    assert.ok(!names.some((n) => n.toLowerCase() === 'sec-fetch-mode'));
  } finally {
    server.close();
  }
});

test('stdlib profile sends JSON bodies with explicit length and no chunking', async () => {
  const { server, port, seen } = await captureWire();
  try {
    const client = stdlibClient(`http://127.0.0.1:${port}`);
    await client.post('/posts.json', { raw: 'hello' });
    assert.equal(seen.length, 1);
    const [requestLine, ...headers] = seen[0].lines;
    assert.equal(requestLine, 'POST /posts.json HTTP/1.1');
    const values = Object.fromEntries(headers.map((h) => {
      const i = h.indexOf(':');
      return [h.slice(0, i), h.slice(i + 1).trim()];
    }));
    assert.equal(values['Content-Type'], 'application/json');
    assert.equal(values['Content-Length'], String(Buffer.byteLength(seen[0].body)));
    assert.deepEqual(JSON.parse(seen[0].body), { raw: 'hello' });
    assert.ok(!Object.keys(values).some((n) => n.toLowerCase() === 'transfer-encoding'));
  } finally {
    server.close();
  }
});

test('stdlib profile surfaces upstream errors as HttpError', async () => {
  const server = http.createServer((_req, res) => {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'denied' }));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const client = stdlibClient(`http://127.0.0.1:${(server.address() as AddressInfo).port}`);
    await assert.rejects(client.get('/about.json'), (e: any) => {
      assert.ok(e instanceof HttpError);
      assert.equal(e.status, 403);
      return true;
    });
  } finally {
    server.close();
  }
});

test('stdlib profile rejects multipart uploads explicitly', async () => {
  const client = stdlibClient('https://example.com');
  await assert.rejects(
    client.postMultipart('/uploads.json', new FormData()),
    /multipart/,
  );
});

test('stdlib profile offers the minimal cipher list in its ClientHello', async () => {
  let hello = '';
  const server = net.createServer((sock) => {
    let buf = Buffer.alloc(0);
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= 5) {
        const ln = buf.readUInt16BE(3);
        if (buf.length >= 5 + ln) {
          hello = buf.subarray(9).toString('hex');
          sock.destroy();
        }
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  try {
    const client = stdlibClient(`https://127.0.0.1:${port}`);
    await client.get('/about.json').catch(() => undefined);
    assert.ok(hello.length > 0, 'expected a ClientHello');
    const b = Buffer.from(hello, 'hex');
    let pos = 2 + 32;
    const sidLen = b[pos];
    pos += 1 + sidLen;
    const cipherBytes = b.readUInt16BE(pos);
    pos += 2;
    const ciphers: string[] = [];
    for (let i = 0; i < cipherBytes; i += 2) {
      ciphers.push(b.readUInt16BE(pos + i).toString(16).padStart(4, '0'));
    }
    const expected = "1302 1303 1301 c02c c030 c02b c02f cca9 cca8 c024 c028 c023 c027 009f 009e 006b 0067".split(" ");
    assert.deepEqual(ciphers, expected);
  } finally {
    server.close();
  }
});

test('SiteState enables the stdlib profile from auth_pairs', async () => {
  const siteState = new SiteState({
    logger: new Logger('silent'),
    timeoutMs: 5000,
    defaultAuth: { type: 'none' },
    authOverrides: [
      { site: 'https://example.com', cookie: 'cf_clearance=x', http_profile: 'stdlib' },
    ],
  });
  const { client } = siteState.buildClientForSite('https://example.com/');
  assert.equal((client as any).opts.httpProfile, 'stdlib');
});
