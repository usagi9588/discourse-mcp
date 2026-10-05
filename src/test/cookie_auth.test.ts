import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Logger } from '../util/logger.js';
import { HttpClient, HttpError } from '../http/client.js';
import { SiteState } from '../site/state.js';
import { redactSecrets } from '../util/redact.js';
import { WAF_COOKIE_EXPIRED_CODE, wafCookieExpiredDetails } from '../util/waf.js';

function mockFetchCapture(captured: { url: string; headers: Record<string, string> }[]) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    captured.push({ url, headers: { ...((init?.headers as Record<string, string>) ?? {}) } });
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }) as typeof fetch;
  return () => {
    globalThis.fetch = originalFetch;
  };
}

test('HttpClient sends Cookie alongside User-Api-Key auth', async () => {
  const captured: { url: string; headers: Record<string, string> }[] = [];
  const restore = mockFetchCapture(captured);
  const logger = new Logger('silent');
  const client = new HttpClient({
    baseUrl: 'https://example.com',
    timeoutMs: 5000,
    logger,
    auth: { type: 'user_api_key', key: 'user-key', client_id: 'discourse-mcp' },
    cookie: 'cf_clearance=abc; __cf_bm=def',
  });

  try {
    await client.get('/about.json');
    assert.equal(captured.length, 1);
    assert.equal(captured[0].headers['User-Api-Key'], 'user-key');
    assert.equal(captured[0].headers['Cookie'], 'cf_clearance=abc; __cf_bm=def');
  } finally {
    restore();
  }
});

test('HttpClient merges extraHeaders without clobbering Cookie', async () => {
  const captured: { url: string; headers: Record<string, string> }[] = [];
  const restore = mockFetchCapture(captured);
  const logger = new Logger('silent');
  const client = new HttpClient({
    baseUrl: 'https://example.com',
    timeoutMs: 5000,
    logger,
    auth: { type: 'none' },
    cookie: 'cf_clearance=abc',
    extraHeaders: { 'X-Custom-Bypass': '1', Cookie: 'should-not-override' },
  });

  try {
    await client.get('/about.json');
    assert.equal(captured[0].headers['Cookie'], 'cf_clearance=abc');
    assert.equal(captured[0].headers['X-Custom-Bypass'], '1');
  } finally {
    restore();
  }
});

test('SiteState propagates cookie and extra_headers from auth_pairs override', async () => {
  const captured: { url: string; headers: Record<string, string> }[] = [];
  const restore = mockFetchCapture(captured);
  const logger = new Logger('silent');
  const siteState = new SiteState({
    logger,
    timeoutMs: 5000,
    defaultAuth: { type: 'none' },
    authOverrides: [
      {
        site: 'https://example.com',
        user_api_key: 'user-key',
        cookie: 'cf_clearance=from-profile',
        extra_headers: { 'X-From-Profile': 'yes' },
      },
    ],
  });

  try {
    const { client } = siteState.buildClientForSite('https://example.com/');
    await client.get('/about.json');
    assert.equal(captured[0].headers['User-Api-Key'], 'user-key');
    assert.equal(captured[0].headers['Cookie'], 'cf_clearance=from-profile');
    assert.equal(captured[0].headers['X-From-Profile'], 'yes');
  } finally {
    restore();
  }
});

test('redactSecrets hides Cookie header and cookie profile fields', () => {
  const redacted = redactSecrets(
    'Cookie: cf_clearance=secret-value {"cookie": "cf_clearance=secret-value", "extra_headers": {"X-A": "1"}}',
  );
  assert.ok(!redacted.includes('cf_clearance=secret-value'));
  assert.ok(redacted.includes('Cookie: <redacted>'));
  assert.ok(redacted.includes('"cookie": "<redacted>"'));
  assert.ok(redacted.includes('"extra_headers": "<redacted>"'));
});

test('SiteState re-reads cookie_file per request without rebuilding the client', async () => {
  const captured: { url: string; headers: Record<string, string> }[] = [];
  const restore = mockFetchCapture(captured);
  const logger = new Logger('silent');
  const dir = mkdtempSync(join(tmpdir(), 'discourse-mcp-cookie-'));
  const cookieFile = join(dir, 'cookie.txt');
  writeFileSync(cookieFile, 'cf_clearance=first');
  const siteState = new SiteState({
    logger,
    timeoutMs: 5000,
    defaultAuth: { type: 'none' },
    authOverrides: [{ site: 'https://example.com', cookie_file: cookieFile }],
  });

  try {
    const { client } = siteState.buildClientForSite('https://example.com/');
    await client.get('/about.json');
    assert.equal(captured[0].headers['Cookie'], 'cf_clearance=first');

    // Rotate the credential externally; the cached client must pick it up.
    writeFileSync(cookieFile, 'cf_clearance=second');
    const later = new Date(Date.now() + 5000);
    utimesSync(cookieFile, later, later);
    await client.get('/about.json');
    assert.equal(captured[1].headers['Cookie'], 'cf_clearance=second');
  } finally {
    restore();
  }
});

test('SiteState prefers a readable cookie_file over inline cookie, falls back when missing', async () => {
  const captured: { url: string; headers: Record<string, string> }[] = [];
  const restore = mockFetchCapture(captured);
  const logger = new Logger('silent');
  const dir = mkdtempSync(join(tmpdir(), 'discourse-mcp-cookie-'));
  const cookieFile = join(dir, 'cookie.txt');
  writeFileSync(cookieFile, 'cf_clearance=from-file');
  const siteState = new SiteState({
    logger,
    timeoutMs: 5000,
    defaultAuth: { type: 'none' },
    authOverrides: [
      {
        site: 'https://example.com',
        cookie: 'cf_clearance=inline',
        cookie_file: cookieFile,
      },
      {
        site: 'https://other.example.com',
        cookie: 'cf_clearance=inline-only',
        cookie_file: join(dir, 'does-not-exist.txt'),
      },
    ],
  });

  try {
    const { client } = siteState.buildClientForSite('https://example.com/');
    await client.get('/about.json');
    assert.equal(captured[0].headers['Cookie'], 'cf_clearance=from-file');

    const { client: other } = siteState.buildClientForSite('https://other.example.com/');
    await other.get('/about.json');
    assert.equal(captured[1].headers['Cookie'], 'cf_clearance=inline-only');
  } finally {
    restore();
  }
});

test('SiteState.hasCookieAuth reflects inline and file-backed configuration', () => {
  const logger = new Logger('silent');
  const siteState = new SiteState({
    logger,
    timeoutMs: 5000,
    defaultAuth: { type: 'none' },
    authOverrides: [
      { site: 'https://with-inline.example.com', cookie: 'cf_clearance=x' },
      { site: 'https://with-file.example.com', cookie_file: '/tmp/cookie.txt' },
      { site: 'https://bare.example.com', user_api_key: 'k' },
    ],
  });

  assert.equal(siteState.hasCookieAuth('https://with-inline.example.com/'), true);
  assert.equal(siteState.hasCookieAuth('https://with-file.example.com/'), true);
  assert.equal(siteState.hasCookieAuth('https://bare.example.com/'), false);
  assert.equal(siteState.hasCookieAuth('https://unknown.example.com/'), false);
  assert.equal(siteState.hasCookieAuth(), false);
});

test('wafCookieExpiredDetails flags 403 only when a cookie is configured', () => {
  const forbidden = new HttpError(403, 'HTTP 403 Forbidden');
  const details = wafCookieExpiredDetails(forbidden, true);
  assert.ok(details);
  assert.equal(details.code, WAF_COOKIE_EXPIRED_CODE);
  assert.match(String(details.action), /refresh/i);

  assert.equal(wafCookieExpiredDetails(forbidden, false), undefined);
  assert.equal(wafCookieExpiredDetails(new HttpError(404, 'HTTP 404'), true), undefined);
  assert.equal(wafCookieExpiredDetails(new Error('boom'), true), undefined);
});
