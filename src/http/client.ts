import { Logger } from "../util/logger.js";
import http from "node:http";
import https from "node:https";

export type AuthMode =
  | { type: "none" }
  | { type: "api_key"; key: string; username?: string }
  | { type: "user_api_key"; key: string; client_id?: string };

/**
 * Request emission profile.
 * - `"fetch"` (default): undici-backed global fetch.
 * - `"stdlib"`: conservative `node:http(s)` requests that mirror a standard-library
 *   client (Python urllib/curl over HTTP/1.1): a minimal OpenSSL-style cipher list,
 *   capitalized `Host` immediately after `Accept-Encoding: identity`, custom headers
 *   in configuration order, and `Connection: close`. No redirect following and no
 *   multipart support. Opt in per site behind a WAF that fingerprints HTTP stacks.
 */
export type HttpRequestProfile = "fetch" | "stdlib";

/**
 * Minimal OpenSSL-style cipher list (Python 3.14 ssl defaults order). Some WAFs
 * challenge Node's default 50+ cipher ClientHello even with a valid clearance
 * cookie; this list is accepted alongside matching conservative headers.
 */
export const STDLIB_CIPHERS = [
  "TLS_AES_256_GCM_SHA384",
  "TLS_CHACHA20_POLY1305_SHA256",
  "TLS_AES_128_GCM_SHA256",
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-AES128-GCM-SHA256",
  "ECDHE-RSA-AES128-GCM-SHA256",
  "ECDHE-ECDSA-CHACHA20-POLY1305",
  "ECDHE-RSA-CHACHA20-POLY1305",
  "ECDHE-ECDSA-AES256-SHA384",
  "ECDHE-RSA-AES256-SHA384",
  "ECDHE-ECDSA-AES128-SHA256",
  "ECDHE-RSA-AES128-SHA256",
  "DHE-RSA-AES256-GCM-SHA384",
  "DHE-RSA-AES128-GCM-SHA256",
  "DHE-RSA-AES256-SHA256",
  "DHE-RSA-AES128-SHA256",
].join(":");

export interface HttpClientOptions {
  baseUrl: string;
  timeoutMs: number;
  logger: Logger;
  auth: AuthMode;
  httpBasicAuth?: { user: string; pass: string };
  /** Raw Cookie header value (e.g. "cf_clearance=...; __cf_bm=...") for WAF bypass. */
  cookie?: string;
  /**
   * Fresh Cookie header value resolved on every request. A non-empty result
   * wins over the static `cookie`; an empty result falls back to it. Used for
   * expiring WAF credentials kept in a refreshable file (see `cookie_file`).
   */
  cookieProvider?: () => string | undefined;
  /** Persistent custom headers merged into every request (e.g. Cloudflare bypass). */
  extraHeaders?: Record<string, string>;
  /** Request emission profile; `"stdlib"` mirrors a conservative stdlib client. */
  httpProfile?: HttpRequestProfile;
}

export class HttpError extends Error {
  constructor(public status: number, message: string, public body?: unknown) {
    super(message);
    this.name = "HttpError";
  }
}

export class HttpClient {
  private base: URL;
  private userAgent = "Discourse-MCP/0.x (+https://github.com/discourse/discourse-mcp)";
  private cache = new Map<string, { value: any; expiresAt: number }>();

  constructor(private opts: HttpClientOptions) {
    this.base = new URL(opts.baseUrl);
    if (!this.base.pathname.endsWith("/")) {
      this.base.pathname += "/";
    }
  }

  private urlFor(path: string): string {
    if (/^https?:\/\//i.test(path)) {
      return new URL(path).toString();
    }

    const relativePath = path.replace(/^\/+/, "");
    return new URL(relativePath, this.base).toString();
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = {
      "User-Agent": this.userAgent,
      "Accept": "application/json",
    };
    if (this.opts.auth.type === "api_key") {
      h["Api-Key"] = this.opts.auth.key;
      if (this.opts.auth.username) h["Api-Username"] = this.opts.auth.username;
    } else if (this.opts.auth.type === "user_api_key") {
      h["User-Api-Key"] = this.opts.auth.key;
      if (this.opts.auth.client_id) h["User-Api-Client-Id"] = this.opts.auth.client_id;
    }
    if (this.opts.httpBasicAuth) {
      const { user, pass } = this.opts.httpBasicAuth;
      const encoded = Buffer.from(`${user}:${pass}`).toString("base64");
      h["Authorization"] = `Basic ${encoded}`;
    }
    const provided = this.opts.cookieProvider?.();
    const cookie = provided ? provided : this.opts.cookie;
    if (cookie) {
      h["Cookie"] = cookie;
    }
    if (this.opts.extraHeaders) {
      for (const [key, value] of Object.entries(this.opts.extraHeaders)) {
        if (key.toLowerCase() === "cookie" && h["Cookie"]) continue;
        h[key] = value;
      }
    }
    return h;
  }

  async get(path: string, { signal, headers }: { signal?: AbortSignal, headers?: Record<string, string>} = {}) {
    return this.request("GET", path, undefined, { signal, extraHeaders: headers });
  }

  async getCached(path: string, ttlMs: number, { signal }: { signal?: AbortSignal } = {}) {
    const url = this.urlFor(path);
    const entry = this.cache.get(url);
    const now = Date.now();
    if (entry && entry.expiresAt > now) return entry.value;
    const value = await this.request("GET", path, undefined, { signal });
    this.cache.set(url, { value, expiresAt: now + ttlMs });
    return value;
  }

  async post(path: string, body: unknown, { signal, headers }: { signal?: AbortSignal, headers?: Record<string, string>} = {}) {
    return this.request("POST", path, body, { signal, extraHeaders: headers});
  }

  /** Send a non-idempotent JSON POST exactly once. */
  async postNoRetry(path: string, body: unknown, { signal, headers }: { signal?: AbortSignal, headers?: Record<string, string>} = {}) {
    return this.request("POST", path, body, { signal, extraHeaders: headers, allowRetries: false });
  }

  async delete(path: string, body?: unknown, { signal, headers }: { signal?: AbortSignal, headers?: Record<string, string>} = {}) {
    return this.request("DELETE", path, body, { signal, extraHeaders: headers });
  }

  /** Send a destructive JSON DELETE exactly once. */
  async deleteNoRetry(path: string, body?: unknown, { signal, headers }: { signal?: AbortSignal, headers?: Record<string, string>} = {}) {
    return this.request("DELETE", path, body, { signal, extraHeaders: headers, allowRetries: false });
  }

  async put(path: string, body: unknown, { signal, headers }: { signal?: AbortSignal, headers?: Record<string, string>} = {}) {
    return this.request("PUT", path, body, { signal, extraHeaders: headers });
  }

  /** Send a non-idempotent JSON PUT exactly once. */
  async putNoRetry(path: string, body: unknown, { signal, headers }: { signal?: AbortSignal, headers?: Record<string, string>} = {}) {
    return this.request("PUT", path, body, { signal, extraHeaders: headers, allowRetries: false });
  }

  async postMultipart(path: string, formData: FormData, { signal, headers, expectedStatus }: { signal?: AbortSignal, headers?: Record<string, string>, expectedStatus?: number } = {}) {
    if (this.opts.httpProfile === "stdlib") {
      throw new Error("http_profile 'stdlib' does not support multipart uploads");
    }
    return this.requestMultipart("POST", path, formData, { signal, extraHeaders: headers, expectedStatus });
  }

  private async request(method: string, path: string, body?: unknown, { signal, extraHeaders, allowRetries = true }: { signal?: AbortSignal, extraHeaders?: Record<string, string>, allowRetries?: boolean } = {}) {
    if (this.opts.httpProfile === "stdlib") {
      return this.executeStdlib(method, path, body, { signal, extraHeaders, allowRetries });
    }
    const headers = this.headers();
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    if (extraHeaders) {
      Object.assign(headers, extraHeaders);
    }
    return this.executeRequest(method, path, body !== undefined ? JSON.stringify(body) : undefined, headers, signal, allowRetries);
  }

  /**
   * Conservative stdlib-profile request over node:http(s). Emits headers in a
   * fixed urllib-like order (Accept-Encoding, explicit Host, configured headers,
   * Connection: close appended by the transport) with a minimal cipher list, and
   * never adds fetch-style auto headers (sec-fetch-mode, keep-alive). Used only
   * when `httpProfile` is `"stdlib"`; error semantics match the fetch path so
   * upstream 403s still surface as HttpError for WAF-expiry detection.
   */
  private async executeStdlib(
    method: string,
    path: string,
    body: unknown,
    { signal, extraHeaders, allowRetries = true }: { signal?: AbortSignal, extraHeaders?: Record<string, string>, allowRetries?: boolean } = {},
  ): Promise<any> {
    const url = this.urlFor(path);
    const parsed = new URL(url);
    const bodyText = body !== undefined ? JSON.stringify(body) : undefined;
    const base = this.headers();
    if (extraHeaders) {
      Object.assign(base, extraHeaders);
    }
    const hasEncoding = Object.keys(base).some((k) => k.toLowerCase() === "accept-encoding");
    const ordered: Record<string, string> = {};
    if (!hasEncoding) {
      ordered["Accept-Encoding"] = "identity";
    }
    ordered["Host"] = parsed.host;
    for (const [key, value] of Object.entries(base)) {
      if (key.toLowerCase() === "host") continue;
      ordered[key] = value;
    }
    if (bodyText !== undefined) {
      ordered["Content-Type"] = "application/json";
      ordered["Content-Length"] = String(Buffer.byteLength(bodyText));
    }

    this.opts.logger.debug(`HTTP ${method} ${url}`);
    const requestFn = (parsed.protocol === "http:" ? http.request : https.request) as typeof https.request;
    const nodeOptions: https.RequestOptions & { ALPNProtocols?: string[] } = {
      method,
      headers: ordered,
      agent: false,
      ciphers: STDLIB_CIPHERS,
      ALPNProtocols: ["http/1.1"],
    };
    const attempt = () =>
      new Promise<any>((resolve, reject) => {
        const req = requestFn(
          url,
          nodeOptions,
          (res) => {
            const chunks: Buffer[] = [];
            res.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
            res.on("end", () => {
              const text = Buffer.concat(chunks).toString("utf8");
              const status = res.statusCode ?? 0;
              const statusText = res.statusMessage ?? "";
              this.opts.logger.debug(`HTTP ${method} ${url} -> ${status} ${statusText}`);
              if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
                this.opts.logger.error(`HTTP ${status} ${statusText} for ${method} ${url}`);
                reject(new HttpError(status, `HTTP ${status} ${statusText}`, safeJson(text)));
                return;
              }
              if (status === 204) {
                resolve({});
                return;
              }
              const ct = res.headers["content-type"] || "";
              if (ct.includes("application/json")) {
                try {
                  resolve(JSON.parse(text));
                } catch (e: any) {
                  reject(new Error(`Invalid JSON for ${method} ${url}: ${e?.message || String(e)}`));
                }
                return;
              }
              resolve(text);
            });
          },
        );
        const onAbort = () => {
          req.destroy(new Error(`Request timeout after ${this.opts.timeoutMs}ms for ${method} ${url}`));
        };
        if (signal) {
          if (signal.aborted) {
            onAbort();
          } else {
            signal.addEventListener("abort", onAbort, { once: true });
          }
        }
        req.setTimeout(this.opts.timeoutMs, () => {
          req.destroy(new Error(`Request timeout after ${this.opts.timeoutMs}ms for ${method} ${url}`));
        });
        req.on("error", (e: any) => {
          if (e instanceof HttpError) {
            reject(e);
          } else if (e?.message?.startsWith("Request timeout after")) {
            this.opts.logger.error(e.message);
            reject(e);
          } else {
            reject(new Error(`Network error for ${method} ${url}: ${e?.message || String(e)}`));
          }
        });
        req.on("close", () => {
          signal?.removeEventListener("abort", onAbort);
        });
        if (bodyText !== undefined) {
          req.write(bodyText);
        }
        req.end();
      });

    const maxRetries = allowRetries ? 3 : 1;
    return withRetries(attempt, this.opts.logger, url, method, maxRetries);
  }

  private async requestMultipart(method: string, path: string, formData: FormData, { signal, extraHeaders, expectedStatus }: { signal?: AbortSignal, extraHeaders?: Record<string, string>, expectedStatus?: number } = {}) {
    const headers = this.headers();
    if (extraHeaders) {
      Object.assign(headers, extraHeaders);
    }
    // Do NOT set Content-Type - let fetch set it with the multipart boundary
    // Delete after merging extraHeaders to prevent overrides breaking the boundary
    delete headers["Content-Type"];
    // Disable retries for multipart - FormData body is consumed after first attempt
    return this.executeRequest(method, path, formData, headers, signal, /* allowRetries */ false, expectedStatus);
  }

  private async executeRequest(method: string, path: string, body: BodyInit | undefined, headers: Record<string, string>, signal?: AbortSignal, allowRetries = true, expectedStatus?: number) {
    const url = this.urlFor(path);
    this.opts.logger.debug(`HTTP ${method} ${url}`);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.opts.timeoutMs);
    const combinedSignal = mergeSignals([signal, controller.signal]);

    const attempt = async () => {
      try {
        const res = await fetch(url, {
          method,
          headers,
          body,
          signal: combinedSignal,
        });

        this.opts.logger.debug(`HTTP ${method} ${url} -> ${res.status} ${res.statusText}`);

        if (expectedStatus !== undefined && res.status !== expectedStatus) {
          const text = await safeText(res);
          throw new HttpError(res.status, `Expected HTTP ${expectedStatus}, received ${res.status} ${res.statusText}`, safeJson(text));
        }
        if (!res.ok) {
          const text = await safeText(res);
          const errorBody = safeJson(text);
          // Keep response bodies available on HttpError for structured client
          // errors, but never write them to logs: admin endpoints can echo
          // prompts, scripts, bindings, import bundles, or test parameters.
          this.opts.logger.error(`HTTP ${res.status} ${res.statusText} for ${method} ${url}`);
          throw new HttpError(res.status, `HTTP ${res.status} ${res.statusText}`, errorBody);
        }
        if (res.status === 204) return {};
        const ct = res.headers.get("content-type") || "";
        if (ct.includes("application/json")) {
          return res.json();
        } else {
          return res.text();
        }
      } catch (e: any) {
        if (e instanceof HttpError) {
          throw e;
        }

        if (e.name === "AbortError") {
          const timeoutMsg = `Request timeout after ${this.opts.timeoutMs}ms for ${method} ${url}`;
          this.opts.logger.error(timeoutMsg);
          throw new Error(timeoutMsg);
        }

        if (e.name === "TypeError" && e.message === "fetch failed") {
          const detailedMsg = `Network error for ${method} ${url}: ${e.message}. Possible causes: DNS resolution failure, network connectivity issue, SSL/TLS error, or server unreachable.`;
          this.opts.logger.error(detailedMsg);
          if (e.cause) {
            this.opts.logger.error(`Underlying cause: ${String(e.cause)}`);
          }
          throw new Error(detailedMsg);
        }

        const genericMsg = `Fetch error for ${method} ${url}: ${e.name}: ${e.message}`;
        this.opts.logger.error(genericMsg);
        if (e.cause) {
          this.opts.logger.error(`Cause: ${String(e.cause)}`);
        }
        if (e.stack) {
          this.opts.logger.debug(`Stack: ${e.stack}`);
        }
        throw new Error(`${e.name}: ${e.message}`);
      }
    };

    try {
      // Disable retries when allowRetries is false (e.g., for multipart where body is consumed)
      const maxRetries = allowRetries ? 3 : 1;
      return await withRetries(attempt, this.opts.logger, url, method, maxRetries);
    } finally {
      clearTimeout(timeout);
    }
  }
}

async function withRetries<T>(fn: () => Promise<T>, logger: Logger, url: string, method: string, retries = 3): Promise<T> {
  let attempt = 0;
  let delay = 250;
  for (;;) {
    try {
      return await fn();
    } catch (e: any) {
      const status = e?.status as number | undefined;
      if (attempt < retries - 1 && (status === 429 || (status && status >= 500))) {
        attempt++;
        logger.info(`Retrying ${method} ${url} (attempt ${attempt}/${retries - 1}) after ${delay}ms due to ${status || 'error'}`);
        await new Promise((r) => setTimeout(r, delay));
        delay *= 2;
        continue;
      }
      // Log final failure
      if (attempt > 0) {
        logger.error(`Request failed after ${attempt + 1} attempts: ${method} ${url}`);
      }
      throw e;
    }
  }
}

function mergeSignals(signals: Array<AbortSignal | undefined>): AbortSignal {
  const controller = new AbortController();
  for (const s of signals) {
    if (!s) continue;
    if (s.aborted) {
      controller.abort();
      break;
    }
    s.addEventListener("abort", () => controller.abort(), { once: true });
  }
  return controller.signal;
}

async function safeText(res: Response): Promise<string> {
  try {
    return await res.text();
  } catch {
    return "";
  }
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}
