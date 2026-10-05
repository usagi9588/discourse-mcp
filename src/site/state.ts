import { readFileSync, statSync } from "node:fs";
import type { Logger } from "../util/logger.js";
import { HttpClient, type AuthMode } from "../http/client.js";
import { expandCurrentUserHome } from "../util/cli.js";

export type AuthOverride = {
  site: string; // base URL or origin to match
  api_key?: string;
  api_username?: string;
  user_api_key?: string;
  user_api_client_id?: string;
  http_basic_user?: string;
  http_basic_pass?: string;
  /** Raw Cookie header value for sites behind a WAF (e.g. Cloudflare cf_clearance). */
  cookie?: string;
  /**
   * Path to a file holding the raw Cookie header value. Re-read before every
   * request (keyed on mtime), so an external refresher can rotate an expiring
   * WAF credential without restarting this process. A readable non-empty file
   * takes precedence over inline `cookie`; otherwise the inline value applies.
   * A leading `~` expands to the current user's home directory.
   */
  cookie_file?: string;
  /** Persistent custom headers merged into every request for the matched site. */
  extra_headers?: Record<string, string>;
  /**
   * Request emission profile. `"stdlib"` sends conservative stdlib-like requests
   * (restricted cipher list, capitalized `Host` right after `Accept-Encoding`,
   * `Connection: close`, no fetch auto headers, no redirects, no multipart) for
   * sites whose WAF fingerprints HTTP stacks. Omit for the default fetch path.
   */
  http_profile?: "stdlib";
};

function normalizeBase(url: string): string {
  const u = new URL(url);
  u.search = "";
  u.hash = "";
  if (u.pathname !== "/") {
    u.pathname = u.pathname.replace(/\/+$/, "");
  }
  return u.toString().replace(/\/$/, "");
}

export class SiteState {
  private currentSiteBase?: string;
  private currentClient?: HttpClient;
  private readonly clientCache = new Map<string, HttpClient>();

  constructor(
    private opts: {
      logger: Logger;
      timeoutMs: number;
      defaultAuth: AuthMode;
      authOverrides?: AuthOverride[];
    }
  ) {}

  getSiteBase(): string | undefined {
    return this.currentSiteBase;
  }

  ensureSelectedSite(): { base: string; client: HttpClient } {
    if (!this.currentSiteBase || !this.currentClient) {
      throw new Error("No site selected. Call discourse_select_site first.");
    }
    return { base: this.currentSiteBase, client: this.currentClient };
  }

  /**
   * Get the auth type for the current site (or a specific site URL).
   * Returns "api_key", "user_api_key", or "none".
   */
  getAuthType(siteUrl?: string): "api_key" | "user_api_key" | "none" {
    const base = siteUrl ? normalizeBase(siteUrl) : this.currentSiteBase;
    if (!base) return "none";
    const match = this.findAuthOverride(base);
    const auth = this.resolveAuthFromOverride(match);
    return auth.type;
  }

  buildClientForSite(siteUrl: string): { base: string; client: HttpClient } {
    const base = normalizeBase(siteUrl);
    const cached = this.clientCache.get(base);
    if (cached) return { base, client: cached };

    const match = this.findAuthOverride(base);
    const auth = this.resolveAuthFromOverride(match);
    const httpBasicAuth = match?.http_basic_user && match?.http_basic_pass
      ? { user: match.http_basic_user, pass: match.http_basic_pass }
      : undefined;
    const client = new HttpClient({
      baseUrl: base,
      timeoutMs: this.opts.timeoutMs,
      logger: this.opts.logger,
      auth,
      httpBasicAuth,
      ...(match?.cookie ? { cookie: match.cookie } : {}),
      ...(match?.cookie_file ? { cookieProvider: this.buildCookieProvider(match.cookie_file) } : {}),
      ...(match?.http_profile === "stdlib" ? { httpProfile: "stdlib" as const } : {}),
      ...(match?.extra_headers ? { extraHeaders: match.extra_headers } : {}),
    });
    this.clientCache.set(base, client);
    return { base, client };
  }

  selectSite(siteUrl: string): { base: string; client: HttpClient } {
    const { base, client } = this.buildClientForSite(siteUrl);
    this.currentSiteBase = base;
    this.currentClient = client;
    return { base, client };
  }

  /** Whether any WAF cookie (inline or file-backed) is configured for a site. */
  hasCookieAuth(siteUrl?: string): boolean {
    const base = siteUrl ? normalizeBase(siteUrl) : this.currentSiteBase;
    if (!base) return false;
    const match = this.findAuthOverride(base);
    return Boolean(match?.cookie || match?.cookie_file);
  }

  /**
   * Build a per-request cookie reader for a refreshable credential file.
   * Content is cached and re-read only when the file's mtime changes, so the
   * steady-state cost is one local stat per request. Unreadable or empty files
   * yield `undefined` so the caller falls back to the inline `cookie` value.
   */
  private buildCookieProvider(rawPath: string): () => string | undefined {
    const path = expandCurrentUserHome(rawPath);
    let cachedMtimeMs = -1;
    let cachedValue: string | undefined;
    return () => {
      let mtimeMs: number;
      try {
        mtimeMs = statSync(path).mtimeMs;
      } catch (e: any) {
        this.opts.logger.debug(`WAF cookie file unreadable (${path}): ${e?.message || String(e)}`);
        return undefined;
      }
      if (mtimeMs === cachedMtimeMs) return cachedValue;
      let text: string;
      try {
        text = readFileSync(path, "utf8").trim();
      } catch (e: any) {
        this.opts.logger.debug(`WAF cookie file re-read failed (${path}): ${e?.message || String(e)}`);
        return undefined;
      }
      cachedMtimeMs = mtimeMs;
      cachedValue = text || undefined;
      if (cachedValue) this.opts.logger.debug(`WAF cookie file reloaded (${path}, ${cachedValue.length} chars)`);
      return cachedValue;
    };
  }

  private findAuthOverride(base: string): AuthOverride | undefined {
    const overrides = this.opts.authOverrides || [];
    return overrides.find((o) => normalizeBase(o.site) === base || this.sameOrigin(o.site, base));
  }

  private resolveAuthFromOverride(match: AuthOverride | undefined): AuthMode {
    if (match) {
      // Prefer user_api_key if provided
      if (match.user_api_key) return { type: "user_api_key", key: match.user_api_key, client_id: match.user_api_client_id };
      if (match.api_key) return { type: "api_key", key: match.api_key, username: match.api_username };
    }
    return this.opts.defaultAuth;
  }

  private sameOrigin(a: string, b: string): boolean {
    try {
      const ua = new URL(a);
      const ub = new URL(b);
      return ua.protocol === ub.protocol && ua.host === ub.host;
    } catch {
      return false;
    }
  }

}

export type SiteStateInit = ConstructorParameters<typeof SiteState>[0];
