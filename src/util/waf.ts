import { HttpError } from "../http/client.js";

/** Machine-readable code for an expired WAF-bypass cookie. */
export const WAF_COOKIE_EXPIRED_CODE = "waf_cookie_expired";

/**
 * When an upstream request fails with HTTP 403 on a site that has a WAF cookie
 * configured, the most likely cause is an expired `cf_clearance`-style
 * credential rather than a permission problem. Returns structured details for
 * `jsonError()` so agents can trigger a cookie refresh instead of guessing.
 * Returns `undefined` when the failure is not a cookie-expiry candidate.
 */
export function wafCookieExpiredDetails(
  error: unknown,
  cookieConfigured: boolean,
): Record<string, unknown> | undefined {
  if (!cookieConfigured) return undefined;
  if (error instanceof HttpError && error.status === 403) {
    return {
      code: WAF_COOKIE_EXPIRED_CODE,
      action: "Refresh the WAF cookie file (scripts/refresh-waf-cookie.mjs) and retry; no process restart is needed when cookie_file is used.",
    };
  }
  return undefined;
}
