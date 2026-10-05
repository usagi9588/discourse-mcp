#!/usr/bin/env node
/*
  Refresh a WAF-bypass cookie file for a Discourse site behind Cloudflare.

  Launches a real browser (Playwright), visits the site so Cloudflare issues a
  fresh clearance, then writes the site's cookies as one Cookie header line to
  --out. Point an auth_pairs entry at that file with "cookie_file" and the MCP
  server picks up rotations on the next request without a restart.

  Usage:
    node scripts/refresh-waf-cookie.mjs --site https://forum.example.com --out /path/to/cookie.txt [--headless] [--timeout-ms 90000]

  Requires the `playwright` package and a Chromium build:
    npm i -D playwright && npx playwright install chromium

  If Cloudflare shows an interactive challenge, solve it in the opened browser
  window before the timeout expires. Cookie values are never printed.
*/

import { writeFile, chmod } from "node:fs/promises";

function usageError(message) {
  console.error(`Error: ${message}\n`);
  console.error(
    "Usage: node scripts/refresh-waf-cookie.mjs --site <url> --out <path> [--headless] [--timeout-ms <ms>]",
  );
  process.exit(1);
}

function parseArgs(argv) {
  const out = { headless: false, timeoutMs: 90000 };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--site") out.site = argv[++i];
    else if (arg === "--out") out.out = argv[++i];
    else if (arg === "--timeout-ms") out.timeoutMs = Number(argv[++i]);
    else if (arg === "--headless") out.headless = true;
    else if (arg === "--help" || arg === "-h") {
      console.error(
        "Usage: node scripts/refresh-waf-cookie.mjs --site <url> --out <path> [--headless] [--timeout-ms <ms>]",
      );
      process.exit(0);
    } else usageError(`Unknown argument: ${arg}`);
  }
  if (!out.site) usageError("--site is required");
  if (!out.out) usageError("--out is required");
  if (!Number.isFinite(out.timeoutMs) || out.timeoutMs <= 0) {
    usageError("--timeout-ms must be a positive number");
  }
  try {
    out.site = new URL(out.site).origin;
  } catch {
    usageError(`--site is not a valid URL: ${out.site}`);
  }
  return out;
}

async function loadPlaywright() {
  try {
    return await import("playwright");
  } catch {
    console.error(
      "Error: the `playwright` package is not installed.\n" +
        "Install it with `npm i -D playwright && npx playwright install chromium`,\n" +
        "or run with NODE_PATH pointing at an environment that has it.",
    );
    process.exit(1);
  }
}

async function main() {
  const { site, out, headless, timeoutMs } = parseArgs(process.argv.slice(2));
  const { chromium } = await loadPlaywright();
  const hostname = new URL(site).hostname;

  const browser = await chromium.launch({ headless });
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(site, { waitUntil: "domcontentloaded", timeout: timeoutMs });

    // Poll until the site answers its API through this browser context, which
    // proves the WAF clearance is in place for exactly this fingerprint.
    const deadline = Date.now() + timeoutMs;
    let ok = false;
    while (Date.now() < deadline) {
      const res = await context.request
        .get(`${site}/about.json`, { timeout: 15000 })
        .catch(() => undefined);
      if (res?.ok()) {
        ok = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 3000));
    }
    if (!ok) {
      console.error(
        `Timed out waiting for ${site}/about.json to return 200. ` +
          `If a challenge is showing in the browser window, solve it and re-run.`,
      );
      process.exit(2);
    }

    const cookies = (await context.cookies()).filter((c) => {
      const domain = c.domain.replace(/^\./, "");
      return hostname === domain || hostname.endsWith(`.${domain}`);
    });
    if (cookies.length === 0) {
      console.error(`No cookies for ${hostname}; refusing to write an empty file.`);
      process.exit(2);
    }
    const header = cookies.map((c) => `${c.name}=${c.value}`).join("; ");
    await writeFile(out, `${header}\n`, { mode: 0o600 });
    await chmod(out, 0o600).catch(() => undefined);
    console.error(
      `Wrote ${header.length} chars (${cookies.length} cookies: ${cookies.map((c) => c.name).join(", ")}) to ${out}`,
    );
  } finally {
    await browser.close();
  }
}

main().catch((e) => {
  console.error(`Failed: ${e?.message || String(e)}`);
  process.exit(1);
});
