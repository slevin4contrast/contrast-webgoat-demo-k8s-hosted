#!/usr/bin/env node
//
// SmartFix preflight: validate your Contrast credentials and app id locally before you
// wire them into GitHub, so a bad value surfaces here instead of in a failed Action run.
//
// It reads values from your environment or .env and makes read-only Contrast API calls.
// It NEVER prints secret values (only whether they are set, and their length).
//
// Reads (same names SmartFix uses, with friendly fallbacks):
//   CONTRAST_HOST                e.g. https://eval.contrastsecurity.com  (or derived from token)
//   CONTRAST_ORG_ID              org UUID                                (or derived from token)
//   CONTRAST_APP_ID              the WebGoat application UUID
//   CONTRAST_AUTHORIZATION_KEY   base64 of "email:service-key"  (CONTRAST_AUTH_HEADER also accepted)
//   CONTRAST_API_KEY             organization API key
//   CONTRAST_APP_NAME            optional; used to look up the app id if CONTRAST_APP_ID is unset
//   CONTRAST_TOKEN               optional; used only to derive host/org if not set explicitly
//
// Usage:
//   node scripts/smartfix-preflight.mjs

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_APP_NAME = "WebGoat IAST/ADR Demo";

function loadEnv() {
  try {
    for (const raw of readFileSync(join(ROOT, ".env"), "utf8").split("\n")) {
      const l = raw.trim();
      if (!l || l.startsWith("#")) continue;
      const i = l.indexOf("=");
      if (i < 0) continue;
      const k = l.slice(0, i).trim();
      const v = l.slice(i + 1).trim().replace(/^["']|["']$/g, "");
      if (process.env[k] === undefined) process.env[k] = v;
    }
  } catch { /* no .env */ }
}

function parseToken(token) {
  try {
    const j = JSON.parse(Buffer.from(token, "base64").toString("utf8"));
    let base = (j.url || "").replace(/\/Contrast$/, "").replace("-agents.", ".");
    const m = /agent_([a-f0-9-]+)[@_]/.exec(j.user_name || "");
    return { baseUrl: base, orgId: m ? m[1] : null };
  } catch { return {}; }
}

const set = (v) => (v ? `set (len ${v.length})` : "MISSING");
const PASS = "PASS", FAIL = "FAIL";

async function main() {
  loadEnv();
  const token = process.env.CONTRAST_TOKEN;
  const fromTok = token ? parseToken(token) : {};
  let host = (process.env.CONTRAST_HOST || fromTok.baseUrl || "").replace(/\/+$/, "");
  const org = process.env.CONTRAST_ORG_ID || fromTok.orgId;
  const appId = process.env.CONTRAST_APP_ID;
  const auth = process.env.CONTRAST_AUTHORIZATION_KEY || process.env.CONTRAST_AUTH_HEADER;
  const apiKey = process.env.CONTRAST_API_KEY;
  const appName = process.env.CONTRAST_APP_NAME || DEFAULT_APP_NAME;

  console.log("SmartFix preflight (read-only; secret values are never printed)\n");
  console.log("  CONTRAST_HOST              ", host || "MISSING");
  console.log("  CONTRAST_ORG_ID            ", org || "MISSING");
  console.log("  CONTRAST_APP_ID            ", appId || "(unset -- will look up by name)");
  console.log("  CONTRAST_AUTHORIZATION_KEY ", set(auth));
  console.log("  CONTRAST_API_KEY           ", set(apiKey));
  console.log("");

  if (!host || !org || !auth || !apiKey) {
    console.error(`${FAIL}: missing host, org, authorization key, or API key. Fill them in .env.`);
    process.exit(1);
  }
  if (!host.startsWith("http")) host = "https://" + host;

  const headers = { Authorization: auth, "API-Key": apiKey, Accept: "application/json" };
  const ng = `${host}/Contrast/api/ng/${org}`;
  const results = [];

  // 1) credentials + org access
  let appResolved = appId;
  try {
    const r = await fetch(`${ng}/applications/filter?includeMerged=true`, {
      method: "POST", headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify({ filterText: appId ? "" : appName }),
    });
    if (r.status === 401 || r.status === 403) {
      results.push([FAIL, `credentials rejected (HTTP ${r.status}) -- check the authorization key and API key`]);
      report(results); process.exit(1);
    }
    if (!r.ok) { results.push([FAIL, `application lookup failed (HTTP ${r.status})`]); report(results); process.exit(1); }
    results.push([PASS, "credentials authenticate and the org is reachable"]);
    const data = await r.json();
    const apps = Array.isArray(data) ? data : data.applications || [];
    if (!appId) {
      const matches = apps.map((a) => ({ id: a.app_id || a.appId, name: a.name }));
      if (matches.length === 0) {
        results.push([FAIL, `no application matching "${appName}" -- set CONTRAST_APP_ID explicitly`]);
      } else {
        results.push([PASS, `found ${matches.length} app(s) matching "${appName}":`]);
        matches.forEach((m) => console.log(`        ${m.id}  ${m.name}`));
        appResolved = matches[0].id;
        results.push(["INFO", `use CONTRAST_APP_ID=${appResolved}`]);
      }
    }
  } catch (e) {
    results.push([FAIL, `network/error reaching ${host}: ${e.message}`]);
    report(results); process.exit(1);
  }

  // 2) app id resolves + has Critical/High findings (SmartFix only fixes those)
  if (appResolved) {
    try {
      const r = await fetch(`${ng}/applications/${encodeURIComponent(appResolved)}`, { headers });
      if (r.ok) {
        const d = await r.json();
        const app = d.application || d;
        const tb = app.trace_breakdown || {};
        const crit = tb.criticals ?? "?", high = tb.highs ?? "?";
        results.push([PASS, `app id resolves: "${app.name || appResolved}"`]);
        results.push([
          (crit !== "?" && (crit > 0 || high > 0)) ? PASS : "WARN",
          `Critical: ${crit}, High: ${high}  (SmartFix fixes Critical/High -- run the exercise script if these are 0)`,
        ]);
      } else if (r.status === 404) {
        results.push([FAIL, `app id does not resolve (HTTP 404) -- wrong CONTRAST_APP_ID`]);
      } else {
        results.push([FAIL, `could not read app (HTTP ${r.status})`]);
      }
    } catch (e) {
      results.push([FAIL, `error reading app: ${e.message}`]);
    }
  }

  report(results);
  const failed = results.some(([s]) => s === FAIL);
  console.log("");
  console.log(failed
    ? "Result: FAIL -- fix the items above before wiring into GitHub."
    : "Result: ready. Put these into the WebGoat fork as GitHub variables (HOST/ORG/APP_ID) and secrets (AUTHORIZATION_KEY/API_KEY).");
  process.exit(failed ? 1 : 0);
}

function report(results) {
  console.log("");
  for (const [s, msg] of results) console.log(`  [${s}] ${msg}`);
}

main();
