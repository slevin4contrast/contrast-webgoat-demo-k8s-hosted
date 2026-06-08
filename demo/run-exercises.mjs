#!/usr/bin/env node
//
// Functional exercise driver for the WebGoat IAST demo.
//
// Registers a fresh WebGoat user, then exercises a set of routes with NORMAL, benign
// input -- the way QA or a click-through would. Because Contrast instruments the code,
// it reports the vulnerable routes the moment their code path runs; it does not need
// an attack payload. Safe (parameterized) routes produce no finding, and the simulated
// WebGoat lessons produce no finding either (that's the false-positive story).
//
// Uses Playwright's request API (a Node HTTP client), so NO browser binaries are
// needed -- just `npm install`. Keep the Contrast UI open on screen while it runs.
//
// Usage:
//   npm install
//   node run-exercises.mjs                 # exercise the routes for real
//   node run-exercises.mjs --dry-run       # print the plan, send nothing
//
// Config via env:
//   BASE_URL   default http://localhost:8080   (WebGoat runs at root context "/")
//   DELAY_MS   default 2500   (pause between routes so findings appear one by one)
//   USERNAME   default contrast-demo-<timestamp>
//   PASSWORD   default password

import { exercises } from "./exercises.mjs";

// Playwright is imported lazily inside main() so that `--dry-run` works with no
// dependencies installed (handy for validating the plan before npm install).

const BASE_URL = (process.env.BASE_URL || "http://localhost:8080").replace(/\/$/, "");
const DELAY_MS = Number(process.env.DELAY_MS || 2500);
const USERNAME = process.env.USERNAME || `contrast-demo-${Date.now()}`;
const PASSWORD = process.env.PASSWORD || "password";
const DRY_RUN = process.argv.includes("--dry-run");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const line = () => console.log("-".repeat(72));

const TAG = {
  VULNERABLE: "[VULNERABLE]",
  SAFE: "[SAFE]      ",
  SIMULATED: "[SIMULATED] ",
};

function banner() {
  line();
  console.log("  Contrast + WebGoat - functional exercise run");
  console.log(`  Target : ${BASE_URL}`);
  console.log(`  User   : ${USERNAME}`);
  console.log(`  Pacing : ${DELAY_MS}ms between routes`);
  if (DRY_RUN) console.log("  MODE   : DRY RUN (no requests sent)");
  line();
}

function printPlan() {
  exercises.forEach((e, i) => {
    console.log(`${String(i + 1).padStart(2)}. ${TAG[e.category]} ${e.method} ${e.path}`);
    console.log(`      ${e.label}`);
    console.log(`      input  -> ${e.input}`);
    console.log(`      expect -> ${e.expect}`);
  });
}

async function register(ctx) {
  // CSRF is disabled in WebGoat, and register.mvc auto-logs-in the new user.
  // We stop at the 302 (maxRedirects:0) so Playwright captures the Set-Cookie
  // from the redirect response; following it can drop the session cookie.
  const res = await ctx.post(`${BASE_URL}/register.mvc`, {
    form: {
      username: USERNAME,
      password: PASSWORD,
      matchingPassword: PASSWORD,
      agree: "agree",
    },
    maxRedirects: 0,
  });
  if (res.status() >= 400) {
    throw new Error(`Registration failed: HTTP ${res.status()} ${res.url()}`);
  }
}

async function verifyAuth(ctx) {
  const res = await ctx.get(`${BASE_URL}/service/lessonmenu.mvc`);
  if (res.status() !== 200 || res.url().includes("/login")) {
    throw new Error(`Not authenticated (HTTP ${res.status()}, url ${res.url()})`);
  }
}

async function exercise(ctx, e) {
  const url = `${BASE_URL}${e.path}`;
  const opts = { method: e.method };
  if (e.params) opts.params = e.params;
  if (e.form) opts.form = e.form;
  if (e.body !== undefined) {
    opts.data = e.body;
    opts.headers = { "content-type": e.contentType || "application/json" };
  }
  return ctx.fetch(url, opts);
}

async function main() {
  banner();
  printPlan();
  line();

  if (DRY_RUN) {
    console.log("Dry run complete. No requests were sent.");
    return;
  }

  const { request } = await import("playwright");
  const ctx = await request.newContext({ ignoreHTTPSErrors: true });
  try {
    process.stdout.write("Registering + logging in... ");
    await register(ctx);
    await verifyAuth(ctx);
    console.log("ok\n");

    const counts = { VULNERABLE: 0, SAFE: 0, SIMULATED: 0 };
    for (const e of exercises) {
      console.log(`${TAG[e.category]} ${e.label}`);
      console.log(`             -> ${e.method} ${e.path}  (${e.input})`);
      try {
        const res = await exercise(ctx, e);
        console.log(`             <- HTTP ${res.status()}  | ${e.expect}`);
        counts[e.category]++;
      } catch (err) {
        console.log(`             !! request error: ${err.message}`);
      }
      console.log("");
      await sleep(DELAY_MS);
    }

    line();
    console.log(
      `Done. Exercised ${counts.VULNERABLE} vulnerable, ${counts.SAFE} safe, ` +
        `${counts.SIMULATED} simulated routes.`
    );
    console.log("In the Contrast UI you should now see findings for the VULNERABLE");
    console.log("routes and nothing for the SAFE or SIMULATED ones -- found through");
    console.log("ordinary functional use, with no attack payloads. That's IAST.");
    line();
  } finally {
    await ctx.dispose();
  }
}

main().catch((e) => {
  console.error("\nFATAL:", e.message);
  process.exit(1);
});
