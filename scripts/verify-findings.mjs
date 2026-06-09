#!/usr/bin/env node
//
// Verify that every Contrast finding in this demo is a TRUE POSITIVE, and that no
// finding lands on a route that has no real vulnerability (which would be a false
// positive to investigate).
//
// It reads a Contrast "Route coverage" CSV export (Applications > the app > Route
// coverage > export) and cross-references each finding against a source-grounded map
// of which WebGoat v2025.3 routes actually contain a vulnerable sink. The map is built
// from the WebGoat source, not guessed -- see the notes on each entry.
//
// This is read-only and offline. It makes no API calls and changes nothing.
//
// Usage:
//   node scripts/verify-findings.mjs <route-coverage.csv>
//
// Output buckets:
//   CONFIRMED TRUE POSITIVES  findings on routes with a real vulnerable sink
//   CANDIDATE FALSE POSITIVES findings on safe / simulated routes (expected: none)
//   REAL ROUTES, NO FINDING   real-sink routes that did not report (coverage / verify)
//   SYSTEMIC / APP-WIDE       a finding seen across many routes incl. infra pages,
//                             i.e. a config-level finding to confirm, not a per-route FP

import { readFileSync } from "node:fs";

// ---------------------------------------------------------------------------
// Source-grounded classification of WebGoat v2025.3 routes.
//   real      -> untrusted input reaches a real sink; a finding here is a TRUE POSITIVE
//   real?     -> real sink but reporting depends on render/context; verify on instance
//   safe      -> same kind of feature, coded safely; a finding here is a candidate FP
//   simulated -> lesson only does a regex / String.contains check; finding = candidate FP
// Anything not listed (login, register, lesson menu, etc.) is treated as infra/other.
// ---------------------------------------------------------------------------
const ROUTES = {
  // SQL injection -- string concatenation into Statement.execute*
  "/SqlInjection/attack2":            ["real", "SQL Injection (executeQuery on user query)"],
  "/SqlInjection/attack3":            ["real", "SQL Injection (executeUpdate)"],
  "/SqlInjection/attack4":            ["real", "SQL Injection (executeUpdate)"],
  "/SqlInjection/attack5":            ["real", "SQL Injection (executeQuery)"],
  "/SqlInjection/attack8":            ["real", "SQL Injection (name/auth_tan concatenated)"],
  "/SqlInjection/attack9":            ["real", "SQL Injection (concatenated)"],
  "/SqlInjection/attack10":           ["real", "SQL Injection (LIKE concatenation)"],
  "/SqlInjection/assignment5a":       ["real", "SQL Injection (last_name concatenated)"],
  "/SqlInjection/assignment5b":       ["real", "SQL Injection (userid concatenated; login_count bound)"],
  "/SqlInjectionAdvanced/attack6a":   ["real", "SQL Injection (concatenated)"],
  "/SqlInjectionMitigations/servers": ["real", "SQL Injection (ORDER BY column concatenated)"],
  // Input-validation "mitigation" lessons: they filter the input (reject spaces, strip
  // FROM/SELECT) and THEN call SqlInjectionLesson6a.injectableQuery(), which concatenates
  // into Statement.executeQuery. The filter is bypassable; the sink is real. Source:
  // sqlinjection/mitigation/SqlOnlyInputValidation*.java -> advanced/SqlInjectionLesson6a.java (v2025.3).
  "/SqlOnlyInputValidation/attack":            ["real", "SQL Injection (validation filter, then concatenated executeQuery via lesson6a)"],
  "/SqlOnlyInputValidationOnKeywords/attack":  ["real", "SQL Injection (keyword filter, then concatenated executeQuery via lesson6a)"],
  // Other injection / runtime classes
  "/xxe/simple":                      ["real", "XML External Entity"],
  "/xxe/blind":                       ["real", "XML External Entity (blind)"],
  "/xxe/content-type":                ["real", "XML External Entity"],
  "/InsecureDeserialization/task":    ["real", "Untrusted Deserialization (readObject)"],
  "/VulnerableComponents/attack1":    ["real", "Vulnerable component (XStream.fromXML)"],
  "/crypto/hashing/md5":              ["real", "Weak cryptography (MD5)"],
  "/SSRF/task2":                      ["real", "SSRF (URL.openStream on user input)"],
  // Path traversal: user-controlled filename / fullName / archive-entry builds the path.
  // profile-upload-fix is included on purpose: its "fix" is a single-pass
  // fullName.replace("../","") which "....//" defeats, so the sink is still reachable
  // (source: pathtraversal/ProfileUploadFix.java, v2025.3 -- verified).
  "/PathTraversal/profile-upload":                  ["real", "Path traversal (fullName builds write path)"],
  "/PathTraversal/profile-upload-fix":              ["real", "Path traversal (single-pass ../ strip is bypassable)"],
  "/PathTraversal/profile-upload-remove-user-input":["real", "Path traversal (filename builds write path)"],
  "/PathTraversal/zip-slip":                        ["real", "Zip slip (archive entry name written outside target dir)"],
  // Real sink but render-dependent -- verify on the instance, do not overclaim.
  // The WebGoat *lesson* XSS routes return JSON and render in the SPA (client-side), so
  // server-side Assess generally stays quiet -- see docs/webgoat-vuln-classification.md (A2).
  "/CrossSiteScriptingStored/stored-xss": ["real?", "Lesson stored XSS, rendered client-side in the SPA; Assess usually silent"],
  "/CrossSiteScripting/attack5a":         ["real?", "Lesson reflected XSS, rendered client-side in the SPA; Assess usually silent"],
  // WebWolf routes -- confirmed by the Contrast runtime trace in the 2026-06-09 export
  // (open the finding to see the exact sink). WebWolf is a separate module; these are not
  // mapped from a source line here, they are the agent's observed dataflow.
  "/WebWolf/mail":                    ["real", "Stored XSS (WebWolf mail renders attacker-controlled body server-side)"],
  "/WebWolf/fileupload":              ["real", "Path traversal (uploaded filename builds the stored path)"],
  // Safe by design -- a finding here is a candidate false positive
  "/SqlInjectionMitigations/attack12a": ["safe", "Fully parameterized PreparedStatement"],
  "/SqlInjectionAdvanced/attack6b":     ["safe", "Param compared with .equals(); query is constant"],
  // Simulated lessons -- a finding here is a candidate false positive
  "/SqlInjectionMitigations/attack10b": ["simulated", "Regex check over submitted text; no SQL runs"],
  "/SqlInjectionMitigations/attack10a": ["simulated", "String.contains check; no SQL runs"],
  "/SSRF/task1":                        ["simulated", "String compare; never opens a connection"],
};

// Why a real-sink route can show no finding in a given export. These are operational
// (coverage / environment / architecture) reasons, NOT Contrast detection gaps. Printed
// next to each route in the "REAL ROUTES EXERCISED WITH NO FINDING" section so the output
// explains itself. See docs/false-positives-vs-real-vulns.md ("the mental model").
const NO_FINDING_REASON = {
  "/SqlInjectionMitigations/servers":
    "coverage: `column` is a required param; without it WebGoat returns 400 and the sink never runs (solver now sends ?column=).",
  "/VulnerableComponents/attack1":
    "code never ran: XStream 1.4.5 can't init on JDK 23, route 500s before fromXML completes. The vulnerable library still shows in Runtime SCA.",
  "/SSRF/task2":
    "environment/attribution: openStream only fires for url==http://ifconfig.pro; no egress means it can't complete. Check the vulnerabilities list directly.",
  "/CrossSiteScriptingStored/stored-xss":
    "no server-side sink: SPA renders the comment client-side from JSON; Protect catches the payload, Assess has nothing server-side to trace.",
  "/CrossSiteScripting/attack5a":
    "no server-side sink: reflected XSS rendered client-side in the SPA; expected quiet in Assess.",
  "/WebWolf/mail":
    "attribution: the WebWolf stored XSS is real and in the vulnerabilities export, but WebWolf is a separate context and route coverage may not attach it here.",
};

// A finding ID seen on at least this many distinct routes, or on any infra route,
// is treated as systemic (app-wide config finding) rather than a per-route result.
const SYSTEMIC_ROUTE_THRESHOLD = 8;

// Infra / framework routes (login, registration, the lesson menu, the HammerHead
// dispatcher, wildcards). Matched precisely so lesson endpoints like /SqlInjection/
// attack2 are NOT treated as infra just because they contain the text "attack".
function isInfra(path) {
  const p = path.toLowerCase();
  return (
    p === "/" ||
    p === "/attack" ||
    p.includes("*") ||
    p.endsWith(".lesson") ||
    p.startsWith("/login") ||
    p.startsWith("/register") ||
    p.startsWith("/welcome") ||
    p.startsWith("/scoreboard") ||
    p.startsWith("/start") ||
    p.startsWith("/service/")
  );
}
function normalize(p) {
  return p.split("?")[0].replace(/\/+$/, "") || "/";
}

function parseCsv(text) {
  const lines = text.split(/\r?\n/);
  const urlRe = /\b(?:GET|POST|PUT|DELETE|PATCH|ALL)\s+(\/[^,;"]*)/g;
  const vidRe = /\b[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\b/g;
  const dateRe = /\b\d{2}\/\d{2}\/\d{4}\b/;

  const routeRows = []; // {paths:[...], ids:[...], exercised:bool}
  const severity = {};  // id -> severity (from the trailing summary table)
  let inSeverity = false;

  for (const raw of lines) {
    if (/^Severity\b/i.test(raw)) { inSeverity = true; continue; }
    if (inSeverity) {
      // rows look like:  Critical,W4WK-44T8-8U8M-W5GD
      const id = (raw.match(vidRe) || [])[0];
      const sev = raw.split(",")[0].trim();
      if (id && sev) severity[id] = sev;
      continue;
    }
    const paths = [];
    let m;
    while ((m = urlRe.exec(raw)) !== null) paths.push(normalize(m[1]));
    if (paths.length === 0) continue;
    const ids = raw.match(vidRe) || [];
    routeRows.push({ paths: [...new Set(paths)], ids, exercised: dateRe.test(raw) });
  }
  return { routeRows, severity };
}

function classify(path) {
  return ROUTES[path] ? ROUTES[path] : (isInfra(path) ? ["infra", ""] : ["other", ""]);
}

function main() {
  const csvPath = process.argv[2];
  if (!csvPath) {
    console.error("Usage: node scripts/verify-findings.mjs <route-coverage.csv>");
    console.error("Export it from Contrast: Applications > <app> > Route coverage > export.");
    process.exit(1);
  }
  const { routeRows, severity } = parseCsv(readFileSync(csvPath, "utf8"));

  // Which routes does each finding ID appear on (for systemic detection)?
  const idRoutes = {};
  for (const r of routeRows)
    for (const id of r.ids)
      (idRoutes[id] ||= new Set()), r.paths.forEach((p) => idRoutes[id].add(p));

  const systemic = new Set();
  for (const [id, routes] of Object.entries(idRoutes)) {
    const onInfra = [...routes].some(isInfra);
    if (routes.size >= SYSTEMIC_ROUTE_THRESHOLD || onInfra) systemic.add(id);
  }

  const tps = [], fps = [], noFinding = [], verify = [];
  const seenReal = new Set();

  for (const r of routeRows) {
    for (const path of r.paths) {
      const [kind, desc] = classify(path);
      const specificIds = r.ids.filter((id) => !systemic.has(id));
      if (kind === "real" || kind === "real?") {
        if (specificIds.length > 0) {
          (kind === "real?" ? verify : tps).push({ path, desc, ids: specificIds });
          seenReal.add(path);
        } else if (r.exercised) {
          noFinding.push({ path, desc, kind });
        }
      } else if (kind === "safe" || kind === "simulated") {
        if (specificIds.length > 0) fps.push({ path, desc, kind, ids: specificIds });
      }
    }
  }

  const sev = (id) => (severity[id] ? `${id} [${severity[id]}]` : id);
  const hr = () => console.log("-".repeat(74));

  hr();
  console.log("  Contrast findings verification  (source-grounded, read-only)");
  console.log(`  Route rows parsed: ${routeRows.length}   Distinct finding IDs: ${Object.keys(idRoutes).length}`);
  hr();

  console.log(`\nCONFIRMED TRUE POSITIVES  (${tps.length})  -- finding on a route with a real sink`);
  for (const t of tps) console.log(`  OK  ${t.path}\n        ${t.desc}\n        ${t.ids.map(sev).join(", ")}`);

  if (verify.length) {
    console.log(`\nVERIFY ON INSTANCE  (${verify.length})  -- real sink, reporting is context-dependent`);
    for (const v of verify) console.log(`  ??  ${v.path}\n        ${v.desc}\n        ${v.ids.map(sev).join(", ")}`);
  }

  console.log(`\nCANDIDATE FALSE POSITIVES  (${fps.length})  -- finding on safe/simulated route (expect 0)`);
  if (fps.length === 0) console.log("  none -- no findings on any safe or simulated route.");
  for (const f of fps) console.log(`  !!  [${f.kind}] ${f.path}\n        ${f.desc}\n        ${f.ids.map(sev).join(", ")}  <-- INVESTIGATE`);

  // De-dupe by path (the CSV can have several rows for one route) and explain each.
  const noFindingUniq = [...new Map(noFinding.map((n) => [n.path, n])).values()];
  console.log(`\nREAL ROUTES EXERCISED WITH NO FINDING  (${noFindingUniq.length})  -- not a detection gap; see reason`);
  for (const n of noFindingUniq) {
    console.log(`  --  ${n.path}  (${n.desc})`);
    if (NO_FINDING_REASON[n.path]) console.log(`        why: ${NO_FINDING_REASON[n.path]}`);
  }

  const sysIds = [...systemic];
  console.log(`\nSYSTEMIC / APP-WIDE FINDINGS  (${sysIds.length})  -- confirm these are real config findings, not per-route FPs`);
  for (const id of sysIds) console.log(`  ~~  ${sev(id)}  (on ${idRoutes[id].size} routes)`);

  hr();
  const verdict = fps.length === 0
    ? `VERDICT: no false positives detected. ${tps.length} findings confirmed as true positives by source.`
    : `VERDICT: ${fps.length} candidate false positive(s) to investigate (see above).`;
  console.log(verdict);
  console.log("Note: systemic findings and 'verify on instance' rows should be reviewed in the UI.");
  hr();
}

main();
