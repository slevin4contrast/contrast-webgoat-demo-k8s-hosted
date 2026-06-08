#!/usr/bin/env node
//
// Clear the WebGoat demo's data from the Contrast UI so the next run is fresh.
//
// Two modes (look up the application by name first, then act on each match):
//   issues (default) -- clear vulnerabilities (in BOTH the classic and ns-ui/North Star
//                        views), Protect attack incidents, and route coverage. KEEPS the
//                        app, its LIBRARIES, and CVE/SCA data. Vulns + incidents need only
//                        the Edit role; route-coverage delete needs Admin (best-effort,
//                        clean skip on 403). Endpoints:
//                          DELETE  /api/ns-ui/v1/.../issues?applicationId=     (ns-ui vulns)
//                          GET     /api/ng/.../traces/{appId}/ids   then
//                          DELETE  /api/ng/.../traces/{appId}  {traces:[...]}   (classic vulns)
//                          POST    /api/ns-ui/v1/.../incidents (list) then
//                          DELETE  /api/ns-ui/v1/.../incidents/{id}             (attacks/incidents)
//                          DELETE  /api/ng/.../applications/{appId}/route       (routes, Admin)
//                        Libraries / CVE / SCA endpoints are never called, so that data stays.
//   reset            -- RESET the application: purge ALL of its data -- vulnerabilities,
//                        libraries, route coverage, stats, and the Behavior/flow (Observe)
//                        data -- while KEEPING the app, its license, and server links.
//                        This is the only way to clear the Behavior tab. Requires Admin.
//                        Endpoint: PUT /api/ng/{org}/applications/{appId}/reset  body {}
//   app              -- DELETE the whole application: app + ALL data. Requires Admin.
//                        Endpoint: DELETE /api/ng/{org}/applications/{appId}
//
// Called automatically by scripts/teardown.sh when API credentials are present.
// Run standalone:
//   node scripts/clear-contrast-ui.mjs                  # clear findings only (default)
//   node scripts/clear-contrast-ui.mjs --mode reset     # purge all incl. Behavior (needs Admin)
//   node scripts/clear-contrast-ui.mjs --mode app       # delete the whole app (needs Admin)
//   node scripts/clear-contrast-ui.mjs --dry-run        # list matching apps, change nothing
//
// Requires (in .env):
//   CONTRAST_TOKEN        the agent token (used to derive org id + base URL)
//   CONTRAST_API_KEY      organization API key   (Contrast UI > User settings > API)
//   CONTRAST_AUTH_HEADER  the "Authorization Header" value from the same page
//                         (issues mode needs Edit role; app mode needs Admin)
// Optional:
//   CONTRAST_CLEAR_MODE   "issues" (default), "reset", or "app"
//   CONTRAST_APP_NAME     application name to match (default below)
//   CONTRAST_ORG_ID       override if token parsing fails
//   CONTRAST_BASE_URL     override if token parsing fails (no trailing /Contrast)

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DRY_RUN = process.argv.includes("--dry-run");
const DEFAULT_APP_NAME = "WebGoat IAST/ADR Demo";

// mode: --mode issues|reset|app  (falls back to env, then "issues")
//   issues -> Edit role; reset and app -> Admin role.
function resolveMode() {
  const i = process.argv.indexOf("--mode");
  const fromArg = i >= 0 ? process.argv[i + 1] : undefined;
  const m = (fromArg || process.env.CONTRAST_CLEAR_MODE || "issues").toLowerCase();
  if (m === "app") return "app";
  if (m === "reset") return "reset";
  return "issues";
}

// --- tiny .env loader (only fills vars not already in the environment) -------
function loadEnv() {
  try {
    const txt = readFileSync(join(ROOT, ".env"), "utf8");
    for (const raw of txt.split("\n")) {
      const l = raw.trim();
      if (!l || l.startsWith("#")) continue;
      const eq = l.indexOf("=");
      if (eq < 0) continue;
      const k = l.slice(0, eq).trim();
      let v = l.slice(eq + 1).trim().replace(/^["']|["']$/g, "");
      if (process.env[k] === undefined) process.env[k] = v;
    }
  } catch {
    /* no .env, rely on process.env */
  }
}

// --- derive org id + base URL from the agent token (same logic as cargo-cats) -
function parseToken(token) {
  const json = JSON.parse(Buffer.from(token, "base64").toString("utf8"));
  let baseUrl = json.url || "";
  if (baseUrl.endsWith("/Contrast")) baseUrl = baseUrl.slice(0, -"/Contrast".length);
  baseUrl = baseUrl.replace("-agents.", ".");
  const m = /agent_([a-f0-9-]+)[@_]/.exec(json.user_name || "");
  return { baseUrl, orgId: m ? m[1] : null };
}

async function main() {
  loadEnv();

  const token = process.env.CONTRAST_TOKEN;
  const apiKey = process.env.CONTRAST_API_KEY;
  const auth = process.env.CONTRAST_AUTH_HEADER;
  const appName = process.env.CONTRAST_APP_NAME || DEFAULT_APP_NAME;

  if (!apiKey || !auth) {
    console.log(
      "Skipping UI clear: CONTRAST_API_KEY and/or CONTRAST_AUTH_HEADER not set in .env."
    );
    console.log("Add them (Contrast UI > User settings > API) to enable this step.");
    return; // exit 0 -- not an error, teardown should continue
  }

  let orgId = process.env.CONTRAST_ORG_ID;
  let baseUrl = process.env.CONTRAST_BASE_URL;
  if ((!orgId || !baseUrl) && token) {
    const parsed = parseToken(token);
    orgId = orgId || parsed.orgId;
    baseUrl = baseUrl || parsed.baseUrl;
  }
  if (!orgId || !baseUrl) {
    console.error("ERROR: could not determine org id / base URL. Set CONTRAST_ORG_ID and CONTRAST_BASE_URL in .env.");
    process.exit(1);
  }

  const headers = {
    Authorization: auth,
    "API-Key": apiKey,
    "Content-Type": "application/json",
    Accept: "application/json",
  };

  const mode = resolveMode();
  const action =
    mode === "app"
      ? "DELETE WHOLE APPLICATION (app + libraries + route coverage)"
      : mode === "reset"
        ? "RESET application (purge ALL data incl. Behavior/flow + libraries; keep app)"
        : "clear vulns (classic + ns-ui) + attacks/incidents + routes; KEEP libraries + CVE/SCA";
  console.log(`Contrast cleanup (${action}) for app matching: "${appName}"`);
  console.log(`Org: ${orgId}  Base: ${baseUrl}${DRY_RUN ? "  (DRY RUN)" : ""}`);

  const okCode = (s) => [200, 202, 204, 404].includes(s);

  // Clear vulnerabilities for an app in BOTH UIs. Libraries / CVE / SCA are never
  // touched, so SCA data is preserved.
  //   (a) ns-ui issues  -> the North Star "issues" view
  //   (b) ng traces     -> the classic "Vulnerabilities" view (list UUIDs, then delete)
  async function clearIssues(appId) {
    let ok = false;

    // (a) ns-ui issues (North Star)
    const nsUrl = `${baseUrl}/api/ns-ui/v1/organizations/${orgId}/issues?applicationId=${encodeURIComponent(appId)}`;
    const nsRes = await fetch(nsUrl, { method: "DELETE", headers });
    console.log(`      issues(ns-ui):  HTTP ${nsRes.status}${okCode(nsRes.status) ? "" : "  " + (await nsRes.text())}`);
    ok = okCode(nsRes.status) || ok;

    // (b) ng traces (classic) -- list vulnerability UUIDs, then delete that set
    const idsRes = await fetch(`${baseUrl}/Contrast/api/ng/${orgId}/traces/${encodeURIComponent(appId)}/ids`, { headers });
    if (!idsRes.ok) {
      console.log(`      vulns(classic): list failed HTTP ${idsRes.status} (skipping)`);
      return ok;
    }
    const idsBody = await idsRes.json();
    const rawIds = idsBody.traces || idsBody.trace_ids || idsBody.traceIds || (Array.isArray(idsBody) ? idsBody : []);
    const ids = rawIds.map((t) => (typeof t === "string" ? t : t.uuid || t.trace_id || t.id)).filter(Boolean);
    if (ids.length === 0) {
      console.log("      vulns(classic): none");
      return ok;
    }
    if (DRY_RUN) {
      console.log(`      vulns(classic): ${ids.length} would be deleted`);
      return true;
    }
    const delRes = await fetch(`${baseUrl}/Contrast/api/ng/${orgId}/traces/${encodeURIComponent(appId)}`, {
      method: "DELETE",
      headers: { ...headers, "Content-Type": "application/json" },
      body: JSON.stringify({ traces: ids }),
    });
    console.log(`      vulns(classic): deleted ${ids.length}  [HTTP ${delRes.status}]${okCode(delRes.status) ? "" : "  " + (await delRes.text())}`);
    return okCode(delRes.status) || ok;
  }

  // Clear route coverage (classic UI "Route Coverage"). NOTE: this endpoint requires
  // the Admin role, so with a non-admin header it returns 403 and we skip cleanly.
  async function clearRoutes(appId) {
    const url = `${baseUrl}/Contrast/api/ng/${orgId}/applications/${encodeURIComponent(appId)}/route`;
    const res = await fetch(url, { method: "DELETE", headers });
    if (okCode(res.status)) {
      console.log(`      routes:    cleared [HTTP ${res.status}]`);
      return true;
    }
    if (res.status === 403) {
      console.log("      routes:    SKIPPED (HTTP 403 — route coverage delete needs Admin role)");
      return false;
    }
    console.log(`      routes:    FAILED HTTP ${res.status}  ${await res.text()}`);
    return false;
  }

  // Clear Protect attack incidents: list them for this app, then delete each by id.
  async function clearIncidents(name) {
    const listUrl = `${baseUrl}/api/ns-ui/v1/organizations/${orgId}/incidents?page=0&size=1000`;
    const listRes = await fetch(listUrl, {
      method: "POST",
      headers,
      body: JSON.stringify({ applicationName: name }),
    });
    if (!listRes.ok) {
      console.log(`      incidents: list failed HTTP ${listRes.status} (skipping)`);
      return false;
    }
    const incidents = (await listRes.json()).incidents || [];
    if (incidents.length === 0) {
      console.log("      incidents: none");
      return true;
    }
    if (DRY_RUN) {
      console.log(`      incidents: ${incidents.length} would be deleted`);
      return true;
    }
    let n = 0;
    for (const inc of incidents) {
      const id = inc.incidentId || inc.id;
      if (!id) continue;
      const res = await fetch(
        `${baseUrl}/api/ns-ui/v1/organizations/${orgId}/incidents/${encodeURIComponent(id)}`,
        { method: "DELETE", headers }
      );
      if (okCode(res.status)) n++;
    }
    console.log(`      incidents: deleted ${n}/${incidents.length}`);
    return true;
  }

  // 1) find the application(s) by name
  const filterUrl = `${baseUrl}/Contrast/api/ng/${orgId}/applications/filter?includeMerged=true`;
  const filterRes = await fetch(filterUrl, {
    method: "POST",
    headers,
    body: JSON.stringify({ filterText: appName }),
  });
  if (!filterRes.ok) {
    console.error(`ERROR: application lookup failed: HTTP ${filterRes.status} ${await filterRes.text()}`);
    process.exit(1);
  }
  const data = await filterRes.json();
  const apps = Array.isArray(data) ? data : data.applications || [];
  if (apps.length === 0) {
    console.log(`No applications matched "${appName}". Nothing to clear.`);
    return;
  }

  // 2) act on each matching app
  let ok = 0;
  for (const app of apps) {
    const appId = app.app_id || app.appId || app.id;
    const name = app.name || appId;
    if (!appId) {
      console.log(`  - skipped (no app id): ${JSON.stringify(app).slice(0, 80)}`);
      continue;
    }
    console.log(`  - ${name} (${appId})`);

    if (mode === "app") {
      if (DRY_RUN) {
        console.log("      would DELETE the whole application");
        ok++;
        continue;
      }
      const res = await fetch(
        `${baseUrl}/Contrast/api/ng/${orgId}/applications/${encodeURIComponent(appId)}`,
        { method: "DELETE", headers }
      );
      if (okCode(res.status)) {
        console.log(`      application: deleted [HTTP ${res.status}]`);
        ok++;
      } else {
        console.log(`      application: FAILED HTTP ${res.status} ${await res.text()}`);
      }
      continue;
    }

    if (mode === "reset") {
      // PUT .../reset purges classic-UI data (vulnerabilities, libraries, route coverage,
      // stats, Behavior/flow) while keeping the app. Requires the Admin role.
      // NS UI issues and incidents are stored separately, so we clear those too.
      if (DRY_RUN) {
        console.log("      would RESET (purge vulns, libraries, routes, Behavior/flow; keep app)");
        console.log("      would clear NS UI issues and incidents");
        ok++;
        continue;
      }
      const res = await fetch(
        `${baseUrl}/Contrast/api/ng/${orgId}/applications/${encodeURIComponent(appId)}/reset`,
        { method: "PUT", headers, body: "{}" }
      );
      if (okCode(res.status)) {
        console.log(`      reset: done [HTTP ${res.status}] (classic UI: vulns, libraries, routes, Behavior/flow purged)`);
      } else if (res.status === 403) {
        console.log("      reset: SKIPPED (HTTP 403 — reset needs Admin role)");
      } else {
        console.log(`      reset: FAILED HTTP ${res.status} ${await res.text()}`);
      }
      // Also clear NS UI issues and incidents (stored separately from classic UI)
      await clearIssues(appId);
      await clearIncidents(name);
      ok++;
      continue;
    }

    // issues mode: clear findings + attack incidents + route coverage; keep libraries
    if (DRY_RUN) {
      console.log("      would clear issues (vulnerabilities)");
      await clearIncidents(name); // read-only list + count in dry-run
      console.log("      would clear route coverage (needs Admin role)");
      ok++;
      continue;
    }
    const a = await clearIssues(appId);
    const b = await clearIncidents(name);
    const c = await clearRoutes(appId);
    if (a || b || c) ok++;
  }

  console.log(
    DRY_RUN
      ? `Dry run complete (${mode} mode): ${ok} app(s) would be processed.`
      : `Done (${mode} mode): processed ${ok} of ${apps.length} matching app(s).`
  );
}

main().catch((e) => {
  console.error("FATAL:", e.message);
  process.exit(1);
});
