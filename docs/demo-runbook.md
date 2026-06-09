# Live demo runbook — WebGoat IAST + ADR evaluation

A session-flow script for the live sync meeting. It maps directly to the three things the
evaluation asks to see in the walkthrough: interface usability, false-positive identification,
and reporting quality. Run the pre-flight before the call so the dashboard is fully populated,
then drive Parts 1 to 3 on screen.

All product behavior here reflects Contrast as observed in this eval (v2025.3 WebGoat, hosted
Contrast). Contrast features change, so confirm anything version-specific against current docs
before stating it as fact.

## Pre-flight (do this before the meeting)

The evaluation requires scans completed in advance and the dashboard populated. Steps:

1. Bring the environment up. `./scripts/setup.sh` installs the operator via Helm, deploys
   WebGoat, and starts port-forwarding. Confirm the agent is reporting and the application
   "WebGoat IAST/ADR Demo" appears in the Contrast UI.
2. Populate Assess findings. From `demo/`, run `python3 full-coverage-exercise.py`. It solves
   nearly every lesson, runs a read-back pass so stored and second-order findings fire in one
   run, and ends with a sink-health check. Watch for any WARN line and fix the request before
   the call.
3. Populate Attacks (Protect/ADR). Run `node demo/run-adr-attacks.mjs` so the Attacks view has
   live attack data. Protect is enabled in the Helm values.
4. Let the agent flush (about 30 to 60 seconds), then export the Route coverage CSV and the
   Vulnerabilities CSV from the UI. Keep them handy for Part 2 and Part 3.
5. Run `node scripts/verify-findings.mjs <route-coverage.csv>` and keep the output on screen.
   It should read 22 confirmed true positives, 0 candidate false positives.
6. Open [`findings-verification-ledger.md`](findings-verification-ledger.md) in a tab. It is
   your per-finding evidence backup if anyone asks "how do you know this is real."

Expected populated state: about 56 to 57 findings, 16 SQL Injection (Critical), path traversal,
XXE, deserialization, the WebWolf stored XSS, plus the medium and note config findings.

## Part 1 — Interface usability (screen by screen)

Goal: show how a vulnerability is displayed, navigated, and investigated. Each finding is
evidence-backed, the request, the line of code, and the source-to-sink dataflow.

1. Application list. Open "WebGoat IAST/ADR Demo." Note the agent reported it automatically
   with no scan to configure.
2. Vulnerabilities / Issues list. Sort by severity. Show the spread, Critical SQL Injection
   down through the Note-level config findings. This is the "what did we find" overview.
3. Open a Critical SQL Injection (for example the `register.mvc` finding). Walk the Overview
   cards, Severity, Rule, MITRE CWE, Sensor (Contrast Agent), Technique (Runtime). Then the
   "What happened?" panel, which is the headline: it tracked the `username` parameter, shows the
   exact code location (`JdbcTemplate...doInStatement` line 435), and the resulting query
   (`CREATE SCHEMA "..." authorization dba`). This is the IAST story, a real request reaching a
   real sink, with proof, not a guess from the response.
4. Show a second class for breadth. Open the WebWolf mail Stored XSS (`GET /WebWolf/mail`) or a
   Path Traversal finding, and walk the same evidence trail. The point is that every finding has
   this depth, not just SQLi.
5. Route coverage view. Show which routes were exercised and that findings attach to routes.
   This frames coverage for Part 3.
6. Attacks view (Protect / ADR). Show the attack payloads from the ADR run detected at runtime.
   Contrast inspects inbound requests and flags or blocks attacks regardless of whether the
   code is vulnerable, which is why this view is distinct from Assess.
7. Libraries / SCA. Show the inventory, including the vulnerable XStream 1.4.5 library. This
   sets up a strong honesty point in Part 2.
8. Optional, Observations / flow. Show the runtime flow, including the database connection
   traveling over a socket to the networked HSQLDB node.

## Part 2 — False-positive identification

Goal: show how Contrast identifies, handles, and filters out false positives in the WebGoat
dataset. The core message is that Contrast reports only observed, unsanitized dataflow into a
real sink at runtime, so it does not generate the noise other techniques do.

1. The mental model in one line. Contrast reports when tainted data reaches a real sink during
   execution. It stays silent, correctly, when the code never ran, the data was neutralized, the
   render is client-side, the issue is not a dataflow class, or the lesson only simulates a vuln.
   See the decision table in
   [`false-positives-vs-real-vulns.md`](false-positives-vs-real-vulns.md).
2. Show a true negative. Open the route coverage for `SqlInjectionMitigations/attack12a` (a
   parameterized `PreparedStatement`) and the simulated lessons (`attack10a/10b`). They were
   exercised and produced no finding. That gap is the false-positive other tools create and
   Contrast does not.
3. Prove it from their own data. Run `node scripts/verify-findings.mjs <route-coverage.csv>`
   live. Walk the output: 22 confirmed true positives, 0 candidate false positives, and the
   "real routes with no finding" section that self-explains each blank (coverage, environment,
   or client-side render), so a quiet route never looks like a miss.
4. Back it with evidence. Open the ledger and show that every finding maps to a source line or a
   confirmed trace. This is how you answer "prove these are real" without hand-waving.
5. The honesty points (these win technical trust):
   - `VulnerableComponents/attack1` shows no Assess finding because XStream 1.4.5 cannot run on
     JDK 23, the path 500s before the sink completes. Contrast did not fabricate a finding for
     code that did not execute, and the vulnerable library still shows in SCA. Show both.
   - WebGoat's SPA lesson XSS is real but renders client-side, so Assess is quiet and Protect
     catches the inbound payload. The WebWolf mail XSS is server-side, so Assess reports it.
     Showing you know the difference is more credible than claiming Contrast finds all XSS.

## Part 3 — Reporting quality (deliverables and metrics)

Goal: the specific deliverables, metrics, and reports the tool generates for their teams.

Reports Contrast generates:
- Vulnerability export (CSV and XML) with rule, severity, CWE, route, request, and status.
- Route coverage export, what was exercised and what carried findings.
- Libraries / SCA inventory with CVE and version data.
- Attacks / Protect events for the ADR view.

Supporting artifacts in this repo (turn raw findings into a defensible story):
- `scripts/verify-findings.mjs` output, a TP/FP attestation generated from their own export.
- [`findings-verification-ledger.md`](findings-verification-ledger.md), per-finding evidence.
- [`webgoat-vuln-classification.md`](webgoat-vuln-classification.md), the real-vs-simulated
  inventory and the Contrast rule coverage in this deploy.

Metrics worth putting on screen: findings by severity, route coverage percentage, true-positive
confirmation with zero false positives on the enumerated safe and simulated routes, and rule
coverage (this WebGoat deploy exercises about 20 of Contrast's Assess rules, bounded by the
target app, not the tool).

## Bonus — remediation with SmartFix

If time allows, show the remediation arc: a Critical SQLi finding, trigger Contrast AI SmartFix,
open the generated pull request and walk the diff, merge, and show Contrast acknowledging the
fix. Setup is in [`../smartfix/README.md`](../smartfix/README.md).

## Quick talking points and gotchas

- Every finding carries request plus code location plus dataflow. Lead with that.
- Stored and second-order findings (stored XSS, WebWolf mail) appear on read-back. The solver's
  read-back pass handles this, so a single pre-work run is enough.
- `SqlInjectionMitigations/servers` needs the `column` parameter to drive the sink. The solver
  sends it. This is the "route-covered is not sink-exercised" lesson, the sink-health check
  guards it.
- SSRF needs outbound egress to complete cleanly, confirm it in the vulnerabilities list rather
  than route coverage.
- Do not claim "Contrast finds every vulnerability class." It finds what executes in this app.
  The coverage-scope framing is more credible and is documented.

## Reset for a fresh run

`./scripts/teardown.sh` clears the Contrast UI (findings, routes, attacks, incidents) while
keeping the libraries and SCA data, so you can re-run the demo from a clean dashboard. It stops
port-forwarding as its last step. To rebuild from scratch, re-run `./scripts/setup.sh`.
