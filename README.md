# Contrast on Kubernetes — WebGoat IAST + ADR Demo

A one-command Kubernetes demo that deploys [OWASP WebGoat](https://github.com/WebGoat/WebGoat)
and instruments it with the Contrast Java agent, injected automatically by the
[Contrast Agent Operator](https://github.com/Contrast-Security-OSS/agent-operator)
(installed via Helm). It shows Contrast's IAST (Assess) finding real vulnerabilities
during ordinary functional use, and its RASP/ADR (Protect) detecting live attacks, with
no changes to the application image.

> WebGoat is a deliberately insecure application. Run this only in an isolated lab
> environment (the default is a throwaway `kind` cluster). Do not expose it to the
> internet.

## Why this demo exists

Evaluations of IAST tools are often scored with a legacy SAST/DAST rubric ("run an
advance scan, then count and triage the findings"). That framing misses how IAST
actually works, and OWASP WebGoat specifically exposes the gap:

1. **IAST is runtime, not a pre-baked scan.** Contrast instruments the running app and
   reports a vulnerability the moment the vulnerable code path executes. You don't
   attack it, you just use it. This demo deploys the app, exercises it with normal
   input, and findings stream into the dashboard within seconds.

2. **WebGoat is a teaching tool, which is a trap for guess-based scanners.** Many
   WebGoat lessons are *simulated*: instead of running a dangerous payload, the app
   just checks whether your input matches a pattern (like `' OR 1=1`) and prints
   "Lesson Passed!". A scanner that guesses from HTTP responses flags these as real
   vulnerabilities. Contrast watches actual code execution, so it correctly ignores the
   fake lessons because no vulnerable code ran. That's the false-positive story: you
   don't triage noise Contrast never generates.

The demo scripts make both points visible, see [Functional exercise vs. attack run](#two-ways-to-drive-the-app).

## How it works

The Contrast Agent Operator runs in the cluster and injects the Java agent into any
workload carrying a matching label, with no edits to the container image. Injection is
scoped to a single namespace so this is safe to run on a shared cluster.

| Component | Namespace | Notes |
|---|---|---|
| Contrast Agent Operator (Helm release) | `contrast-agent-operator` | CRDs + operator + mutating webhook |
| WebGoat Deployment + Service | `webgoat` | labeled `contrast-agent: java` for injection |
| Agent injectors | scoped to `webgoat` only | via `agentInjectors.namespaces` in the Helm values |

Assess (IAST) and Protect (RASP/ADR) are both enabled in the agent configuration.

## Prerequisites

- `kubectl`, `helm` (3.11+), and a Kubernetes cluster. `kind` is only needed if you use
  the throwaway-cluster path (recommended).
- `node` 18+ (for the demo scripts and the Contrast UI cleanup helper).
- A Contrast **Agent Token** (one base64 string from the Contrast UI, under the Java
  agent setup / agent keys page).
- Optional, for the teardown UI cleanup: a Contrast **API Key** and **Authorization
  Header** (Contrast UI > User settings > API).

## Quick start

```bash
cp .env.example .env        # paste your CONTRAST_TOKEN (and optional API creds)
./scripts/setup.sh
```

`setup.sh` creates the cluster (if `KIND=1`), installs the operator via Helm scoped to
the `webgoat` namespace, deploys WebGoat, and — once it's ready — automatically starts
port-forwarding and holds it open (Ctrl-C to stop). Then browse to:

```
http://localhost:8080/       (WebGoat at root context; WebWolf at http://localhost:9090/WebWolf)
```

Set `PORT_FORWARD=0 ./scripts/setup.sh` to skip the auto-forward (e.g. in CI). You can
start or restart forwarding any time; it waits for readiness and auto-reconnects if the
tunnel drops:

```bash
./scripts/port-forward.sh
```

Confirm instrumentation:

```bash
./scripts/status.sh
kubectl -n webgoat logs deployment/webgoat | grep -i contrast
```

## Two ways to drive the app

Both scripts live in `demo/`. Run `npm install` once, then:

```bash
cd demo
node run-exercises.mjs      # FUNCTIONAL exercise: benign input, IAST finds the flaws
node run-adr-attacks.mjs    # ATTACK run: real payloads, Protect/ADR detects them
```

`run-exercises.mjs` sends normal, benign input to a catalog of routes tagged
`VULNERABLE`, `SAFE`, or `SIMULATED`. Because Contrast instruments the code, the
vulnerable routes are reported with no attack payload, the safe (parameterized) routes
produce nothing (a true negative), and the simulated WebGoat lessons produce nothing
(the false-positive story). This is the headline IAST demonstration.

`run-adr-attacks.mjs` (bonus) is the mirror image: it sends canonical attack payloads
(SQLi, reflected XSS, path traversal, XXE) so Contrast Protect detects them at runtime
and they appear under the Attacks view. With Protect rules in monitor mode the requests
return normally and are logged; in block mode they're blocked (HTTP 403/406).

Add `--dry-run` to either script to print the plan without sending anything. See
[`demo/README.md`](demo/README.md) for details and configuration.

## Teardown and resetting for a fresh demo

```bash
./scripts/teardown.sh          # remove WebGoat + operator, and clear the Contrast UI
./scripts/teardown.sh --crds   # also remove the Contrast CRDs (cluster-wide)
KIND=1 ./scripts/teardown.sh   # delete the throwaway kind cluster instead
```

Teardown also clears this app's data from the Contrast UI (via the Contrast API) so the
next run starts fresh. The behavior is controlled by `CONTRAST_CLEAR_MODE`:

| Mode | Clears | Keeps | Role needed |
|---|---|---|---|
| `issues` (default) | vulnerabilities (classic + ns-ui), attack incidents, route coverage | the app, **libraries, CVE/SCA** | Edit (route delete needs Admin, best-effort) |
| `reset` | **all** data incl. the Behavior/flow (Observe) tab and libraries | the app shell | Admin |
| `app` | the entire application | nothing | Admin |

Run the cleanup standalone (with `--dry-run` to preview):

```bash
node scripts/clear-contrast-ui.mjs                # default: issues mode
node scripts/clear-contrast-ui.mjs --mode reset   # clears the Behavior tab too (Admin)
node scripts/clear-contrast-ui.mjs --dry-run
```

This step needs `CONTRAST_API_KEY` and `CONTRAST_AUTH_HEADER` in `.env`; without them
it's skipped (teardown still completes). Set `CLEAR_UI=0` to skip it entirely.

**Library safety:** teardown will not silently destroy library/CVE data. If
`CONTRAST_CLEAR_MODE` is `reset` or `app` (the modes that purge libraries), teardown
downgrades the cleanup to `issues` to preserve them, unless you explicitly set
`CLEAR_ALLOW_LIBRARY_LOSS=1`. Library data is reported by the running agent, so if it
ever does get purged, redeploy with `setup.sh` and exercise the app and it repopulates.

As its final step, teardown also stops the port-forward started by `setup.sh`. The
approach mirrors Contrast's [cargo-cats](https://github.com/Contrast-Security-OSS/cargo-cats)
demo.

## kind vs. existing cluster

**Recommended: `kind`.** A throwaway cluster in Docker, fully isolated from any real
cluster. Set `KIND=1` in `.env`. `KIND=1 ./scripts/teardown.sh` drops the whole cluster,
so the operator's CRDs and webhook never touch anything else.

**An existing cluster (e.g. kubeadm).** Safe, with one caveat. Injection is scoped to
the `webgoat` namespace (`agentInjectors.namespaces: [webgoat]`), and even there only
pods labeled `contrast-agent: java` are touched, so other workloads are never selected.
The one unavoidably cluster-wide piece is the operator's CRDs and mutating webhook
(installed in `contrast-agent-operator`); the webhook only mutates pods an injector
selects. For zero cluster-scoped footprint, use `kind`. Set `KUBE_CONTEXT` in `.env` as
a guard against deploying into the wrong cluster.

## Repository layout

```
manifests/00-namespace.yaml                webgoat namespace
manifests/10-webgoat.yaml                  WebGoat Deployment + Service (labeled for injection)
helm/contrast-agent-operator.values.yaml   Helm values: cluster defaults + webgoat-scoped injectors
kind-cluster.yaml                          throwaway kind cluster config (KIND=1)
scripts/setup.sh                           install operator (Helm) + deploy WebGoat + auto port-forward
scripts/port-forward.sh                    wait for WebGoat, forward to localhost, auto-reconnect
scripts/status.sh                          health check (operator, pod, injection)
scripts/teardown.sh                        remove everything + clear the Contrast UI
scripts/clear-contrast-ui.mjs              clear findings / attacks / routes / Behavior via the Contrast API
scripts/verify-findings.mjs                vet TPs vs FPs: cross-reference a route-coverage CSV against a source-grounded sink map
docs/false-positives-vs-real-vulns.md      TP/FP analysis and the technique-based comparison
docs/webgoat-vuln-classification.md        full v2025.3 lesson inventory: real vs simulated vs logic-only
smartfix/smartfix.yml                      Contrast AI SmartFix GitHub Actions workflow (copy into a WebGoat source fork)
smartfix/README.md                         SmartFix setup: API-only user, credentials, where it runs
scripts/smartfix-preflight.mjs             validate Contrast creds + app id locally before the GitHub run (no secrets printed)
demo/run-exercises.mjs                     functional exercise run (benign input -> IAST findings)
demo/exercises.mjs                         route catalog: vulnerable vs safe vs simulated
demo/run-adr-attacks.mjs                   attack run (payloads -> Protect/ADR detection)
demo/full-coverage-exercise.py             alternative: solves nearly every lesson for max route coverage (Python)
demo/README.md                             demo script details
.env.example                              configuration template (copy to .env)
```

## Configuration

All configuration is via `.env` (copy from `.env.example`). The only required value is
`CONTRAST_TOKEN`. The Contrast application name defaults to `WebGoat IAST/ADR Demo` and
can be changed in the Helm values (and matched via `CONTRAST_APP_NAME` for cleanup).

`.env` is git-ignored and must never be committed, it contains your agent token and API
credentials.

## Root context path (Assess + ADR URL alignment)

WebGoat is deployed at the **root context (`/`)** via `WEBGOAT_CONTEXT=/` in
`manifests/10-webgoat.yaml`, not the default `/WebGoat`. With the default context,
Contrast records two URLs per endpoint, the Spring route mapping (`/SqlInjection/attack2`)
that Assess uses and the full request URI (`/WebGoat/SqlInjection/attack2`) that ADR/
Protect attacks carry, so they don't line up in the UI. Serving at root makes the request
URI equal the route mapping, so Assess findings and ADR attacks share one URL.

If you change this, keep the demo scripts' `BASE_URL` in step (root = `http://localhost:8080`).
Note that routes already recorded under the old `/WebGoat` prefix persist, clear routes
(teardown, or `--mode reset` with admin) and re-exercise so only the clean URLs remain.

## Notes and accuracy

Manifest, chart, and API details were taken from current Contrast documentation and the
[Contrast OSS](https://github.com/Contrast-Security-OSS) repos. Some Contrast UI cleanup
endpoints are internal (`ns-ui`) APIs rather than the published REST reference. Contrast
product behavior, chart values, and APIs can change, verify against
[the Contrast docs](https://docs.contrastsecurity.com/en/agent-operator.html) and your
own instance before relying on this elsewhere. WebGoat's host-binding env vars
(`WEBGOAT_HOST`, etc.) and the `/WebGoat` context path can change between image versions;
if the UI won't load, check those first.

## License

No license is specified yet. Add one before publishing if these materials are intended
for outside use.
