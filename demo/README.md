# Demo scripts: functional exercise and ADR attack runs

A small Playwright-based driver that authenticates to WebGoat and exercises a set of
routes with **normal, benign input** -- the way QA or a click-through would. Because
Contrast is IAST and instruments the running code, it reports a vulnerability the
moment the vulnerable code path executes; it does **not** need an attack payload. So
this isn't an "attack" script, it's a functional exercise that lets Contrast do what
it does during ordinary use.

Keep the Contrast UI on screen and run this during the call: vulnerable routes light
up, safe routes stay quiet, and the simulated WebGoat lessons stay quiet too.

## Run it

WebGoat must be up and reachable (port-forward from the cluster):

```bash
kubectl -n webgoat port-forward svc/webgoat 8080:8080 9090:9090
```

Then, from this `demo/` folder:

```bash
npm install            # one time; pulls Playwright (no browser download needed)
node run-exercises.mjs
```

Preview the plan without sending anything (works before npm install):

```bash
node run-exercises.mjs --dry-run
```

## Options (env vars)

| Var | Default | Purpose |
|---|---|---|
| `BASE_URL` | `http://localhost:8080` | WebGoat base URL (root context) |
| `DELAY_MS` | `2500` | Pause between routes so findings appear one at a time |
| `USERNAME` | `contrast-demo-<timestamp>` | A fresh user is registered each run |
| `PASSWORD` | `password` | Password for the registered user |

Example, slower pacing against a different host:

```bash
BASE_URL=http://localhost:8080 DELAY_MS=4000 node run-exercises.mjs
```

## The three categories (why this proves the point)

The catalog lives in `exercises.mjs`, each route tagged `VULNERABLE`, `SAFE`, or
`SIMULATED`. All of them are exercised with benign input.

`VULNERABLE` routes run genuinely unsafe code: SQL built by string concatenation and
executed via `Statement`, XML parsed with external entities enabled, `readObject` on
request bytes, `XStream.fromXML`, `MessageDigest` MD5, `URL.openStream` on a
user-supplied URL. Contrast traces these from the dataflow alone, no payload needed.
Covered classes: SQL injection (8 routes), XXE, insecure deserialization, vulnerable
component (XStream), weak hashing, SSRF, stored XSS.

`SAFE` is the same kind of feature coded correctly -- a fully parameterized
`PreparedStatement` (`/SqlInjectionMitigations/attack12a`). Exercising it produces no
finding. That's a true negative you can point to: Contrast looked at the parameter and
correctly stayed silent, so there's nothing to triage.

`SIMULATED` are WebGoat teaching lessons that only run a regex or `String.contains()`
check (`/SqlInjectionMitigations/attack10b`, `/SSRF/task1`, `/CrossSiteScripting/attack5a`).
No vulnerable code runs, so Contrast reports nothing. A guess-based scanner that reads
the HTTP response will flag these. That gap is the false-positive talking point: you
don't triage noise Contrast never creates.

## Why benign input is the headline

A legacy scanner has to *attack* an app, throwing `' OR 1=1` and `<script>` at it and
guessing from responses, which is where the false positives come from. Contrast watches
the code from the inside, so simply using the feature normally is enough for it to see
that untrusted data reached a dangerous sink without being neutralized. This run is
designed to make that visible: no exploit strings, real findings.

## Coverage

Before this run, the Contrast route-coverage export showed 11 of 180 routes exercised.
This catalog deliberately spans more routes and more vulnerability classes to raise
that number and show breadth. To go further, add routes to `exercises.mjs`: open a lesson,
use it once, and copy the request from your browser's Network tab or from Contrast's
route-coverage view.

## Bonus: ADR / Protect attack run

`run-adr-attacks.mjs` is the mirror image of the exercise run. Instead of benign input,
it sends canonical **attack payloads** (SQLi, reflected XSS, path traversal, XXE) so
Contrast **Protect** (RASP / ADR) detects them at runtime and they appear under the
**Attacks** view. These are standard detection test vectors fired at your own WebGoat
lab to validate Protect, not weaponized exploits.

```bash
node run-adr-attacks.mjs              # fire the attacks
node run-adr-attacks.mjs --dry-run    # print the plan, send nothing
```

Requires Protect enabled (the Helm values set `protect.enable: true`). With Protect
rules in monitor mode the requests return normally and the attack is logged; in block
mode Contrast blocks them (HTTP 403/406). The script prints the status and whether each
was likely blocked. Use the benign `run-exercises.mjs` to show IAST finding flaws from
normal use, and this script to show Protect catching active attacks.

## Full coverage exercise (alternative)

`full-coverage-exercise.py` is a heavier alternative to `run-exercises.mjs`. Instead of a
curated set of benign requests, it **solves nearly every WebGoat lesson** with its real
solution, which drives the full set of lesson routes. Use it to maximize Contrast route
coverage and populate findings broadly before a demo (the eval's pre-work expectation).

```bash
pip install requests PyJWT cryptography
python3 full-coverage-exercise.py
```

Config via env: `WEBGOAT_BASE`, `WEBWOLF_BASE`, `WEBGOAT_USER`, `WEBGOAT_PASS`.

Pick the right tool for the moment:

- `run-exercises.mjs` -- benign input, curated routes. The headline IAST story ("no
  attack needed"). Use this on the call.
- `full-coverage-exercise.py` -- solves lessons (real exploit payloads) to maximize
  route coverage and breadth. Use this to populate the dashboard ahead of time.
- `run-adr-attacks.mjs` -- attack payloads to light up Protect/ADR.

It targets WebGoat v2025.3 (the version this repo deploys); lessons that only exist on
newer WebGoat were removed so every call hits a real route. Because it solves lessons,
it sends real exploit payloads, so treat it like the ADR attack run, only against your
own lab.

## Notes

- Endpoints, parameters, and code behavior were verified against WebGoat **v2025.3**
  source (the tag pinned in `manifests/10-webgoat.yaml`).
- WebGoat has CSRF disabled, so no token handling is needed.
- A unique user is registered per run, so reruns never collide.
- Uses Playwright's request API (a Node HTTP client), so no Chromium download.
- The SSRF route opens an external URL server-side; the finding is created when the
  sink runs, even if your cluster has no outbound network access.
