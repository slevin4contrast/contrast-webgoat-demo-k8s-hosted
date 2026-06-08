# WebGoat v2025.3 — real vulnerabilities vs. simulated lessons

A source-grounded inventory of WebGoat v2025.3 lessons, classified by whether the
endpoint runs genuinely vulnerable code or only *checks* your input. This is the basis
for the false-positive story: a runtime tool (Contrast Assess) reports the real ones and
stays silent on the simulated ones, because it watches code execution rather than
guessing from responses.

This is the complete reference inventory. For the narrative version (how we vet true
positives, and the false-positive classes each tool technique produces), see
[`false-positives-vs-real-vulns.md`](false-positives-vs-real-vulns.md).

Each row was checked against the WebGoat v2025.3 source. Three buckets:

- **A. Real, dataflow vulnerabilities** — untrusted input reaches a real sink. Contrast
  Assess traces these. This is the strong demo set.
- **B. Simulated lessons** — the endpoint only runs a regex / `String.contains` /
  `.equals` / quiz comparison. No vulnerable code executes. A guess-based scanner can
  flag these (false positives); Contrast does not.
- **C. Real flaws, but not an injection/dataflow class** — genuine vulnerabilities
  (authorization, CSRF, logic), but not something an IAST dataflow engine reports. A
  scanner that labels these as "injection" would itself be producing false positives.

Caveats: behavior can shift with WebGoat version and JDK, and Contrast rule behavior can
change. Confirm against your live instance and current Contrast docs before using
externally.

## A. Real, dataflow vulnerabilities (Contrast Assess reports)

### SQL injection — string concatenated into an executed query

| Route | Sink |
|---|---|
| `POST /SqlInjection/attack2` | user-supplied string passed to `Statement.executeQuery` |
| `POST /SqlInjection/attack3` | user string to `executeUpdate` |
| `POST /SqlInjection/attack4` | user string to `executeUpdate` |
| `POST /SqlInjection/attack5` | user string to `executeQuery` |
| `POST /SqlInjection/assignment5a` | `account` concatenated into `... last_name = '<input>'` |
| `POST /SqlInjection/assignment5b` | `userid` concatenated (only `login_count` is bound) |
| `POST /SqlInjection/attack8` | `name` + `auth_tan` concatenated |
| `POST /SqlInjection/attack9` | `name` concatenated (blind) |
| `POST /SqlInjection/attack10` | search term concatenated into `LIKE '%...%'` |
| `POST /SqlInjectionAdvanced/attack6a` | last name concatenated |
| `GET /SqlInjectionMitigations/servers` | sort `column` concatenated into `ORDER BY` |
| `POST /SqlInjectionAdvanced/login`, `POST /challenge/5` | login-bypass SQLi challenge |

### Other injection / crypto / runtime classes

| Route(s) | Class | Sink |
|---|---|---|
| `POST /xxe/simple`, `/xxe/content-type`, `/xxe/blind` | XXE | untrusted XML parsed with the hardening branch disabled (`parseXml(.., false)`) |
| `POST /InsecureDeserialization/task` | Untrusted deserialization | `ObjectInputStream.readObject()` on request bytes |
| `POST /VulnerableComponents/attack1` | Vulnerable component | `XStream.fromXML(input)` on a known-vulnerable library |
| `GET /crypto/hashing/md5`, `/crypto/hashing/sha256`, `POST /crypto/hashing` | Weak cryptography | `MessageDigest` with MD5 / SHA-1 |
| `POST /SSRF/task2` | SSRF | `new URL(input).openStream()` server-side |
| `POST /PathTraversal/profile-upload`, `/profile-upload-remove-user-input` | Path traversal | user `fullName` / filename used to build the write path |
| `GET /PathTraversal/random-picture` | Path traversal | `id` used to build a file path |
| `POST /PathTraversal/zip-slip` | Zip slip (path traversal) | archive entry name used to write outside the target dir |

True negative worth showing: `POST /SqlInjectionMitigations/attack12a` is the same kind
of lookup written safely (fully parameterized `PreparedStatement`), so Contrast reports
nothing. Exercising it and getting no finding is the point, not a miss.

## A2. Real XSS, but rendered client-side (not a server-side Assess finding)

WebGoat's XSS lessons are **real** XSS, the `<script>` / `<img onerror>` payloads execute
in your browser. But WebGoat is a single-page app: the server returns your input inside a
**JSON** response (`@ResponseBody`) and the browser's JavaScript injects it into the DOM.
The dangerous render happens client-side, so a server-side runtime tool (Contrast Assess)
has no server-rendered-HTML sink to trace and generally does not report these. A DAST or
browser-based scanner, which sees the payload execute in the page, would correctly flag
them, so these are **not** good "false positive" examples. Protect/ADR detects the inbound
`<script>` payload as an XSS *attack* at the request layer, which is why XSS shows under
Attacks but not as an Assess vulnerability.

| Route | What's real | Why Assess is quiet |
|---|---|---|
| `GET /CrossSiteScripting/attack5a` | `field1` reflected into the cart HTML, executes in the DOM | returned as JSON `AttackResult`, rendered by the SPA |
| `POST /CrossSiteScriptingStored/stored-xss` | comment with script stored, executes when the comment list renders | comments returned as `application/json`, rendered by the SPA |
| `POST /CrossSiteScripting/phone-home-xss` (DOM) | DOM-based XSS executes entirely in the browser | no server-side sink at all |

Verify on your instance: if no XSS *vulnerability* appears in Assess but XSS *attacks* do
appear in Protect, that's expected for WebGoat's architecture, not a missed real bug on a
server-rendered app.

## B. Simulated lessons (no vulnerable code — the WebGoat trap)

These decide success with a regex / `contains` / `equals` / quiz comparison. No
vulnerable code runs, so there is nothing for a runtime tool to trace. A scanner that
infers from the response can flag them.

| Route(s) | What it actually does |
|---|---|
| `POST /SqlInjectionMitigations/attack10a`, `/attack10b` | regex / `contains` over *submitted code text*; no DB call |
| `POST /SqlOnlyInputValidation/attack`, `/SqlOnlyInputValidationOnKeywords/attack` | `contains(" ")` / `replace` input-validation check; no query executes |
| `POST /SqlInjectionAdvanced/attack6b` | `userid_6b.equals(password)`; the query is a constant |
| `POST /SSRF/task1` | string-compares the URL to fixed values; never connects |
| `POST /CrossSiteScripting/attack1`, `/attack6a`, `/dom-follow-up` | checkbox / route / success-message checks (the lesson's pass/fail gates) |
| `POST /CrossSiteScripting/attack3`, `/attack4` | regex over submitted JSP / AntiSamy *code* (code-review checks) |
| `POST /LogSpoofing/log-spoofing` | `replace("\n",...)` + `contains` check on echoed text; no logger sink |
| `crypto/encoding/basic`, `/basic-auth`, `/xor`, `/secure/defaults`, `/signing/verify` | base64 / `.equals` / format checks (only `crypto/hashing` is a real weak-hash) |
| Quizzes: `cia/quiz`, `SqlInjectionAdvanced/quiz`, `CrossSiteScripting/quiz`, `JWT/quiz`, `HttpBasics/attack2` | multiple-choice answer comparison |
| `HttpBasics/attack1`, `ChromeDevTools/*`, `HttpProxies/*`, `SecurePasswords/assignment`, `lesson-template/*`, `BypassRestrictions/*`, `ClientSideFiltering/*`, `HtmlTampering/task` | teaching/echo/validation checks |

## C. Real flaws, but not an injection/dataflow class

Genuine vulnerabilities WebGoat teaches, but they are authorization, session, or logic
issues, not data flowing into an injection/crypto sink. An IAST dataflow engine does not
generate findings for these, and a tool that reported them as "SQL injection" or "XSS"
would be producing false positives.

| Lesson area | Routes | Why not an Assess dataflow finding |
|---|---|---|
| IDOR | `/IDOR/*` | missing object-level authorization (logic) |
| Missing function-level access control | `/access-control/*` | authorization logic |
| Auth bypass | `/auth-bypass/verify-account` | flawed verification logic |
| CSRF | `/csrf/*` | missing anti-CSRF control (request-level) |
| Spoof cookie | `/SpoofCookie/*` | weak cookie scheme (logic/crypto-misuse) |
| Hijack session | `/HijackSession/login` | predictable session id |
| Insecure login | `/InsecureLogin/*` | credentials over the wire (transport) |
| Password reset | `/PasswordReset/*` | reset-flow logic (some paths send mail via a URL fetch) |
| JWT | `/JWT/*` | token forgery / alg confusion (crypto-misuse). Edge cases: the `kid` lesson does a SQL lookup with the `kid` value and the `jku` lesson fetches a URL, so those two could surface SQLi/SSRF-style findings, verify on the instance |

## How to use this

For the demo, drive the bucket-A routes with `demo/run-exercises.mjs` (benign input) and
confirm Contrast reports them and reports nothing on the bucket-B routes. The verifier
`scripts/verify-findings.mjs` checks exactly that against your route-coverage export. For
breadth and route coverage, `demo/full-coverage-exercise.py` solves nearly every lesson
across all three buckets.
