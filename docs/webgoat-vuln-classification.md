# WebGoat v2025.3 — real vulnerabilities vs. simulated lessons

A source-grounded inventory of WebGoat v2025.3 lessons, classified by whether the
endpoint runs genuinely vulnerable code or only *checks* your input. This is the basis
for the false-positive story: a runtime tool (Contrast Assess) reports the real ones and
stays silent on the simulated ones, because it watches code execution rather than
guessing from responses.

This is the complete reference inventory. For the narrative version (how we vet true
positives, and the false-positive classes each tool technique produces), see
[`false-positives-vs-real-vulns.md`](false-positives-vs-real-vulns.md). For the one-paragraph
mental model of why Contrast reports a finding or stays silent, see the
["Why Contrast reports a finding, or stays silent"](false-positives-vs-real-vulns.md#why-contrast-reports-a-finding-or-stays-silent-the-mental-model)
section there.

Each row was checked against the WebGoat v2025.3 source. Three buckets:

- **A. Real, dataflow vulnerabilities** — untrusted input reaches a real sink. Contrast
  Assess traces these. This is the strong demo set.
- **B. Simulated lessons** — the endpoint only runs a regex / `String.contains` /
  `.equals` / quiz comparison. No vulnerable code executes. A guess-based scanner can
  flag these (false positives); Contrast does not.
- **C. Real flaws that are not injection/dataflow vulns** — genuine vulnerabilities that are
  authorization, session, or logic issues. Important: Contrast is not only a dataflow engine, it
  also has dedicated control/configuration rules, so it *does* report some of these (for example
  Cross-Site Request Forgery, cookie-flag and session rules). What no automated tool reliably
  finds is the pure business-logic and authorization class (IDOR, function-level access control,
  auth-bypass logic, JWT forgery). See bucket C for which is which.

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
| `POST /SqlOnlyInputValidation/attack` | **input-validation "mitigation" that is still vulnerable** — rejects spaces, then calls `SqlInjectionLesson6a.injectableQuery()`, which concatenates into `executeQuery`. The filter is bypassable; the sink is real. |
| `POST /SqlOnlyInputValidationOnKeywords/attack` | same pattern — strips `FROM`/`SELECT`, then the same concatenated `executeQuery`. Validation is not parameterization, and Contrast traces straight through the filter to the sink. |

The two `SqlOnlyInputValidation*` rows are a strong demo moment: the lesson *looks* mitigated
(it validates input) but the underlying query is still built by string concatenation, so the
vulnerability is real and Contrast reports it. A tool that judged "input is validated, so it's
safe" would miss it. (Verified in v2025.3 source: both delegate to `injectableQuery`.)

### Other injection / crypto / runtime classes

| Route(s) | Class | Sink |
|---|---|---|
| `POST /xxe/simple`, `/xxe/content-type`, `/xxe/blind` | XXE | untrusted XML parsed with the hardening branch disabled (`parseXml(.., false)`) |
| `POST /InsecureDeserialization/task` | Untrusted deserialization | `ObjectInputStream.readObject()` on request bytes |
| `POST /VulnerableComponents/attack1` | Vulnerable component | `XStream.fromXML(input)` on a known-vulnerable library |
| `GET /crypto/hashing/md5`, `/crypto/hashing/sha256`, `POST /crypto/hashing` | Insecure Hash Algorithms (Contrast rule) | `MessageDigest` with MD5 / SHA-1 |
| `POST /SSRF/task2` | SSRF | `new URL(input).openStream()` server-side |
| `POST /PathTraversal/profile-upload`, `/profile-upload-remove-user-input` | Path traversal | user `fullName` / filename used to build the write path |
| `POST /PathTraversal/profile-upload-fix` | Path traversal (incomplete fix) | the "fix" is a single-pass `fullName.replace("../","")`, which `....//` defeats, so the sink is still reachable (verified in v2025.3 source) |
| `GET /PathTraversal/random-picture` | Path traversal **and Header Injection** | `id` builds a file path (traversal, CWE-22) and is reflected into the `Location` response header via `.location(new URI(".../?id=" + ...))` (header injection, CWE-113) |
| `POST /PathTraversal/zip-slip` | Zip slip (path traversal) | archive entry name used to write outside the target dir |
| `POST /WebWolf/fileupload` | Path traversal | uploaded filename builds the stored path (WebWolf module) |

Findings reported in the 2026-06-09 export but not source-verified here (open the trace in
the UI to see the exact sink): SQL Injection on `/SqlInjectionAdvanced/register` and
`/register.mvc` (registration), and the WebWolf stored XSS below. Each carries its own
request + dataflow proof in Contrast, which is itself ground truth.

### Configuration and code-level findings Assess also reports

These are real findings the agent raises beyond the injection/dataflow headline. They are not
false positives, but they are lower severity and partly app-wide. Confirm each in the UI.

The header and cookie-hygiene findings are a direct, verifiable consequence of WebGoat's config:
`WebSecurityConfig` calls `.headers(headers -> headers.disable())`, which turns off Spring's
security headers, so the responses genuinely lack CSP, HSTS, X-Content-Type-Options, and the
rest. Contrast reports exactly what is missing. This is a good thing to show, the finding maps to
a real line of configuration.

| Class | Where it showed (2026-06-09 export) | Note |
|---|---|---|
| Log Injection (Note) | `/WebWolf/landing/password-reset`, `/WebWolf/fileupload`, `/register.mvc` | untrusted input reaches a logging call. This is *not* the `LogSpoofing` lesson (that one is a string check, see bucket B) — it's incidental logging elsewhere. |
| Hardcoded Password (Medium) | code-level (no single route) | credential literal in source |
| Weak Random Number Generation (Note) | `/challenge/7`, `/csrf/basic-get-flag`, `crypto/*` | `java.util.Random` used where security-relevant |
| Unchecked Spring Autobinding (Medium) | `/registration`, `/PasswordReset/reset/change-password` | mass-assignment / over-binding |
| Insecure Encryption Algorithms (Note) | `/WebWolf/jwt/encode` | weak/!AEAD cipher use |
| Insecure Hash Algorithms (Medium) | `/crypto/hashing/md5`, `/login` | MD5 / SHA-1 |
| Header & cookie hygiene (Note/Medium) | app-wide | CSP, HSTS, X-Content-Type-Options, X-XSS-Protection, anti-clickjacking, anti-caching, autocomplete, `secure` cookie flag, parameter pollution |

True negative worth showing: `POST /SqlInjectionMitigations/attack12a` is the same kind
of lookup written safely (fully parameterized `PreparedStatement`), so Contrast reports
nothing. Exercising it and getting no finding is the point, not a miss.

### Three real routes that can show no finding (coverage notes, not detection gaps)

Routes that were blank in an early run but are explained (none is a Contrast miss, and two now
fire after a fix or with the right input):

- `GET /SqlInjectionMitigations/servers` — real `order by " + column` concatenation, but
  `column` is a **required** request param. The earlier full-coverage solver hit the route
  with no `column`, so WebGoat returned HTTP 400 and the sink never ran. Fixed in
  `demo/full-coverage-exercise.py` (now sends `?column=hostname`); it fires after the fix.
- `POST /VulnerableComponents/attack1` — **this one now fires as Untrusted Deserialization,
  and how it fires is a great IAST story.** The full-coverage solver throws a heavy XStream RCE
  gadget, which fails to initialize on JDK 23 (XStream 1.4.5) and returns 500, so the exploit
  does not complete. But the curated benign run sends simple XML that reaches `XStream.fromXML`,
  and Contrast traces the deserialization sink from that alone. The working exploit found
  nothing; benign functional use found the vulnerability. The vulnerable library also appears in
  Runtime SCA. If you see no finding, drive the route with simple XML rather than a gadget.
- `POST /SSRF/task2` — `new URL(url).openStream()` only runs when `url` exactly matches
  `http://ifconfig.pro`; the solver sends that, so the sink is invoked. If the pod has no
  outbound network the call throws and WebGoat still returns success. Check the UI
  vulnerabilities list directly: like the WebWolf finding, an SSRF finding may exist without
  being attached to this route in the route-coverage export. Give the pod egress (or point
  the URL at an in-cluster address) if you need the outbound call to complete cleanly.

## A2. XSS: client-side lessons (Assess quiet) vs. the server-side WebWolf mail finding (Assess reports)

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

**Important exception — WebWolf mail stored XSS, which Assess DOES report.** Separate from the
SPA lessons above, the 2026-06-09 export contains a real **Stored Cross-Site Scripting**
finding (High) on `GET /WebWolf/mail`. WebWolf's mailbox renders the attacker-controlled email
body **server-side** into HTML, so there is a real server-rendered sink and Contrast Assess
traces it. So the accurate statement is: Assess stays quiet on the *client-side SPA lesson* XSS,
but it does report the *server-side* stored XSS in the WebWolf mail viewer. Do not tell a
prospect "Assess never reports XSS in WebGoat" — it reports this one. (Confirmed by the Contrast
trace; open the finding to see the render sink.)

Verify on your instance: if no XSS *vulnerability* appears in Assess for the SPA lesson routes
but XSS *attacks* do appear in Protect, that's expected for WebGoat's architecture, not a missed
real bug — while the WebWolf mail stored XSS should appear as an Assess vulnerability.

## B. Simulated lessons (no vulnerable code — the WebGoat trap)

These decide success with a regex / `contains` / `equals` / quiz comparison. No
vulnerable code runs, so there is nothing for a runtime tool to trace. A scanner that
infers from the response can flag them.

| Route(s) | What it actually does |
|---|---|
| `POST /SqlInjectionMitigations/attack10a`, `/attack10b` | regex / `contains` over *submitted code text*; no DB call |
| `POST /SqlInjectionAdvanced/attack6b` | `userid_6b.equals(password)`; the query is a constant |
| `POST /SSRF/task1` | string-compares the URL to fixed values; never connects |
| `POST /CrossSiteScripting/attack1`, `/attack6a`, `/dom-follow-up` | checkbox / route / success-message checks (the lesson's pass/fail gates) |
| `POST /CrossSiteScripting/attack3`, `/attack4` | regex over submitted JSP / AntiSamy *code* (code-review checks) |
| `POST /LogSpoofing/log-spoofing` | `replace("\n",...)` + `contains` check on echoed text; no logger sink. **Note:** this *lesson* is simulated, but real Log Injection findings appear elsewhere in the app (WebWolf, registration) where input genuinely reaches a logger — see bucket A. |
| `/csrf/*` (basic-get-flag, review, feedback, login) | the CSRF *lessons* gate success on a `Referer` string check and a hardcoded weak token; they do not perform a real, protected state change. The Contrast Assess team confirmed "the CSRF page isn't real," so the CSRF rule correctly stays quiet here. The real CSRF target is `register.mvc`, see bucket C1. |
| `crypto/encoding/basic`, `/basic-auth`, `/xor`, `/secure/defaults`, `/signing/verify` | base64 / `.equals` / format checks (only `crypto/hashing` is a real weak-hash) |
| Quizzes: `cia/quiz`, `SqlInjectionAdvanced/quiz`, `CrossSiteScripting/quiz`, `JWT/quiz`, `HttpBasics/attack2` | multiple-choice answer comparison |
| `HttpBasics/attack1`, `ChromeDevTools/*`, `HttpProxies/*`, `SecurePasswords/assignment`, `lesson-template/*`, `BypassRestrictions/*`, `ClientSideFiltering/*`, `HtmlTampering/task` | teaching/echo/validation checks |

## C. Real flaws that are not injection/dataflow vulns

These WebGoat lessons are authorization, session, or logic issues, not data flowing into an
injection or crypto sink, so they would not show up as a dataflow finding (SQLi, XXE, and so on).
But that does **not** mean Contrast ignores them. Contrast also ships control and configuration
rules, so some of these *do* have a matching Contrast rule. The table splits them.

C1. Contrast has a dedicated rule for these (it can report them, separate from dataflow):

| Lesson area | Routes | Matching Contrast rule |
|---|---|---|
| CSRF | `POST /register.mvc` (the real target), not `/csrf/*` | **Cross-Site Request Forgery** (High). WebGoat disables Spring CSRF app-wide (`.csrf().disable()`), so a genuine state-changing request with no token is unprotected. The Contrast Assess team confirmed the rule fires on `register.mvc`, because registration is a real DB write, and correctly does not fire on the `/csrf/*` lessons, which are simulated (Referer plus hardcoded-token checks, not a real protected operation). The trigger is a bare form-style POST without the `X-Requested-With` header. |
| Spoof cookie / session cookies | `/SpoofCookie/*` | cookie rules: **Application Disables 'secure' Flag on Cookies**, **Session Cookie Has No 'HttpOnly' Flag** (the `secure`-flag one did fire in our export) |
| Hijack session | `/HijackSession/login` | session rules: **Session Rewriting**, **Overly Long Session Timeout** (the predictable-id weakness itself is logic, see C2) |
| Insecure login | `/InsecureLogin/*` | **Insecure Authentication Protocol**, **Insecure SSL Socket Creation** (transport-level) |

C2. Genuinely out of scope for automated detection (business logic / authorization, no tool
reliably finds these without understanding intent):

| Lesson area | Routes | Why it needs human review |
|---|---|---|
| IDOR | `/IDOR/*` | missing object-level authorization (logic) |
| Missing function-level access control | `/access-control/*` | authorization logic |
| Auth bypass | `/auth-bypass/verify-account` | flawed verification logic |
| Hijack session (predictability) | `/HijackSession/login` | judging that a session id is *predictable* is analysis, not a sink |
| Password reset | `/PasswordReset/*` | reset-flow logic (though related findings did fire here: hardcoded password, weak random, mass assignment) |
| JWT | `/JWT/*` | token forgery / alg confusion (crypto-misuse logic). Edge cases: the `kid` lesson does a SQL lookup with the `kid` value and the `jku` lesson fetches a URL, so those two could surface SQLi/SSRF-style findings, verify on the instance |

## Contrast Assess rule coverage in this deploy

Important framing for the call. Contrast Assess ships a large catalog of rules (NoSQL, JNDI,
Hibernate, LDAP, XPath, OS command, expression-language injection, GraphQL controls, and many
more). This WebGoat deploy exercises **22 of them** across the two exercise scripts combined,
because WebGoat is a Spring + JDBC app and most other categories have no matching code path to
observe. The number of findings here is bounded by the target, not by Contrast. Do not present
"22 rule types" as Contrast's ceiling.

The 22 rule types observed in this deploy (exact Contrast rule names and severities):

| Severity | Contrast rule |
|---|---|
| Critical | SQL Injection |
| High | Path Traversal |
| High | XML External Entity Injection (XXE) |
| High | Stored Cross-Site Scripting |
| High | Untrusted Deserialization |
| High | Header Injection |
| Medium | Unchecked Spring Autobinding |
| Medium | Insecure Hash Algorithms |
| Medium | Application Disables ''secure'' Flag on Cookies |
| Medium | Hardcoded Password |
| Note | Log Injection |
| Note | Weak Random Number Generation |
| Note | Insecure Encryption Algorithms |
| Note | Parameter Pollution |
| Note | Forms Without Autocomplete Prevention |
| Note | Anti-Caching Controls Missing |
| Note | Pages Without Anti-Clickjacking Controls |
| Note | Response With X-XSS-Protection Disabled |
| Note | Response Without X-Content-Type-Options Header |
| Note | Response Without Content-Security-Policy Header |
| Note | Response With Insecurely Configured Content-Security-Policy Header |
| Note | Response With Insecurely Configured Strict-Transport-Security Header |

Note: Header Injection and Untrusted Deserialization on `VulnerableComponents/attack1` came from
the curated functional exercise (`run-exercises.mjs`), not the full-coverage solver. The two
scripts are complementary, run both for the widest coverage.

Rules WebGoat *does* have a lesson for but that did not surface in our export, each for a
different reason:

- **Cross-Site Scripting** (Medium) — the reflected SPA lesson renders client-side, so Assess
  is quiet and Protect catches the inbound payload. (Distinct from **Stored Cross-Site
  Scripting** (High), which *did* fire on the server-side WebWolf mail render, see section A2.)
- **Server-Side Request Forgery** (Medium) — the egress / attribution case on `SSRF/task2`.
- **Cross-Site Request Forgery** (High) — did not surface on the `/csrf/*` lessons because those
  are simulated (the Assess team confirmed "the CSRF page isn't real"). It DOES fire on the real
  target, `register.mvc`, a genuine unprotected state-changing DB write. See the resolved CSRF
  note below.

Contrast splits XSS into two rules, **Stored Cross-Site Scripting** (High) and **Cross-Site
Scripting** (Medium), which is exactly the distinction in section A2.

## CSRF — resolved, and Hardcoded Cryptographic Key — open

**Cross-Site Request Forgery (High) — resolved.** The Contrast Assess team confirmed the rule
fires on `register.mvc`, because registration is a real, unprotected, state-changing DB write
(WebGoat disables Spring CSRF app-wide). It correctly does not fire on the `/csrf/*` lessons,
which are simulated (Referer and hardcoded-token checks, not a real protected operation). The
trigger is a bare form-style POST to `register.mvc` without the `X-Requested-With` header. Our
solver's main registration is already a bare POST, so a fresh run should surface it. If it does
not appear on our instance, compare the agent version and applied policy with the peer instance
where it fired, rather than changing the exercise. Earlier hypotheses about a disabled
`CsrfFilter` blocking the rule were wrong, the rule keys on the real state-changing request.

**Hardcoded Cryptographic Key (Medium) — open.** `JWTSecretKeyEndpoint` holds a hardcoded
`SECRETS` array used as the HS256 signing key, and the script calls `/JWT/secret/gettoken`, so
the signing code runs, yet no finding appears. The likely reason is that the key is a plain
`String` handed to jjwt's `signWith`, not a `javax.crypto.spec.SecretKeySpec` or `KeyGenerator`,
so it may not match the rule's sink pattern. The hardcoded **password** rule did fire, so
hardcoded-secret detection works in general. Confirm the rule is enabled in the policy, and if so
raise the jjwt String-key case with the product team. This is a rule-pattern question, not a
coverage gap.

## How to use this

For the demo, drive the bucket-A routes with `demo/run-exercises.mjs` (benign input) and
confirm Contrast reports them and reports nothing on the bucket-B routes. The verifier
`scripts/verify-findings.mjs` checks exactly that against your route-coverage export. For
breadth and route coverage, `demo/full-coverage-exercise.py` solves nearly every lesson
across all three buckets.
