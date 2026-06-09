# True positives, false positives, and the WebGoat trap

This explains two separate things, and keeps them separate on purpose.

1. What we can prove: every vulnerability Contrast reports in this demo is a true
   positive, and nothing is reported on a route that has no real vulnerability.
2. What we can reason about but not measure here: the classes of false positive that
   other tool *techniques* tend to produce, and why a runtime Java agent avoids them.

We do not assert how many false positives any specific competing product would produce.
That number only exists if you actually run that product against the same target. Where
this matters for the evaluation, we make a technique-based argument, not a measured claim
about a named tool.

## Why Contrast reports a finding, or stays silent (the mental model)

This is the single idea to hold in your head on a call. Contrast Assess is a runtime
agent. It reports a vulnerability when, and only when, it **observes untrusted data reach a
real security sink during actual execution**, without being neutralized on the way. Untrusted
data means a tracked source such as a request parameter, header, body, cookie, or uploaded
filename. A real sink means a dangerous operation such as `Statement.executeQuery`,
`ObjectInputStream.readObject`, `new URL(..).openStream`, a file path built from input, a weak
`MessageDigest`, or a server-side HTML render. Every finding carries its own proof, the exact
request, the line of code, and the source-to-sink dataflow, so you can open it and check it.

That single rule explains every "yes" and every "no" in this demo. The silences are not gaps,
they are the agent being correct.

| Contrast does this | Because | WebGoat example |
|---|---|---|
| **Reports** a finding | tainted data was observed reaching a real sink during execution | the 21 confirmed true positives (SQLi, XXE, path traversal, deserialization, weak hash, server-side stored XSS) |
| Stays silent, **code never ran** | the vulnerable line did not execute, so there was nothing to observe | `VulnerableComponents/attack1`: XStream 1.4.5 cannot initialize on JDK 23, the route 500s before `fromXML` completes. The vulnerable library still shows in Runtime SCA. |
| Stays silent, **input never reached the sink** | a guard, required-parameter check, or validation rejected the request first | `SqlInjectionMitigations/servers` with no `column` param returns 400. `SSRF/task2` does not call `openStream` unless the URL exactly matches `http://ifconfig.pro`. |
| Stays silent, **data was neutralized** | the input was parameterized or encoded before the sink, a true negative | `attack12a` uses a `PreparedStatement`. `attack6b` compares with `.equals` over a constant query. |
| Stays silent, **no server-side sink** | the vulnerability executes in the browser, there is nothing server-side to trace | the SPA lesson XSS, returned as JSON and rendered client-side. Protect still flags the inbound payload as an attack. |
| Stays silent on the *dataflow* rules, **not a dataflow class** | the bug is authorization or logic, not source-to-sink. Note Contrast still has control rules for some of these (it has a dedicated CSRF rule, plus cookie and session rules), so "not a dataflow finding" is not the same as "Contrast can't detect it" | IDOR, access-control, JWT forgery are the genuinely logic-only cases. A tool that called these "injection" would be the one producing false positives. |
| Stays silent, **lesson is simulated** | the endpoint only runs a regex, `contains`, `equals`, or quiz check, no vulnerable code | `attack10a/10b`, `SSRF/task1`, the `LogSpoofing` lesson. |

A real finding can also be **absent from a particular export for operational reasons, not
detection reasons**. Treat these as "drive it again," not "Contrast missed it":

- **Coverage.** The route was loaded but not exercised with input that reaches the sink. The
  `servers` case above is exactly this, and the fix was to send the `column` parameter.
- **Attribution.** The finding exists but the route-coverage export does not attach it to that
  route, or it lives in a separate context. The WebWolf mail stored XSS is real and in the
  vulnerabilities export, yet it does not appear against a WebGoat route in route coverage.
  Check the vulnerabilities list, not just route coverage.
- **Environment.** An outbound sink cannot complete because the pod has no network egress. The
  SSRF route is the candidate, give the pod egress or point the URL at an in-cluster address.

And the Protect (ADR) side is the mirror image. Protect inspects **inbound requests** at runtime
and flags or blocks attack payloads (SQLi strings, `<script>`, `../`, XXE doctypes) whether or
not the underlying code is vulnerable. So Protect can light up on a route where Assess is
correctly silent, the SPA XSS is the clearest case. In monitor mode the request completes and
the attack is logged, in block mode Contrast returns 403/406.

## 1. Vetting that Contrast's findings are true positives

Contrast Assess reports a vulnerability only when it observes untrusted data reach a
security-sensitive sink during real execution, and each finding carries its own proof:
the exact HTTP request, the line of code, and the data flow from source to sink. So each
one is independently checkable.

For this demo we mapped every reported route to the actual vulnerable sink in the OWASP
WebGoat v2025.3 source. These are unambiguous true positives. The per-finding evidence basis
(which sinks we read in source, which are verified by the HTTP response, and which still need a
quick UI confirmation) is recorded in
[`findings-verification-ledger.md`](findings-verification-ledger.md).

A few representative cases (the complete list lives elsewhere, see below):

| Route | Vulnerability | The sink that executes (WebGoat source) |
|---|---|---|
| `POST /SqlInjection/attack2` | SQL Injection | user-supplied string passed to `Statement.executeQuery` |
| `POST /SqlOnlyInputValidation/attack` | SQL Injection | input validated (spaces rejected), then concatenated into `executeQuery`, validation is not a fix |
| `POST /xxe/simple` | XXE | XML body parsed with external entities enabled |
| `POST /InsecureDeserialization/task` | Untrusted deserialization | `ObjectInputStream.readObject()` on request bytes |
| `POST /PathTraversal/profile-upload-fix` | Path traversal | the "fix" is a single-pass `replace("../","")`, defeated by `....//` |
| `GET /WebWolf/mail` | Stored XSS (server-side) | WebWolf renders the attacker-controlled email body into HTML server-side |

The `SqlOnlyInputValidation` row is the sharpest example: the lesson validates the input, yet the
underlying query is still concatenated, so the vulnerability is real and Contrast traces straight
through the filter to the sink. A tool that reasoned "input is validated, therefore safe" would
miss it. The `profile-upload-fix` row makes the same point for a bypassable sanitizer.

To avoid repeating the same lists in three places, this doc stays focused on the argument. The
two complete references are: the full route-by-route inventory in
[`webgoat-vuln-classification.md`](webgoat-vuln-classification.md), and the per-finding evidence
(which sink we read in source, with file and line) in
[`findings-verification-ledger.md`](findings-verification-ledger.md). All 22 confirmed true
positives and the lower-severity real findings (log injection, weak random, hardcoded password,
mass assignment, weak crypto, header/cookie hygiene) are itemized there. None are false positives.

Two we describe carefully so we neither over- nor under-claim:

- **XSS has two cases, and Assess reports one of them.** The WebGoat *lesson* XSS (reflected
  `CrossSiteScripting/attack5a`, stored `CrossSiteScriptingStored/stored-xss`, DOM
  `phone-home-xss`) is **real** but rendered **client-side**: WebGoat is a single-page app, your
  input comes back as JSON and the browser injects it into the DOM, so there's no server-rendered
  HTML sink and server-side Assess generally stays quiet (Protect/ADR still detects the inbound
  payload as an attack). But the **WebWolf mail viewer** stored XSS (`GET /WebWolf/mail`) renders
  the attacker-controlled email body into HTML **server-side**, so Assess *does* report it (it's
  in the export as a High). So the correct line is "Assess is quiet on the SPA lesson XSS, and
  reports the server-side WebWolf mail XSS" — never "Assess reports no XSS in WebGoat." And don't
  present the SPA lesson XSS as a scanner false positive, a browser-based scanner would correctly
  flag it. See [`webgoat-vuln-classification.md`](webgoat-vuln-classification.md) (section A2).
- **Several systemic low-severity findings** appear across many routes (in the export, header and
  cookie-hygiene findings such as CSP, HSTS, X-Content-Type-Options, anti-clickjacking, and the
  `secure` cookie flag show up app-wide, including on the login and lesson-menu pages). These are
  configuration-level findings, not per-route results, and not false positives. Identify what each
  one is before describing it.

### Prove it from your own data

`scripts/verify-findings.mjs` turns the above into a check you run against your instance.
Export the app's Route coverage CSV from the Contrast UI, then:

```bash
node scripts/verify-findings.mjs route-coverage.csv
```

It cross-references every finding against the source-grounded sink map and prints:
confirmed true positives, any finding on a safe or simulated route (a candidate false
positive to investigate, expected to be zero), real routes exercised with no finding
(coverage gaps to verify), and systemic app-wide findings to confirm separately. The
"no false positives" claim then comes from your data, not from this document.

## 2. Why these specific WebGoat routes never produce a Contrast finding

WebGoat includes lessons that only *simulate* a vulnerability. Exercising them produces
nothing in Contrast because no vulnerable code runs. A tool that infers from responses can
flag them.

| Route | What the code actually does | Contrast |
|---|---|---|
| `POST /SqlInjectionMitigations/attack10b` | runs a regex over the text you submit; no database call | no finding |
| `POST /SqlInjectionMitigations/attack10a` | `String.contains` check on submitted text; no database call | no finding |
| `POST /SSRF/task1` | compares your URL to fixed strings; never opens a connection | no finding |

(WebGoat's XSS lessons are intentionally left out of this table, they are real client-side
XSS, not no-vuln lessons; see the XSS note above.)

And one that is the same kind of feature coded safely, a true negative, not a miss:

| Route | Why it is safe | Contrast |
|---|---|---|
| `POST /SqlInjectionMitigations/attack12a` | fully parameterized `PreparedStatement`, all values bound | no finding |
| `POST /SqlInjectionAdvanced/attack6b` | the parameter is compared with `.equals()`; the query is constant | no finding |

## 3. False-positive classes by technique (architectural, not measured)

Framed as tendencies of each approach. Not all tools labeled "IAST" work the same way:
some are runtime instrumentation, others are a scanner driving traffic with a passive
agent, others are static analysis correlated with a scan. A tool inherits the
false-positive behavior of whatever technique it actually uses.

**Response-inference (DAST, or a DAST-driven "IAST").** Infers a vulnerability from the
HTTP response. On WebGoat it tends to flag the simulated lessons above, because the app
returns "Lesson Passed!" or reflects the input and that reads as success. It also tends to
flag error-based guesses (a 500 from a malformed payload read as injection) and reflected
input as XSS even when the output context is safe.

**Static analysis (SAST, or a SAST-plus-scan "IAST").** Analyzes code paths without
running them. It tends to flag infeasible paths, inputs neutralized by a sanitizer or
framework encoder it cannot model, and string handling near SQL even when the call is a
parameterized `PreparedStatement` (the `attack12a` route is the textbook case). It also
tends to flag a library CVE because the vulnerable version is present, without knowing
whether the vulnerable class was ever loaded or called.

**Runtime instrumentation (Contrast's Java agent).** Reports only on observed, unsanitized
data flow into a real sink during execution. That is why the simulated lessons and the
parameterized route produce nothing, and it is the structural reason its false-positive
rate is low. Confirm exact rule semantics with current Contrast documentation or the
product team before stating them to a prospect, and prefer "every finding is evidence
backed and verifiable" over an absolute "zero false positives."

## 4. If you want measured comparison numbers

Run the comparator tool against the *same* WebGoat deployment and diff its findings
against Contrast's. For a response-inference tool, an OWASP ZAP baseline scan is the usual
choice. Without that, do not put a competitor false-positive count on a slide, the
technique-based argument above is defensible, an invented number is not.

---

*Internal: external-facing collateral. Verify findings against the live Contrast instance
and current product behavior, do not state competitor numbers you have not measured, and
route through review before sharing with a prospect. Endpoints reflect OWASP WebGoat
v2025.3.*
