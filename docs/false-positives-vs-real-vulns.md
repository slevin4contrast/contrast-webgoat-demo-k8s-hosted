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

## 1. Vetting that Contrast's findings are true positives

Contrast Assess reports a vulnerability only when it observes untrusted data reach a
security-sensitive sink during real execution, and each finding carries its own proof:
the exact HTTP request, the line of code, and the data flow from source to sink. So each
one is independently checkable.

For this demo we mapped every reported route to the actual vulnerable sink in the OWASP
WebGoat v2025.3 source. These are unambiguous true positives.

| Route | Vulnerability | The sink that executes (WebGoat source) |
|---|---|---|
| `POST /SqlInjection/attack2` | SQL Injection | user-supplied string passed to `Statement.executeQuery` |
| `POST /SqlInjection/attack8` | SQL Injection | `name` + `auth_tan` concatenated into the query |
| `POST /SqlInjection/assignment5a` | SQL Injection | input concatenated into `... last_name = '<input>'` |
| `POST /SqlInjection/assignment5b` | SQL Injection | `userid` concatenated (only `login_count` is bound) |
| `POST /SqlInjectionAdvanced/attack6a` | SQL Injection | last name concatenated into the query |
| `GET /SqlInjectionMitigations/servers` | SQL Injection | sort column concatenated into `ORDER BY` |
| `POST /xxe/simple`, `/xxe/blind` | XXE | XML body parsed with external entities enabled |
| `POST /InsecureDeserialization/task` | Untrusted deserialization | `ObjectInputStream.readObject()` on request bytes |
| `POST /VulnerableComponents/attack1` | Vulnerable component | `XStream.fromXML(input)` |
| `GET /crypto/hashing/md5` | Weak cryptography | `MessageDigest.getInstance("MD5")` |
| `POST /SSRF/task2` | SSRF | `new URL(input).openStream()` server-side |

This table is a representative subset of the headline cases. For the complete v2025.3
lesson-by-lesson inventory (every real, simulated, and logic-only lesson), see
[`webgoat-vuln-classification.md`](webgoat-vuln-classification.md).

Two we deliberately do not overclaim:

- **XSS** (reflected `CrossSiteScripting/attack5a`, stored `CrossSiteScriptingStored/stored-xss`,
  DOM `phone-home-xss`) is **real** but rendered client-side. WebGoat is a single-page app:
  your input comes back in a JSON response and the browser injects it into the DOM, so the
  payload executes in the browser, not via a server-rendered HTML sink. Server-side Assess
  therefore generally does not report it (Protect/ADR does detect the inbound payload as an
  attack). Do not present WebGoat XSS as a scanner false positive, a browser-based scanner
  would correctly flag it. See [`webgoat-vuln-classification.md`](webgoat-vuln-classification.md) (section A2).
- **A systemic low-severity finding** may appear across many routes (in a sample export,
  a single "Note" finding showed up on most routes including the login and lesson-menu
  pages). That is a configuration-level finding, not a per-route result, and not a false
  positive. Identify what it is before describing it.

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
