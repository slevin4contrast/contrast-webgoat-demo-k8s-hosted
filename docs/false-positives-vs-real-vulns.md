# False Positives vs. Real Vulnerabilities in WebGoat

How a runtime (IAST) approach reports real flaws and stays silent on the noise that
guess-based scanners produce. Every row below maps to a real WebGoat v2025.3 endpoint
exercised by `demo/run-exercises.mjs`, with normal, benign input.

## The short version

A legacy SAST/DAST scanner infers vulnerabilities from source patterns or HTTP
responses. It cannot see whether the dangerous code actually ran, so it flags things
that look risky but are not. WebGoat is full of these, because many of its lessons only
*simulate* a vulnerability (they check your input against a pattern and print "Lesson
Passed!").

Contrast Assess instruments the running code. It reports a vulnerability only when
untrusted data actually reaches a dangerous operation during execution. So it reports
WebGoat's real flaws and ignores the simulated ones, no manual triage required. The best
way to handle a false positive is to never generate it.

## Simulated lessons (a legacy scanner flags these, Contrast does not)

These endpoints run no vulnerable code. They evaluate your input with a regular
expression or a string comparison and return a pass/fail message. A scanner that guesses
from the request or response can flag them. Contrast sees that no dangerous sink
executed and stays silent.

| Endpoint | What the code actually does | Why a scanner false-positives | Contrast |
|---|---|---|---|
| `POST /SqlInjectionMitigations/attack10b` | Runs a regex over the *text you submitted* to check whether your answer mentions `PreparedStatement`. No database call. | Sees SQL-looking input and a "SQL" lesson, guesses injection. | No finding |
| `POST /SSRF/task1` | Compares your `url` string to fixed values (`images/jerry.png`). Never opens a connection. | Sees a URL parameter on an "SSRF" lesson, guesses SSRF. | No finding |
| `GET /CrossSiteScripting/attack5a` | Decides success with `String.contains("<script>")`. The value is not rendered to a live HTML sink. | Sees `<script>` reflected in the response body, guesses XSS. | No finding |

This is the false-positive story for the eval. You are not filtering noise in the
Contrast UI. The noise is never created, because the vulnerable code never ran.

## Real vulnerabilities (Contrast reports these from normal use)

These endpoints build a dangerous operation from untrusted input and execute it. No
attack payload is needed. Simply exercising the feature is enough for Contrast to trace
the unsafe dataflow.

| Endpoint | Vulnerability | The actual sink | Contrast |
|---|---|---|---|
| `POST /SqlInjection/attack2` | SQL Injection | `Statement.executeQuery(userQuery)` | Reports |
| `POST /SqlInjection/assignment5a` | SQL Injection | account concatenated into `... last_name = '<input>'` | Reports |
| `POST /SqlInjection/attack8` | SQL Injection | name + auth_tan concatenated into the query | Reports |
| `POST /SqlInjection/attack10` | SQL Injection | term concatenated into a `LIKE '%<input>%'` | Reports |
| `POST /SqlInjectionAdvanced/attack6a` | SQL Injection | last name concatenated into the query | Reports |
| `POST /SqlInjection/assignment5b` | SQL Injection | `login_count` is bound, but `userid` is still concatenated | Reports |
| `GET /SqlInjectionMitigations/servers` | SQL Injection | sort column concatenated into `ORDER BY` | Reports |
| `POST /xxe/simple` | XML External Entity | XML body parsed with external entities enabled | Reports |
| `POST /InsecureDeserialization/task` | Untrusted Deserialization | `ObjectInputStream.readObject()` on request bytes | Reports |
| `POST /VulnerableComponents/attack1` | Vulnerable component | `XStream.fromXML(input)` on a known-vulnerable library | Reports |
| `GET /crypto/hashing/md5` | Weak cryptography | `MessageDigest.getInstance("MD5")` | Reports |
| `POST /SSRF/task2` | SSRF | `new URL(input).openStream()` server-side | Reports |

The contrast with the simulated table is the point. The "SQLi mitigation" lesson
(`attack10b`) and the real SQLi lessons sit in the same WebGoat menu and look similar to
a scanner. Contrast tells them apart because it watches which one actually runs a query.

## Safe by design (a true negative, not a miss)

| Endpoint | Why it is safe | Contrast |
|---|---|---|
| `POST /SqlInjectionMitigations/attack12a` | Fully parameterized `PreparedStatement`, every value bound with `setString` | No finding |

Exercising this route and getting nothing is a feature. Contrast inspected the parameter,
saw it could not influence the query structure, and correctly reported nothing to triage.

## Why this matters for the evaluation

A false-positive count only makes sense relative to a tool that produces false positives.
A guess-based scanner will flag the simulated lessons above and the burden lands on your
team to investigate and dismiss each one. Contrast reports the real flaws and the safe
code stays quiet, so the triage queue starts smaller and cleaner.

You can confirm every claim here against a live run. Deploy with `scripts/setup.sh`, run
`demo/run-exercises.mjs`, and compare the Contrast findings to the tables above.

---

*Internal note: this is external-facing collateral. Verify the specific findings against
the live Contrast instance and current product behavior before sharing, and route it
through the appropriate review before distributing to a prospect.*
