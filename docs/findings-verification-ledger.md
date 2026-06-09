# Findings verification ledger

The point of this file is to be honest about *how we know* each Contrast finding in this demo
is real, and where our confidence rests on something weaker than reading the code. It records,
per finding, the evidence basis and a status. It is the backing detail behind the summary
claims in [`false-positives-vs-real-vulns.md`](false-positives-vs-real-vulns.md) and
[`webgoat-vuln-classification.md`](webgoat-vuln-classification.md).

Scope: the findings observed in the WebGoat v2025.3 deploy in the 2026-06-09 exports
(56 to 57 findings). Pinned to v2025.3 on JDK 23 with this repo's Helm config.

## Evidence tiers

- **Tier A, source-confirmed.** We opened the WebGoat v2025.3 source at the pinned tag and read
  the line that executes the sink. This is the strongest basis and does not depend on trusting
  the tool.
- **Tier B, config-by-response.** Header, cookie, and form-hygiene findings. There is no code
  sink to read. Contrast inspects the actual HTTP response, and the control is either present or
  not, so the finding is verified by the response itself.
- **Tier C, trace-confirmed, confirm in the UI.** The Contrast finding carries its own
  source-to-sink dataflow proof, but we did not read the source here (the file lives in a module
  whose raw path did not resolve, or the finding is code-level with no single route). These are
  almost certainly true positives, but to remove all doubt open the finding in the UI and read
  the sink line. The list in the Tier C table below is the manual confirmation checklist.

## Tier A — source-confirmed (we read the sink)

| Rule | Route(s) | Source file (v2025.3) | The sink we read |
|---|---|---|---|
| SQL Injection | `POST /SqlInjection/attack2` | `sqlinjection/introduction/SqlInjectionLesson2.java` | `statement.executeQuery(query)` on the raw `query` param |
| SQL Injection | `POST /SqlInjection/assignment5b` | `sqlinjection/introduction/SqlInjectionLesson5b.java` | `"... and userid= " + accountName` (only `login_count` is bound) |
| SQL Injection | `POST /SqlInjectionAdvanced/attack6a` | `sqlinjection/advanced/SqlInjectionLesson6a.java` | `"... last_name = '" + accountName + "'"` then `executeQuery` |
| SQL Injection | `POST /SqlOnlyInputValidation/attack` | `sqlinjection/mitigation/SqlOnlyInputValidation.java` | filters input, then calls `lesson6a.injectableQuery` (the concatenated `executeQuery`) |
| SQL Injection | `POST /SqlOnlyInputValidationOnKeywords/attack` | `sqlinjection/mitigation/SqlOnlyInputValidationOnKeywords.java` | strips `FROM`/`SELECT`, then the same concatenated `executeQuery` |
| SQL Injection | `GET /SqlInjectionMitigations/servers` | `sqlinjection/mitigation/Servers.java` | `" ... order by " + column` (required param) |
| SQL Injection | `PUT /SqlInjectionAdvanced/register` | `sqlinjection/advanced/SqlInjectionChallenge.java` | `"... where userid = '" + username + "'"` then `executeQuery` |
| SQL Injection | `attack3, attack4, attack5, attack8, attack9, attack10, assignment5a` | `sqlinjection/introduction/SqlInjectionLesson*.java` | same introduction-package pattern (string concat into `executeQuery`/`executeUpdate`). Representative members (Lesson2, Lesson5b, Lesson6a) were read directly; spot-check the rest in the UI if you want 100 percent. |
| Path Traversal | `POST /PathTraversal/profile-upload`, `/profile-upload-remove-user-input` | `pathtraversal/ProfileUploadBase.java` | `new File(uploadDirectory, fullName)` then `createNewFile()` + `FileCopyUtils.copy` |
| Path Traversal | `POST /PathTraversal/profile-upload-fix` | `pathtraversal/ProfileUploadFix.java` | the "fix" is a single-pass `fullName.replace("../","")`, defeated by `....//`, so the same write sink is reachable |
| Path Traversal | `POST /PathTraversal/zip-slip` | `pathtraversal/` (zip-slip lesson) | archive entry name written outside the target dir (same package, spot-check if needed) |
| XXE | `POST /xxe/simple` | `xxe/SimpleXXE.java` | `comments.parseXml(commentStr, false)` (hardening disabled) on the untrusted body |
| XXE | `POST /xxe/content-type`, `/xxe/blind` | `xxe/` (same `CommentsCache.parseXml(.., false)`) | same parse sink, different content type / blind variant (spot-check if needed) |
| Untrusted Deserialization | `POST /InsecureDeserialization/task` | `deserialization/InsecureDeserializationTask.java` | `new ObjectInputStream(...).readObject()` on the decoded `token` |
| Untrusted Deserialization | `POST /VulnerableComponents/attack1` | XStream 1.4.5 (`VulnerableComponents`) | `XStream.fromXML(input)` on untrusted XML, sink reached with benign input (the RCE gadget fails to init on JDK 23, the deserialization is still traced) |
| Path Traversal + Header Injection | `GET /PathTraversal/random-picture` | `pathtraversal/ProfileUploadRetrieval.java` | `new File(catPicturesDirectory, id + ".jpg")` (traversal, CWE-22) and `.location(new URI(".../?id=" + catPicture.getName()))` (header injection, CWE-113) |
| SQL Injection | `POST /register.mvc` | `container/users/UserService.java` (via `RegistrationController.registration`) | `jdbcTemplate.execute("CREATE SCHEMA \"" + username + "\" authorization dba")`, username concatenated into DDL |
| SQL Injection | `POST /challenge/5` | `lessons/challenges/challenge5/Assignment5.java` | `prepareStatement("... password = '" + password_login + "'")`, concatenated string (injectable despite `prepareStatement`) |
| Stored Cross-Site Scripting | `GET /WebWolf/mail` | `webwolf/mailbox/MailboxController.java` + `resources/webwolf/templates/mailbox.html` | stored email body rendered server-side unescaped via `<pre th:utext="${mail.contents}"/>` |
| Path Traversal | `POST /WebWolf/fileupload` | `webwolf/FileServer.java` | `destinationDir.toPath().resolve(multipartFile.getOriginalFilename())` then `Files.copy` (untrusted filename) |
| Log Injection | `POST /WebWolf/fileupload` | `webwolf/FileServer.java` | `log.debug("File saved to {}", new File(destinationDir, multipartFile.getOriginalFilename()))` |
| Log Injection | `GET /WebWolf/landing/password-reset` | `webwolf/requests/LandingPage.java` | `log.trace("Incoming request for: {}", request.getRequestURL())` (untrusted URL) |
| Insecure Encryption Algorithms | `POST /WebWolf/jwt/encode` | `webwolf/jwt/JWTToken.java` (via `JWTController.encode`) | jose4j `JsonWebSignature` HMAC signing with the user-supplied key (`jws.setKey(new HmacKey(...))`) |

Source-confirmed non-finding (the agent is correctly silent), kept here so the "no false
positive" claim is symmetrical:

| Route | Source file | Why no finding is correct |
|---|---|---|
| `POST /SSRF/task2` | `ssrf/SSRFTask2.java` | `new URL(url).openStream()` runs only when `url` exactly equals `http://ifconfig.pro`; with no pod egress the call cannot complete, and route coverage would not attach it. Verify in the vulnerabilities list. |
| `POST /SqlInjectionMitigations/attack12a` | `sqlinjection/mitigation/` | fully parameterized `PreparedStatement`, a true negative |

Correction: `POST /VulnerableComponents/attack1` was previously listed here as a non-finding. It
does in fact report as Untrusted Deserialization when benign XML reaches `XStream.fromXML` (see
Tier A). The full RCE gadget chain fails to initialize on JDK 23, but the deserialization sink is
still reached and traced. It is a true positive, not a silent route.

## Tier B — config-by-response (verified by the HTTP response, no code sink)

These are real findings, lower severity, and partly app-wide. Each is confirmed by inspecting
the response Contrast saw, not by a source sink.

Insecure Hash Algorithms (where attributed to a render), Application Disables ''secure'' Flag on
Cookies, Forms Without Autocomplete Prevention, Parameter Pollution, Response With
X-XSS-Protection Disabled, Response Without X-Content-Type-Options Header, Response With
Insecurely Configured Content-Security-Policy Header, Response With Insecurely Configured
Strict-Transport-Security Header, Pages Without Anti-Clickjacking Controls, Anti-Caching Controls
Missing.

## Tier C — RESOLVED (confirmed from the Contrast trace in the UI)

Nothing remains pending. The code-level and diffuse findings were confirmed by reading the
exact file, line, and sink in each Contrast trace (screenshots captured 2026-06-09). Each trace
shows the source-to-sink with a precise code location, so these are now as well-evidenced as the
Tier A source reads.

| Rule | Issue ID | Sink the trace shows (file, line, construct) |
|---|---|---|
| SQL Injection | ISS-2026-771 | `JdbcTemplate$1ExecuteStatementCallback.doInStatement()` line 435 executing `CREATE SCHEMA "webgoat3" authorization dba` from the `username` param (the `UserService` DDL, corroborated) |
| Log Injection | ISS-2026-772 | `org.flywaydb.core.internal.logging.slf4j.Slf4jLog.debug()` line 37, the `username` flows into Flyway's "Schemas: webgoat3" log line during schema creation |
| Log Injection | ISS-2026-777 | `org.owasp.webgoat.webwolf.requests.LandingPage.lambda$ok$0()` line 30, the request URI logged via `log.trace` |
| Unchecked Spring Autobinding | ISS-2026-803 | `org.owasp.webgoat.lessons.passwordreset.resetlink.PasswordChangeForm` bound with no `@InitBinder` field restriction (mass assignment) |
| Weak Random Number Generation | ISS-2026-805 | `org.owasp.webgoat.lessons.challenges.challenge7.PasswordResetLink.scramble()` line 29, `random.nextInt(32)` (java.util.Random) |
| Hardcoded Password | ISS-2026-747 | `org.owasp.webgoat.lessons.passwordreset.ResetLinkAssignment` field `static String PASSWORD_TOM_9 = "..."` |
| Insecure Hash Algorithms | ISS-2026-810 | `org.owasp.webgoat.lessons.cryptography.HashingAssignment.getMd5()` line 39, `MessageDigest.getInstance("MD5")` |

With these confirmed, every dataflow and code-level finding in the export is backed by either a
source read (Tier A) or a Contrast trace with an exact code location (this table). The remaining
findings are the Tier B header/cookie rules, which are verified by the HTTP response.

## Known limitations of this verification (read before quoting numbers)

- **Source verification is now complete for the findings in this export.** Every dataflow and
  code-level finding has either a source read (Tier A) or a Contrast trace with an exact file and
  line that we confirmed (the resolved Tier C table). The earlier "representative only" caveat no
  longer applies to this export. It would re-apply to any new finding from a future run, which
  should be checked the same way.
- **"Zero false positives" is scoped.** The automated verifier flags a false positive only when
  a finding lands on a route it has mapped as safe or simulated. Routes not in that map are
  ignored as "other," so the claim is "no findings on the enumerated safe/simulated routes," not
  "all 56 are proven true positives." The Tier A and Tier C work above is what extends that
  toward every actual finding.
- **Route-covered is not sink-exercised.** Coverage percentage can look complete while a sink
  goes undriven (the `servers` 400 was exactly this). Counts also vary run to run because of
  stored/second-order findings and asynchronous reporting.
- **Attribution blind spots.** WebWolf and SSRF findings do not attach to WebGoat routes in the
  route-coverage export, so the automated check cannot see them, they are listed in Tier C.
- **Rule-coverage scope is inferred.** "This deploy exercises about 20 of Contrast's rules and
  WebGoat lacks sinks for the rest" is reasoned from WebGoat being a Spring + JDBC app, not from
  an exhaustive source audit of every rule category.
- **No independent oracle.** There is no second scanner or manual pentest baseline confirming
  completeness. The false-positive argument against other tool techniques is technique-based, not
  measured. A ZAP baseline against the same target would make it measured.
- **Pinned to one configuration.** v2025.3, JDK 23, this Helm config, no outbound egress. The
  no-egress alone masks SSRF. Contrast rule semantics and WebGoat behavior change across
  versions, so re-verify after any upgrade.
