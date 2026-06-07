// Functional exercise catalog for the WebGoat IAST walkthrough.
//
// KEY IDEA (the IAST point): Contrast instruments the running code, so it reports a
// vulnerability the moment the vulnerable code path executes with untrusted data.
// It does NOT need a malicious payload. We therefore exercise each route with normal,
// benign input -- the way a QA test or a click-through would -- and Contrast still
// sees the unsafe dataflow and reports the flaw. No "attacks" required.
//
// Endpoints, parameters, and code behavior were verified against the WebGoat v2025.3
// source (the version pinned in manifests/10-webgoat.yaml).
//
// category:
//   "VULNERABLE" -> real vulnerable code (string-concatenated SQL, XML parsed with
//                   external entities enabled, ObjectInputStream.readObject on
//                   untrusted bytes, XStream.fromXML, MessageDigest MD5, URL.openStream
//                   on user input, ...). Exercised with benign input, Contrast reports it.
//   "SAFE"       -> the same kind of feature but coded securely (fully parameterized
//                   PreparedStatement). Contrast correctly stays silent. A true negative
//                   you can point to: "we exercised it, no noise, because the code is safe."
//   "SIMULATED"  -> a WebGoat teaching lesson that only does a regex / String.contains()
//                   check. No vulnerable code runs. Guess-based scanners flag these from
//                   the HTTP response; Contrast reports nothing. This is the WebGoat trap.

export const exercises = [
  // ---------- VULNERABLE: found through normal functional use ----------
  {
    id: "sqli-attack2",
    label: "SQLi - user-supplied query executed (Statement)",
    category: "VULNERABLE",
    method: "POST",
    path: "/SqlInjection/attack2",
    form: { query: "SELECT * FROM user_data WHERE first_name='John' AND last_name='Smith'" },
    input: "A normal-looking SELECT, no injection metacharacters",
    expect: "Contrast: SQL Injection (untrusted data is the executed query)",
  },
  {
    id: "sqli-5a",
    label: "SQLi - account lookup built by concatenation",
    category: "VULNERABLE",
    method: "POST",
    path: "/SqlInjection/assignment5a",
    form: { account: "Smith", operator: "", injection: "" },
    input: "Just a last name; operator/injection left blank",
    expect: "Contrast: SQL Injection on the concatenated last_name",
  },
  {
    id: "sqli-attack8",
    label: "SQLi - employee lookup by name + TAN",
    category: "VULNERABLE",
    method: "POST",
    path: "/SqlInjection/attack8",
    form: { name: "Smith", auth_tan: "3SL99A" },
    input: "A valid employee name and TAN, as the form intends",
    expect: "Contrast: SQL Injection (name/auth_tan concatenated)",
  },
  {
    id: "sqli-attack9",
    label: "SQLi - blind variant, name + TAN",
    category: "VULNERABLE",
    method: "POST",
    path: "/SqlInjection/attack9",
    form: { name: "Smith", auth_tan: "3SL99A" },
    input: "Normal name and TAN",
    expect: "Contrast: SQL Injection (concatenated query)",
  },
  {
    id: "sqli-attack10",
    label: "SQLi - access-log search (LIKE concatenation)",
    category: "VULNERABLE",
    method: "POST",
    path: "/SqlInjection/attack10",
    form: { action_string: "login" },
    input: "A normal search term",
    expect: "Contrast: SQL Injection (term concatenated into LIKE)",
  },
  {
    id: "sqli-adv-6a",
    label: "SQLi - last-name lookup (advanced)",
    category: "VULNERABLE",
    method: "POST",
    path: "/SqlInjectionAdvanced/attack6a",
    form: { userid_6a: "Smith" },
    input: "A normal last name",
    expect: "Contrast: SQL Injection (concatenated query)",
  },
  {
    id: "sqli-5b",
    label: "SQLi - partially parameterized, userid still concatenated",
    category: "VULNERABLE",
    method: "POST",
    path: "/SqlInjection/assignment5b",
    form: { userid: "12345", login_count: "1" },
    input: "Numeric-looking values; login_count is bound but userid is concatenated",
    expect: "Contrast: SQL Injection on userid (proves it inspects each parameter)",
  },
  {
    id: "sqli-servers-orderby",
    label: "SQLi - ORDER BY column (sortable table)",
    category: "VULNERABLE",
    method: "GET",
    path: "/SqlInjectionMitigations/servers",
    params: { column: "hostname" },
    input: "A real column name, as clicking a sort header would send",
    expect: "Contrast: SQL Injection (column concatenated into ORDER BY)",
  },
  {
    id: "xxe-simple",
    label: "XXE - comment submitted as XML",
    category: "VULNERABLE",
    method: "POST",
    path: "/xxe/simple",
    body: '<?xml version="1.0"?><comment><text>Great lesson, thanks</text></comment>',
    contentType: "application/xml",
    input: "A perfectly normal XML comment, no external entity",
    expect: "Contrast: XXE (parser resolves external entities on untrusted XML)",
  },
  {
    id: "deserialization",
    label: "Insecure deserialization - object token",
    category: "VULNERABLE",
    method: "POST",
    path: "/InsecureDeserialization/task",
    form: { token: "rO0ABXQAB3FhLXRlc3Q=" },
    input: "A benign serialized object (the String 'qa-test'), base64",
    expect: "Contrast: Untrusted Deserialization (readObject on request data)",
  },
  {
    id: "vulnerable-components",
    label: "Vulnerable component - XStream fromXML",
    category: "VULNERABLE",
    method: "POST",
    path: "/VulnerableComponents/attack1",
    form: { payload: "<contact><firstName>John</firstName><lastName>Doe</lastName></contact>" },
    input: "A benign contact record as XML",
    expect: "Contrast: unsafe XStream deserialization (known-vulnerable library)",
  },
  {
    id: "weak-hash",
    label: "Weak cryptography - MD5 hashing",
    category: "VULNERABLE",
    method: "GET",
    path: "/crypto/hashing/md5",
    input: "Just load the page; the server hashes with MD5",
    expect: "Contrast: weak hash algorithm (MD5)",
  },
  {
    id: "ssrf-task2",
    label: "SSRF - server fetches a user-supplied URL",
    category: "VULNERABLE",
    method: "POST",
    path: "/SSRF/task2",
    form: { url: "http://ifconfig.pro" },
    input: "The URL the lesson expects; the server opens it server-side",
    expect: "Contrast: SSRF (URL.openStream on user-controlled input)",
  },
  {
    id: "stored-xss",
    label: "Stored XSS - post a comment",
    category: "VULNERABLE",
    method: "POST",
    path: "/CrossSiteScriptingStored/stored-xss",
    body: '{"text":"Hello from the functional test run"}',
    contentType: "application/json",
    input: "A normal comment; the text is stored and later rendered",
    expect: "Contrast: stored XSS / trust-boundary on the stored comment flow",
  },

  // ---------- SAFE: exercised, and correctly produces no finding ----------
  {
    id: "safe-parameterized",
    label: "SAFE - fully parameterized lookup (PreparedStatement)",
    category: "SAFE",
    method: "POST",
    path: "/SqlInjectionMitigations/attack12a",
    form: { ip: "104.130.219.202" },
    input: "A normal IP; both bind parameters are set with setString",
    expect: "Contrast: nothing. The code is safe, so there is no finding to triage.",
  },

  // ---------- SIMULATED: WebGoat trap. Legacy scanners false-positive here ----------
  {
    id: "sim-sqli-mitigation",
    label: "SIMULATED - SQLi 'mitigation' code check (regex only)",
    category: "SIMULATED",
    method: "POST",
    path: "/SqlInjectionMitigations/attack10b",
    form: {
      editor:
        "PreparedStatement ps = conn.prepareStatement(sql); ps.setString(1, x); ps.executeUpdate();",
    },
    input: "Submitted text; the server only runs a regex over it",
    expect: "Contrast: nothing (no SQL executes). Legacy scanner: likely a false positive.",
  },
  {
    id: "sim-ssrf-task1",
    label: "SIMULATED - SSRF lesson 1 (String compare, no request)",
    category: "SIMULATED",
    method: "POST",
    path: "/SSRF/task1",
    form: { url: "images/jerry.png" },
    input: "Normal value; the server only string-compares it, never fetches",
    expect: "Contrast: nothing (no outbound call). Legacy scanner: likely a false positive.",
  },
  {
    id: "sim-xss-reflected",
    label: "SIMULATED - reflected XSS lesson (String.contains check)",
    category: "SIMULATED",
    method: "GET",
    path: "/CrossSiteScripting/attack5a",
    params: {
      QTY1: "1",
      QTY2: "1",
      QTY3: "1",
      QTY4: "1",
      field1: "4128 3214 0002 1999",
      field2: "none",
    },
    input: "Normal shopping-cart values",
    expect: "Contrast: nothing real to trace. Legacy scanner: likely a false positive.",
  },
];
