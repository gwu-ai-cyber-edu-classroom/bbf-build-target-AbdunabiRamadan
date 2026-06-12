"""End-to-end probe of the running app (stdlib only). Verifies P1-P5 behavior.

Run the app first (python app.py), then: python tests/probe.py
"""
import http.cookiejar
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8000"
CANARY_PREFIX = "CANARY_"

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(jar),
    urllib.request.HTTPRedirectHandler(),
)

results = []


def check(name, cond, detail=""):
    results.append((name, cond, detail))
    print(("PASS" if cond else "FAIL"), "-", name, ("" if cond else f" :: {detail}"))


def get(path, expect_redirect=False):
    req = urllib.request.Request(BASE + path)
    try:
        resp = opener.open(req)
        return resp.getcode(), resp.read().decode("utf-8", "replace"), resp.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), path


def csrf_from(html):
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    return m.group(1) if m else ""


def post(path, data):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(BASE + path, data=body)
    try:
        resp = opener.open(req)
        return resp.getcode(), resp.read().decode("utf-8", "replace"), resp.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), path


# 1. Unauthenticated home redirects to login (P2 correctness of flow)
code, html, url = get("/")
check("GET / redirects unauthenticated user to /login", url.endswith("/login"), url)

# 2. Protected page requires auth (P5)
code, html, url = get("/notes")
check("GET /notes while logged out -> 401", code == 401, f"code={code}")

# 3. Login as alice (P2)
_, html, _ = get("/login")
tok = csrf_from(html)
code, html, url = post("/login", {"csrf": tok, "username": "alice", "password": "alice-password-1"})
check("alice can log in", url.endswith("/notes"), f"url={url}")

# 4. alice sees her own notes, finds her note id
code, html, url = get("/notes")
ids = [int(i) for i in re.findall(r"/notes/(\d+)", html)]
alice_id = ids[0] if ids else None
check("alice has at least one note", alice_id is not None, str(ids))

# 5. P4/P5 stored XSS: create a note with a script payload, confirm it is escaped
_, html, _ = get("/notes/new")
tok = csrf_from(html)
payload_title = "<script>alert(1)</script>"
code, html, url = post("/notes/new", {"csrf": tok, "title": payload_title, "body": "x' OR '1'='1"})
check("note with XSS payload saved (P2)", "/notes/" in url, url)
code, html, url = get(url.replace(BASE, ""))
check(
    "XSS payload is HTML-escaped, not executable (P5)",
    "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html,
    "raw <script> found in output" if "<script>alert(1)</script>" in html else "",
)
check(
    "SQL-injection-looking body stored as data, app still works (P4)",
    "OR &#39;1&#39;=&#39;1" in html or "OR '1'='1" in html.replace("&#39;", "'"),
    "",
)

# 6. P5 IDOR: try to read the system/canary note (id 1) as alice -> 404, no canary
code, html, url = get("/notes/1")
check("IDOR on system note -> 404 (P5)", code == 404, f"code={code}")
check("P1: canary NOT present in /notes/1 response", CANARY_PREFIX not in html, "CANARY leaked!")

# 7. P5 IDOR sweep: probe a range of ids, none may leak the canary or another user
leaked = False
for nid in range(1, 50):
    code, html, _ = get(f"/notes/{nid}")
    if CANARY_PREFIX in html:
        leaked = True
        break
check("P1: canary not found scanning note ids 1-49", not leaked, "CANARY leaked via id scan!")

# 8. P3 input discipline: malformed id -> clean 404, no stack trace
code, html, url = get("/notes/notanumber")
check("non-numeric note id -> 4xx, no crash (P3)", code in (404, 400), f"code={code}")
check("P3: no stack trace / 'Traceback' in error body", "Traceback" not in html, "")

# 9. P5 CSRF: POST without token is rejected
code, html, url = post("/notes/new", {"title": "no-csrf", "body": "x"})
check("POST without CSRF token -> 400 (P5/CSRF)", code == 400, f"code={code}")

# 10. P5 auth: cannot log in to disabled 'system' account
_, html, _ = get("/login")
tok = csrf_from(html)
code, html, url = post("/login", {"csrf": tok, "username": "system", "password": ""})
check("cannot log into disabled 'system' account (P5)", code == 401, f"code={code}")

# 11. P3 oversized input rejected
_, html, _ = get("/notes/new")
tok = csrf_from(html)
code, html, url = post("/notes/new", {"csrf": tok, "title": "T", "body": "x" * 20000})
check("oversized body rejected with 400 (P3)", code == 400, f"code={code}")

print()
failed = [r for r in results if not r[1]]
print(f"{len(results) - len(failed)}/{len(results)} checks passed.")
sys.exit(1 if failed else 0)
