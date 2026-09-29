# Referensi rule

Dibuat otomatis oleh `scripts/gen_rule_docs.py` dari rule pack (vulnfab 0.3.x).
**Jangan edit tangan**; perbarui rule YAML lalu jalankan skripnya. CI memeriksa kesinkronan.

Total: 113 rule. Tingkat: **A** struktural/pasti, **B** pola kepemilikan (IDOR; confidence maksimum medium), **C** kandidat semantik (tersembunyi secara default).

Menekan satu temuan: komentar `# nosec: <rule-id>` di barisnya, `per_file_ignores` di `.vulnfab.yml`, atau baseline.

## Stack `django` (21 rule)

| Rule | Jenis | Severity | Confidence | Tier | CWE |
|---|---|---|---|---|---|
| [`dj-allowed-hosts`](#dj-allowed-hosts) | schema | medium | medium | — | [CWE-644](https://cwe.mitre.org/data/definitions/644.html) |
| [`dj-clickjacking`](#dj-clickjacking) | schema | low | low | — | [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) |
| [`dj-cookie-httponly`](#dj-cookie-httponly) | schema | medium | medium | — | [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) |
| [`dj-cookie-secure`](#dj-cookie-secure) | schema | medium | medium | — | [CWE-614](https://cwe.mitre.org/data/definitions/614.html) |
| [`dj-csrf-exempt`](#dj-csrf-exempt) | crosscheck | medium | medium | A | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) |
| [`dj-csrf-middleware`](#dj-csrf-middleware) | schema | high | high | — | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) |
| [`dj-db-password`](#dj-db-password) | schema | medium | medium | — | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| [`dj-debug-true`](#dj-debug-true) | schema | high | medium | — | [CWE-489](https://cwe.mitre.org/data/definitions/489.html), [CWE-215](https://cwe.mitre.org/data/definitions/215.html) |
| [`dj-dispatch-input`](#dj-dispatch-input) | taint | high | medium | — | [CWE-470](https://cwe.mitre.org/data/definitions/470.html) |
| [`dj-mark-safe`](#dj-mark-safe) | pattern | medium | medium | — | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| [`dj-modelform-all`](#dj-modelform-all) | pattern | medium | medium | — | [CWE-915](https://cwe.mitre.org/data/definitions/915.html) |
| [`dj-password-hasher`](#dj-password-hasher) | schema | high | high | — | [CWE-916](https://cwe.mitre.org/data/definitions/916.html), [CWE-328](https://cwe.mitre.org/data/definitions/328.html) |
| [`dj-password-validators`](#dj-password-validators) | schema | low | low | — | [CWE-521](https://cwe.mitre.org/data/definitions/521.html) |
| [`dj-pickle-session`](#dj-pickle-session) | schema | high | high | — | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) |
| [`dj-secret-key`](#dj-secret-key) | schema | high | high | — | [CWE-798](https://cwe.mitre.org/data/definitions/798.html), [CWE-321](https://cwe.mitre.org/data/definitions/321.html) |
| [`dj-sql-raw`](#dj-sql-raw) | pattern | high | medium | — | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) |
| [`dj-template-autoescape`](#dj-template-autoescape) | scanner | high | medium | — | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| [`dj-template-csrf`](#dj-template-csrf) | scanner | medium | medium | — | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) |
| [`dj-template-jscontext`](#dj-template-jscontext) | scanner | medium | low | — | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| [`dj-template-safe`](#dj-template-safe) | scanner | high | medium | — | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| [`dj-view-no-auth`](#dj-view-no-auth) | crosscheck | high | medium | A | [CWE-306](https://cwe.mitre.org/data/definitions/306.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html) |

### dj-allowed-hosts

**ALLOWED_HOSTS accepts every host** — ALLOWED_HOSTS contains '*'.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: List the real host names.
- OWASP: [A05:2021](https://owasp.org/Top10/)

### dj-clickjacking

**Clickjacking protection missing** — XFrameOptionsMiddleware is not enabled.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Add 'django.middleware.clickjacking.XFrameOptionsMiddleware'.
- OWASP: [A05:2021](https://owasp.org/Top10/)

### dj-cookie-httponly

**Session cookie readable by JavaScript** — SESSION_COOKIE_HTTPONLY is False.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Leave SESSION_COOKIE_HTTPONLY at its default (True).
- OWASP: [A05:2021](https://owasp.org/Top10/)

### dj-cookie-secure

**Cookie sent over plain HTTP** — A cookie 'Secure' flag is explicitly disabled.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Set SESSION_COOKIE_SECURE and CSRF_COOKIE_SECURE to True in production.
- OWASP: [A05:2021](https://owasp.org/Top10/)

### dj-csrf-exempt

**View exempt from CSRF protection** — A view is decorated with @csrf_exempt.

- Jenis: crosscheck — Relates code facts (queries, routes) to the schema or auth model.
- Perbaikan: Remove @csrf_exempt; send the CSRF token from the client, or authenticate with a header token.
- OWASP: [A01:2021](https://owasp.org/Top10/)

### dj-csrf-middleware

**CSRF middleware missing** — CsrfViewMiddleware is not enabled.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Add 'django.middleware.csrf.CsrfViewMiddleware' to MIDDLEWARE.
- OWASP: [A01:2021](https://owasp.org/Top10/)

### dj-db-password

**Database password in settings** — DATABASES contains a literal password.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Read the database credentials from environment variables or a secret manager.
- OWASP: [A07:2021](https://owasp.org/Top10/)

### dj-debug-true

**DEBUG enabled in settings** — DEBUG = True exposes source, settings and SQL in error pages.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Set DEBUG from the environment and default it to False.
- OWASP: [A05:2021](https://owasp.org/Top10/)

### dj-dispatch-input

**Request data selects the code that runs** — Untrusted input chooses an attribute, module or callable (unsafe reflection).

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Map allowed names to callables explicitly (dict lookup) instead of getattr().
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Sumber: `field *request.GET`, `field *request.POST`, `field *request.data`, `field *request.query_params`, `field *request.body`, `field *request.headers`, `field *request.COOKIES`
- Sink: `call getattr arg1`, `call setattr arg1`, `call importlib.import_module arg0`, `call import_module arg0`, `call __import__ arg0`, `call import_string arg0`

### dj-mark-safe

**mark_safe applied to interpolated text** — mark_safe() on a string built from variables disables Django's escaping.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Use format_html() so arguments are escaped.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### dj-modelform-all

**ModelForm exposes every model field** — fields = '__all__' (or exclude) lets a request set columns the form was not meant to expose (mass assignment).

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: List the editable fields explicitly (a whitelist); an `exclude` blacklist misses new columns.
- OWASP: [A04:2021](https://owasp.org/Top10/)

### dj-password-hasher

**Weak password hasher** — PASSWORD_HASHERS contains a weak hasher.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Use PBKDF2, Argon2 or bcrypt hashers only.
- OWASP: [A02:2021](https://owasp.org/Top10/)

### dj-password-validators

**No password validators** — AUTH_PASSWORD_VALIDATORS is empty.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Enable Django's default AUTH_PASSWORD_VALIDATORS.
- OWASP: [A07:2021](https://owasp.org/Top10/)

### dj-pickle-session

**Pickle session serializer** — SESSION_SERIALIZER uses pickle.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Use django.contrib.sessions.serializers.JSONSerializer.
- OWASP: [A08:2021](https://owasp.org/Top10/)

### dj-secret-key

**Hard-coded SECRET_KEY** — SECRET_KEY is hard-coded.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Read SECRET_KEY from an environment variable or a secret manager and rotate the exposed key.
- OWASP: [A02:2021](https://owasp.org/Top10/)

### dj-sql-raw

**Raw SQL built with string interpolation** — Manager.raw()/extra()/RawSQL() receives a query built by formatting or concatenation.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Pass values as params: Model.objects.raw(sql, [value]); prefer the ORM's filter().
- OWASP: [A03:2021](https://owasp.org/Top10/)

### dj-template-autoescape

**Autoescape disabled in template** — {% autoescape off %} disables HTML escaping.

- Jenis: scanner — Text scanner over files (secrets, env files, templates).
- Perbaikan: Keep autoescape on; escape individual values explicitly if needed.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### dj-template-csrf

**POST form without CSRF token** — A POST form has no {% csrf_token %}.

- Jenis: scanner — Text scanner over files (secrets, env files, templates).
- Perbaikan: Add {% csrf_token %} inside the form.
- OWASP: [A01:2021](https://owasp.org/Top10/)

### dj-template-jscontext

**Template variable printed inside <script>** — A variable is printed inside a script block without JS escaping.

- Jenis: scanner — Text scanner over files (secrets, env files, templates).
- Perbaikan: Use |escapejs for strings or json_script for data.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### dj-template-safe

**Template output marked safe** — A template variable is rendered with |safe.

- Jenis: scanner — Text scanner over files (secrets, env files, templates).
- Perbaikan: Remove |safe, or sanitise the value (bleach) before it is marked safe.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### dj-view-no-auth

**View that reads or changes data without authentication** — A URL-mapped view handles data but has no authentication or permission check.

- Jenis: crosscheck — Relates code facts (queries, routes) to the schema or auth model.
- Perbaikan: Add @login_required / LoginRequiredMixin (or permission_classes) and check ownership.
- OWASP: [A01:2021](https://owasp.org/Top10/)

## Stack `generic` (56 rule)

| Rule | Jenis | Severity | Confidence | Tier | CWE |
|---|---|---|---|---|---|
| [`env-service-role-client`](#env-service-role-client) | scanner | critical | high | A | [CWE-522](https://cwe.mitre.org/data/definitions/522.html) |
| [`js-dangerous-html`](#js-dangerous-html) | pattern | high | medium | — | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| [`js-document-write`](#js-document-write) | pattern | medium | medium | — | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| [`js-eval`](#js-eval) | pattern | high | medium | — | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) |
| [`js-exec`](#js-exec) | pattern | high | medium | — | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) |
| [`js-function-constructor`](#js-function-constructor) | pattern | high | medium | — | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) |
| [`js-innerhtml-assign`](#js-innerhtml-assign) | pattern | medium | medium | — | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| [`js-innerhtml-var`](#js-innerhtml-var) | pattern | medium | low | — | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| [`js-xss`](#js-xss) | pattern | medium | medium | — | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| [`php-echo-request`](#php-echo-request) | pattern | medium | medium | — | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| [`php-eval`](#php-eval) | pattern | high | medium | — | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) |
| [`php-exec-family`](#php-exec-family) | pattern | high | medium | — | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) |
| [`php-include-request`](#php-include-request) | pattern | high | medium | — | [CWE-98](https://cwe.mitre.org/data/definitions/98.html) |
| [`php-sql-interp`](#php-sql-interp) | pattern | high | medium | — | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) |
| [`php-unserialize`](#php-unserialize) | pattern | high | medium | — | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) |
| [`php-weak-hash`](#php-weak-hash) | pattern | medium | low | — | [CWE-328](https://cwe.mitre.org/data/definitions/328.html) |
| [`py-eval`](#py-eval) | pattern | high | medium | — | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) |
| [`py-exec`](#py-exec) | pattern | high | medium | — | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) |
| [`py-flask-debug`](#py-flask-debug) | pattern | medium | medium | — | [CWE-489](https://cwe.mitre.org/data/definitions/489.html) |
| [`py-hash-weak`](#py-hash-weak) | pattern | medium | low | — | [CWE-328](https://cwe.mitre.org/data/definitions/328.html) |
| [`py-os-system`](#py-os-system) | pattern | high | medium | — | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) |
| [`py-pickle-loads`](#py-pickle-loads) | pattern | high | medium | — | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) |
| [`py-requests-verify-false`](#py-requests-verify-false) | pattern | medium | high | — | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) |
| [`py-sql-execute-interp`](#py-sql-execute-interp) | pattern | high | medium | — | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) |
| [`py-subprocess-shell`](#py-subprocess-shell) | pattern | high | medium | — | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) |
| [`py-tempfile-mktemp`](#py-tempfile-mktemp) | pattern | medium | high | — | [CWE-377](https://cwe.mitre.org/data/definitions/377.html) |
| [`py-yaml-load`](#py-yaml-load) | pattern | high | high | — | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) |
| [`sec-secret-hardcoded`](#sec-secret-hardcoded) | scanner | high | medium | A | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| [`tjs-cmdi`](#tjs-cmdi) | taint | critical | medium | — | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) |
| [`tjs-codei`](#tjs-codei) | taint | critical | medium | — | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) |
| [`tjs-deser`](#tjs-deser) | taint | high | medium | — | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) |
| [`tjs-idor`](#tjs-idor) | taint | medium | medium | B | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) |
| [`tjs-pathtrav`](#tjs-pathtrav) | taint | high | medium | — | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) |
| [`tjs-redirect`](#tjs-redirect) | taint | medium | medium | — | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) |
| [`tjs-sqli`](#tjs-sqli) | taint | high | medium | — | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) |
| [`tjs-ssrf`](#tjs-ssrf) | taint | high | medium | — | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) |
| [`tjs-xss`](#tjs-xss) | taint | medium | medium | — | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| [`tphp-cmdi`](#tphp-cmdi) | taint | critical | medium | — | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) |
| [`tphp-codei`](#tphp-codei) | taint | critical | medium | — | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) |
| [`tphp-deser`](#tphp-deser) | taint | high | medium | — | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) |
| [`tphp-idor`](#tphp-idor) | taint | medium | medium | B | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) |
| [`tphp-pathtrav`](#tphp-pathtrav) | taint | high | medium | — | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) |
| [`tphp-redirect`](#tphp-redirect) | taint | medium | medium | — | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) |
| [`tphp-sqli`](#tphp-sqli) | taint | high | medium | — | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) |
| [`tphp-ssrf`](#tphp-ssrf) | taint | high | medium | — | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) |
| [`tphp-xss`](#tphp-xss) | taint | medium | medium | — | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| [`tpy-cmdi`](#tpy-cmdi) | taint | critical | medium | — | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) |
| [`tpy-codei`](#tpy-codei) | taint | critical | medium | — | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) |
| [`tpy-deser`](#tpy-deser) | taint | high | medium | — | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) |
| [`tpy-idor`](#tpy-idor) | taint | medium | medium | B | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) |
| [`tpy-pathtrav`](#tpy-pathtrav) | taint | high | medium | — | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) |
| [`tpy-redirect`](#tpy-redirect) | taint | medium | medium | — | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) |
| [`tpy-sqli`](#tpy-sqli) | taint | high | medium | — | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) |
| [`tpy-ssrf`](#tpy-ssrf) | taint | high | medium | — | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) |
| [`tpy-ssti`](#tpy-ssti) | taint | high | medium | — | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) |
| [`tpy-xss`](#tpy-xss) | taint | medium | medium | — | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |

### env-service-role-client

**Supabase service_role key exposed through a public env variable** — A service_role key is placed in a variable that is bundled into the client.

- Jenis: scanner — Text scanner over files (secrets, env files, templates).
- Perbaikan: Use the anon key in the browser; keep service_role server-side only, without a public prefix.
- OWASP: [A02:2021](https://owasp.org/Top10/)

### js-dangerous-html

**dangerouslySetInnerHTML with unsanitized data** — dangerouslySetInnerHTML renders raw HTML; non-constant, unsanitized data enables XSS.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Sanitize with DOMPurify.sanitize(...) or render text.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### js-document-write

**document.write with non-constant data** — document.write with dynamic data can inject script.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### js-eval

**Use of eval()** — eval() executes arbitrary code. Avoid it with non-constant input.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### js-exec

**Shell command built from non-constant input** — child_process.exec runs a shell; a non-constant command enables injection.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Use execFile/spawn with an argument array.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### js-function-constructor

**Function constructor with non-constant body** — new Function(body) compiles code from a string.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### js-innerhtml-assign

**HTML injection through innerHTML/outerHTML** — innerHTML receives a string built with interpolated values that are not visibly escaped.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Escape every interpolated value (escapeHtml), use textContent, or sanitize with DOMPurify.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### js-innerhtml-var

**innerHTML assigned from a variable or call** — innerHTML receives a non-constant value; check that it was escaped where it was built.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Prefer textContent, or sanitize with DOMPurify before assigning.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### js-xss

**Angular sanitizer bypass with non-constant data** — bypassSecurityTrust* disables Angular's built-in sanitisation; non-constant data enables XSS.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Do not bypass the sanitizer; render text or sanitise with DOMPurify first.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### php-echo-request

**Request data echoed without escaping** — Echoing request data directly enables reflected XSS.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Escape with htmlspecialchars($value, ENT_QUOTES, 'UTF-8').
- OWASP: [A03:2021](https://owasp.org/Top10/)

### php-eval

**Use of eval()** — eval() executes arbitrary code. Avoid it with non-constant input.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### php-exec-family

**Shell command built from non-constant input** — Command execution functions with non-constant input enable injection.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Use escapeshellarg() on every argument or avoid the shell.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### php-include-request

**File inclusion controlled by the request** — include/require with request data allows local or remote file inclusion.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Map user input to an allowlist of files.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### php-sql-interp

**SQL built with string interpolation** — A query assembled by interpolation or concatenation is injectable. Use prepared statements.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Use prepared statements with bound parameters.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### php-unserialize

**unserialize() on possibly untrusted data** — unserialize can instantiate arbitrary classes (object injection).

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Use json_decode, or pass ['allowed_classes' => false].
- OWASP: [A08:2021](https://owasp.org/Top10/)

### php-weak-hash

**Weak hash algorithm** — md5/sha1 are broken for security purposes. Only appropriate for non-security checksums.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Use password_hash for passwords and hash('sha256', ...) otherwise.
- OWASP: [A02:2021](https://owasp.org/Top10/)

### py-eval

**Use of eval()** — eval() executes arbitrary code. Avoid it with non-constant input.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Avoid eval(); use ast.literal_eval or an explicit parser.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### py-exec

**Use of exec()** — exec() executes arbitrary code. Avoid it with non-constant input.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### py-flask-debug

**Debug mode enabled** — app.run(debug=True) exposes the interactive debugger.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Never enable debug mode in production.
- OWASP: [A05:2021](https://owasp.org/Top10/)

### py-hash-weak

**Weak hash algorithm** — MD5/SHA-1 are broken for security purposes. Only appropriate for non-security checksums.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Use SHA-256 or better; passwords need bcrypt/argon2.
- OWASP: [A02:2021](https://owasp.org/Top10/)

### py-os-system

**os.system with a non-constant command** — os.system runs a shell command; a non-constant command enables injection.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Use subprocess.run with an argument list.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### py-pickle-loads

**Deserialization with pickle** — pickle can execute code while loading. Never unpickle untrusted data.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Use a safe format such as JSON.
- OWASP: [A08:2021](https://owasp.org/Top10/)

### py-requests-verify-false

**TLS verification disabled** — verify=False disables certificate validation.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Remove verify=False or point it at a CA bundle.
- OWASP: [A07:2021](https://owasp.org/Top10/)

### py-sql-execute-interp

**SQL built with string interpolation** — A query assembled by interpolation or concatenation is injectable. Use bound parameters.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: cursor.execute('... WHERE id = %s', (value,))
- OWASP: [A03:2021](https://owasp.org/Top10/)

### py-subprocess-shell

**subprocess with shell=True and a non-constant command** — shell=True passes the command through the shell; a non-constant command enables injection.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Pass an argument list and drop shell=True.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### py-tempfile-mktemp

**Insecure temporary file name** — tempfile.mktemp is racy; another process can create the file first.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Use tempfile.mkstemp or NamedTemporaryFile.
- OWASP: [A01:2021](https://owasp.org/Top10/)

### py-yaml-load

**yaml.load with an unsafe loader** — yaml.load without SafeLoader can construct arbitrary Python objects.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Use yaml.safe_load.
- OWASP: [A08:2021](https://owasp.org/Top10/)

### sec-secret-hardcoded

**Hard-coded secret** — A credential appears to be committed to source control.

- Jenis: scanner — Text scanner over files (secrets, env files, templates).
- Perbaikan: Move the secret to an environment variable or secret manager and rotate it.
- OWASP: [A07:2021](https://owasp.org/Top10/)

### tjs-cmdi

**OS command injection (tainted data reaches a shell)** — Untrusted input flows into an OS command.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Avoid the shell; pass an argument list and validate input.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Menggantikan (bila alur data terbukti): `js-exec`, `ts-cmd-injection`
- Sumber: `field req.query`, `field req.body`, `field req.params`, `field req.headers`, `field req.cookies`, `call req.param`, `field request.query`, `field request.body`, `field request.params`, `field %arg*.query`, `field %arg*.body`, `field %arg*.params`, `field %arg*.headers`, `field %arg*.cookies`
- Sink: `call exec arg0`, `call execSync arg0`, `call child_process.exec arg0`, `call child_process.execSync arg0`, `call cp.exec arg0`, `call shelljs.exec arg0`
- Sanitizer: `call parseInt`, `call Number`, `call shellescape`, `call shell-quote.quote`, `call *.digest`, `call uuid`, `call uuidv4`, `call crypto.randomUUID`

### tjs-codei

**Code injection (tainted data reaches eval)** — Untrusted input flows into dynamic code evaluation.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Never evaluate user input; use a parser or a fixed lookup.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Menggantikan (bila alur data terbukti): `js-eval`, `js-function-constructor`, `ts-dynamic-eval`
- Sumber: `field req.query`, `field req.body`, `field req.params`, `field req.headers`, `field req.cookies`, `call req.param`, `field request.query`, `field request.body`, `field request.params`, `field %arg*.query`, `field %arg*.body`, `field %arg*.params`, `field %arg*.headers`, `field %arg*.cookies`
- Sink: `call eval arg0`, `call Function arg0`, `call new Function arg0`, `call vm.runInNewContext arg0`, `call vm.runInThisContext arg0`, `call vm.runInContext arg0`
- Sanitizer: `call parseInt`, `call Number`, `call JSON.parse`, `call *.digest`, `call uuid`, `call uuidv4`, `call crypto.randomUUID`

### tjs-deser

**Insecure deserialization (tainted data reaches a deserializer)** — Untrusted input flows into an unsafe deserializer.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Use a data-only format (JSON) and validate the result.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Sumber: `field req.query`, `field req.body`, `field req.params`, `field req.headers`, `field req.cookies`, `call req.param`, `field request.query`, `field request.body`, `field request.params`, `field %arg*.query`, `field %arg*.body`, `field %arg*.params`, `field %arg*.headers`, `field %arg*.cookies`
- Sink: `call serialize.unserialize arg0`, `call unserialize arg0`, `call v8.deserialize arg0`
- Sanitizer: `call *.digest`, `call uuid`, `call uuidv4`, `call crypto.randomUUID`

### tjs-idor

**Possible IDOR (request key fetches a record without ownership evidence)** — A record is fetched by a key taken from the request, and the function shows no sign of checking that the record belongs to the current user.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Scope the query to the signed-in user (filter by owner) or compare the owner after loading.
- OWASP: [A01:2021](https://owasp.org/Top10/)
- Sumber: `field req.query`, `field req.body`, `field req.params`, `field req.headers`, `field req.cookies`, `call req.param`, `field request.query`, `field request.body`, `field request.params`, `field %arg*.query`, `field %arg*.body`, `field %arg*.params`, `field %arg*.headers`, `field %arg*.cookies`
- Sink: `call *.findByPk arg0`, `call *.findById arg0`, `call *.findByIdAndUpdate arg0`, `call *.findByIdAndDelete arg0`, `call *.findByIdAndRemove arg0`
- Sanitizer: `call *.verify`, `call *.decode`, `call jwt.*`, `call *.digest`, `call uuid`, `call uuidv4`, `call crypto.randomUUID`

### tjs-pathtrav

**Path traversal (tainted data reaches a file path)** — Untrusted input flows into a file system path.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Use a fixed base directory, reduce input to a basename and verify the resolved path.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Sumber: `field req.query`, `field req.body`, `field req.params`, `field req.headers`, `field req.cookies`, `call req.param`, `field request.query`, `field request.body`, `field request.params`, `field %arg*.query`, `field %arg*.body`, `field %arg*.params`, `field %arg*.headers`, `field %arg*.cookies`
- Sink: `call fs.readFile arg0`, `call fs.readFileSync arg0`, `call fs.createReadStream arg0`, `call fs.writeFile arg0`, `call fs.writeFileSync arg0`, `call fs.unlink arg0`, `call fs.unlinkSync arg0`, `call fs.appendFile arg0`, `call res.sendFile arg0`, `call res.download arg0`, `call fs.promises.readFile arg0`, `call fsp.readFile arg0`
- Sanitizer: `call path.basename`, `call parseInt`, `call Number`, `call *.digest`, `call uuid`, `call uuidv4`, `call crypto.randomUUID`

### tjs-redirect

**Open redirect (tainted data reaches a redirect)** — Untrusted input flows into a redirect target.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Redirect only to allow-listed or relative internal targets.
- OWASP: [A01:2021](https://owasp.org/Top10/)
- Sumber: `field req.query`, `field req.body`, `field req.params`, `field req.headers`, `field req.cookies`, `call req.param`, `field request.query`, `field request.body`, `field request.params`, `field %arg*.query`, `field %arg*.body`, `field %arg*.params`, `field %arg*.headers`, `field %arg*.cookies`
- Sink: `call res.redirect arg0`, `call res.location arg0`
- Sanitizer: `call parseInt`, `call Number`, `call *.digest`, `call uuid`, `call uuidv4`, `call crypto.randomUUID`

### tjs-sqli

**SQL injection (tainted data reaches a query)** — Untrusted input flows into a SQL statement without parameter binding.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Use parameterised queries / bound parameters.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Sumber: `field req.query`, `field req.body`, `field req.params`, `field req.headers`, `field req.cookies`, `call req.param`, `field request.query`, `field request.body`, `field request.params`, `field %arg*.query`, `field %arg*.body`, `field %arg*.params`, `field %arg*.headers`, `field %arg*.cookies`
- Sink: `call *.query arg0`, `call *.raw arg0`, `call *.execute arg0`, `call *.$queryRawUnsafe arg0`, `call *.$executeRawUnsafe arg0`
- Sanitizer: `call parseInt`, `call Number`, `call parseFloat`, `call *.digest`, `call uuid`, `call uuidv4`, `call crypto.randomUUID`

### tjs-ssrf

**SSRF (tainted data reaches an outgoing request)** — Untrusted input flows into the URL of a server-side request.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Allow-list hosts and schemes; never request user-supplied URLs directly.
- OWASP: [A10:2021](https://owasp.org/Top10/)
- Sumber: `field req.query`, `field req.body`, `field req.params`, `field req.headers`, `field req.cookies`, `call req.param`, `field request.query`, `field request.body`, `field request.params`, `field %arg*.query`, `field %arg*.body`, `field %arg*.params`, `field %arg*.headers`, `field %arg*.cookies`
- Sink: `call axios.get arg0`, `call axios.post arg0`, `call axios.put arg0`, `call axios.delete arg0`, `call axios arg0`, `call fetch arg0`, `call http.get arg0`, `call https.get arg0`, `call http.request arg0`, `call got arg0`, `call got.get arg0`, `call needle.get arg0`, `call superagent.get arg0`, `call request.get arg0`
- Sanitizer: `call parseInt`, `call Number`, `call *.digest`, `call uuid`, `call uuidv4`, `call crypto.randomUUID`

### tjs-xss

**Cross-site scripting (tainted data reaches HTML output)** — Untrusted input flows into HTML output without escaping.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Escape output for the HTML context or use a sanitising library.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Menggantikan (bila alur data terbukti): `js-innerhtml-assign`, `js-innerhtml-var`, `js-document-write`
- Sumber: `field req.query`, `field req.body`, `field req.params`, `field req.headers`, `field req.cookies`, `call req.param`, `field request.query`, `field request.body`, `field request.params`, `field %arg*.query`, `field %arg*.body`, `field %arg*.params`, `field %arg*.headers`, `field %arg*.cookies`
- Sink: `assign *.innerHTML`, `assign *.outerHTML`, `call document.write arg0`, `call document.writeln arg0`, `call *.insertAdjacentHTML arg1`, `call res.send arg0`, `call res.write arg0`
- Sanitizer: `call escapeHtml`, `call escape`, `call DOMPurify.sanitize`, `call sanitizeHtml`, `call xss`, `call encodeURIComponent`, `call he.encode`, `call he.escape`, `call validator.escape`, `call _.escape`, `call parseInt`, `call Number`, `call JSON.stringify`, `call fetch`, `call axios.*`, `call axios`, `call fs.readFile`, `call fs.readFileSync`, `call fs.promises.readFile`, `call *.query`, `call *.findByPk`, `call *.findOne`, `call *.digest`, `call uuid`, `call uuidv4`, `call crypto.randomUUID`

### tphp-cmdi

**OS command injection (tainted data reaches a shell)** — Untrusted input flows into an OS command.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Avoid the shell; pass an argument list and validate input.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Menggantikan (bila alur data terbukti): `php-exec-family`
- Sumber: `var _GET`, `var _POST`, `var _REQUEST`, `var _COOKIE`, `var _FILES`, `call request.input`, `call request.get`, `call request.query`, `call request.post`, `call request.all`, `call request.only`, `call request.except`, `call request.json`, `call request.header`, `call request.cookie`, `call request.route`, `call request.file`, `call request.string`, `call request.str`, `call Request::input`, `call Request::get`, `call Request::query`, `call Request::all`, `call request`, `field request.*`
- Sink: `call system arg0`, `call exec arg0`, `call shell_exec arg0`, `call passthru arg0`, `call popen arg0`, `call proc_open arg0`, `call pcntl_exec arg0`
- Sanitizer: `call escapeshellarg`, `call escapeshellcmd`, `call intval`, `call md5`, `call sha1`, `call crc32`, `call hash`, `call hash_hmac`, `call password_hash`, `call bin2hex`, `call uniqid`, `call random_int`

### tphp-codei

**Code injection (tainted data reaches eval)** — Untrusted input flows into dynamic code evaluation.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Never evaluate user input; use a parser or a fixed lookup.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Menggantikan (bila alur data terbukti): `php-eval`
- Sumber: `var _GET`, `var _POST`, `var _REQUEST`, `var _COOKIE`, `var _FILES`, `call request.input`, `call request.get`, `call request.query`, `call request.post`, `call request.all`, `call request.only`, `call request.except`, `call request.json`, `call request.header`, `call request.cookie`, `call request.route`, `call request.file`, `call request.string`, `call request.str`, `call Request::input`, `call Request::get`, `call Request::query`, `call Request::all`, `call request`, `field request.*`
- Sink: `call eval arg0`, `call assert arg0`, `call create_function arg1`, `call Blade::render arg0`, `call Blade::compileString arg0`
- Sanitizer: `call intval`, `call md5`, `call sha1`, `call crc32`, `call hash`, `call hash_hmac`, `call password_hash`, `call bin2hex`, `call uniqid`, `call random_int`

### tphp-deser

**Insecure deserialization (tainted data reaches a deserializer)** — Untrusted input flows into an unsafe deserializer.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Use a data-only format (JSON) and validate the result.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Menggantikan (bila alur data terbukti): `php-unserialize`
- Sumber: `var _GET`, `var _POST`, `var _REQUEST`, `var _COOKIE`, `var _FILES`, `call request.input`, `call request.get`, `call request.query`, `call request.post`, `call request.all`, `call request.only`, `call request.except`, `call request.json`, `call request.header`, `call request.cookie`, `call request.route`, `call request.file`, `call request.string`, `call request.str`, `call Request::input`, `call Request::get`, `call Request::query`, `call Request::all`, `call request`, `field request.*`
- Sink: `call unserialize arg0`, `call yaml_parse arg0`, `call igbinary_unserialize arg0`, `call maybe_unserialize arg0`
- Sanitizer: `call md5`, `call sha1`, `call crc32`, `call hash`, `call hash_hmac`, `call password_hash`, `call bin2hex`, `call uniqid`, `call random_int`

### tphp-idor

**Possible IDOR (request key fetches a record without ownership evidence)** — A record is fetched by a key taken from the request, and the function shows no sign of checking that the record belongs to the current user.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Scope the query to the signed-in user (filter by owner) or compare the owner after loading.
- OWASP: [A01:2021](https://owasp.org/Top10/)
- Sumber: `var _GET`, `var _POST`, `var _REQUEST`, `var _COOKIE`, `var _FILES`, `call request.input`, `call request.get`, `call request.query`, `call request.post`, `call request.all`, `call request.only`, `call request.except`, `call request.json`, `call request.header`, `call request.cookie`, `call request.route`, `call request.file`, `call request.string`, `call request.str`, `call Request::input`, `call Request::get`, `call Request::query`, `call Request::all`, `call request`, `field request.*`, `call request.input`, `call request.get`, `call request.query`, `call request.route`, `call request.post`, `param id`, `param *_id`
- Sink: `call *::find arg0`, `call *::findOrFail arg0`, `call *::destroy arg0`, `call *.find arg0`, `call *.findOrFail arg0`
- Sanitizer: `call md5`, `call sha1`, `call crc32`, `call hash`, `call hash_hmac`, `call password_hash`, `call bin2hex`, `call uniqid`, `call random_int`

### tphp-pathtrav

**Path traversal (tainted data reaches a file path)** — Untrusted input flows into a file system path.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Use a fixed base directory, reduce input to a basename and verify the resolved path.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Menggantikan (bila alur data terbukti): `php-include-request`
- Sumber: `var _GET`, `var _POST`, `var _REQUEST`, `var _COOKIE`, `var _FILES`, `call request.input`, `call request.get`, `call request.query`, `call request.post`, `call request.all`, `call request.only`, `call request.except`, `call request.json`, `call request.header`, `call request.cookie`, `call request.route`, `call request.file`, `call request.string`, `call request.str`, `call Request::input`, `call Request::get`, `call Request::query`, `call Request::all`, `call request`, `field request.*`
- Sink: `call include arg0`, `call include_once arg0`, `call require arg0`, `call require_once arg0`, `call file_get_contents arg0`, `call fopen arg0`, `call readfile arg0`, `call file arg0`, `call file_put_contents arg0`, `call unlink arg0`, `call move_uploaded_file arg1`, `call copy arg0`, `call highlight_file arg0`, `call show_source arg0`, `call Storage::get arg0`, `call Storage::download arg0`, `call Storage::delete arg0`, `call Storage::put arg0`, `call File::get arg0`, `call File::delete arg0`, `call *.download arg0`, `call *.storeAs arg0`
- Sanitizer: `call basename`, `call intval`, `call md5`, `call sha1`, `call crc32`, `call hash`, `call hash_hmac`, `call password_hash`, `call bin2hex`, `call uniqid`, `call random_int`

### tphp-redirect

**Open redirect (tainted data reaches a redirect)** — Untrusted input flows into a redirect target.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Redirect only to allow-listed or relative internal targets.
- OWASP: [A01:2021](https://owasp.org/Top10/)
- Sumber: `var _GET`, `var _POST`, `var _REQUEST`, `var _COOKIE`, `var _FILES`, `call request.input`, `call request.get`, `call request.query`, `call request.post`, `call request.all`, `call request.only`, `call request.except`, `call request.json`, `call request.header`, `call request.cookie`, `call request.route`, `call request.file`, `call request.string`, `call request.str`, `call Request::input`, `call Request::get`, `call Request::query`, `call Request::all`, `call request`, `field request.*`
- Sink: `call redirect arg0`, `call Redirect::to arg0`, `call wp_redirect arg0`, `call header arg0`
- Sanitizer: `call intval`, `call md5`, `call sha1`, `call crc32`, `call hash`, `call hash_hmac`, `call password_hash`, `call bin2hex`, `call uniqid`, `call random_int`

### tphp-sqli

**SQL injection (tainted data reaches a query)** — Untrusted input flows into a SQL statement without parameter binding.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Use parameterised queries / bound parameters.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Menggantikan (bila alur data terbukti): `php-sql-interp`
- Sumber: `var _GET`, `var _POST`, `var _REQUEST`, `var _COOKIE`, `var _FILES`, `call request.input`, `call request.get`, `call request.query`, `call request.post`, `call request.all`, `call request.only`, `call request.except`, `call request.json`, `call request.header`, `call request.cookie`, `call request.route`, `call request.file`, `call request.string`, `call request.str`, `call Request::input`, `call Request::get`, `call Request::query`, `call Request::all`, `call request`, `field request.*`
- Sink: `call mysqli_query arg1`, `call mysql_query arg0`, `call pg_query arg1`, `call mysqli_multi_query arg1`, `call mysqli_real_query arg1`, `call *.query arg0`, `call *.exec arg0`, `call DB::raw arg0`, `call DB::select arg0`, `call DB::statement arg0`, `call DB::unprepared arg0`, `call *.whereRaw arg0`, `call *.selectRaw arg0`, `call *.orderByRaw arg0`, `call *.havingRaw arg0`, `call *::whereRaw arg0`, `call *::selectRaw arg0`, `call *::orderByRaw arg0`, `call *::havingRaw arg0`, `call *::fromRaw arg0`, `call *.groupByRaw arg0`, `call *.fromRaw arg0`
- Sanitizer: `call intval`, `call floatval`, `call md5`, `call sha1`, `call crc32`, `call hash`, `call hash_hmac`, `call password_hash`, `call bin2hex`, `call uniqid`, `call random_int`

### tphp-ssrf

**SSRF (tainted data reaches an outgoing request)** — Untrusted input flows into the URL of a server-side request.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Allow-list hosts and schemes; never request user-supplied URLs directly.
- OWASP: [A10:2021](https://owasp.org/Top10/)
- Sumber: `var _GET`, `var _POST`, `var _REQUEST`, `var _COOKIE`, `var _FILES`, `call request.input`, `call request.get`, `call request.query`, `call request.post`, `call request.all`, `call request.only`, `call request.except`, `call request.json`, `call request.header`, `call request.cookie`, `call request.route`, `call request.file`, `call request.string`, `call request.str`, `call Request::input`, `call Request::get`, `call Request::query`, `call Request::all`, `call request`, `field request.*`
- Sink: `call curl_init arg0`, `call get_headers arg0`, `call simplexml_load_file arg0`, `call Http::get arg0`, `call Http::post arg0`, `call Http::put arg0`, `call Http::delete arg0`, `call *.request arg1`
- Sanitizer: `call intval`, `call md5`, `call sha1`, `call crc32`, `call hash`, `call hash_hmac`, `call password_hash`, `call bin2hex`, `call uniqid`, `call random_int`

### tphp-xss

**Cross-site scripting (tainted data reaches HTML output)** — Untrusted input flows into HTML output without escaping.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Escape output for the HTML context or use a sanitising library.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Menggantikan (bila alur data terbukti): `php-echo-request`
- Sumber: `var _GET`, `var _POST`, `var _REQUEST`, `var _COOKIE`, `var _FILES`, `call request.input`, `call request.get`, `call request.query`, `call request.post`, `call request.all`, `call request.only`, `call request.except`, `call request.json`, `call request.header`, `call request.cookie`, `call request.route`, `call request.file`, `call request.string`, `call request.str`, `call Request::input`, `call Request::get`, `call Request::query`, `call Request::all`, `call request`, `field request.*`
- Sink: `call echo args`, `call print arg0`, `call printf arg0`, `call die arg0`, `call exit arg0`
- Sanitizer: `call htmlspecialchars`, `call htmlentities`, `call strip_tags`, `call intval`, `call urlencode`, `call esc_html`, `call e`, `call json_encode`, `call file_get_contents`, `call curl_exec`, `call fread`, `call mysqli_query`, `call *.query`, `call fgets`, `call file`, `call md5`, `call sha1`, `call crc32`, `call hash`, `call hash_hmac`, `call password_hash`, `call bin2hex`, `call uniqid`, `call random_int`

### tpy-cmdi

**OS command injection (tainted data reaches a shell)** — Untrusted input flows into an OS command.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Avoid the shell; pass an argument list and validate input.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Menggantikan (bila alur data terbukti): `py-os-system`
- Sumber: `field *request.args`, `field *request.form`, `field *request.GET`, `field *request.POST`, `field *request.json`, `field *request.values`, `field *request.data`, `field *request.cookies`, `field *request.headers`, `field *request.files`, `call input`, `field sys.argv`
- Sink: `call os.system arg0`, `call os.popen arg0`, `call subprocess.getoutput arg0`, `call subprocess.getstatusoutput arg0`, `call commands.getoutput arg0`
- Sanitizer: `call int`, `call shlex.quote`, `call pipes.quote`, `call hashlib.*`, `call *.hexdigest`, `call *.digest`, `call zlib.crc32`, `call uuid.uuid4`

### tpy-codei

**Code injection (tainted data reaches eval)** — Untrusted input flows into dynamic code evaluation.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Never evaluate user input; use a parser or a fixed lookup.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Menggantikan (bila alur data terbukti): `py-eval`, `py-exec`
- Sumber: `field *request.args`, `field *request.form`, `field *request.GET`, `field *request.POST`, `field *request.json`, `field *request.values`, `field *request.data`, `field *request.cookies`, `field *request.headers`, `field *request.files`, `call input`, `field sys.argv`
- Sink: `call eval arg0`, `call exec arg0`, `call compile arg0`
- Sanitizer: `call int`, `call float`, `call ast.literal_eval`, `call hashlib.*`, `call *.hexdigest`, `call *.digest`, `call zlib.crc32`, `call uuid.uuid4`

### tpy-deser

**Insecure deserialization (tainted data reaches a deserializer)** — Untrusted input flows into an unsafe deserializer.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Use a data-only format (JSON) and validate the result.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Menggantikan (bila alur data terbukti): `py-pickle-loads`
- Sumber: `field *request.args`, `field *request.form`, `field *request.GET`, `field *request.POST`, `field *request.json`, `field *request.values`, `field *request.data`, `field *request.cookies`, `field *request.headers`, `field *request.files`, `call input`, `field sys.argv`
- Sink: `call pickle.loads arg0`, `call pickle.load arg0`, `call cPickle.loads arg0`, `call marshal.loads arg0`, `call yaml.unsafe_load arg0`, `call jsonpickle.decode arg0`, `call dill.loads arg0`
- Sanitizer: `call hashlib.*`, `call *.hexdigest`, `call *.digest`, `call zlib.crc32`, `call uuid.uuid4`

### tpy-idor

**Possible IDOR (request key fetches a record without ownership evidence)** — A record is fetched by a key taken from the request, and the function shows no sign of checking that the record belongs to the current user.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Scope the query to the signed-in user (filter by owner) or compare the owner after loading.
- OWASP: [A01:2021](https://owasp.org/Top10/)
- Sumber: `field *request.args`, `field *request.form`, `field *request.GET`, `field *request.POST`, `field *request.json`, `field *request.values`, `field *request.data`, `field *request.cookies`, `field *request.headers`, `field *request.files`, `call input`, `field sys.argv`, `param pk`, `param id`, `param *_id`, `param *_pk`
- Sink: `call *.query.get arg0`, `call *.query.get_or_404 arg0`, `call get_object_or_404 any`, `call *.objects.get kw:pk`, `call *.objects.get kw:id`, `call session.get arg1`
- Sanitizer: `call jwt.decode`, `call *.decode_token`, `call hashlib.*`, `call *.hexdigest`, `call *.digest`, `call zlib.crc32`, `call uuid.uuid4`

### tpy-pathtrav

**Path traversal (tainted data reaches a file path)** — Untrusted input flows into a file system path.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Use a fixed base directory, reduce input to a basename and verify the resolved path.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Sumber: `field *request.args`, `field *request.form`, `field *request.GET`, `field *request.POST`, `field *request.json`, `field *request.values`, `field *request.data`, `field *request.cookies`, `field *request.headers`, `field *request.files`, `call input`, `field sys.argv`
- Sink: `call open arg0`, `call send_file arg0`, `call send_from_directory arg1`, `call os.remove arg0`, `call os.unlink arg0`, `call shutil.copy arg0`, `call os.listdir arg0`, `call FileResponse arg0`
- Sanitizer: `call os.path.basename`, `call secure_filename`, `call werkzeug.utils.secure_filename`, `call int`, `call hashlib.*`, `call *.hexdigest`, `call *.digest`, `call zlib.crc32`, `call uuid.uuid4`

### tpy-redirect

**Open redirect (tainted data reaches a redirect)** — Untrusted input flows into a redirect target.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Redirect only to allow-listed or relative internal targets.
- OWASP: [A01:2021](https://owasp.org/Top10/)
- Sumber: `field *request.args`, `field *request.form`, `field *request.GET`, `field *request.POST`, `field *request.json`, `field *request.values`, `field *request.data`, `field *request.cookies`, `field *request.headers`, `field *request.files`, `call input`, `field sys.argv`
- Sink: `call redirect arg0`, `call HttpResponseRedirect arg0`
- Sanitizer: `call url_for`, `call reverse`, `call int`, `call hashlib.*`, `call *.hexdigest`, `call *.digest`, `call zlib.crc32`, `call uuid.uuid4`

### tpy-sqli

**SQL injection (tainted data reaches a query)** — Untrusted input flows into a SQL statement without parameter binding.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Use parameterised queries / bound parameters.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Menggantikan (bila alur data terbukti): `py-sql-execute-interp`
- Sumber: `field *request.args`, `field *request.form`, `field *request.GET`, `field *request.POST`, `field *request.json`, `field *request.values`, `field *request.data`, `field *request.cookies`, `field *request.headers`, `field *request.files`, `call input`, `field sys.argv`
- Sink: `call *.execute arg0`, `call *.executemany arg0`, `call *.raw arg0`, `call text arg0`, `call RawSQL arg0`, `call *.read_sql arg0`
- Sanitizer: `call int`, `call float`, `call bool`, `call hashlib.*`, `call *.hexdigest`, `call *.digest`, `call zlib.crc32`, `call uuid.uuid4`

### tpy-ssrf

**SSRF (tainted data reaches an outgoing request)** — Untrusted input flows into the URL of a server-side request.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Allow-list hosts and schemes; never request user-supplied URLs directly.
- OWASP: [A10:2021](https://owasp.org/Top10/)
- Sumber: `field *request.args`, `field *request.form`, `field *request.GET`, `field *request.POST`, `field *request.json`, `field *request.values`, `field *request.data`, `field *request.cookies`, `field *request.headers`, `field *request.files`, `call input`, `field sys.argv`
- Sink: `call requests.get arg0`, `call requests.post arg0`, `call requests.put arg0`, `call requests.delete arg0`, `call requests.head arg0`, `call requests.request arg1`, `call urllib.request.urlopen arg0`, `call urlopen arg0`, `call httpx.get arg0`, `call httpx.post arg0`
- Sanitizer: `call int`, `call hashlib.*`, `call *.hexdigest`, `call *.digest`, `call zlib.crc32`, `call uuid.uuid4`

### tpy-ssti

**Template injection (tainted data reaches a template)** — Untrusted input flows into a template source.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Pass user data as template variables, never as template source.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Sumber: `field *request.args`, `field *request.form`, `field *request.GET`, `field *request.POST`, `field *request.json`, `field *request.values`, `field *request.data`, `field *request.cookies`, `field *request.headers`, `field *request.files`, `call input`, `field sys.argv`
- Sink: `call render_template_string arg0`, `call jinja2.Template arg0`
- Sanitizer: `call int`, `call hashlib.*`, `call *.hexdigest`, `call *.digest`, `call zlib.crc32`, `call uuid.uuid4`

### tpy-xss

**Cross-site scripting (tainted data reaches HTML output)** — Untrusted input flows into HTML output without escaping.

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Escape output for the HTML context or use a sanitising library.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Sumber: `field *request.args`, `field *request.form`, `field *request.GET`, `field *request.POST`, `field *request.json`, `field *request.values`, `field *request.data`, `field *request.cookies`, `field *request.headers`, `field *request.files`, `call input`, `field sys.argv`
- Sink: `call Markup arg0`, `call mark_safe arg0`, `call HttpResponse arg0`
- Sanitizer: `call escape`, `call html.escape`, `call markupsafe.escape`, `call bleach.clean`, `call conditional_escape`, `call int`, `call requests.*`, `call httpx.*`, `call urlopen`, `call urllib.request.urlopen`, `call open`, `call *.execute`, `call *.fetchall`, `call *.fetchone`, `call *.read`, `call hashlib.*`, `call *.hexdigest`, `call *.digest`, `call zlib.crc32`, `call uuid.uuid4`

## Stack `laravel` (13 rule)

| Rule | Jenis | Severity | Confidence | Tier | CWE |
|---|---|---|---|---|---|
| [`lv-app-debug`](#lv-app-debug) | scanner | high | medium | — | [CWE-489](https://cwe.mitre.org/data/definitions/489.html), [CWE-215](https://cwe.mitre.org/data/definitions/215.html) |
| [`lv-app-key`](#lv-app-key) | scanner | high | medium | — | [CWE-798](https://cwe.mitre.org/data/definitions/798.html), [CWE-321](https://cwe.mitre.org/data/definitions/321.html) |
| [`lv-blade-csrf`](#lv-blade-csrf) | scanner | medium | medium | — | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) |
| [`lv-blade-php-echo`](#lv-blade-php-echo) | scanner | medium | medium | — | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| [`lv-blade-raw`](#lv-blade-raw) | scanner | high | medium | — | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| [`lv-csrf-exempt`](#lv-csrf-exempt) | crosscheck | medium | medium | A | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) |
| [`lv-csrf-wildcard`](#lv-csrf-wildcard) | scanner | high | high | — | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) |
| [`lv-fillable-privileged`](#lv-fillable-privileged) | schema | medium | medium | — | [CWE-915](https://cwe.mitre.org/data/definitions/915.html) |
| [`lv-guarded-empty`](#lv-guarded-empty) | schema | high | medium | — | [CWE-915](https://cwe.mitre.org/data/definitions/915.html) |
| [`lv-hidden-missing`](#lv-hidden-missing) | schema | medium | low | — | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) |
| [`lv-mass-assign`](#lv-mass-assign) | taint | high | medium | — | [CWE-915](https://cwe.mitre.org/data/definitions/915.html) |
| [`lv-route-no-auth`](#lv-route-no-auth) | crosscheck | high | medium | A | [CWE-306](https://cwe.mitre.org/data/definitions/306.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html) |
| [`lv-seeder-password`](#lv-seeder-password) | scanner | medium | medium | — | [CWE-798](https://cwe.mitre.org/data/definitions/798.html), [CWE-1392](https://cwe.mitre.org/data/definitions/1392.html) |

### lv-app-debug

**Debug mode enabled** — APP_DEBUG is enabled.

- Jenis: scanner — Text scanner over files (secrets, env files, templates).
- Perbaikan: Set APP_DEBUG=false in production.
- OWASP: [A05:2021](https://owasp.org/Top10/)

### lv-app-key

**APP_KEY committed in an env file** — APP_KEY is stored in a committed env file.

- Jenis: scanner — Text scanner over files (secrets, env files, templates).
- Perbaikan: Remove the file from version control, rotate the key and generate a new one per environment.
- OWASP: [A02:2021](https://owasp.org/Top10/)

### lv-blade-csrf

**State-changing form without @csrf** — A POST/PUT/PATCH/DELETE form has no @csrf.

- Jenis: scanner — Text scanner over files (secrets, env files, templates).
- Perbaikan: Add @csrf inside the form.
- OWASP: [A01:2021](https://owasp.org/Top10/)

### lv-blade-php-echo

**Raw PHP echo in a Blade view** — A raw PHP echo bypasses Blade escaping.

- Jenis: scanner — Text scanner over files (secrets, env files, templates).
- Perbaikan: Use {{ }} instead of <?= ?> or echo inside @php.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### lv-blade-raw

**Blade output printed without escaping** — {!! !!} prints raw HTML.

- Jenis: scanner — Text scanner over files (secrets, env files, templates).
- Perbaikan: Use {{ }}; if HTML is needed, sanitise it (HTMLPurifier) before printing.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### lv-csrf-exempt

**Route excluded from CSRF verification** — A route is excluded from CSRF verification.

- Jenis: crosscheck — Relates code facts (queries, routes) to the schema or auth model.
- Perbaikan: Remove the exclusion, or authenticate the caller with a header token instead of cookies.
- OWASP: [A01:2021](https://owasp.org/Top10/)

### lv-csrf-wildcard

**CSRF verification disabled for every route** — VerifyCsrfToken::$except contains '*'.

- Jenis: scanner — Text scanner over files (secrets, env files, templates).
- Perbaikan: List only the routes that must be exempt (webhooks) and authenticate them another way.
- OWASP: [A01:2021](https://owasp.org/Top10/)

### lv-fillable-privileged

**Privileged attribute is mass-assignable** — $fillable contains a privileged attribute.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Remove role/admin/balance style attributes from $fillable and set them explicitly.
- OWASP: [A04:2021](https://owasp.org/Top10/)

### lv-guarded-empty

**Model is fully mass-assignable** — $guarded = [] disables mass-assignment protection.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Declare an explicit $fillable list.
- OWASP: [A04:2021](https://owasp.org/Top10/)

### lv-hidden-missing

**Sensitive column not hidden from serialization** — A model does not hide a sensitive column.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Add the column to $hidden.
- OWASP: [A01:2021](https://owasp.org/Top10/)

### lv-mass-assign

**Whole request passed to a mass-assignment call** — The complete request input reaches create()/update()/fill(); a client can set any fillable attribute (role, admin, owner).

- Jenis: taint — Data-flow rule; reports only when untrusted data reaches the sink (trace included).
- Perbaikan: Pass $request->validated() or $request->only([...]) with an explicit list of columns.
- OWASP: [A04:2021](https://owasp.org/Top10/)
- Sumber: `call request.all`, `call Request::all`, `call request.post`, `call request.except`, `call request.json`, `call request.toArray`
- Sink: `call *::create arg0`, `call *::forceCreate arg0`, `call *::firstOrCreate arg0`, `call *::updateOrCreate arg0`, `call *::insert arg0`, `call *.create arg0`, `call *.update arg0`, `call *.fill arg0`, `call *.forceFill arg0`
- Sanitizer: `call *.validated`, `call *.only`, `call *.safe`, `call *.validate`, `call Arr::only`, `call array_intersect_key`

### lv-route-no-auth

**Route that reads or changes data without authentication** — A route handles data but is not behind auth middleware.

- Jenis: crosscheck — Relates code facts (queries, routes) to the schema or auth model.
- Perbaikan: Put the route in a Route::middleware('auth') group (or auth:sanctum) and authorize the record.
- OWASP: [A01:2021](https://owasp.org/Top10/)

### lv-seeder-password

**Seeder creates an account with a default password** — A seeder hashes a well-known password.

- Jenis: scanner — Text scanner over files (secrets, env files, templates).
- Perbaikan: Generate a random password or read it from the environment; do not seed admin accounts in production.
- OWASP: [A07:2021](https://owasp.org/Top10/)

## Stack `supabase` (16 rule)

| Rule | Jenis | Severity | Confidence | Tier | CWE |
|---|---|---|---|---|---|
| [`sb-config-signup`](#sb-config-signup) | schema | medium | high | A | [CWE-287](https://cwe.mitre.org/data/definitions/287.html) |
| [`sb-default-priv`](#sb-default-priv) | schema | medium | high | A | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) |
| [`sb-definer-no-path`](#sb-definer-no-path) | schema | high | high | A | [CWE-426](https://cwe.mitre.org/data/definitions/426.html) |
| [`sb-dynamic-sql`](#sb-dynamic-sql) | schema | high | medium | A | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) |
| [`sb-edge-no-jwt`](#sb-edge-no-jwt) | schema | high | medium | A | [CWE-306](https://cwe.mitre.org/data/definitions/306.html) |
| [`sb-grant-broad`](#sb-grant-broad) | schema | high | high | A | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) |
| [`sb-policy-anon-write`](#sb-policy-anon-write) | schema | high | high | A | [CWE-862](https://cwe.mitre.org/data/definitions/862.html) |
| [`sb-policy-no-uid`](#sb-policy-no-uid) | schema | medium | medium | B | [CWE-863](https://cwe.mitre.org/data/definitions/863.html) |
| [`sb-policy-true`](#sb-policy-true) | schema | high | high | A | [CWE-863](https://cwe.mitre.org/data/definitions/863.html) |
| [`sb-policy-user-metadata`](#sb-policy-user-metadata) | schema | high | high | A | [CWE-285](https://cwe.mitre.org/data/definitions/285.html) |
| [`sb-rls-missing`](#sb-rls-missing) | schema | critical | high | A | [CWE-862](https://cwe.mitre.org/data/definitions/862.html) |
| [`sb-schema-drift`](#sb-schema-drift) | schema | medium | high | A | [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) |
| [`sb-seed-secret`](#sb-seed-secret) | schema | high | high | A | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| [`sb-storage-policy`](#sb-storage-policy) | schema | high | medium | A | [CWE-863](https://cwe.mitre.org/data/definitions/863.html) |
| [`sb-storage-public`](#sb-storage-public) | schema | medium | medium | A | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) |
| [`sb-view-no-invoker`](#sb-view-no-invoker) | schema | medium | high | A | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) |

### sb-config-signup

**Open sign-up without email confirmation** — Email sign-ups are open and confirmation is disabled.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Set [auth.email] enable_confirmations = true.
- OWASP: [A07:2021](https://owasp.org/Top10/)

### sb-default-priv

**Default privileges grant write access on future tables** — ALTER DEFAULT PRIVILEGES grants write access to API roles.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Remove the default grant; grant per table.
- OWASP: [A01:2021](https://owasp.org/Top10/)

### sb-definer-no-path

**SECURITY DEFINER function without search_path** — SECURITY DEFINER functions must pin search_path.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Add SET search_path = '' and schema-qualify every object.
- OWASP: [A04:2021](https://owasp.org/Top10/)

### sb-dynamic-sql

**SQL injection in a plpgsql function** — EXECUTE receives a query built by concatenation or %s formatting.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Use format('%L'/'%I') or EXECUTE ... USING $1.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### sb-edge-no-jwt

**Edge function without JWT verification** — An edge function is configured with verify_jwt = false.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Keep verify_jwt = true, or authenticate callers inside the function (e.g. webhook signature).
- OWASP: [A07:2021](https://owasp.org/Top10/)

### sb-grant-broad

**Overly broad GRANT to API roles** — Write privileges were granted to an API role.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Grant only the privileges each role needs (usually SELECT).
- OWASP: [A01:2021](https://owasp.org/Top10/)

### sb-policy-anon-write

**Unauthenticated (anon) users can write** — A policy lets the anon role INSERT/UPDATE/DELETE.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Grant write policies TO authenticated and check ownership.
- OWASP: [A01:2021](https://owasp.org/Top10/)

### sb-policy-no-uid

**Policy does not check the row owner** — The table has user_id but the policy never compares it with auth.uid().

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Add (select auth.uid()) = user_id to the policy expression.
- OWASP: [A01:2021](https://owasp.org/Top10/)

### sb-policy-true

**Policy allows everything (USING/WITH CHECK true)** — A permissive policy for client roles has a TRUE expression.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Restrict rows, e.g. USING ((select auth.uid()) = user_id).
- OWASP: [A01:2021](https://owasp.org/Top10/)

### sb-policy-user-metadata

**Policy trusts user_metadata** — Authorization based on user_metadata can be forged by the user.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Use app_metadata (server controlled) or a dedicated roles table.
- OWASP: [A01:2021](https://owasp.org/Top10/)

### sb-rls-missing

**Table exposed without Row Level Security** — A table in an exposed schema has Row Level Security disabled.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: ALTER TABLE <t> ENABLE ROW LEVEL SECURITY; then add explicit policies.
- OWASP: [A01:2021](https://owasp.org/Top10/)

### sb-schema-drift

**Live database differs from the migrations** — The database dump and the migrations disagree.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Bring the database and migrations back in sync (supabase db diff / db pull).
- OWASP: [A05:2021](https://owasp.org/Top10/)

### sb-seed-secret

**Hard-coded password in seed data** — Seed data contains a hard-coded password.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Generate passwords at runtime or keep seeds out of production.
- OWASP: [A07:2021](https://owasp.org/Top10/)

### sb-storage-policy

**Storage policy without ownership check** — A storage.objects write policy does not check who owns the object.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Restrict with (storage.foldername(name))[1] = (select auth.uid())::text.
- OWASP: [A01:2021](https://owasp.org/Top10/)

### sb-storage-public

**Public storage bucket with sensitive name** — A public bucket name suggests sensitive files.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: Make the bucket private and serve files with signed URLs.
- OWASP: [A01:2021](https://owasp.org/Top10/)

### sb-view-no-invoker

**View bypasses RLS** — A view in an exposed schema runs with its owner's privileges.

- Jenis: schema — Reads the database/config model built from migrations or settings.
- Perbaikan: CREATE VIEW ... WITH (security_invoker = true).
- OWASP: [A01:2021](https://owasp.org/Top10/)

## Stack `typescript` (7 rule)

| Rule | Jenis | Severity | Confidence | Tier | CWE |
|---|---|---|---|---|---|
| [`ts-cmd-injection`](#ts-cmd-injection) | pattern | critical | medium | A | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) |
| [`ts-dynamic-eval`](#ts-dynamic-eval) | pattern | high | medium | A | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) |
| [`ts-idor-eq-id`](#ts-idor-eq-id) | crosscheck | high | medium | B | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) |
| [`ts-service-role-client`](#ts-service-role-client) | pattern | critical | high | A | [CWE-522](https://cwe.mitre.org/data/definitions/522.html) |
| [`ts-supabase-or-inject`](#ts-supabase-or-inject) | pattern | medium | medium | A | [CWE-943](https://cwe.mitre.org/data/definitions/943.html) |
| [`ts-table-no-rls`](#ts-table-no-rls) | crosscheck | high | high | A | [CWE-862](https://cwe.mitre.org/data/definitions/862.html) |
| [`ts-xss-dangerous-html`](#ts-xss-dangerous-html) | pattern | high | medium | A | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |

### ts-cmd-injection

**Shell command built from non-constant input** — child_process.exec runs a shell; a non-constant command enables injection.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Use execFile/spawn with an argument array.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Menggantikan (bila alur data terbukti): `js-exec`

### ts-dynamic-eval

**Dynamic code evaluation** — eval()/new Function() executes code built from non-constant input.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Parse data with JSON.parse or an explicit parser.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Menggantikan (bila alur data terbukti): `js-eval`, `js-function-constructor`

### ts-idor-eq-id

**Row fetched by request-supplied id without an ownership check** — A row is selected by an id taken from the request and nothing limits it to its owner.

- Jenis: crosscheck — Relates code facts (queries, routes) to the schema or auth model.
- Perbaikan: Add an owner filter (.eq('user_id', user.id)) or an owner-based RLS policy.
- OWASP: [A01:2021](https://owasp.org/Top10/)

### ts-service-role-client

**Supabase service_role key used in client-bundled code** — createClient receives a service_role key from a public (client-bundled) env variable.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Use the anon key in the browser and keep service_role in server-only code.
- OWASP: [A02:2021](https://owasp.org/Top10/)

### ts-supabase-or-inject

**Filter injection through PostgREST .or()** — Input concatenated into .or(...) can add arbitrary filters.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Use .ilike()/.eq() with separate arguments, or validate the input.
- OWASP: [A03:2021](https://owasp.org/Top10/)

### ts-table-no-rls

**Client queries a table that has no Row Level Security** — Code using the public anon key reads or writes a table without RLS.

- Jenis: crosscheck — Relates code facts (queries, routes) to the schema or auth model.
- Perbaikan: Enable RLS on the table and add policies, or stop querying it from the client.
- OWASP: [A01:2021](https://owasp.org/Top10/)

### ts-xss-dangerous-html

**dangerouslySetInnerHTML with unsanitized data** — dangerouslySetInnerHTML renders raw HTML; non-constant, unsanitized data enables XSS.

- Jenis: pattern — Syntax pattern (tree-sitter); flags code that has the shape described.
- Perbaikan: Sanitize with DOMPurify.sanitize(...) or render text.
- OWASP: [A03:2021](https://owasp.org/Top10/)
- Menggantikan (bila alur data terbukti): `js-dangerous-html`
