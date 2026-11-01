"""
CoverSec — Test Case Mapping

Maps vulnerability types (by title/CWE) to pentester test cases.
Every known vulnerability class gets a "How to Test" regardless of
what the report's recommendations say.

Used by both extractor.py and pdf_extractor.py.
"""

import re

# ---------------------------------------------------------------------------
# Vulnerability type → Test cases
# Matched against technique title and CWE
# ---------------------------------------------------------------------------

TECHNIQUE_TESTS = [
    # --- Injection ---
    (r"SQL\s+Injection|CWE-89",
     ["Inject payloads in all input fields and parameters: ' OR 1=1--, ' UNION SELECT null--, ' AND SLEEP(5)--",
      "Test with sqlmap: sqlmap -u 'URL' --batch --risk=3 --level=5",
      "Try blind SQLi: submit ' AND 1=1-- (true) vs ' AND 1=2-- (false) and compare responses",
      "Test in search fields, login forms, filters, sort parameters, and hidden fields"]),

    (r"Command\s+(?:Injection|Execution)|\bRCE\b|Remote\s+Code\s+Execution|CWE-78|CWE-94",
     ["Inject OS commands using separators: ; ls, | whoami, && id, `id`, $(whoami)",
      "Test in all input fields, file names, headers (User-Agent, Referer), and API parameters",
      "Try time-based detection: ; sleep 5 or | ping -c 5 127.0.0.1 and measure response delay",
      "Check if the app passes user input to system(), exec(), eval(), or similar functions"]),

    (r"Server.Side\s+Template\s+Injection|SSTI|CWE-1336",
     ["Inject template syntax: {{7*7}}, ${7*7}, <%= 7*7 %>, #{7*7}, {7*7}",
      "If 49 appears in response, test for RCE with framework-specific payloads (Jinja2, Twig, Freemarker, etc.)",
      "Test in all user inputs that get reflected in rendered pages: names, profile fields, email templates"]),

    (r"XSS|Cross.Site\s+Scripting|CWE-79",
     ["Inject in all input fields, URL parameters, headers, and file upload names: <script>alert(1)</script>",
      "Try filter bypass payloads: \"><img src=x onerror=alert(1)>, <svg onload=alert(1)>, javascript:alert(1)",
      "For stored XSS: submit payload in one field (e.g., username), check if it executes when another user views it",
      "Check if output encoding is applied — view page source and search for your payload unescaped"]),

    (r"HTML\s+Injection|CWE-80",
     ["Inject HTML tags: <h1>test</h1>, <img src=x>, <a href='evil'>click</a>",
      "Check if injected HTML renders in the page — if it does, escalate to XSS testing"]),

    (r"CSV\s+Injection|CWE-1236",
     ["Enter payloads in input fields that get exported to CSV: =cmd|'/C calc'!A0, =HYPERLINK(\"http://evil.com\")",
      "Export the data to CSV/Excel and check if formulas execute when opened"]),

    (r"LDAP\s+Injection|CWE-90",
     ["Inject LDAP metacharacters in login/search fields: *, )(, )(objectClass=*), admin)(&)",
      "Test if authentication can be bypassed with *)(&password= or similar"]),

    (r"XML\s+Injection|XXE|CWE-611",
     ["Submit XML with external entity: <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
      "Test for blind XXE with out-of-band: <!ENTITY xxe SYSTEM \"http://your-burp-collaborator\">",
      "Check all endpoints that accept XML input including SOAP, SVG uploads, and DOCX/XLSX uploads"]),

    # --- Authentication ---
    (r"Broken\s+Authentication|Authentication\s+Bypass|CWE-287",
     ["Try accessing protected pages directly without logging in — paste the URL in a new browser/incognito",
      "Intercept the login response and change error codes or status fields (e.g., 'success: false' → 'success: true')",
      "Test if removing/modifying the session token still allows access to authenticated endpoints"]),

    (r"(?:User|Email|Account)\s*(?:name)?\s*Enumeration|CWE-204",
     ["Submit valid vs invalid usernames on login, registration, and password reset — compare response messages, timing, and HTTP status codes",
      "Use Burp Intruder with a username wordlist and look for differences in response length or content",
      "Check if error messages differ: 'user not found' vs 'wrong password' reveals valid usernames"]),

    (r"Brute.Force|Rate\s+Limit|Lockout|CWE-307|CWE-770",
     ["Send 50+ rapid login attempts with Burp Intruder — check if the server throttles, blocks, or returns 429",
      "Test on all auth endpoints: login, OTP verification, password reset, API keys",
      "Check if account lockout exists: send 10+ wrong passwords and see if the account gets locked",
      "Try IP rotation or header spoofing (X-Forwarded-For) to bypass rate limiting"]),

    (r"Weak\s+Password|Password\s+Policy|CWE-521",
     ["Try creating accounts with weak passwords: 123456, password, aaa, single character, empty string",
      "Check minimum length, uppercase/lowercase/number/special char requirements",
      "Test if common passwords from rockyou.txt top 100 are accepted"]),

    (r"Credential|Hardcoded.+(?:Secret|Key|Password|Token)|CWE-798|CWE-260",
     ["Decompile the app (jadx for Android, Hopper for iOS) and search for: API keys, passwords, tokens, secrets",
      "Search config files, source code, and git history: grep -r 'password\\|secret\\|api_key\\|token'",
      "Use tools like trufflehog or gitleaks to scan for leaked secrets"]),

    # --- Access Control ---
    (r"Broken\s+Access\s+Control|BAC|Missing.+Authorization|IDOR|Insecure\s+Direct\s+Object|CWE-862|CWE-284|CWE-639",
     ["Log in as User A, capture a request to their resource. Change the ID to User B's and replay",
      "Try accessing admin endpoints (/admin, /api/admin/) as a regular user",
      "Swap cookies/tokens between a low-privilege and high-privilege account and access restricted functions",
      "Test all CRUD operations: can you view/edit/delete other users' data by changing IDs?"]),

    (r"Privilege\s+Escalation|CWE-269",
     ["Log in as a low-privilege user. Capture requests to admin-only functions and replay them",
      "Modify role/privilege parameters in requests: role=user → role=admin, isAdmin=false → isAdmin=true",
      "Check if horizontal escalation works: access another same-level user's data by changing user IDs"]),

    (r"Mass\s+Assignment|CWE-915",
     ["Add extra parameters to POST/PUT requests: role=admin, isVerified=true, balance=99999",
      "Check API docs for all model fields and try including read-only fields in write requests"]),

    (r"RBAC|Role.Based|Misconfigured\s+(?:Role|Permission)|CWE-863",
     ["Map all roles (admin, user, guest). For each restricted function, test access with every other role",
      "Check if role enforcement is server-side: modify role claims in JWT or session data"]),

    # --- SSRF ---
    (r"SSRF|Server.Side\s+Request\s+Forgery|CWE-918",
     ["Find parameters accepting URLs (webhooks, image URLs, imports). Try: http://127.0.0.1, http://localhost, http://169.254.169.254/latest/meta-data/",
      "Use Burp Collaborator to detect blind SSRF — inject your collaborator URL and check for DNS/HTTP callbacks",
      "Try bypasses: http://0x7f000001, http://[::1], http://127.1, http://evil.com@127.0.0.1"]),

    # --- CSRF ---
    (r"CSRF|Cross.Site\s+Request\s+Forgery|CWE-352",
     ["Capture a state-changing request (password change, settings update, transfer). Remove the CSRF token and replay",
      "Create an HTML page that auto-submits the form to the target endpoint from a different origin",
      "Check if the app validates CSRF tokens — try empty token, another user's token, or a token from a different session"]),

    # --- Session ---
    (r"Session\s+(?:Management|Misconfiguration|Fixation|Expir)|Concurrent\s+Session|CWE-613|CWE-384",
     ["Log in from two browsers simultaneously — check if both sessions remain active",
      "After logout, replay the old session token — check if it's still valid",
      "After password change, check if all other sessions are invalidated",
      "Check session timeout: leave the app idle, then try to use it after the expected timeout"]),

    (r"Cookie.+(?:Secure|HttpOnly|SameSite|Flag)|CWE-614",
     ["Open browser DevTools → Application → Cookies. Check if session cookies have Secure, HttpOnly, and SameSite flags",
      "Try accessing the cookie via JavaScript: document.cookie — if HttpOnly is set it shouldn't appear"]),

    (r"JWT|Token.+(?:Local\s*Storage|Insecure\s*Storage)",
     ["Open browser DevTools → Application → Local Storage. Check if JWTs or tokens are stored there instead of HttpOnly cookies",
      "Decode the JWT at jwt.io — check if sensitive data is in the payload and if the algorithm can be changed to 'none'"]),

    # --- File Upload ---
    (r"(?:File\s+Upload|Unrestricted\s+Upload)|CWE-434",
     ["Upload a web shell with double extension: shell.php.jpg, shell.aspx.png",
      "Change Content-Type header: upload .php file but set Content-Type to image/jpeg",
      "Try null byte injection: shell.php%00.jpg",
      "Upload oversized files and files with special characters in names",
      "After upload, check if the file is accessible and executable via direct URL"]),

    # --- Path Traversal ---
    (r"Path\s+Traversal|Directory\s+Traversal|LFI|CWE-22",
     ["Inject traversal sequences in file parameters: ../../../etc/passwd, ..\\..\\..\\windows\\win.ini",
      "Try encoded variants: %2e%2e%2f, ..%252f, ....//",
      "Test in file download, file include, template selection, and language selection parameters"]),

    # --- Directory Listing ---
    (r"Directory\s+Listing|CWE-548",
     ["Browse to directories without index files: /images/, /uploads/, /backup/, /temp/",
      "Check Server and X-Powered-By response headers for version info",
      "Try common sensitive paths: /.git, /.env, /web.config, /wp-config.php, /server-status"]),

    # --- Information Disclosure ---
    (r"Information\s+Disclosure|Sensitive\s+(?:Data\s+)?(?:Exposure|Leak)|Fingerprint|CWE-200",
     ["Check response headers for server version info: Server, X-Powered-By, X-AspNet-Version",
      "Trigger errors and check if they leak stack traces, file paths, SQL queries, or internal IPs",
      "Check HTML source, JavaScript files, and API responses for comments, debug info, or internal endpoints",
      "Try accessing: /robots.txt, /sitemap.xml, /.git/HEAD, /swagger, /api-docs"]),

    (r"Error\s+Handling|Stack\s+Trace|Debug|CWE-209",
     ["Send malformed requests: wrong data types, missing required fields, extremely long strings, special characters",
      "Trigger 404, 500, and 403 errors and check if responses leak server version, file paths, SQL queries, or stack traces",
      "Check if debug mode is enabled: look for detailed error pages (Django debug, Laravel debug bar, Spring Whitelabel)"]),

    # --- Transport Security ---
    (r"Cleartext|Unencrypted|HTTP(?!S)|Insecure\s+(?:Communication|Transport)|SSL|TLS|CWE-319",
     ["Check if the app is accessible over plain HTTP — try http:// instead of https://",
      "Use Wireshark/tcpdump on the network to verify sensitive data is not sent in cleartext",
      "Check SSL/TLS configuration with testssl.sh or ssllabs.com: look for weak ciphers, expired certs, missing HSTS"]),

    # --- Security Headers ---
    (r"Security\s+Header|CSP|HSTS|X-Frame|CWE-644|CWE-693",
     ["Send a request and check response headers for: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, X-XSS-Protection",
      "Use securityheaders.com to scan the target",
      "Test clickjacking: create an HTML page with <iframe src='target'> — if it loads, X-Frame-Options is missing"]),

    # --- CORS ---
    (r"CORS|Cross.Origin|Access.Control.Allow|CWE-942",
     ["Send a request with header Origin: https://evil.com — check if the response includes Access-Control-Allow-Origin: * or reflects your origin",
      "Test with Origin: null — some apps whitelist null",
      "If credentials are allowed (Access-Control-Allow-Credentials: true), try stealing data with a malicious page using fetch() with credentials: 'include'"]),

    # --- Open Redirect ---
    (r"Open\s+Redirect|URL\s+Redirect|CWE-601",
     ["Find redirect parameters: redirect_url, return_to, next, url, continue, dest",
      "Try: https://evil.com, //evil.com, /\\evil.com, /%09/evil.com, javascript:alert(1)",
      "Check if the redirect is used after login — it can be chained with phishing to steal credentials"]),

    # --- Outdated Components ---
    (r"Outdated|Vulnerable.+Component|End.of.Life|CWE-937|CWE-1104",
     ["Identify all framework/library/server versions from headers, JavaScript files, package.json, pom.xml",
      "Check versions against CVE databases: NVD, Snyk, retire.js",
      "Use tools: npm audit, OWASP Dependency-Check, pip-audit, bundler-audit"]),

    # --- Business Logic ---
    (r"Price\s+(?:Tamper|Manipulat)|Payment\s+Bypass|CWE-1284",
     ["Add item to cart, intercept checkout request, modify price/quantity/discount/total fields",
      "Try negative quantities or zero prices",
      "Check if the server recalculates totals from its own data or trusts client values"]),

    # --- Mobile: Root/Jailbreak ---
    (r"Root\s+Detection|Jailbreak|Emulator\s+Detection|CWE-919",
     ["Install the app on a rooted device (Magisk) or jailbroken device — check if the app detects it",
      "If detected, bypass with: Frida scripts, objection, MagiskHide/Shamiko, or Liberty Lite (iOS)",
      "Check if the detection is client-side only by hooking the detection function with Frida"]),

    (r"SSL\s+(?:Certificate\s+)?Pinning|Certificate\s+Pinning",
     ["Set up Burp as proxy and try to intercept HTTPS traffic from the app",
      "If pinning blocks it, bypass with: objection (android sslpinning disable), Frida scripts, or apk-mitm",
      "Check if pinning is implemented for all endpoints or only some"]),

    (r"Obfuscation|Reverse\s+Engineering|Code\s+Tamper",
     ["Decompile: jadx/apktool (Android), Hopper/class-dump (iOS)",
      "Check if class names, method names, and strings are readable or obfuscated",
      "Try modifying the APK (smali patching), repackaging, and check if the app detects tampering"]),

    # --- Mobile: Data Storage ---
    (r"(?:Sensitive\s+)?Data\s+Stored\s+Locally|Local\s+Storage|Insecure\s+(?:Data\s+)?Storage|CWE-922|CWE-312",
     ["Android: check /data/data/<package>/shared_prefs/, databases/, cache/ for cleartext sensitive data",
      "iOS: check app sandbox, NSUserDefaults, Keychain, plist files, CoreData databases",
      "Use objection: env, ios plist cat, android hooking list activities",
      "Check if data is encrypted at rest or stored in plaintext"]),

    (r"Data.+(?:Memory|Cached\s+in\s+Memory)|CWE-316",
     ["Use Fridump or objection to dump the app's memory while sensitive data is displayed on screen",
      "Search the memory dump for: passwords, tokens, PII, credit card numbers, encryption keys"]),

    (r"Data.+(?:Log|Application\s+Log)|Insecure\s+Logging|CWE-532",
     ["Android: run 'adb logcat' while using the app — search for tokens, passwords, PII, API keys, internal URLs",
      "iOS: open Console.app or Xcode → Devices → select device → check logs",
      "Check if debug logging is disabled in production builds"]),

    # --- Deserialization ---
    (r"Deserialization|Unserialize|CWE-502",
     ["Identify serialized data in requests (base64 encoded objects, Java serialized, PHP serialized, .NET ViewState)",
      "Use ysoserial (Java), phpggc (PHP), or similar tools to generate deserialization payloads",
      "Test if the app deserializes untrusted data by modifying serialized objects in cookies, parameters, or headers"]),

    # --- Miscellaneous ---
    (r"Unauthenticated\s+(?:Access|Endpoint)|Missing\s+Authentication|CWE-306",
     ["Try accessing all API endpoints and pages without any authentication token or session cookie",
      "Use tools like Burp to spider the app, then replay each request without the Authorization header",
      "Check if API documentation endpoints are accessible: /swagger, /api-docs, /graphql"]),

    (r"IIS\s+Tilde|Short\s+Filename|CWE-58",
     ["Send requests with tilde: http://target/~1/.aspx, http://target/a~1/.aspx",
      "Use IIS-ShortName-Scanner tool to enumerate short filenames on the server"]),

    (r"Clickjack|CWE-1021",
     ["Create an HTML page: <iframe src='https://target/sensitive-action' style='opacity:0'>",
      "If the page loads in the iframe, clickjacking is possible — check for X-Frame-Options or CSP frame-ancestors"]),

    (r"Mail\s+Flood|Email\s+Flood|CWE-799",
     ["Find email-triggering functions (password reset, invitations, notifications). Send 50+ rapid requests",
      "Check if the app limits the number of emails sent per user/IP/time period"]),

    (r"(?:Dead\s*Code|Unused\s+File|Backup\s+File)",
     ["Check for backup and leftover files: .bak, .old, .swp, .orig, ~, .git/, .DS_Store",
      "Try common paths: /backup/, /old/, /test/, /dev/, index.php.bak, web.config.old"]),
]

# Compile all patterns
_COMPILED_TESTS = [(re.compile(pat, re.IGNORECASE), tests) for pat, tests in TECHNIQUE_TESTS]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_test_cases(title: str, cwe: str = "") -> list[str]:
    """Get test cases for a technique by matching title and CWE."""
    search_text = f"{title} {cwe}"

    for pattern, test_cases in _COMPILED_TESTS:
        if pattern.search(search_text):
            return test_cases

    return []


def recommendations_to_testcases(recommendations: list[str]) -> list[str]:
    """Legacy wrapper — not used anymore but kept for compatibility."""
    return []


def generalize_title(title: str) -> str:
    """Generalize a finding-specific title into a technique name."""
    t = title.strip()
    # Remove leading finding IDs
    t = re.sub(r"^(?:R-)?(?:WAPT|EIPT|SCR|WBPT|MAPT|AND|iOS|API|POS|DAPT|PAPT|IIPT|ATMPT)\d+\s*:\s*", "", t)
    # Remove "in X Application/System/Portal" suffixes
    t = re.sub(r"\s+(?:in|on|for)\s+(?:the\s+)?(?:\w+\s+){0,3}(?:application|system|portal|module|platform|page|endpoint|function|functionality)\s*$", "", t, flags=re.IGNORECASE)
    # Remove "Leads to..." suffixes
    t = re.sub(r"\s+(?:leads?\s+to|resulting\s+in|allows?|enabling)\s+.+$", "", t, flags=re.IGNORECASE)
    return t.strip()
