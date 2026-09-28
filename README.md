# Cookie Security Analyzer

Inspects HTTP `Set-Cookie` response headers and flags missing or misconfigured security attributes that leave session tokens exposed to XSS theft, network interception, and cross-site request forgery.

## What This Demonstrates

Every web application that uses cookies for session management relies on three browser-enforced flags to keep those cookies safe:

- **`HttpOnly`** — prevents JavaScript from reading the cookie. Without it, any XSS vulnerability on the page gives an attacker a one-liner to steal your session: `document.cookie`.
- **`Secure`** — instructs the browser to only send the cookie over HTTPS. Without it, the cookie travels in plaintext over any HTTP connection — visible to anyone on the same network path.
- **`SameSite`** — controls whether the browser includes the cookie in cross-origin requests. Without it (or with `SameSite=None`), every cross-site form submission and AJAX call from an attacker's page carries the victim's session cookie — the mechanism behind CSRF attacks.

There is also a fourth trap: `SameSite=None` **requires** the `Secure` flag (RFC 6265bis §8.8). Setting `SameSite=None; Path=/` without `Secure` is rejected silently by Chrome 80+, Firefox, and Safari, meaning the cookie is never stored at all — an authentication-breaking misconfiguration.

## How It Works

```
server/main.py          Six FastAPI endpoints, each setting a cookie differently:
                          /set-cookie/bare             → no flags at all
                          /set-cookie/httponly-only    → HttpOnly only
                          /set-cookie/httponly-secure  → HttpOnly + Secure, no SameSite
                          /set-cookie/full-secure      → HttpOnly + Secure + SameSite=Strict ✓
                          /set-cookie/samesite-lax     → HttpOnly + Secure + SameSite=Lax ✓
                          /set-cookie/none-no-secure   → SameSite=None without Secure ✗

tool/main.py            Fetches /targets, probes each endpoint, parses the raw
                        Set-Cookie header, and emits JSON findings for:
                          MISSING_HTTPONLY      HIGH
                          MISSING_SECURE        HIGH
                          MISSING_SAMESITE      MEDIUM
                          INSECURE_SAMESITE_NONE  HIGH

tests/test.py           35 pytest tests — server health, true positives,
                        false positives, output format, edge cases.
```

## Quick Start

```bash
# Install dependencies
cd server  && pip install -r requirements.txt && cd ..
cd tool    && pip install -r requirements.txt && cd ..

# Run the demo server
cd server && python main.py
# Server listens on http://127.0.0.1:3000

# Run the scanner (separate terminal)
cd tool && python main.py --target http://localhost:3000

# Run the tests
cd tests && pip install -r requirements.txt && pytest test.py -v
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "/set-cookie/bare",
      "vulnerability_type": "MISSING_HTTPONLY",
      "evidence": "Cookie 'session' does not have the HttpOnly flag. JavaScript executing on the page — including injected scripts from XSS — can read this cookie via document.cookie and exfiltrate the session token.",
      "severity": "HIGH"
    },
    {
      "endpoint": "/set-cookie/bare",
      "vulnerability_type": "MISSING_SECURE",
      "evidence": "Cookie 'session' does not have the Secure flag. The cookie will be sent over plain HTTP connections as well as HTTPS, making it readable to any network observer on the same path.",
      "severity": "HIGH"
    },
    {
      "endpoint": "/set-cookie/bare",
      "vulnerability_type": "MISSING_SAMESITE",
      "evidence": "Cookie 'session' has no SameSite attribute. Without SameSite, the browser includes this cookie in all cross-site requests, leaving the session exposed to cross-site request forgery (CSRF) attacks.",
      "severity": "MEDIUM"
    },
    {
      "endpoint": "/set-cookie/none-no-secure",
      "vulnerability_type": "INSECURE_SAMESITE_NONE",
      "evidence": "Cookie 'session' sets SameSite=None without the Secure flag. RFC 6265bis §8.8 requires that SameSite=None cookies always carry the Secure attribute. Modern browsers (Chrome 80+, Firefox, Safari) silently reject this cookie, meaning it will never be stored — a misconfiguration that breaks authentication.",
      "severity": "HIGH"
    }
  ],
  "summary": "Found 8 cookie security issue(s) across 6 endpoint(s): 6 HIGH, 2 MEDIUM. Issues: 3× MISSING_HTTPONLY, 3× MISSING_SECURE, 2× MISSING_SAMESITE, 1× INSECURE_SAMESITE_NONE."
}
```

## Key Takeaways

- **Always set all three flags** — `HttpOnly; Secure; SameSite=Strict` (or `Lax`) — on every session cookie. There is no legitimate reason to omit any of them.
- **`SameSite=None` requires `Secure`** — if you need cross-site cookie delivery (e.g. for a third-party widget), you must use `Secure`. Without it, modern browsers silently discard the cookie.
- **`SameSite=Lax`** has been the browser default since Chrome 80 (2020). It allows cookie sending on top-level navigations but blocks them in subresource requests — a reasonable trade-off for most applications that don't need cross-origin cookie delivery.
- **Header inspection is a reliable audit method** — a scanner that checks Set-Cookie attributes requires no authentication and no application knowledge; it works on any HTTP endpoint.

## Further Reading

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [RFC 6265bis — Cookies: HTTP State Management Mechanism](https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html)
- [MDN — Using HTTP cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)
