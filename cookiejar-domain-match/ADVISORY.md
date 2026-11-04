# cookiejar: domain matching has no dot boundary, so cookies for `example.com` are sent to `notexample.com` (reachable through superagent agents)

**Reporter:** EkremSel
**Package:** `cookiejar` (npm)
**Component:** `Cookie.prototype.collidesWith` in `cookiejar.js` (used by `CookieJar#getCookies` and `CookieJar#setCookie`)
**Affected versions:** 2.0.0 – 2.1.4. 2.1.4 is the latest release (January 2023). 1.x is not affected because it never matched subdomains.
**Downstream:** `superagent` 10.4.1 (latest). `superagent.agent()` sends the leaked cookies on the wire, including after cross-origin redirects. Older superagent versions use the same code path but were not tested.
**Severity:** Medium (CVSS 3.1 5.9, `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N`)
**Type:** CWE-187 (Partial String Comparison) leading to CWE-200 (Exposure of Sensitive Information)

## Summary

To decide whether a stored cookie goes to a request host, `cookiejar` checks only that the
host *ends with* the cookie's `Domain`. It does not require a `.` before that suffix. A cookie
that `example.com` sets with `Domain=example.com` is therefore also returned for
`notexample.com`, a different domain that anyone can register.

RFC 6265 §5.1.3 says a host domain-matches a cookie domain only if the two are identical, or
the domain is a suffix of the host **and the character just before the suffix is `.`**.
Browsers and tough-cookie enforce this. Python's `http.cookiejar` had the same bug
([CVE-2018-20852](https://nvd.nist.gov/vuln/detail/CVE-2018-20852), where `pythonicexample.com`
received `example.com` cookies).

## Root cause

`cookiejar.js` 2.1.4, `Cookie.prototype.collidesWith`:

```js
var access_domain = access_info.domain && access_info.domain.replace(/^[\.]/,'');
var cookie_domain = this.domain && this.domain.replace(/^[\.]/,'');
if (cookie_domain === access_domain) {
    return true;
}
if (cookie_domain) {
    if (!this.explicit_domain) {
        return false; // we already checked if the domains were exactly the same
    }
    var wildcard = access_domain.indexOf(cookie_domain);
    if (wildcard === -1 || wildcard !== access_domain.length - cookie_domain.length) {
        return false;
    }
    return true;
}
```

The `indexOf` test is a plain suffix check: `"notexample.com"` ends with `"example.com"`, so it
passes. Only cookies with an explicit `Domain` attribute take this branch. Host-only cookies
(no `Domain`) are matched exactly and are not affected.

`setCookie()` uses the same function to decide which stored cookie a new one replaces, so the
flaw also affects what the jar keeps (see Impact).

## Behaviour

cookiejar 2.1.4 compared with tough-cookie 6.0.2's `domainMatch()` (RFC 6265 §5.1.3):

| Cookie `Domain` | Request host | RFC 6265 | cookiejar 2.1.4 |
|---|---|---|---|
| `example.com` | `notexample.com` | no | **sent** |
| `ample.com` | `example.com` | no | **sent** |
| `example.com` | `example.com` | yes | sent |
| `example.com` | `shop.example.com` | yes | sent |
| `example.com` | `example.com.evil.com` | no | not sent |
| `example.com` | `evil.com` | no | not sent |
| `example.com` | `example.com.example.com` | yes | not sent (a false negative, not a security issue) |
| *(none, host-only)* | `notexample.com` | no | not sent |

All 20 published versions were tested: 2.0.0 – 2.1.4 leak, 1.x does not.

## Reachability through superagent

`superagent.agent()` stores cookies in a `cookiejar` `CookieJar`:

- **When storing**, `lib/node/agent.js` already filters `Set-Cookie` with `filterCookiesForHost()`,
  which applies a correct dot-boundary check. So `example.com` setting `Domain=example.com` is
  accepted, as it should be.
- **When sending**, `_attachCookies()` relies on `jar.getCookies()`, which returns that cookie
  for `notexample.com`.
- **Redirects:** on a cross-origin 302, `Request#_redirect` deletes the `Cookie` header. The
  agent's `redirect` listener then calls `_attachCookies()` for the new URL, and the jar adds the
  cookie back.

## Proof of concept

Run `npm install`, then:

`node repro.js` (cookiejar alone, exits 1 while the bug is present):

```
Domain=example.com  -> notexample.com        RFC 6265: no    cookiejar: SENT   <-- leak
Domain=ample.com    -> example.com           RFC 6265: no    cookiejar: SENT   <-- leak
Domain=example.com  -> example.com           RFC 6265: send  cookiejar: SENT
Domain=example.com  -> shop.example.com      RFC 6265: send  cookiejar: SENT
Domain=example.com  -> example.com.evil.com  RFC 6265: no    cookiejar: not sent
Domain=example.com  -> evil.com              RFC 6265: no    cookiejar: not sent

after notexample.com sets "session", example.com gets "" (expected "session=VICTIM")
```

`node poc-superagent.js` (superagent 10.4.1 over real HTTP; hostnames are mapped to 127.0.0.1
with `.connect()`, so no DNS changes are needed). The server prints the `Cookie` header it
receives:

```
notexample.com:61713 /direct -> Cookie: session=abc123
notexample.com:61713 /landing -> Cookie: session=abc123
```

`/direct` is a plain request to `notexample.com`. `/landing` is reached through a 302 from
`example.com`. Tested on Node 26.

## Impact

1. **Session cookie disclosure.** A server-side app uses one superagent agent (or a `cookiejar`
   jar directly) to log in to `example.com`, which sets `Domain=example.com` (common for cookies
   shared across subdomains). An attacker registers a lookalike such as `notexample.com` and gets
   the agent to request it, for example through an open redirect on `example.com`, or a
   user-supplied URL (webhook, link preview, scraper) fetched with the same agent. The attacker's
   server receives the session cookie. The `Secure` flag does not help, because the attacker can
   get a TLS certificate for their own domain.
2. **Cookie eviction.** A same-named cookie set by `notexample.com` replaces the one `example.com`
   set, so the client silently loses its `example.com` session. The replacement is not sent to
   `example.com`.

Preconditions: the cookie has an explicit `Domain` attribute, the client reuses one jar across
hosts, and the attacker can get that client to request a host they control whose name ends in
the cookie's domain without a dot boundary. Browsers and clients built on tough-cookie are not
affected.

## Suggested fix

**cookiejar** (root cause). Replace the `indexOf` test in `collidesWith` with a dot-boundary check:

```js
if (!access_domain.endsWith('.' + cookie_domain)) {
    return false;
}
return true;
```

Tested: all cases in the table above then follow RFC 6265 (including the
`example.com.example.com` false negative), and the eviction no longer happens.

**superagent** (mitigation while cookiejar is unmaintained). Filter jar results in
`_attachCookies()` with the existing `domainMatches()` helper:

```js
_attachCookies(request_) {
  const url = new URL(request_.url);
  const host = url.hostname.toLowerCase();
  const access = new CookieAccessInfo(url.hostname, url.pathname, url.protocol === 'https:');
  request_.cookies = this.jar.getCookies(access)
    .filter(c => !c.explicit_domain ||
      domainMatches(host, String(c.domain).replace(/^\./, '').toLowerCase()))
    .map(c => c.toValueString())
    .join('; ');
}
```

Tested against `poc-superagent.js`: both leaks stop, and the cookie is still sent to
`example.com` and `shop.example.com`. This does not stop the eviction, which needs the cookiejar fix.

## Timeline

- 2026-11-03: issue found.
- 2026-11-04: verified against every published cookiejar version and end-to-end through superagent 10.4.1.
- 2026-11-04: reported to the superagent maintainer by email, per superagent's SECURITY.md.
- 2026-11-04: reported to the cookiejar maintainers by email, using the addresses listed on npm.
  cookiejar has no security policy or private reporting channel.
- 2026-11-04 13:30 UTC: published.

## References

- RFC 6265 §5.1.3 (domain matching): https://www.rfc-editor.org/rfc/rfc6265#section-5.1.3
- CVE-2018-20852, same bug class in Python `http.cookiejar`: https://nvd.nist.gov/vuln/detail/CVE-2018-20852
- GHSA-h452-7996-h45h, an earlier and unrelated cookiejar issue (ReDoS in `Cookie.parse`)
