# cookiejar — cookies for `example.com` are sent to `notexample.com` (no dot boundary in domain matching)

**Reporter:** [EkremSel](https://github.com/EkremSel)
**Component:** `cookiejar.js` → `Cookie.prototype.collidesWith` (used by `getCookies` and `setCookie`)
**Affected versions:** cookiejar 2.0.0 – 2.1.4 (2.1.4 is the latest release). 1.x is not affected.
**Reachable through:** superagent 10.4.1 (latest) `superagent.agent()`, including after cross-origin redirects
**Severity:** Medium (CVSS 3.1 5.9)
**CWE:** CWE-187 (Partial String Comparison), CWE-200 (Exposure of Sensitive Information)
**Reported to superagent and cookiejar maintainers:** 2026-11-04

`cookiejar` sends a cookie to any host that *ends with* the cookie's `Domain`, without requiring a
`.` before it, as RFC 6265 §5.1.3 does. A cookie that `example.com` sets with `Domain=example.com`
is therefore also sent to `notexample.com`, a domain anyone can register.

superagent agents use `cookiejar` to pick the cookies for each request. superagent already checks
the dot boundary when it *stores* cookies, but not when it *sends* them. After a cross-origin
redirect it re-adds cookies from the jar for the new host. An attacker who gets a server-side agent
to request their lookalike domain (an open redirect, or a user-supplied URL) receives the session
cookie. A same-named cookie from the lookalike domain can also evict the real one from the jar.

Only cookies with an explicit `Domain` attribute are affected. Host-only cookies are matched exactly.

## Proof of concept

```
$ npm install
$ node poc-superagent.js
notexample.com:61713 /direct -> Cookie: session=abc123
notexample.com:61713 /landing -> Cookie: session=abc123
```

`/direct` is a plain request to `notexample.com`; `/landing` is reached through a 302 from
`example.com`. `node repro.js` shows the same bug in cookiejar alone, compared case by case with
RFC 6265.

## Suggested fix

In `collidesWith`, match only when the host equals the cookie domain or ends with `'.' + domain`:

```js
if (!access_domain.endsWith('.' + cookie_domain)) {
    return false;
}
```

superagent can also protect itself by filtering jar results in `_attachCookies()` with its
existing `domainMatches()` helper. Both fixes are in [ADVISORY.md](./ADVISORY.md).

## Full report

See [ADVISORY.md](./ADVISORY.md) for the complete write-up.
