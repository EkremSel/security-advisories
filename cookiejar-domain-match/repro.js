// cookiejar 2.1.4: a cookie for example.com is returned for notexample.com.
// Run: npm install && node repro.js   (exits 1 while the bug is present)
const { CookieJar, CookieAccessInfo } = require('cookiejar');

const cases = [
  // [cookie Domain, request host, does RFC 6265 5.1.3 say send?]
  ['example.com', 'notexample.com', false],
  ['ample.com', 'example.com', false],
  ['example.com', 'example.com', true],
  ['example.com', 'shop.example.com', true],
  ['example.com', 'example.com.evil.com', false],
  ['example.com', 'evil.com', false],
];

let leak = false;
for (const [domain, host, rfc] of cases) {
  const jar = new CookieJar();
  jar.setCookie(`session=abc123; Domain=${domain}`, domain, '/');
  const sent = jar.getCookies(new CookieAccessInfo(host, '/')).length > 0;
  if (sent && !rfc) leak = true;
  console.log(`Domain=${domain.padEnd(12)} -> ${host.padEnd(21)} RFC 6265: ${rfc ? 'send' : 'no  '}  cookiejar: ${sent ? 'SENT' : 'not sent'}${sent && !rfc ? '   <-- leak' : ''}`);
}

// Eviction: setCookie() uses the same check, so a same-named cookie set by
// notexample.com replaces the one example.com set.
const jar = new CookieJar();
jar.setCookie('session=VICTIM; Domain=example.com', 'example.com', '/');
jar.setCookie('session=OTHER; Domain=notexample.com', 'notexample.com', '/');
const left = jar.getCookies(new CookieAccessInfo('example.com', '/')).toValueString();
console.log(`\nafter notexample.com sets "session", example.com gets ${JSON.stringify(left)} (expected "session=VICTIM")`);

process.exit(leak ? 1 : 0);
