# node-fetch: `_fileName()` mangles remote-controlled `Content-Disposition: filename` (backslash truncation + HTML/percent entity decoding)

**Reporter:** EkremSel
**Component:** `src/utils/multipart-parser.js` → `MultipartParser._fileName()` (reached via `response.formData()`)
**Affected versions:** 3.1.0 – 3.3.2 (3.3.2 is the latest release; commit `8b3320d`) and 4.0.0-beta.4. 3.0.0 is not affected — it has no `response.formData()`.
**Severity:** Low (potential Medium where `File.name` feeds a local file path)
**Type:** Improper input handling / external control of file name (CWE-20, CWE-73)

## Summary

`response.formData()` parses `multipart/form-data` responses. For each part it extracts
`filename` from the **server-controlled** `Content-Disposition` header using `_fileName()`.
That helper applies three transformations that are **not** part of the RFC 7578 / RFC 2616
`filename` grammar, allowing a remote (potentially untrusted) peer to rewrite the resulting
`File.name` beyond the bytes actually transmitted:

```js
function _fileName(headerValue) {
  const m = headerValue.match(/\bfilename=("(.*?)"|([^()<>@,;:\\"/[\]?={}\s\t]+))($|;\s)/i);
  if (!m) return;
  const match = m[2] || m[3] || '';
  let filename = match.slice(match.lastIndexOf('\\') + 1);        // (1) truncate at last backslash
  filename = filename.replace(/%22/g, '"');                        // (2) decode %22 -> "
  filename = filename.replace(/&#(\d{4});/g, (m, code) => String.fromCharCode(code)); // (3) decode &#NNNN;
  return filename;
}
```

1. **Backslash truncation** — `match.lastIndexOf('\\') + 1` drops everything up to and
   including the final backslash. A server sending `filename="a\\..\\..\\pwned"` (the
   quoted-string form of `a\..\..\pwned`) yields `File.name = "pwned"`.
2. **HTML numeric character reference decoding** — `&#0034;` becomes `"`. Filenames are a
   byte string / quoted-string, not HTML; entity decoding is not specified. Only 4-digit
   references match (`&#34;` is left alone).
3. **Percent-decoding of `%22`** — becomes `"`.

## Why it matters

Downstream code routinely takes `File.name` and builds a **local filesystem path** from it
(e.g. `path.join(dest, file.name)` in `express-fileupload`, `multer`, or custom upload
handlers). Because a remote peer controls the transformation:

- The **backslash truncation** silently strips path components. A payload like
  `x.txt\..\evil.txt` arrives to the app as `evil.txt` — the app sees a "safe" name that no
  longer matches what was sent, defeating name-based allow/deny or de-duplication logic, and
  on Windows (where `\` is a path separator) the original value carried traversal intent the
  parser re-wrote.
- The **entity/percent decoding** lets a remote peer inject characters not literally present
  in the header (e.g. `a&#0032;b` → `a b`, with a space), so consumers doing character-class
  checks on the *wire* value operate on a value the peer can steer.

## Proof of concept

`repro.mjs` in this folder (Node 18+). Run `npm install && node repro.mjs`:

```js
// PoC: node-fetch's _fileName() rewrites the server-controlled Content-Disposition filename.
// Run: npm install && node repro.mjs   (Node 18+)
//
// Per RFC 7578 / RFC 2616 the filename is a quoted-string or token. On top of that,
// node-fetch's _fileName() (1) truncates at the last backslash, (2) decodes 4-digit HTML
// numeric references (&#NNNN;) and (3) decodes %22 -- so a remote server can steer File.name.
import http from 'node:http';
import fetch from 'node-fetch';

async function run(filenamePart, label) {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'multipart/form-data; boundary=XB' });
    res.end(
      '--XB\r\n' +
      'Content-Disposition: form-data; name=f; filename="' + filenamePart + '"\r\n' +
      '\r\nhello\r\n--XB--\r\n'
    );
  });
  await new Promise(r => server.listen(0, r));
  const port = server.address().port;
  const fd = await (await fetch('http://127.0.0.1:' + port)).formData();
  const f = fd.get('f');
  console.log(label.padEnd(28), 'wire =', JSON.stringify(filenamePart),
              '=> File.name =', JSON.stringify(f && f.name));
  server.close();
}

await run('a\\\\..\\\\..\\\\pwned', 'backslash ../ escape');
await run('x.txt\\\\..\\\\evil.txt', 'backslash + ../ path');
await run('a&#0034;b', 'html-numeric &#0034; (")');
await run('a%22b', 'pct-encoded %22 (")');
await run('plain.txt', 'control');
```

Observed output (identical on node-fetch 3.1.0, 3.3.2 and 4.0.0-beta.4):

```
backslash ../ escape         wire = "a\\\\..\\\\..\\\\pwned" => File.name = "pwned"
backslash + ../ path         wire = "x.txt\\\\..\\\\evil.txt" => File.name = "evil.txt"
html-numeric &#0034; (")     wire = "a&#0034;b" => File.name = "a\"b"
pct-encoded %22 (")          wire = "a%22b" => File.name = "a\"b"
control                      wire = "plain.txt" => File.name = "plain.txt"
```

`wire` is printed with `JSON.stringify`, so every backslash appears doubled once more.

## Suggested fix

Treat the extracted `filename` as an opaque byte string per RFC 7578 — drop the three
transformations (or make them opt-in):

```js
function _fileName(headerValue) {
  const m = headerValue.match(/\bfilename=("(.*?)"|([^()<>@,;:\\"/[\]?={}\s\t]+))($|;\s)/i);
  if (!m) return;
  return m[2] !== undefined ? m[2] : m[3];
}
```

At minimum, remove the `lastIndexOf('\\')` truncation — it's the one that changes path
semantics for Windows-targeted upload handlers.

## Impact

Low severity in isolation (a spec-conformance quirk in a rarely-exercised path). Becomes a
practical path-manipulation primitive when the parsed `File.name` feeds a local file path in
an upload pipeline that trusts it without re-validation.
