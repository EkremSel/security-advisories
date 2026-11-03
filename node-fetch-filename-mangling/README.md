# node-fetch — `_fileName()` mangles remote-controlled `Content-Disposition: filename`

**Reporter:** [EkremSel](https://github.com/EkremSel)
**Component:** `src/utils/multipart-parser.js` → `MultipartParser._fileName()` (reached via `response.formData()`)
**Affected versions:** 3.1.0 – 3.3.2 (3.3.2 is the latest release; commit `8b3320d`) and 4.0.0-beta.4. 3.0.0 is not affected — it has no `response.formData()`.
**Severity:** Low (potential Medium where `File.name` feeds a local file path)
**CWE:** CWE-20 (Improper Input Validation), CWE-73 (External Control of File Name or Path)
**Disclosed to maintainer:** 2026-11-03

`response.formData()` extracts `filename` from the **server-controlled**
`Content-Disposition` header using `_fileName()`. That helper applies three
transformations that are not part of the RFC 7578 / RFC 2616 `filename` grammar,
letting a remote (potentially untrusted) peer rewrite the resulting `File.name`
beyond the bytes actually transmitted:

1. **Backslash truncation** — `match.lastIndexOf('\\') + 1` drops everything up to and
   including the final backslash: `filename="a\\..\\..\\pwned"` (the quoted-string form of
   `a\..\..\pwned`) → `File.name = "pwned"`.
2. **HTML numeric character reference decoding** — `a&#0034;b` → `a"b`
   (only 4-digit refs match, via `&#(\d{4});` — `&#34;` is left alone).
3. **Percent-decoding** — `a%22b` → `a"b`.

Downstream upload pipelines (express-fileupload, multer, custom handlers) routinely
build a **local filesystem path** from `File.name`, so a remote peer can strip path
components and inject characters — a practical path-manipulation primitive.

## Proof of concept

`repro.mjs` (Node 18+, no dependencies besides node-fetch):

```
$ npm install
$ node repro.mjs
backslash ../ escape         wire = "a\\\\..\\\\..\\\\pwned" => File.name = "pwned"
backslash + ../ path         wire = "x.txt\\\\..\\\\evil.txt" => File.name = "evil.txt"
html-numeric &#0034; (")     wire = "a&#0034;b" => File.name = "a\"b"
pct-encoded %22 (")          wire = "a%22b" => File.name = "a\"b"
control                      wire = "plain.txt" => File.name = "plain.txt"
```

`wire` is printed with `JSON.stringify`, so every backslash appears doubled once more.
Verified against node-fetch 3.1.0, 3.3.2 and 4.0.0-beta.4 (identical output); 3.0.0 has no
`response.formData()`.

## Suggested fix

Treat the extracted filename as an opaque byte string per RFC 7578 — drop the three
transformations (or make them opt-in). At minimum, remove the `lastIndexOf('\\')`
truncation, which is the one that changes path semantics for Windows-targeted
upload handlers.

## Full report

See [ADVISORY.md](./ADVISORY.md) for the complete write-up.
