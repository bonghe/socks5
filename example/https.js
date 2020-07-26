

const https = require('https');
const socks5 = require('../index');

const agent = new socks5.HttpsAgent({
  host: '127.0.0.1',
  port: 8888,
  username: 'username',
  password: 'password',
});

https.get({
  host: 'google.com',
  port: 443,
  agent: agent,
}, (resp) => {
  console.log(resp.statusCode);
}).on('error', (err) => {
  console.error(err);
});
