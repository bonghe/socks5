
const http = require('http');
const socks5 = require('../index');

const agent = new socks5.HttpAgent({
  host: '127.0.0.1',
  port: 8888,
  username: 'username',
  password: 'password',
});

http.get({
  host: 'github.com',
  port: 80,
  agent: agent,
}, (resp) => {
  console.log(resp.statusCode);
}).on('error', (err) => {
  console.error(err);
});
