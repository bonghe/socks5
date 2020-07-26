const assert = require('assert');
const net = require('net');
const http = require('http');
const https = require('https');
const socks5 = require('../index');

describe('SOCKS5 Library', () => {
  describe('MethodMessage', () => {
    it('should return MethodNotRequired', () => {
      const buf = socks5.createMethodMessage(false);
      const methods = socks5.parseMethodMessage(buf);
      assert.strictEqual(methods[0], socks5.MethodNotRequired);
    });
    it('should return MethodUsernamePassword', () => {
      const buf = socks5.createMethodMessage(true);
      const methods = socks5.parseMethodMessage(buf);
      assert.strictEqual(methods[0], socks5.MethodUsernamePassword);
    });
  });

  describe('MethodSelection', () => {
    const tests = [
      {info: 'MethodNotRequired', arg: socks5.MethodNotRequired},
      {info: 'MethodUsernamePassword', arg: socks5.MethodUsernamePassword},
    ];

    tests.forEach((t) => {
      it('should return '+t.info, () => {
        const buf = socks5.createMethodSelection(t.arg);
        const method = socks5.parseMethodSelection(buf);
        assert.strictEqual(method, t.arg);
      });
    });
  });

  describe('Request', () => {
    const tests = [
      {info: 'IPv4', args: ['192.168.0.1', 1234]},
      {info: 'IPv6', args: ['::1', 4567]},
      {info: 'host name', args: ['example.com', 7890]},
    ];

    tests.forEach((t) => {
      it('test ' + t.info, () => {
        const host = t.args[0];
        const port = t.args[1];
        const buf = socks5.createRequest(host, port);
        const req = socks5.parseRequest(buf);
        assert.strictEqual(req.cmd, socks5.CmdConnect);
        assert.strictEqual(req.host, host);
        assert.strictEqual(req.port, port);
      });
    });
  });

  describe('Reply', () => {
    const tests = [
      {info: 'IPv4', args: [true, '192.168.0.1', 1234]},
      {info: 'IPv6', args: [true, '::1', 4567]},
      {info: 'host name', args: [true, 'this.is.an.example.com', 7890]},
      {info: 'failed', args: [false, '192.168.0.1', 0]},
    ];

    tests.forEach((t) => {
      it('test ' + t.info, () => {
        const host = t.args[1];
        const port = t.args[2];
        const buf = socks5.createReply(t.args[0], host, port);
        const req = socks5.parseReply(buf);
        if (t.args[0]) {
          assert.strictEqual(req.reply, socks5.ReplySucceed);
          assert.strictEqual(req.host, host);
          assert.strictEqual(req.port, port);
        } else {
          assert.notStrictEqual(req.reply, socks5.Reply);
        }
      });
    });
  });

  describe('AuthMessage', () => {
    it('test username & password', ()=>{
      const name = 'theUsername';
      const pw = 'thePassword';
      const buf = socks5.createAuthMessage(name, pw);
      const auth = socks5.parseAuthMessage(buf);
      assert.strictEqual(name, auth.username);
      assert.strictEqual(pw, auth.password);
    });
  });

  describe('AuthReply', () => {
    it('reply success', ()=>{
      const buf = socks5.createAuthReply(true);
      assert.strictEqual(socks5.parseAuthReply(buf), true);
    });
    it('reply fail', ()=>{
      const buf = socks5.createAuthReply(false);
      assert.strictEqual(socks5.parseAuthReply(buf), false);
    });
  });
});

describe('TCP via SOCKS5', function() {
  this.timeout(1000);

  let tcpServer;
  let socks5Server;
  before(() => {
    tcpServer = net.createServer((socket) => {
      socket.on('data', (data) => {
        socket.write(data);
      });
    });
    tcpServer.listen(9999);

    socks5Server = net.createServer((socket) => {
      const conn = new socks5.ServerSocket(socket);
      socks5.proxy(conn);
    });
    socks5Server.listen(8888);
  });

  after(()=>{
    tcpServer.close();
    socks5Server.close();
  });

  it('tcp connect', (done)=>{
    const socket = new socks5.ClientSocket(
        {host: '127.0.0.1', port: 8888},
        {host: 'localhost', port: 9999},
    );
    socket.on('error', (err)=>{
      done(err);
    });
    socket.on('connect', ()=>{
      socket.write('Hello');
    });
    socket.on('data', (chunk)=>{
      assert.strictEqual('Hello', chunk.toString());
      socket.end();
    });
    socket.on('end', ()=>{
      done();
    });
  });
});

describe('HTTP Agent via SOCKS5', function() {
  this.timeout(3000);

  let server;
  before(function() {
    server = net.createServer((socket) => {
      const conn = new socks5.ServerSocket(socket);
      socks5.proxy(conn);
    });
    server.listen(8888);
  });

  after(function() {
    server.close();
  });

  it('http agent connect to github.com:80', function(done) {
    http.get({
      host: 'github.com',
      port: 80,
      agent: new socks5.HttpAgent({
        host: '127.0.0.1',
        port: 8888,
        username: 'username',
        password: 'password',
      }),
    }, (resp) => {
      done();
    }).on('error', (err) => {
      done(err);
    });
  });

  it('https agent connect gto google.com:443', function(done) {
    https.get({
      host: 'google.com',
      port: 443,
      agent: new socks5.HttpsAgent({
        host: '127.0.0.1',
        port: 8888,
        username: 'username',
        password: 'password',
      }),
    }, (resp) => {
      done();
    }).on('error', (err) => {
      done(err);
    });
  });
});
