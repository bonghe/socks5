
const net = require('net');
const events = require('events');
const socks5 = require('./socks5');

/**
 * @param {net.Socket} socket
 */
function ServerSocket(socket) {
  const self = this;
  events.EventEmitter.call(this);

  self.socket = socket;
  self.connecting = true;
  self._onData = onData.bind(self);
  self._onError = onError.bind(self);
  self._onReady = onReady.bind(self);
  self._handshake = handshake(self);
  self._handshake.next();
  self._writeBuffer = [];
  self.write = (...args) =>{
    self._writeBuffer.push(args);
  };

  for (const name of ['timeout', 'close', 'end', 'error', 'lookup']) {
    socket.on(name, (...args)=>{
      self.emit(name, ...args);
    });
  }
  socket.on('data', self._onData);
  Object.setPrototypeOf(self, self.socket);
}

const onData = function(chunk) {
  const self = this;
  try {
    if (self._handshake.next(chunk).done) {
      self._onReady();
    }
  } catch (err) {
    self._onError(err);
  }
};

/**
 * @generator
 * @param {ServerSocket} self
 */
const handshake = function* (self) {
  const socket = self.socket;
  let buf = undefined;

  // method selection
  let methods = undefined;
  while (methods === undefined) {
    const chunk = yield;
    buf = buf === undefined ? chunk : Buffer.concat([buf, chunk]);
    methods = socks5.parseMethodMessage(buf);
  }
  buf = undefined;

  while (methods.length > 0 &&
    methods[0] !== socks5.MethodUsernamePassword &&
    methods[0] !== socks5.MethodNotRequired) {
    methods.shift();
  }
  if (methods.length === 0) {
    throw new Error('unsupported method');
  }
  socket.write(socks5.createMethodSelection(methods[0]));

  // authentication
  if (methods[0] === socks5.MethodUsernamePassword) {
    let auth = undefined;
    while (auth === undefined) {
      const chunk = yield;
      buf = buf === undefined ? chunk : Buffer.concat([buf, chunk]);
      auth = socks5.parseAuthMessage(buf);
    }
    buf = undefined;

    self.username = auth.username;
    self.password = auth.password;
    socket.write(socks5.createAuthReply(true));
  }

  // read request
  let req = undefined;
  while (req === undefined) {
    const chunk = yield;
    buf = buf === undefined ? chunk : Buffer.concat([buf, chunk]);
    req = socks5.parseRequest(buf);
  }
  buf = undefined;

  if (req.cmd != socks5.CmdConnect) {
    throw new Error('invalid request cmd');
  }
  self.dstHost = req.host;
  self.dstPort = req.port;
  socket.write(socks5.createReply(true, '0.0.0.0', 0));
};

const onError = function(err) {
  const self = this;
  self.connecting = false;
  self.socket.removeListener('data', self._onData);
  self.socket.destroy();
  self.emit('error', err);
};

const onReady = function() {
  const self = this;
  self.connecting = false;
  self.socket.removeListener('data', self._onData);
  self.emit('connect');
  self.emit('ready');

  for (const name of ['data', 'drain']) {
    self.socket.on(name, (...args)=>{
      self.emit(name, ...args);
    });
  }

  delete self.write;
  while (self._writeBuffer.length > 0) {
    try {
      const args = self._writeBuffer.shift();
      self.write(...args);
    } catch (err) {
      self.onError(err);
      break;
    }
  }
};

/**
 * @param {ServerSocket} conn
 */
const proxy = function(conn) {
  if (conn.connecting) {
    conn.on('connect', ()=>{
      proxy(conn);
    });
    return;
  }
  const socket = net.connect(conn.dstPort, conn.dstHost);
  socket.on('data', (data)=>{
    if (!conn.destroyed) {
      conn.write(data);
    }
  });
  socket.on('error', (err)=>{
    conn.emit('error', err);
  });
  socket.on('end', ()=>{
    conn.end();
  });

  conn.on('data', (data)=>{
    if (!socket.destroyed) {
      socket.write(data);
    }
  });
  conn.on('end', ()=>{
    socket.end();
  });
};

module.exports = {
  ServerSocket,
  proxy,
};
