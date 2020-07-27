const socks5 = require('./socks5');
const net = require('net');
const events = require('events');
const tls = require('tls');


/**
 * class ClientSocket
 * ClientSocket could be used as net.Socket
 * @param {object} config
 * @param {string} config.host - socks5 proxy host name
 * @param {number} config.port - socks5 proxy port
 * @param {string=} config.username - socks5 username (optional)
 * @param {string=} config.password - socks5 password (optional)
 * @param {object} options - options will also be passed to net.connect
 */
function ClientSocket(config, options) {
  const self = this;
  init.call(self, config, options);

  const s5 = self._socks5;
  const _socket = self._socket;
  Object.setPrototypeOf(self, self.socket);

  options.host = s5.sHost;
  options.port = s5.sPort;
  _socket.connect(options);
  options.host = s5.host;
  options.port = s5.port;
}

/**
 * class ClientTLSSocket
 * ClientTLSSocket could be used as tls.TLSSocket
 * @param {object} config
 * @param {string} config.host - socks5 proxy host name
 * @param {number} config.port - socks5 proxy port
 * @param {string=} config.username - socks5 username (optional)
 * @param {string=} config.password - socks5 password (optional)
 * @param {object} options - options will also be passed to tls.connect
 */
function ClientTLSSocket(config, options) {
  const self = this;
  init.call(self, config, options);

  const s5 = self._socks5;
  const _socket = self._socket;
  Object.setPrototypeOf(self, self.socket);

  s5.onReady = ()=>{
    options.socket = _socket;
    self._tlsSocket = tls.connect(options, ()=>{
      onReady.call(self);
    });
    options.socket = undefined;
    self._tlsSocket.on('error', (err)=>{
      self.emit('error', err);
    });
    self.socket = self._tlsSocket;
    Object.setPrototypeOf(self, self.socket);
  };

  options.host = s5.sHost;
  options.port = s5.sPort;
  _socket.connect(options);
  options.host = s5.host;
  options.port = s5.port;
}

const init = function(config, options) {
  if (typeof options.host !== 'string' || options.host.length > 255) {
    throw new Error(`invalid options.host name ${options.host}`);
  }
  if (!Number.isInteger(options.port) ||
    options.port < 1 || options.port > 65535) {
    throw new Error(`invalid options.port ${options.port}`);
  }
  const self = this;
  self.connecting = true;
  // socks5 information
  self._socks5 = {
    host: options.host,
    port: options.port,
    sHost: config.host,
    sPort: config.port,
    username: config.username,
    password: config.password,
    auth: (config.username && config.password),

    onError: onError.bind(self),
    onReady: onReady.bind(self),
    onData: onData.bind(self),
    handshake: handshake(self),

    writeBuffer: [],
  };
  events.EventEmitter.call(this);

  const s5 = self._socks5;
  self.write = function(...args) {
    s5.writeBuffer.push(args);
  };

  self._socket = new net.Socket();
  self.socket = self._socket;
  const _socket = self._socket;
  for (const name of ['timeout', 'close', 'end', 'error', 'lookup']) {
    _socket.on(name, (...args)=>{
      self.emit(name, ...args);
    });
  }
  _socket.once('connect', ()=>{
    try {
      s5.handshake.next();
    } catch (err) {
      s5.onError(err);
    }
  });
  _socket.on('data', s5.onData);
};

const onError = function(err) {
  const self = this;
  const s5 = self._socks5;
  self.connecting = false;
  self._socket.removeListener('data', s5.onData);
  self.socket.destroy();
  self.emit('error', err);
};

const onReady = function() {
  const self = this;
  const s5 = this._socks5;
  self.connecting = false;
  self._socket.removeListener('data', s5.onData);
  self.emit('connect');
  self.emit('ready');

  for (const name of ['data', 'drain']) {
    self.socket.on(name, (...args)=>{
      self.emit(name, ...args);
    });
  }

  delete self.write;
  while (s5.writeBuffer.length > 0) {
    try {
      const args = s5.writeBuffer.shift();
      self.write(...args);
    } catch (err) {
      self.onError(err);
      break;
    }
  }
};

const onData = function(chunk) {
  const s5 = this._socks5;
  try {
    if (s5.handshake.next(chunk).done) {
      s5.onReady();
    }
  } catch (err) {
    s5.onError(err);
  }
};

/**
 * @generator
 * @param {ClientSocket | ClientTLSSocket} self
 */
const handshake = function* (self) {
  const socket = self._socket;
  const s5 = self._socks5;
  const {host, port, auth, username, password} = s5;

  // send method message
  socket.write(socks5.createMethodMessage(auth));

  // read method selection
  let method = undefined;
  for (let buf = null; method === undefined;) {
    const chunk = yield;
    buf = buf === null? chunk : Buffer.concat([buf, chunk]);
    method = socks5.parseMethodSelection(buf);
  }

  if (method == socks5.MethodUsernamePassword && auth) {
    // send auth message
    socket.write(socks5.createAuthMessage(username, password));

    // read auth reply
    let res = undefined;
    for (let buf = null; res === undefined; ) {
      const chunk = yield;
      buf = buf === null? chunk : Buffer.concat([buf, chunk]);
      res = socks5.parseAuthReply(buf);
    }
    if (!res) {
      throw new Error('authentication failed');
    }
  } else if (method !== socks5.MethodNotRequired) {
    throw new Error('unsupported method');
  }

  // send request
  socket.write(socks5.createRequest(host, port));

  // read reply
  let reply = undefined;
  for (let buf = null; reply === undefined;) {
    const chunk = yield;
    buf = buf === null? chunk : Buffer.concat([buf, chunk]);
    reply = socks5.parseReply(buf);
  }
  if (reply.reply !== socks5.ReplySucceed) {
    throw new Error(`socks5 reply ${socks5.replyString(reply.reply)}`);
  }
};

module.exports = {
  ClientSocket,
  ClientTLSSocket,
};
