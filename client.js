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
    handshake: handshake.bind(self),

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
    s5.onData();
  });
  _socket.on('data', s5.onData);
};

const onError = function(err) {
  const self = this;
  const s5 = self._socks5;
  s5.state = 'error';
  self.connecting = false;
  self._socket.removeListener('data', s5.onData);
  self.socket.destroy();
  self.emit('error', err);
};

const onReady = function() {
  const self = this;
  const s5 = this._socks5;
  self.connecting = false;
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
  const self = this;
  const s5 = this._socks5;
  chunk = chunk === undefined ? Buffer.alloc(0) : chunk;
  if (s5.chunk instanceof Buffer) {
    chunk = Buffer.concat([s5.chunk, chunk]);
    s5.chunk = undefined;
  }

  try {
    const nextState = s5.handshake(chunk);
    if (nextState === s5.state) {
      s5.chunk = chunk;
    }
    s5.state = nextState;
  } catch (err) {
    s5.onError(err);
    return;
  }

  if (s5.state === 'finished') {
    self._socket.removeListener('data', s5.onData);
    s5.onReady();
  }
};

/**
 * @param {Buffer} chunk
 * @return {string} nextState
 */
const handshake = function(chunk) {
  const socket = this._socket;
  const s5 = this._socks5;
  let state = s5.state;
  const {host, port, auth, username, password} = s5;

  // read
  switch (state) {
    case undefined:
      state = 'sendMethodMessage';
      break;
    case 'readMethodSelection':
      const method = socks5.parseMethodSelection(chunk);
      if (method === undefined) {
        return state;
      }
      if (method == socks5.MethodNotRequired) {
        state = 'sendRequest';
      } else if (method == socks5.MethodUsernamePassword && auth) {
        state = 'sendAuthMessage';
      } else {
        throw new Error('unsupported method');
      }
      break;
    case 'readAuthReply':
      const res = socks5.parseAuthReply(chunk);
      if (res === undefined) {
        return state;
      } else if (res) {
        state = 'sendRequest';
      } else {
        throw new Error('authentication failed');
      }
      break;
    case 'readReply':
      const reply = socks5.parseReply(chunk);
      if (reply === undefined) {
        return state;
      }
      if (reply.reply !== socks5.ReplySucceed) {
        throw new Error(`socks5 reply ${socks5.replyString(reply.reply)}`);
      }
      state = 'finished';
      break;
    default:
      throw new Error('handshake error');
  }

  // write
  switch (state) {
    case 'sendMethodMessage':
      socket.write(socks5.createMethodMessage(auth));
      state = 'readMethodSelection';
      break;
    case 'sendAuthMessage':
      socket.write(socks5.createAuthMessage(username, password));
      state = 'readAuthReply';
      break;
    case 'sendRequest':
      socket.write(socks5.createRequest(host, port));
      state = 'readReply';
      break;
    case 'finished':
      break;
    default:
      throw new Error('handshake error');
  }
  return state;
};

module.exports = {
  ClientSocket,
  ClientTLSSocket,
};
