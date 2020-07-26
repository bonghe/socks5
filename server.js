
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
  self._state = 'readMethodMessage';
  self._onData = onData.bind(self);
  self._handshake = handshake.bind(self);
  self._onError = onError.bind(self);
  self._onReady = onReady.bind(self);
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
  chunk = chunk === undefined ? Buffer.alloc(0) : chunk;
  if (self._chunk instanceof Buffer) {
    chunk = Buffer.concat([self._chunk, chunk]);
    self._chunk = undefined;
  }

  try {
    const nextState = self._handshake(chunk);
    if (nextState === self._state) {
      self._chunk = chunk;
    }
    self._state = nextState;
  } catch (err) {
    self._onError(err);
    return;
  }
  if (self._state === 'finished') {
    self._onReady();
  }
};

/**
 * @param {Buffer} chunk
 * @return {string} nextState
 */
const handshake = function(chunk) {
  const self = this;
  const socket = self.socket;
  let state = self._state;

  switch (state) {
    case 'readMethodMessage':
      const methods = socks5.parseMethodMessage(chunk);
      if (methods === undefined) {
        return state;
      }
      let selection = undefined;
      for (let i = 0; i < methods.length; i++) {
        const m = methods[i];
        if (m === socks5.MethodNotRequired ||
            m === socks5.MethodUsernamePassword) {
          selection = m;
          break;
        }
      }
      if (selection === undefined) {
        throw new Error('unsupported method');
      }
      socket.write(socks5.createMethodSelection(selection));
      if (selection == socks5.MethodUsernamePassword) {
        state = 'readAuthMessage';
      } else if (selection == socks5.MethodNotRequired) {
        state = 'readRequest';
      }
      break;
    case 'readAuthMessage':
      const auth = socks5.parseAuthMessage(chunk);
      if (auth === undefined) {
        return state;
      }
      self.username = auth.username;
      self.password = auth.password;

      socket.write(socks5.createAuthReply(true));
      state = 'readRequest';
      break;
    case 'readRequest':
      const req = socks5.parseRequest(chunk);
      if (req === undefined) {
        return state;
      }
      if (req.cmd != socks5.CmdConnect) {
        throw new Error('invalid request cmd');
      }
      self.dstHost = req.host;
      self.dstPort = req.port;

      socket.write(socks5.createReply(true, '0.0.0.0', 0));
      state = 'finished';
      break;
    default:
      throw new Error('handshake error');
  }
  return state;
};

const onError = function(err) {
  const self = this;
  self._state = 'error';
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
