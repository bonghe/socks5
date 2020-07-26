const net = require('net');
const ip = require('ip');


const Version = 0x05;
const ErrVersion = new Error('invalid socks version');

const MethodNotRequired = 0x00;
const MethodUsernamePassword = 0x02;

const ReplySucceed = 0x00;
const ReplyGeneralFailure = 0x01;
const ReplyConnectionNotAllowed = 0x02;
const ReplyNetworkUnreachable = 0x03;
const ReplyHostUnreachable = 0x04;
const ReplyConnectionRefused = 0x05;
const ReplyTTLExpired = 0x06;
const ReplyCommandNotSupported = 0x07;
const ReplyAddressNotSupported = 0x08;

const CmdConnect = 0x01;
// const CmdBind = 0x02;
// const CmdUDP = 0x03;

const AddrTypeIPv4 = 0x01;
const AddrTypeDN = 0x03;
const AddrTypeIPv6 = 0x04;

const AuthSuccess = 0x00;
const AuthFailure = 0xff;

/**
 * @param {socks5.reply} code
 * @return {string}
 */
const replyString = function(code) {
  switch (code) {
    case ReplySucceed:
      return 'succeeded';
    case ReplyGeneralFailure:
      return 'general SOCKS server failure';
    case ReplyConnectionNotAllowed:
      return 'connection not allowed by ruleset';
    case ReplyNetworkUnreachable:
      return 'network unreachable';
    case ReplyHostUnreachable:
      return 'host unreachable';
    case ReplyConnectionRefused:
      return 'connection refused';
    case ReplyTTLExpired:
      return 'TTL expired';
    case ReplyCommandNotSupported:
      return 'command not supported';
    case ReplyAddressNotSupported:
      return 'address type not supported';
    default:
      return `unknown code= ${code}`;
  }
};


/*
+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+
*/
/**
 * @param {bool} auth
 * @return {Buffer}
 */
const createMethodMessage = function(auth) {
  if (auth) {
    return Buffer.from([Version, 2,
      MethodUsernamePassword, MethodNotRequired]);
  }
  return Buffer.from([Version, 1, MethodNotRequired]);
};

/**
 * @param {string} chunk
 * @return {socks5.Method[] | undefined}
 */
const parseMethodMessage = function(chunk) {
  if (chunk.length < 2 || chunk.length < chunk[1] + 2) {
    return;
  }
  if (chunk[0] != Version) {
    throw ErrVersion;
  }
  const methods = [];
  for (let i = 0; i < chunk[1]; i++) {
    methods.push(chunk[i+2]);
  }
  return methods;
};

/*
+----+--------+
|VER | METHOD |
+----+--------+
| 1  |   1    |
+----+--------+
*/
/**
 * @param {Method} method
 * @return {Buffer}
 */
const createMethodSelection = function(method) {
  return Buffer.from([Version, method]);
};

/**
 * @param {Buffer} chunk
 * @return {socks5.Method | undefined}
 */
const parseMethodSelection = function(chunk) {
  if (chunk.length < 2) {
    return;
  }
  if (chunk[0] != Version) {
    throw ErrVersion;
  }
  return chunk[1];
};


/*
 +----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
*/

/**
 * @param {string} host
 * @param {number} port
 * @return {Buffer}
 */
const createRequest = function(host, port) {
  const ipType = net.isIP(host);
  const addrLen = ipType === 0 ? host.length : (ipType === 4 ? 4 : 16);
  const buf = Buffer.alloc(6 + addrLen + (ipType === 0 ? 1 : 0));
  buf[0] = Version;
  buf[1] = CmdConnect;
  buf[2] = 0x00;
  switch (ipType) {
    case 4:
      buf[3] = AddrTypeIPv4;
      ip.toBuffer(host).copy(buf, 4);
      buf.writeUInt16BE(port, 8);
      break;
    case 6:
      buf[3] = AddrTypeIPv6;
      ip.toBuffer(host).copy(buf, 4);
      buf.writeUInt16BE(port, 20);
      break;
    default:
      buf[3] = AddrTypeDN;
      buf[4] = host.length;
      buf.write(host, 5);
      buf.writeUInt16BE(port, 5 + host.length);
  }
  return buf;
};

/**
 * @param {Buffer} chunk
 * @return {object | undefined} addr
 * @return {number} addr.cmd
 * @return {string} addr.host
 * @return {number} addr.port
 */
const parseRequest = function(chunk) {
  if (chunk.length < 5) {
    return;
  }
  if (chunk[0] != Version) {
    throw ErrVersion;
  }
  const cmd = chunk[1];
  switch (chunk[3]) {
    case AddrTypeIPv4:
      if (chunk.length < 10) {
        return;
      }
      return {
        cmd: cmd,
        host: ip.toString(chunk.slice(4, 8)),
        port: chunk.readUInt16BE(8),
      };
    case AddrTypeIPv6:
      if (chunk.length < 22) {
        return;
      }
      return {
        cmd: cmd,
        host: ip.toString(chunk.slice(4, 20)),
        port: chunk.readUInt16BE(20),
      };
    case AddrTypeDN:
      if (chunk.length < chunk[4] + 7) {
        return;
      }
      return {
        cmd: cmd,
        host: chunk.slice(5, 5 + chunk[4]).toString(),
        port: chunk.readUInt16BE(5 + chunk[4]),
      };
  }
  throw new Error('invalid request');
};

/*
+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
*/
/**
 * @param {bool} isSuccessful
 * @param {string=} host
 * @param {number=} port
 * @return {Buffer}
 */
const createReply = function(isSuccessful, host, port) {
  if (!isSuccessful) {
    const buf = Buffer.alloc(10);
    buf[0] = Version;
    buf[1] = ReplyConnectionNotAllowed;
    buf[2] = AddrTypeIPv4;
    return buf;
  }
  const ipType = net.isIP(host);
  const addrLen = ipType === 0 ? host.length : (ipType === 4 ? 4 : 16);
  const buf = Buffer.alloc(6 + addrLen + (ipType === 0 ? 1 : 0));
  buf[0] = Version;
  buf[1] = ReplySucceed;
  buf[2] = 0x00;
  switch (ipType) {
    case 4:
      buf[3] = AddrTypeIPv4;
      ip.toBuffer(host).copy(buf, 4);
      buf.writeUInt16BE(port, 8);
      break;
    case 6:
      buf[3] = AddrTypeIPv6;
      ip.toBuffer(host).copy(buf, 4);
      buf.writeUInt16BE(port, 20);
      break;
    default:
      buf[3] = AddrTypeDN;
      buf[4] = host.length;
      buf.write(host, 5);
      buf.writeUInt16BE(port, 5 + host.length);
  }
  return buf;
};

/**
 * @param {Buffer} chunk
 * @return {object | undefined} reply
 * @return {number} reply.reply
 * @return {string | undefined} reply.host
 * @return {number | undefined} reply.port
 */
const parseReply = function(chunk) {
  if (chunk.length < 5) {
    return;
  }
  if (chunk[0] != Version) {
    throw ErrVersion;
  }
  const reply = chunk[1];
  if (reply != ReplySucceed) {
    return {reply: reply};
  }
  switch (chunk[3]) {
    case AddrTypeIPv4:
      if (chunk.length < 10) {
        return;
      }
      return {
        reply: reply,
        host: ip.toString(chunk.slice(4, 8)),
        port: chunk.readUInt16BE(8),
      };
    case AddrTypeIPv6:
      if (chunk.length < 22) {
        return;
      }
      return {
        reply: reply,
        host: ip.toString(chunk.slice(4, 20)),
        port: chunk.readUInt16BE(20),
      };
    case AddrTypeDN:
      if (chunk.length < chunk[4] + 7) {
        return;
      }
      return {
        reply: reply,
        host: (chunk.slice(5, 5 + chunk[4])).toString(),
        port: chunk.readUInt16BE(5 + chunk[4]),
      };
  }
  return {reply: reply};
};


/*
+----+------+----------+------+----------+
|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
+----+------+----------+------+----------+
| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
+----+------+----------+------+----------+
*/
/**
 * @param {string} username
 * @param {string} password
 * @return {Buffer}
 */
const createAuthMessage = function(username, password) {
  if (!(username) || !(password)) {
    throw new Error('invalid username or password');
  }
  const buf = Buffer.alloc(3 + username.length + password.length);
  buf[0] = Version;
  buf[1] = username.length;
  buf.write(username, 2);
  const i = 2 + username.length;
  buf[i] = password.length;
  buf.write(password, i+1);
  return buf;
};

/**
 * @param {Buffer} chunk
 * @return {object | undefined} auth
 * @return {string} auth.username
 * @return {string} auth.password
 */
const parseAuthMessage = function(chunk) {
  if (chunk.length < 2) {
    return;
  }
  if (chunk[0] != Version) {
    return ErrVersion;
  }
  if (chunk.length < 2 + chunk[1]) {
    return;
  }
  const i = 2 + chunk[1];
  const username = chunk.toString('utf8', 2, i);
  if (chunk.length < chunk[i] + i + 1) {
    return;
  }
  const password = chunk.toString('utf8', i+1);
  return {username: username, password: password};
};


/*
+----+--------+
|VER | STATUS |
+----+--------+
| 1  |   1    |
+----+--------+
*/
/**
 * @param {bool} isSuccessful
 * @return {Buffer}
 */
const createAuthReply = function(isSuccessful) {
  if (isSuccessful) {
    return Buffer.from([Version, AuthSuccess]);
  }
  return Buffer.from([Version, AuthFailure]);
};

/**
 * @param {Buffer} chunk
 * @return {bool | undefined}
 */
const parseAuthReply = function(chunk) {
  if (chunk.length < 2) {
    return;
  }
  if (chunk[0] != Version) {
    return ErrVersion;
  }
  return chunk[1] === AuthSuccess;
};

module.exports = {
  MethodNotRequired,
  MethodUsernamePassword,
  CmdConnect,
  ReplySucceed,
  replyString,

  createMethodMessage,
  parseMethodMessage,
  createMethodSelection,
  parseMethodSelection,
  createRequest,
  parseRequest,
  createReply,
  parseReply,
  createAuthMessage,
  parseAuthMessage,
  createAuthReply,
  parseAuthReply,
};
