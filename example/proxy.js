
const net = require('net');
const socks5 = require('../index');

const socks5Server = net.createServer((socket) => {
  // upgrade socket
  const conn = new socks5.ServerSocket(socket);
  socket.on('error', (err) => {
    console.error(err);
  });
  conn.on('connect', ()=>{
    let s = `${conn.remoteAddress}:${conn.remotePort}` +
     ` > ${conn.dstHost}:${conn.dstPort}`;
    if (conn.username !== undefined && conn.password !== undefined) {
      s += `  [ ${conn.username} : ${conn.password} ]`;
    }
    console.log(s);
  });
  socks5.proxy(conn);
});
socks5Server.listen(8888, () => {
  console.log('SOCKS5 Proxy listen on :8888');
});

