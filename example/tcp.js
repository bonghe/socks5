
const net = require('net');
const socks5 = require('../index');

// TCP echo server
const tcpServer = net.createServer((socket) => {
  socket.on('data', (data) => {
    socket.write(data);
  });
});

tcpServer.listen(9999, ()=>{
  const socket = new socks5.ClientSocket(
      {
        host: '127.0.0.1',
        port: 8888,
        username: 'user',
        password: 'pw',
      }, // SOCKS5 configuration
      {host: 'localhost', port: 9999}, // same as net.createConnection
  );
  socket.on('error', (err) => {
    done(err);
  });
  socket.on('connect', () => {
    const s = 'Hello';
    console.log(' < ', s);
    socket.write(s);
  });
  socket.on('data', (chunk) => {
    console.log(' > ', chunk.toString());
    socket.end();
  });

  socket.on('end', ()=>{
    tcpServer.close();
  });
});
