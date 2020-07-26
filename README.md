# SOCKS5-js

Package socks5-js provides SOCKS5 server and client implementation for **node.js**.

## Requirements

* [indutny/node-ip](https://github.com/indutny/node-ip)

## Feature

* No Authentication mode
* UserName/Password authentication
* Support CONNECT command

## Example

Create a SOCKS5 proxy server
```js
const socks5Server = net.createServer((socket) => {
  // upgrade socket
  const conn = new socks5.ServerSocket(socket);
  socket.on('error', (err) => {
      // handle error
  });
  socks5.proxy(conn);
});
socks5Server.listen(1080, () => {
  console.log('SOCKS5 Proxy listen on :1080');
});
```

Create a tcp connect via SOCKS5
```js
// similar to net.createConnection
const socket = new socks5.ClientSocket(
    {
      host: 'localhost',
      port: 1080,
      username: 'user',
      password: 'password',
    }, 
    {host: 'target', port: 80}, 
);
```

Create a HTTP Agent using SOCKS5
```js
const agent = new socks5.HttpAgent({
  host: 'localhost',
  port: 1080,
  username: 'username',
  password: 'password',
});

http.get({
  host: 'github.com',
  port: 80,
  agent: agent,
}, (resp) => {
  //...
}).on('error', (err) => {
  //...
});
```

Create a HTTPS Agent using SOCKS5
```js
const agent = new socks5.HttpsAgent({
  host: 'localhost',
  port: 1080,
  username: 'username',
  password: 'password',
});

https.get({
  host: 'google.com',
  port: 443,
  agent: agent,
}, (resp) => {
  //...
}).on('error', (err) => {
  //...
});
```

## API 

* **new ClientSocket (config, options?)**
    * config - socks5 configuration
        * host - socks5 server host name
        * port - socks5 server ip
        * username - (optional)
        * password - (optional)
    * options - See **<net.connect>**
* **new ClientTLSSocket (config, options?)**
    * config - socks5 configuration
        * host - socks5 server host name
        * port - socks5 server ip
        * username - (optional)
        * password - (optional)
    * options - See **<tls.connect>**

* **new HttpAgent (config, options?)**
    * config - socks5 configuration
        * host - socks5 server host name
        * port - socks5 server ip
        * username - (optional)
        * password - (optional)
    * options - See **<http.Agent>**

* **new HttpsAgent (config, options?)**
    * config - socks5 configuration
        * host - socks5 server host name
        * port - socks5 server ip
        * username - (optional)
        * password - (optional)
    * options - See **<https.Agent>**

* **new ServerSocket (socket)**
    * socket - **< net.Socket >**

* **proxy (ss)**
    * ss - **< ServerSocket >**


## References

* [RFC 1928](https://tools.ietf.org/html/rfc1928)
* [RFC 1929](https://tools.ietf.org/html/rfc1929)
* [BoundaryH/socks5](https://github.com/BoundaryH/socks5)
* [mscdex/socksv5](https://github.com/mscdex/socksv5)


## License

This software is licensed under the MIT License. 
