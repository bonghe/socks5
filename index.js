
for (const f of ['socks5', 'server', 'client', 'agent']) {
  const exp = require('./' + f);
  const keys = Object.keys(exp);
  for (let i = 0; i < keys.length; ++i) {
    exports[keys[i]] = exp[keys[i]];
  }
}

