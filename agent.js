
const http = require('http');
const https = require('https');
const client = require('./client');

/**
 * HttpAgent
 * @param {object} config
 * @param {string} config.host
 * @param {number} config.port
 * @param {string=} config.username
 * @param {string=} config.password
 * @param {object} options - options will be passed to http.Agent
 */
function HttpAgent(config, options) {
  Object.setPrototypeOf(this, new http.Agent(options));
  this.createConnection = (...args)=>{
    const {options, listener} = normalizeArgs(args);
    const socket = new client.ClientSocket(config, options);
    if (listener !== null) {
      socket.once('connect', listener);
    }
    return socket;
  };
};

/**
 * HttpsAgent
 * @param {object} config
 * @param {string} config.host
 * @param {number} config.port
 * @param {string=} config.username
 * @param {string=} config.password
 * @param {object} options - options will be passed to http.Agent
 */
function HttpsAgent(config, options) {
  Object.setPrototypeOf(this, new https.Agent(options));
  this.createConnection = (...args)=>{
    const {options, listener} = normalizeArgs(args);
    const socket = new client.ClientTLSSocket(config, options);
    if (listener !== null) {
      socket.once('connect', listener);
    }
    return socket;
  };
};

const normalizeArgs = function(args) {
  let options = {};
  let listener = undefined;
  if (args.length > 0) {
    if (typeof args[0] === 'string') {
      options.path = args[0];
    } else if (typeof args[0] === 'number') {
      options.port = args[0];
      if (args.length > 1 && typeof args[1] === 'string') {
        options.host = args[1];
      }
    } else {
      options = args[0];
    }

    const cb = args[args.length - 1];
    if (typeof cb === 'function') {
      listener = cb;
    }
  }
  return {options: options, listener: listener};
};

module.exports = {
  HttpAgent,
  HttpsAgent,
};

