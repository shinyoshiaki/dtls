"use strict";

const { Duplex, pipeline } = require("readable-stream");
const unicast = require("unicast");
const isDtls = require("is-dtls");
const streamfilter = require("streamfilter");
const debug = require("../utils/debug")("dtls:socket");
const ClientSession = require("../session/client");
const ProtocolReader = require("../fsm/protocol");
const Sender = require("./sender");
const Decoder = require("../filter/decoder");
const Defragmentation = require("../filter/defragmentation");
const Reordering = require("../filter/reordering");
const x509 = require("@fidm/x509");
const { duplex: isDuplexStream } = require("is-stream");
const { toCipherSuite } = require("../utils/cipher-suite");

const _session = Symbol("_session");
const _queue = Symbol("_queue");
const _protocol = Symbol("_protocol");
const _socket = Symbol("_socket");
const _timeout = Symbol("_timeout");
const _onTimeout = Symbol("_onTimeout");
const _resetTimer = Symbol("_resetTimer");

const DTLS_MAX_MTU = 1420; // 1500 - IP/UDP/DTLS headers
const DTLS_MIN_MTU = 100;

const isString = (str) => typeof str === "string";

/**
 * DTLS socket.
 */
class Socket extends Duplex {
  /**
   * @class Socket
   * @param {Object} options
   * @param {number} [options.maxHandshakeRetransmissions]
   * @param {boolean} [options.extendedMasterSecret]
   * @param {Function} [options.checkServerIdentity]
   * @param {string|string[]} [options.alpn]
   * @param {Buffer} [options.certificate]
   * @param {Buffer} [options.certificatePrivateKey]
   * @param {string|Buffer} [options.pskIdentity]
   * @param {string|Buffer} [options.pskSecret]
   * @param {boolean} [options.ignorePSKIdentityHint]
   * @param {number[]} [options.cipherSuites]
   */
  constructor(options = {}) {
    super({ objectMode: false, decodeStrings: false, allowHalfOpen: true });

    const { socket } = options;

    const session = new ClientSession();
    const protocol = new ProtocolReader(session);
    const writer = new Sender(session);
    const decoder = new Decoder(session);
    const defrag = new Defragmentation();
    const reorder = new Reordering(session);

    // Disable Extended Master Secret Extension, RFC7627
    if (options.extendedMasterSecret === false) {
      session.extendedMasterSecret = false;
    }

    // Set up server certificate verify callback.
    if (typeof options.checkServerIdentity === "function") {
      session.serverCertificateVerifyCallback = options.checkServerIdentity;
    }

    if (Buffer.isBuffer(options.certificate)) {
      session.clientCertificate = x509.Certificate.fromPEM(options.certificate);

      if (options.certificatePrivateKey !== undefined) {
        session.clientCertificatePrivateKey = options.certificatePrivateKey;
      } else {
        throw new Error("Expected private key");
      }
    }

    if (
      Number.isSafeInteger(options.maxHandshakeRetransmissions) &&
      options.maxHandshakeRetransmissions > 0
    ) {
      session.retransmitter.maxTries = options.maxHandshakeRetransmissions;
    }

    if (isString(options.alpn)) {
      session.alpnProtocols.push(options.alpn);
    }

    if (Array.isArray(options.alpn)) {
      if (options.alpn.every(isString)) {
        session.alpnProtocols.push(...options.alpn);
      } else {
        throw new TypeError(
          "Argument `options.alpn` accept a string or an array of a strings."
        );
      }
    }

    // Entering PSK identities consisting of up to 128 printable Unicode characters.
    if (Buffer.isBuffer(options.pskIdentity)) {
      validatePSKIdentity(options.pskIdentity);
      session.clientPSKIdentity = options.pskIdentity;
    } else if (typeof options.pskIdentity === "string") {
      validatePSKIdentity(options.pskIdentity);
      session.clientPSKIdentity = Buffer.from(options.pskIdentity);
    }

    // Entering PSKs up to 64 octets in length as ASCII strings.
    if (Buffer.isBuffer(options.pskSecret)) {
      session.pskSecret = options.pskSecret;
      validatePSKSecret(session.pskSecret);
    } else if (typeof options.pskSecret === "string") {
      session.pskSecret = Buffer.from(options.pskSecret, "ascii");
      validatePSKSecret(session.pskSecret);
    }

    if (options.ignorePSKIdentityHint === false) {
      session.ignorePSKIdentityHint = false;
    }

    // Set up custom cipher suites.
    if (
      Array.isArray(options.cipherSuites) &&
      options.cipherSuites.length > 0
    ) {
      const supportedCiphers = options.cipherSuites
        .map(toCipherSuite)
        .filter((cipher) => cipher > -1);

      if (supportedCiphers.length === 0) {
        throw new Error("Invalid cipher suites list");
      }

      session.cipherSuites = supportedCiphers;
    }

    session.retransmitter.once("close", () => {
      this.emit("timeout");
    });

    const onerror = (err) => {
      if (err) {
        this.emit("error", err);
      }
    };
    const isdtls = streamfilter(chunkFilter);

    pipeline(writer, socket, onerror);
    pipeline(socket, isdtls, decoder, reorder, defrag, protocol, onerror);

    this[_session] = session;
    this[_queue] = [];
    this[_protocol] = protocol;
    this[_socket] = socket;
    this[_timeout] = null;

    session.on("data", (packet) => {
      this[_resetTimer]();
      this.push(packet);
    });

    session.once("handshake:finish", () => {
      process.nextTick(() => this.emit("connect"));

      this[_queue].forEach((data) => session.sendMessage(data));
      this[_queue].length = 0;

      session.retransmitter.removeAllListeners("close");

      if (session.connectionTimeout > 0) {
        this[_resetTimer]();
      }
    });

    session.once("certificate", (cert) =>
      process.nextTick(() => this.emit("certificate", cert))
    );

    session.on("error", (code) =>
      this.emit("error", new Error(`alert code ${code}`))
    );

    this.once("timeout", () => {
      debug("got timeout, close connection");
      this.close();
    });
  }

  /**
   * Opens DTLS connection.
   * @param {Function} [callback]
   */
  connect(callback) {
    if (typeof callback === "function") {
      this.once("connect", callback);
    }

    process.nextTick(() => this[_protocol].start());
  }

  /**
   * Set MTU (Minimal Transfer Unit) for the socket.
   * @param {number} mtu
   */
  setMTU(mtu) {
    if (typeof mtu !== "number") {
      throw new TypeError("Invalid type of argument `mtu`");
    }

    const isValid =
      Number.isInteger(mtu) && mtu <= DTLS_MAX_MTU && mtu >= DTLS_MIN_MTU;

    if (isValid) {
      this[_session].mtu = mtu;
    } else {
      throw new Error("Invalid MTU");
    }
  }

  /**
   * Get MTU (Minimal Transfer Unit) for the socket.
   * @returns {number}
   */
  getMTU() {
    return this[_session].mtu;
  }

  /**
   * Sets the socket to timeout after timeout milliseconds of inactivity on the socket.
   * By default `dtls.Socket` do not have a timeout.
   * @param {number} timeout
   * @param {Function} [callback]
   */
  setTimeout(timeout, callback) {
    if (Number.isSafeInteger(timeout) && timeout > 0) {
      this[_session].connectionTimeout = timeout;
    }

    if (typeof callback === "function") {
      this.once("timeout", callback);
    }
  }

  /**
   * @private
   */
  [_onTimeout]() {
    clearTimeout(this[_timeout]);
    this[_timeout] = null;

    this.emit("timeout");
  }

  /**
   * @private
   */
  [_resetTimer]() {
    const { connectionTimeout } = this[_session];

    if (connectionTimeout === 0) {
      return;
    }

    if (this[_timeout] !== null) {
      clearTimeout(this[_timeout]);
    }

    this[_timeout] = setTimeout(() => this[_onTimeout](), connectionTimeout);
    this[_timeout].unref();
  }

  /**
   * Get a string that contains the selected ALPN protocol.
   * When ALPN has no selected protocol, Socket.alpnProtocol
   * equals to an empty string.
   * @returns {string}
   */
  get alpnProtocol() {
    return this[_session].selectedALPNProtocol;
  }

  /**
   * Close the underlying socket and stop listening for data on it.
   */
  close() {
    this[_socket].close();

    if (this[_timeout] !== null) {
      clearTimeout(this[_timeout]);
    }
  }

  /**
   * @private
   */
  _read() {} // eslint-disable-line class-methods-use-this

  /**
   * @private
   * @param {Buffer} chunk
   * @param {string} encoding
   * @param {Function} callback
   */
  _write(chunk, encoding, callback) {
    if (this[_session].isHandshakeInProcess) {
      this[_queue].push(chunk);
      this.once("connect", () => callback());
    } else {
      this[_session].sendMessage(chunk);
      this[_resetTimer]();
      callback();
    }
  }

  /**
   * @private
   */
  _destroy() {
    this[_queue].length = 0;
    this[_session] = null;
  }
}

/**
 * Connect the socket to dtls server.
 * @param {Object} options
 * @param {Function} [callback]
 * @returns {Socket}
 */
function connect(options = {}, callback) {
  if (!isDuplexStream(options.socket)) {
    options.socket = unicast.createSocket(options);
  }

  const socket = new Socket(options);
  socket.connect(callback);

  return socket;
}

/**
 * Check if incoming message is dtls.
 * @param {Buffer} data
 * @param {string} enc
 * @param {Function} callback
 */
function chunkFilter(data, enc, callback) {
  const isCorrect = isDtls(data);
  debug("got message, is dtls = %s", isCorrect);
  callback(!isCorrect);
}

/**
 * Validates PSK secret.
 * @param {Buffer} pskSecret
 */
function validatePSKSecret(pskSecret) {
  if (pskSecret.length === 0) {
    throw new Error("Invalid PSK secret");
  }
}

/**
 * Validates PSK identity.
 * @param {string|Buffer} pskIdentity
 */
function validatePSKIdentity(pskIdentity) {
  if (pskIdentity.length === 0) {
    throw new Error("Invalid PSK identity");
  }
}

module.exports = {
  connect,
};
