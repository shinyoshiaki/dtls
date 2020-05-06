"use strict";

import { Duplex, pipeline } from "readable-stream";
import { toCipherSuite } from "../utils/cipher-suite";
import ClientSession from "../session/client";
const ProtocolReader = require("../fsm/protocol");

const unicast = require("unicast");
const isDtls = require("is-dtls");
const streamfilter = require("streamfilter");
const debug = require("../utils/debug")("dtls:socket");
const Sender = require("./sender");
const Decoder = require("../filter/decoder");
const Defragmentation = require("../filter/defragmentation");
const Reordering = require("../filter/reordering");
const x509 = require("@fidm/x509");
const { duplex: isDuplexStream } = require("is-stream");

const DTLS_MAX_MTU = 1420; // 1500 - IP/UDP/DTLS headers
const DTLS_MIN_MTU = 100;

const isString = (str: any) => typeof str === "string";

type Options = Partial<{
  socket: any;
  extendedMasterSecret: boolean;
  certificate: Buffer;
  certificatePrivateKey: Buffer;
  alpn: string;
  pskIdentity: Buffer;
  pskSecret: Buffer;
  ignorePSKIdentityHint: boolean;
  cipherSuites: number[];
}> & {
  maxHandshakeRetransmissions: number;
  remoteAddress: string;
  type: string;
  remotePort: number;
};

/**
 * DTLS socket.
 */
class Socket extends Duplex {
  private session = new ClientSession();
  private queue: any[] = [];
  private protocol?: any;
  private socket?: any;
  private timeout?: any;

  constructor(options: Options = {} as any) {
    super({ objectMode: false, decodeStrings: false, allowHalfOpen: true });

    const { socket } = options;

    const protocol = new ProtocolReader(this.session);
    const writer = new Sender(this.session);
    const decoder = new Decoder(this.session);
    const defrag = new Defragmentation();
    const reorder = new Reordering(this.session);

    // Disable Extended Master Secret Extension, RFC7627
    if (options.extendedMasterSecret === false) {
      this.session.extendedMasterSecret = false;
    }

    if (Buffer.isBuffer(options.certificate)) {
      this.session.clientCertificate = x509.Certificate.fromPEM(
        options.certificate
      );

      if (options.certificatePrivateKey !== undefined) {
        this.session.clientCertificatePrivateKey =
          options.certificatePrivateKey;
      } else {
        throw new Error("Expected private key");
      }
    }

    if (
      Number.isSafeInteger(options.maxHandshakeRetransmissions) &&
      options.maxHandshakeRetransmissions > 0
    ) {
      this.session.retransmitter.maxTries = options.maxHandshakeRetransmissions;
    }

    if (isString(options.alpn)) {
      this.session.alpnProtocols.push(options.alpn);
    }

    if (Array.isArray(options.alpn)) {
      if (options.alpn.every(isString)) {
        this.session.alpnProtocols.push(...options.alpn);
      } else {
        throw new TypeError(
          "Argument `options.alpn` accept a string or an array of a strings."
        );
      }
    }

    // Entering PSK identities consisting of up to 128 printable Unicode characters.
    if (Buffer.isBuffer(options.pskIdentity)) {
      validatePSKIdentity(options.pskIdentity);
      this.session.clientPSKIdentity = options.pskIdentity;
    } else if (typeof options.pskIdentity === "string") {
      validatePSKIdentity(options.pskIdentity);
      this.session.clientPSKIdentity = Buffer.from(options.pskIdentity);
    }

    // Entering PSKs up to 64 octets in length as ASCII strings.
    if (Buffer.isBuffer(options.pskSecret)) {
      this.session.pskSecret = options.pskSecret;
      validatePSKSecret(this.session.pskSecret);
    } else if (typeof options.pskSecret === "string") {
      this.session.pskSecret = Buffer.from(options.pskSecret, "ascii");
      validatePSKSecret(this.session.pskSecret);
    }

    if (options.ignorePSKIdentityHint === false) {
      this.session.ignorePSKIdentityHint = false;
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

      this.session.cipherSuites = supportedCiphers;
    }

    this.session.retransmitter.once("close", () => {
      this.emit("timeout");
    });

    const onerror = (err: any) => {
      if (err) {
        this.emit("error", err);
      }
    };
    const isdtls = streamfilter(chunkFilter);

    pipeline(writer, socket, onerror);
    pipeline(socket, isdtls, decoder, reorder, defrag, protocol, onerror);

    this.queue = [];
    this.protocol = protocol;
    this.socket = socket;
    this.timeout = null;

    this.session.on("data", (packet: Buffer) => {
      this.resetTimer();
      this.push(packet);
    });

    this.session.once("handshake:finish", () => {
      process.nextTick(() => this.emit("connect"));

      this.queue.forEach((data) => this.session.sendMessage(data));
      this.queue.length = 0;

      this.session.retransmitter.removeAllListeners("close");

      if (this.session.connectionTimeout > 0) {
        this.resetTimer();
      }
    });

    this.session.once("certificate", (cert: Buffer) =>
      process.nextTick(() => this.emit("certificate", cert))
    );

    this.session.on("error", (code: number) =>
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

  connect(callback: any) {
    if (typeof callback === "function") {
      this.once("connect", callback);
    }

    process.nextTick(() => this.protocol.start());
  }

  /**
   * Set MTU (Minimal Transfer Unit) for the socket.
   * @param {number} mtu
   */
  setMTU(mtu: number) {
    const isValid =
      Number.isInteger(mtu) && mtu <= DTLS_MAX_MTU && mtu >= DTLS_MIN_MTU;

    if (isValid) {
      this.session.mtu = mtu;
    } else {
      throw new Error("Invalid MTU");
    }
  }

  /**
   * Get MTU (Minimal Transfer Unit) for the socket.
   * @returns {number}
   */
  getMTU() {
    return this.session.mtu;
  }

  /**
   * Sets the socket to timeout after timeout milliseconds of inactivity on the socket.
   * By default `dtls.Socket` do not have a timeout.
   * @param {number} timeout
   * @param {Function} [callback]
   */
  setTimeout(timeout: number, callback: any) {
    if (Number.isSafeInteger(timeout) && timeout > 0) {
      this.session.connectionTimeout = timeout;
    }

    if (typeof callback === "function") {
      this.once("timeout", callback);
    }
  }

  /**
   * @private
   */
  private onTimeout() {
    clearTimeout(this.timeout);
    this.timeout = null;

    this.emit("timeout");
  }

  /**
   * @private
   */
  private resetTimer() {
    const { connectionTimeout } = this.session;

    if (connectionTimeout === 0) {
      return;
    }

    if (this.timeout !== null) {
      clearTimeout(this.timeout);
    }

    this.timeout = setTimeout(() => this.onTimeout(), connectionTimeout);
    this.timeout.unref();
  }

  /**
   * Get a string that contains the selected ALPN protocol.
   * When ALPN has no selected protocol, Socket.alpnProtocol
   * equals to an empty string.
   * @returns {string}
   */
  get alpnProtocol() {
    return this.session.selectedALPNProtocol;
  }

  /**
   * Close the underlying socket and stop listening for data on it.
   */
  close() {
    this.socket.close();

    if (this.timeout !== null) {
      clearTimeout(this.timeout);
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
  _write(chunk: Buffer, encoding: string, callback: any) {
    if (this.session.isHandshakeInProcess) {
      this.queue.push(chunk);
      this.once("connect", () => callback());
    } else {
      this.session.sendMessage(chunk);
      this.resetTimer();
      callback();
    }
  }

  /**
   * @private
   */
  _destroy() {
    this.queue.length = 0;
    this.session = null as any;
  }
}

/**
 * Connect the socket to dtls server.
 * @param {Object} options
 * @param {Function} [callback]
 * @returns {Socket}
 */
export function connect(options: Options = {} as any, callback?: any) {
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
function chunkFilter(data: Buffer, enc: string, callback: any) {
  const isCorrect = isDtls(data);
  debug("got message, is dtls = %s", isCorrect);
  callback(!isCorrect);
}

/**
 * Validates PSK secret.
 * @param {Buffer} pskSecret
 */
function validatePSKSecret(pskSecret: Buffer) {
  if (pskSecret.length === 0) {
    throw new Error("Invalid PSK secret");
  }
}

/**
 * Validates PSK identity.
 * @param {string|Buffer} pskIdentity
 */
function validatePSKIdentity(pskIdentity: Buffer) {
  if (pskIdentity.length === 0) {
    throw new Error("Invalid PSK identity");
  }
}
