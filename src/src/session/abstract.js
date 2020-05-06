"use strict";

/* eslint class-methods-use-this: ["error", { "exceptMethods": ["type"] }] */
/* eslint-disable getter-return */

const assert = require("assert");
const crypto = require("crypto");
const Emitter = require("events");
const { encode, BinaryStream } = require("binary-data");
const {
  protocolVersion,
  signTypes,
  sessionType,
  kxTypes,
  defaultCipherSuites,
} = require("../lib/constants");
const {
  createMasterSecret,
  createPreMasterSecret,
  createExtendedMasterSecret,
  createPSKPreMasterSecret,
} = require("./utils");
const NullCipher = require("../cipher/null");
const debug = require("../utils/debug")("dtls:session");
const { Handshake } = require("../lib/protocol");
const SlidingWindow = require("../lib/sliding-window");
const nacl = require("tweetnacl");

/**
 * This class implements abstract DTLS session.
 */
module.exports = class AbstractSession extends Emitter {
  /**
   * @class AbstractSession
   */
  constructor() {
    super();

    this.version = protocolVersion.DTLS_1_2;
    this.clientRandom = null;
    this.serverRandom = null;
    this.clientEpoch = 0;
    this.serverEpoch = 0;
    this.recordSequenceNumber = 0;
    this.handshakeSequenceNumber = 0;
    this.clientFinished = null;
    this.serverFinished = null;
    this.id = null;
    this.mtu = 1200; // default value for Google Chrome

    this.isHandshakeInProcess = false; // getter from FSM?
    this.lastRvHandshake = -1;

    this.cipher = new NullCipher();
    this.nextCipher = null;
    this.prevCipher = null;

    // List of supported cipher cuites.
    this.cipherSuites = defaultCipherSuites;

    this.serverPublicKey = null;
    this.masterSecret = null;
    this.clientPremaster = null;

    this.peerEllipticPublicKey = null; // peer's ecdhe public key
    this.ellipticPublicKey = null; // my public ecdhe key
    this.ellipticCurve = null; // curve name
    this.ecdhe = null;

    this.extendedMasterSecret = true;
    this.peerExtendedMasterSecret = false;

    this.handshakeProtocolReaderState = null;
    this.handshakeQueue = new BinaryStream();

    this.retransmitter = null;
    this.window = new SlidingWindow();

    this.serverCertificate = null;
    this.clientCertificate = null;

    this.connectionTimeout = 0;

    // secret part of PSK key exchange
    this.pskSecret = null;
  }

  /**
   * Abstract method to get session type.
   */
  get type() {
    notImplemented();
  }

  /**
   * Emit the event to send a message.
   * @param {number} type Message type to send.
   */
  send(type) {
    this.emit("send", type);
  }

  /**
   * Send the `application data` message.
   * @param {Buffer} data
   */
  sendMessage(data) {
    this.emit("send:appdata", data);
  }

  /**
   * Send the `alert` message.
   * @param {number} description
   * @param {number} level
   */
  sendAlert(description, level) {
    this.emit("send:alert", description, level);
  }

  /**
   * Handles starting handshake.
   */
  startHandshake() {
    debug("start handshake");
    this.emit("handshake:start");

    this.isHandshakeInProcess = true;
    this.lastRvHandshake = -1;
    this.handshakeSequenceNumber = -1;
  }

  /**
   * Handshake successfully ends.
   */
  finishHandshake() {
    debug("stop handshake");
    this.isHandshakeInProcess = false;
    this.handshakeProtocolReaderState = null;
    this.peerEllipticPublicKey = null;
    this.ellipticPublicKey = null;
    this.ecdhe = null;
    this.resetHandshakeQueue();

    this.emit("handshake:finish");
  }

  /**
   * Emit the error event.
   * @param {number} type Alert description type.
   */
  error(type) {
    this.emit("error", type);
  }

  /**
   * Notify the application about arrived server certificate.
   * @param {Object} cert The x509 server certificate.
   */
  certificate(cert) {
    this.serverCertificate = cert;
    this.emit("certificate", cert);
  }

  /**
   * @protected
   * @param {Function} done
   */
  createPreMasterSecret(done) {
    if (this.nextCipher.kx.signType === signTypes.ECDHE) {
      this.clientPremaster = Buffer.from(
        nacl.scalarMult(
          Buffer.from(this.ecdhe.secretKey.buffer),
          this.peerEllipticPublicKey
        )
      );
      process.nextTick(done);
    }
  }

  /**
   * @protected
   */
  createMasterSecret() {
    // if (this.extendedMasterSecret) {
    //   const handshakes = this.handshakeQueue.slice();

    //   this.masterSecret = createExtendedMasterSecret(
    //     this.clientPremaster,
    //     handshakes,
    //     this.nextCipher
    //   );
    // } else {
    this.masterSecret = createMasterSecret(
      this.clientRandom,
      this.serverRandom,
      this.clientPremaster,
      this.nextCipher
    );
    // }

    this.clientPremaster = null;
  }

  /**
   * @protected
   */
  createElliptic() {
    assert.strictEqual(signTypes.ECDHE, this.nextCipher.kx.signType);

    this.ecdhe = nacl.box.keyPair();
    this.ellipticPublicKey = Buffer.from(this.ecdhe.publicKey.buffer);
  }

  /**
   * Starts next epoch for clients.
   */
  nextEpochClient() {
    this.clientEpoch += 1;

    this.prevCipher = this.cipher;
    this.cipher = this.nextCipher;
    this.nextCipher = null;

    this.cipher.init(this);
  }

  /**
   * Starts next epoch for server.
   */
  nextEpochServer() {
    this.serverEpoch += 1;
    assert(this.clientEpoch === this.serverEpoch, "mismatch epoches");
  }

  /**
   * Increment outgoing sequence number of record layer
   * and return this one.
   * @returns {number}
   */
  nextRecordNumber() {
    this.recordSequenceNumber += 1;
    return this.recordSequenceNumber;
  }

  /**
   * Increment outgoing sequence number of handshake layer
   * and return this one.
   * @returns {number}
   */
  nextHandshakeNumber() {
    this.handshakeSequenceNumber += 1;
    return this.handshakeSequenceNumber;
  }

  /**
   * Get epoch of connected peer.
   */
  get peerEpoch() {
    return this.type === sessionType.CLIENT
      ? this.serverEpoch
      : this.clientEpoch;
  }

  /**
   * Store the handshake message for the finished checksum.
   * @param {Buffer} packet Encoded handshake message.
   */
  appendHandshake(packet) {
    assert(this.isHandshakeInProcess);

    if (!Buffer.isBuffer(packet)) {
      packet = encode(packet, Handshake).buffer; // eslint-disable-line no-param-reassign
    }

    debug("packet added to handshake queue, type = %s", packet.readUInt8(0));
    this.handshakeQueue.append(packet);
  }

  /**
   * Sometimes we need to clear queue. Just re-create queue for this.
   */
  resetHandshakeQueue() {
    debug("reset handshake queue");
    this.handshakeQueue = new BinaryStream();
  }

  /**
   * Encrypt outgoing record message.
   * @param {Cipher} cipher
   * @param {Object} record Record layer message.
   */
  encrypt(cipher, record) {
    const data = record.fragment;

    const encrypted = cipher.encrypt(this, data, record);
    record.fragment = encrypted;
    record.length = encrypted.length;
  }

  /**
   * Decrypt incoming record message.
   * @param {Cipher} cipher
   * @param {Object} record Record layer message.
   */
  decrypt(cipher, record) {
    const encrypted = record.fragment;
    const data = cipher.decrypt(this, encrypted, record);

    record.fragment = data;
  }

  /**
   * Notify about `application data` message.
   * @param {Buffer} data
   */
  packet(data) {
    this.emit("data", data);
  }
};

/**
 * Fallback for abstract methods.
 */
function notImplemented() {
  throw new Error("not implemented");
}
