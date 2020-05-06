"use strict";

const crypto = require("crypto");
const { createDecode, encode } = require("binary-data");
const debug = require("../utils/debug")("dtls:cipher:aead");
const { sessionType } = require("../lib/constants");
const { AEADAdditionalData } = require("../lib/protocol");
const { phash } = require("./utils");
const Cipher = require("../cipher/abstract");

/**
 * This class implements AEAD cipher family.
 */
module.exports = class AEADCipher extends Cipher {
  /**
   * @class AEADCipher
   */
  constructor() {
    super();

    this.keyLength = 0;
    this.nonceLength = 0;
    this.ivLength = 0;
    this.authTagLength = 0;

    this.nonceImplicitLength = 0;
    this.nonceExplicitLength = 0;

    this.clientWriteKey = null;
    this.serverWriteKey = null;

    this.clientNonce = null;
    this.serverNonce = null;
  }

  /**
   * Initialize encryption and decryption parts.
   * @param {Session} session
   */
  init(session) {
    const size = this.keyLength * 2 + this.ivLength * 2;
    const secret = session.masterSecret;
    const seed = Buffer.concat([session.serverRandom, session.clientRandom]);
    const keyBlock = this.prf(size, secret, "key expansion", seed);
    const stream = createDecode(keyBlock);

    this.clientWriteKey = stream.readBuffer(this.keyLength);
    this.serverWriteKey = stream.readBuffer(this.keyLength);

    debug("CLIENT WRITE KEY %h", this.clientWriteKey);
    debug("SERVER WRITE KEY %h", this.serverWriteKey);

    const clientNonceImplicit = stream.readBuffer(this.ivLength);
    const serverNonceImplicit = stream.readBuffer(this.ivLength);

    debug("CLIENT WRITE IV %h", clientNonceImplicit);
    debug("SERVER WRITE IV %h", serverNonceImplicit);

    this.clientNonce = Buffer.alloc(this.nonceLength, 0);
    this.serverNonce = Buffer.alloc(this.nonceLength, 0);

    clientNonceImplicit.copy(this.clientNonce, 0);
    serverNonceImplicit.copy(this.serverNonce, 0);
  }

  /**
   * Encrypt message.
   * @param {Session} session
   * @param {Buffer} data Message to encrypt.
   * @param {Object} header Record layer message header.
   * @returns {Buffer}
   */
  encrypt(session, data, header) {
    const isClient = session.type === sessionType.CLIENT;
    const iv = isClient ? this.clientNonce : this.serverNonce;

    const writeKey = isClient ? this.clientWriteKey : this.serverWriteKey;

    iv.writeUInt16BE(header.epoch, this.nonceImplicitLength);
    iv.writeUIntBE(header.sequenceNumber, this.nonceImplicitLength + 2, 6);

    const explicitNonce = iv.slice(this.nonceImplicitLength);

    const additionalData = {
      epoch: header.epoch,
      sequence: header.sequenceNumber,
      type: header.type,
      version: header.version,
      length: data.length,
    };

    const additionalBuffer = encode(additionalData, AEADAdditionalData).slice();

    const cipher = crypto.createCipheriv(this.blockAlgorithm, writeKey, iv, {
      authTagLength: this.authTagLength,
    });

    cipher.setAAD(additionalBuffer, {
      plaintextLength: data.length,
    });

    const headPart = cipher.update(data);
    const finalPart = cipher.final();
    const authtag = cipher.getAuthTag();

    return Buffer.concat([explicitNonce, headPart, finalPart, authtag]);
  }

  /**
   * Decrypt message.
   * @param {Buffer} session
   * @param {Buffer} data Encrypted message.
   * @param {Object} header Record layer headers.
   * @returns {Buffer}
   */
  decrypt(session, data, header) {
    const isClient = session.type === sessionType.CLIENT;
    const iv = isClient ? this.serverNonce : this.clientNonce;
    const final = createDecode(data);

    const explicitNonce = final.readBuffer(this.nonceExplicitLength);
    explicitNonce.copy(iv, this.nonceImplicitLength);

    const encryted = final.readBuffer(final.length - this.authTagLength);
    const authTag = final.readBuffer(this.authTagLength);
    const writeKey = isClient ? this.serverWriteKey : this.clientWriteKey;

    const additionalData = {
      epoch: header.epoch,
      sequence: header.sequenceNumber,
      type: header.type,
      version: header.version,
      length: encryted.length,
    };

    const additionalBuffer = encode(additionalData, AEADAdditionalData).slice();

    const decipher = crypto.createDecipheriv(
      this.blockAlgorithm,
      writeKey,
      iv,
      {
        authTagLength: this.authTagLength,
      }
    );

    decipher.setAuthTag(authTag);
    decipher.setAAD(additionalBuffer, {
      plaintextLength: encryted.length,
    });

    const headPart = decipher.update(encryted);
    const finalPart = decipher.final();

    return finalPart.length > 0
      ? Buffer.concat([headPart, finalPart])
      : headPart;
  }

  /**
   * Pseudorandom Function.
   * @param {number} size - The number of required bytes.
   * @param {Buffer} secret - Hmac secret.
   * @param {string} label - Identifying label.
   * @param {Buffer} seed - Input data.
   * @returns {Buffer}
   */
  prf(size, secret, label, seed) {
    const isLabelString = typeof label === "string";
    const name = isLabelString ? Buffer.from(label, "ascii") : label;

    return phash(size, this.hash, secret, Buffer.concat([name, seed]));
  }
};
