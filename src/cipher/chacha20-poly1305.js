import AEADCipher from "./aead";
import crypto from "crypto";
import xor from "buffer-xor/inplace";
import { createDecode, encode } from "binary-data";
const { AEAD_CHACHA20_POLY1305 } = require("../lib/constants");
const debug = require("../utils/debug")("dtls:cipher:aead");
const { sessionType } = require("../lib/constants");
const { AEADAdditionalData } = require("../lib/protocol");

/**
 * This class implements chacha20-poly1305 cipher which is
 * part of AEAD cipher family.
 */
export default class Chacha20Poly1305Cipher extends AEADCipher {
  /**
   * @class Chacha20Poly1305Cipher
   */
  constructor() {
    super();

    this.keyLength = AEAD_CHACHA20_POLY1305.K_LEN;
    this.nonceLength = AEAD_CHACHA20_POLY1305.N_MIN;
    this.ivLength = AEAD_CHACHA20_POLY1305.N_MIN;
    this.authTagLength = 16;
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

    this.clientNonce = stream.readBuffer(this.ivLength);
    this.serverNonce = stream.readBuffer(this.ivLength);

    debug("CLIENT WRITE IV %h", this.clientNonce);
    debug("SERVER WRITE IV %h", this.serverNonce);
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

    // 1. The 64-bit record sequence number is serialized as an 8-byte,
    // big-endian value and padded on the left with four 0x00 bytes.
    const nonce = Buffer.alloc(this.nonceLength);
    nonce.writeUInt16BE(header.epoch, 4);
    nonce.writeUIntBE(header.sequenceNumber, 6, 6);

    // 2. The padded sequence number is XORed with the client_write_IV
    // (when the client is sending) or server_write_IV (when the server
    // is sending).
    xor(nonce, iv);

    const additionalData = {
      epoch: header.epoch,
      sequence: header.sequenceNumber,
      type: header.type,
      version: header.version,
      length: data.length,
    };

    const additionalBuffer = encode(additionalData, AEADAdditionalData).slice();

    const cipher = crypto.createCipheriv(this.blockAlgorithm, writeKey, nonce, {
      authTagLength: this.authTagLength,
    });

    cipher.setAAD(additionalBuffer, {
      plaintextLength: data.length,
    });

    const headPart = cipher.update(data);
    const finalPart = cipher.final();
    const authtag = cipher.getAuthTag();

    return Buffer.concat([headPart, finalPart, authtag]);
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

    const encryted = final.readBuffer(final.length - this.authTagLength);
    const authTag = final.readBuffer(this.authTagLength);
    const writeKey = isClient ? this.serverWriteKey : this.clientWriteKey;

    // 1. The 64-bit record sequence number is serialized as an 8-byte,
    // big-endian value and padded on the left with four 0x00 bytes.
    const nonce = Buffer.alloc(this.nonceLength);
    nonce.writeUInt16BE(header.epoch, 4);
    nonce.writeUIntBE(header.sequenceNumber, 6, 6);

    // 2. The padded sequence number is XORed with the client_write_IV
    // (when the client is sending) or server_write_IV (when the server
    // is sending).
    xor(nonce, iv);

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
      nonce,
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
}
