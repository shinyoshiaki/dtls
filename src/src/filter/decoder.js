"use strict";

const { Transform } = require("readable-stream");
const { decode, createDecode } = require("binary-data");
const { contentType } = require("../lib/constants");
const { DTLSPlaintext, Handshake } = require("../lib/protocol");
const debug = require("../utils/debug")("dtls:decoder");

const _session = Symbol("_session");

/**
 * Decode record and handshake layer messages into objects.
 */
module.exports = class Decoder extends Transform {
  /**
   * @class Decoder
   * @param {AbstractSession} session
   */
  constructor(session) {
    super({
      writableObjectMode: false,
      readableObjectMode: true,
    });

    this[_session] = session;
  }

  /**
   * @returns {AbstractSession}
   */
  get session() {
    return this[_session];
  }

  /**
   * @private
   * @param {*} chunk
   * @param {*} enc
   * @param {*} callback
   */
  _transform(chunk, enc, callback) {
    const stream = createDecode(chunk);

    while (stream.length > 0) {
      debug("process new chunk");
      const record = decode(stream, DTLSPlaintext);
      debug("decoded %s bytes", decode.bytes);

      const isHandshake = record.type === contentType.HANDSHAKE;
      const isAlert = record.type === contentType.ALERT;
      const isCipher = record.type === contentType.CHANGE_CIPHER_SPEC;

      if (!isAlert && !isCipher) {
        const isPreviousEpoch =
          this.session.clientEpoch - this.session.serverEpoch === 1;
        const cipher = isPreviousEpoch
          ? this.session.prevCipher
          : this.session.cipher;
        try {
          debug("decrypt record layer");
          this.session.decrypt(cipher, record);
          debug("decryption success");
        } catch (error) {
          debug("decryption error, ignore");
        }
      }

      if (isHandshake) {
        record.fragment = decode(record.fragment, Handshake);
      }

      this.push(record);
    }

    callback();
  }
};
