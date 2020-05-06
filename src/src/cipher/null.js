"use strict";

/* eslint-disable class-methods-use-this */

const Cipher = require("../cipher/abstract");
const { createNULLKeyExchange } = require("../cipher/key-exchange");

/**
 * Default passthrough cipher.
 */
module.exports = class NullCipher extends Cipher {
  /**
   * @class NullCipher
   */
  constructor() {
    super();

    this.name = "NULL_NULL_NULL"; // key, mac, hash
    this.blockAlgorithm = "NULL";
    this.kx = createNULLKeyExchange();
    this.hash = "NULL";
  }

  /**
   * Encrypts data.
   * @param {AbstractSession} session
   * @param {Buffer} data Content to encryption.
   * @returns {Buffer}
   */
  encrypt(session, data) {
    return data;
  }

  /**
   * Decrypts data.
   * @param {AbstractSession} session
   * @param {Buffer} data Content to encryption.
   * @returns {Buffer}
   */
  decrypt(session, data) {
    return data;
  }
};
