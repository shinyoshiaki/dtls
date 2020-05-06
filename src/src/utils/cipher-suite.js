"use strict";

const { cipherSuites } = require("../lib/constants");
const isChachaSupported = require("is-chacha20-poly1305-supported");

const ciphers = new Set(Object.values(cipherSuites));

const chacha20Ciphers = [
  "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
  "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
];

module.exports = {
  isCipherSuite,
  toCipherSuite,
};

/**
 * Check if argument is supported cipher suite.
 * @param {number} cipher
 * @returns {boolean}
 */
function isCipherSuite(cipher) {
  return ciphers.has(cipher);
}

/**
 * Convert cipher name to it's value.
 * @param {string|number} cipher
 * @returns {number}
 */
function toCipherSuite(cipher) {
  const toCipher = (maybe) => (isCipherSuite(maybe) ? maybe : -1);

  if (typeof cipher === "string") {
    if (!isChachaSupported && chacha20Ciphers.includes(cipher)) {
      return -1;
    }

    return toCipher(cipherSuites[cipher]);
  }

  if (typeof cipher === "number") {
    return toCipher(cipher);
  }

  return -1;
}
