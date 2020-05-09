"use strict";
import Chacha20Poly1305Cipher from "./chacha20-poly1305";
const {
  cipherSuites,
  AEAD_AES_128_GCM,
  AEAD_AES_256_GCM,
} = require("../lib/constants");
const AEADCipher = require("./aead");
const {
  createRSAKeyExchange,
  createECDHERSAKeyExchange,
  createECDHEECDSAKeyExchange,
  createPSKKeyExchange,
  createECDHEPSKKeyExchange,
} = require("./key-exchange");

const RSA_KEY_EXCHANGE = createRSAKeyExchange();
const ECDHE_RSA_KEY_EXCHANGE = createECDHERSAKeyExchange();
const ECDHE_ECDSA_KEY_EXCHANGE = createECDHEECDSAKeyExchange();
const PSK_KEY_EXCHANGE = createPSKKeyExchange();
const ECDHE_PSK_KEY_EXCHANGE = createECDHEPSKKeyExchange();

/**
 * Convert cipher value to cipher instance.
 * @param {number} cipher
 * @returns {AEADCipher}
 */
export function createCipher(cipher) {
  switch (cipher) {
    case cipherSuites.TLS_RSA_WITH_AES_128_GCM_SHA256:
      return createAEADCipher(
        cipherSuites.TLS_RSA_WITH_AES_128_GCM_SHA256,
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "aes-128-gcm",
        RSA_KEY_EXCHANGE,
        AEAD_AES_128_GCM
      );
    case cipherSuites.TLS_RSA_WITH_AES_256_GCM_SHA384:
      return createAEADCipher(
        cipherSuites.TLS_RSA_WITH_AES_256_GCM_SHA384,
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "aes-256-gcm",
        RSA_KEY_EXCHANGE,
        AEAD_AES_256_GCM,
        "sha384"
      );
    case cipherSuites.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
      return createAEADCipher(
        cipherSuites.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "aes-128-gcm",
        ECDHE_RSA_KEY_EXCHANGE,
        AEAD_AES_128_GCM
      );
    case cipherSuites.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
      return createAEADCipher(
        cipherSuites.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "aes-256-gcm",
        ECDHE_RSA_KEY_EXCHANGE,
        AEAD_AES_256_GCM,
        "sha384"
      );
    case cipherSuites.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
      return createAEADCipher(
        cipherSuites.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "aes-128-gcm",
        ECDHE_ECDSA_KEY_EXCHANGE,
        AEAD_AES_128_GCM
      );
    case cipherSuites.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
      return createAEADCipher(
        cipherSuites.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "aes-256-gcm",
        ECDHE_ECDSA_KEY_EXCHANGE,
        AEAD_AES_256_GCM,
        "sha384"
      );
    case cipherSuites.TLS_PSK_WITH_AES_128_GCM_SHA256:
      return createAEADCipher(
        cipherSuites.TLS_PSK_WITH_AES_128_GCM_SHA256,
        "TLS_PSK_WITH_AES_128_GCM_SHA256",
        "aes-128-gcm",
        PSK_KEY_EXCHANGE,
        AEAD_AES_128_GCM,
        "sha256"
      );
    case cipherSuites.TLS_PSK_WITH_AES_256_GCM_SHA384:
      return createAEADCipher(
        cipherSuites.TLS_PSK_WITH_AES_256_GCM_SHA384,
        "TLS_PSK_WITH_AES_256_GCM_SHA384",
        "aes-256-gcm",
        PSK_KEY_EXCHANGE,
        AEAD_AES_256_GCM,
        "sha384"
      );
    case cipherSuites.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
      return createChacha20Cipher(
        cipherSuites.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "chacha20-poly1305",
        ECDHE_ECDSA_KEY_EXCHANGE,
        "sha256"
      );
    case cipherSuites.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
      return createChacha20Cipher(
        cipherSuites.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "chacha20-poly1305",
        ECDHE_RSA_KEY_EXCHANGE,
        "sha256"
      );
    case cipherSuites.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
      return createChacha20Cipher(
        cipherSuites.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
        "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
        "chacha20-poly1305",
        PSK_KEY_EXCHANGE,
        "sha256"
      );
    case cipherSuites.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:
      return createAEADCipher(
        cipherSuites.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
        "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
        "aes-128-gcm",
        ECDHE_PSK_KEY_EXCHANGE,
        AEAD_AES_128_GCM,
        "sha256"
      );
    case cipherSuites.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:
      return createAEADCipher(
        cipherSuites.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384,
        "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
        "aes-256-gcm",
        ECDHE_PSK_KEY_EXCHANGE,
        AEAD_AES_256_GCM,
        "sha384"
      );
    case cipherSuites.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
      return createChacha20Cipher(
        cipherSuites.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
        "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
        "chacha20-poly1305",
        ECDHE_PSK_KEY_EXCHANGE,
        "sha256"
      );
    default:
      break;
  }

  return null;
}

/**
 * @param {number} id An internal id of cipher suite.
 * @param {string} name A valid cipher suite name.
 * @param {string} block A valid nodejs cipher name.
 * @param {KeyExchange} kx Key exchange type.
 * @param {Object} constants Cipher specific constants.
 * @param {string} hash
 * @returns {AEADCipher}
 */
function createAEADCipher(id, name, block, kx, constants, hash = "sha256") {
  const cipher = new AEADCipher();

  cipher.id = id;
  cipher.name = name;
  cipher.blockAlgorithm = block;
  cipher.kx = kx;
  cipher.hash = hash;

  cipher.keyLength = constants.K_LEN;
  cipher.nonceLength = constants.N_MAX;

  // RFC5288, sec. 3
  cipher.nonceImplicitLength = 4;
  cipher.nonceExplicitLength = 8;

  cipher.ivLength = cipher.nonceImplicitLength;

  cipher.authTagLength = 16;

  return cipher;
}

/**
 * @param {number} id An internal id of cipher suite.
 * @param {string} name A valid cipher suite name.
 * @param {string} block A valid nodejs cipher name.
 * @param {KeyExchange} kx Key exchange type.
 * @param {string} hash
 * @returns {AEADCipher}
 */
function createChacha20Cipher(id, name, block, kx, hash = "sha256") {
  const cipher = new Chacha20Poly1305Cipher();

  cipher.id = id;
  cipher.name = name;
  cipher.blockAlgorithm = block;
  cipher.kx = kx;
  cipher.hash = hash;

  return cipher;
}
