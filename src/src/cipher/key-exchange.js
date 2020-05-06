"use strict";

const { signTypes, keyTypes, kxTypes } = require("../lib/constants");

module.exports = {
  createRSAKeyExchange,
  createECDHERSAKeyExchange,
  createECDHEECDSAKeyExchange,
  createNULLKeyExchange,
  createPSKKeyExchange,
  createECDHEPSKKeyExchange,
};

/**
 * This class represent type of key exchange mechanism.
 */
class KeyExchange {
  /**
   * @class KeyExchange
   */
  constructor() {
    this.id = 0;
    this.name = null;

    this.signType = null;
    this.keyType = null;
  }

  /**
   * @returns {string}
   */
  toString() {
    return this.name;
  }
}

/**
 * Creates `RSA` key exchange.
 * @returns {KeyExchange}
 */
function createRSAKeyExchange() {
  const exchange = new KeyExchange();

  exchange.id = kxTypes.RSA;
  exchange.name = "RSA";

  exchange.keyType = keyTypes.RSA;

  return exchange;
}

/**
 * Creates `ECDHE_RSA` key exchange.
 * @returns {KeyExchange}
 */
function createECDHERSAKeyExchange() {
  const exchange = new KeyExchange();

  exchange.id = kxTypes.ECDHE_RSA;
  exchange.name = "ECDHE_RSA";

  exchange.signType = signTypes.ECDHE;
  exchange.keyType = keyTypes.RSA;

  return exchange;
}

/**
 * Creates `ECDHE_ECDSA` key exchange.
 * @returns {KeyExchange}
 */
function createECDHEECDSAKeyExchange() {
  const exchange = new KeyExchange();

  exchange.id = kxTypes.ECDHE_ECDSA;
  exchange.name = "ECDHE_ECDSA";

  exchange.signType = signTypes.ECDHE;
  exchange.keyType = keyTypes.ECDSA;

  return exchange;
}

/**
 * Creates `NULL` key exchange.
 * @returns {KeyExchange}
 */
function createNULLKeyExchange() {
  const exchange = new KeyExchange();

  exchange.id = kxTypes.NULL;
  exchange.name = "NULL";

  exchange.signType = signTypes.NULL;
  exchange.keyType = keyTypes.NULL;

  return exchange;
}

/**
 * Creates `PSK` key exchange.
 * @returns {KeyExchange}
 */
function createPSKKeyExchange() {
  const exchange = new KeyExchange();

  exchange.id = kxTypes.PSK;
  exchange.name = "PSK";

  exchange.signType = signTypes.NULL;
  exchange.keyType = keyTypes.PSK;

  return exchange;
}

/**
 * Creates `ECDHE_PSK` key exchange.
 * @returns {KeyExchange}
 */
function createECDHEPSKKeyExchange() {
  const exchange = new KeyExchange();

  exchange.id = kxTypes.ECDHE_PSK;
  exchange.name = "ECDHE_PSK";

  exchange.signType = signTypes.ECDHE;
  exchange.keyType = keyTypes.PSK;

  return exchange;
}
