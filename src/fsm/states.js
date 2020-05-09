"use strict";

const { handshakeType, contentType } = require("../lib/constants");

const {
  CLIENT_HELLO,
  SERVER_HELLO,
  HELLO_VERIFY_REQUEST,
  CERTIFICATE,
  SERVER_KEY_EXCHANGE,
  CERTIFICATE_REQUEST,
  SERVER_HELLO_DONE,
  CERTIFICATE_VERIFY,
  CLIENT_KEY_EXCHANGE,
  FINISHED,
} = handshakeType;

const { CHANGE_CIPHER_SPEC, HANDSHAKE, ALERT, APPLICATION_DATA } = contentType;

/**
 * Create state based on handshake and protocol types.
 * @param {number} protocol
 * @param {number} type
 * @returns {number}
 */
function createState(protocol, type) {
  return (protocol << 8) | type; // eslint-disable-line no-bitwise
}

/**
 * Get message protocol from state.
 * @param {number} state
 * @returns {number}
 */
function getProtocol(state) {
  return (state >>> 8) & 0xff; // eslint-disable-line no-bitwise
}

/**
 * Get message type from state.
 * @param {number} state
 * @returns {number}
 */
function getType(state) {
  return state & 0xff; // eslint-disable-line no-bitwise
}

const constants = {
  CLIENT_HELLO: createState(HANDSHAKE, CLIENT_HELLO),
  SERVER_HELLO: createState(HANDSHAKE, SERVER_HELLO),
  HELLO_VERIFY_REQUEST: createState(HANDSHAKE, HELLO_VERIFY_REQUEST),
  CERTIFICATE: createState(HANDSHAKE, CERTIFICATE),
  SERVER_KEY_EXCHANGE: createState(HANDSHAKE, SERVER_KEY_EXCHANGE),
  CERTIFICATE_REQUEST: createState(HANDSHAKE, CERTIFICATE_REQUEST),
  SERVER_HELLO_DONE: createState(HANDSHAKE, SERVER_HELLO_DONE),
  CERTIFICATE_VERIFY: createState(HANDSHAKE, CERTIFICATE_VERIFY),
  CLIENT_KEY_EXCHANGE: createState(HANDSHAKE, CLIENT_KEY_EXCHANGE),
  FINISHED: createState(HANDSHAKE, FINISHED),
  CHANGE_CIPHER_SPEC: createState(CHANGE_CIPHER_SPEC, 0),
  ALERT: createState(ALERT, 0),
  APPLICATION_DATA: createState(APPLICATION_DATA, 0),
  HANDSHAKE: createState(HANDSHAKE, 0),
};

module.exports = {
  createState,
  getProtocol,
  getType,
  constants,
};
