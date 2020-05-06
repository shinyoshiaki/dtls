"use strict";

/* eslint-disable class-methods-use-this */

const { Transform } = require("readable-stream");
const { contentType } = require("../lib/constants");
const debug = require("../utils/debug")("dtls:fragment");

const _queue = Symbol("_queue");

/**
 * This class drops incoming handshake defragmentation.
 */
module.exports = class Defragmentation extends Transform {
  /**
   * @class Defragmentation
   */
  constructor() {
    super({ objectMode: true });

    this[_queue] = [];
  }

  /**
   * @private
   * @param {Object} record Record / handshake message.
   * @param {string} enc
   * @param {Function} callback
   */
  _transform(record, enc, callback) {
    if (record.type !== contentType.HANDSHAKE) {
      callback(null, record);
      return;
    }

    const handshake = record.fragment;
    const endOffset = handshake.fragment.offset + handshake.fragment.length;

    // Check for invalid fragment.
    const isInvalidLength = endOffset > handshake.length;

    if (handshake.length > 0 && isInvalidLength) {
      debug("Unexpected packet length");
      callback();
      return;
    }

    // Handle fragments.
    if (handshake.length > handshake.fragment.length) {
      // Incomplete message, waiting for next fragment.
      if (handshake.length > endOffset) {
        debug("got incomplete fragment");

        this[_queue].push(handshake);
        callback();
        return;
      }

      debug("got final fragment");

      // Reassembly handshake.
      this[_queue].push(handshake);
      const queue = this[_queue].map((packet) => packet.body);
      const fragment = Buffer.concat(queue);

      handshake.fragment.offset = 0;
      handshake.fragment.length = fragment.length;
      handshake.body = fragment;

      if (handshake.length !== fragment.length) {
        debug(new Error("Invalid fragment."));
        callback();
        return;
      }

      // Reset queue.
      this[_queue].length = 0;

      debug("complete handshake fragment, length = %s", handshake.length);
      record.fragment = handshake;
      this.push(record);
    } else {
      debug("got full handshake");
      this.push(record);
    }

    callback();
  }
};
