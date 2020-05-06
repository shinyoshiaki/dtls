"use strict";

const debug = require("../utils/debug")("dtls:window");

const _step = Symbol("_step");
const _left = Symbol("_left");
const _right = Symbol("_right");

/**
 * Record layer anti-replay protection.
 * @link https://tools.ietf.org/html/rfc6347#section-4.1.2.6
 * @link https://tools.ietf.org/html/rfc4303#section-3.4.3
 */
module.exports = class SlidingWindow {
  /**
   * @class SlidingWindow
   * @param {number} step
   */
  constructor(step = 64) {
    this[_step] = step;

    this.reset();
  }

  /**
   * Get left edge.
   * @returns {number}
   */
  get left() {
    return this[_left];
  }

  /**
   * Get right edge.
   * @returns {number}
   */
  get right() {
    return this[_right];
  }

  /**
   * Update edges.
   * @param {number} sequence
   * @returns {bool}
   */
  accept(sequence) {
    if (this.check(sequence)) {
      this[_left] = sequence;
      this[_right] = sequence + this[_step];

      return true;
    }

    return false;
  }

  /**
   * Validate number.
   * @param {number} sequence
   * @returns {bool}
   */
  check(sequence) {
    if (sequence < this[_left]) {
      return false;
    }

    if (sequence >= this[_right]) {
      return false;
    }

    return true;
  }

  /**
   * Resets internals state of edges.
   */
  reset() {
    debug("reset sliding window");

    this[_left] = 0;
    this[_right] = this[_step];
  }

  /**
   * @public
   * @returns {string}
   */
  toString() {
    return `left = ${this.left}, right = ${this.right}, step = ${this[_step]}`;
  }
};
