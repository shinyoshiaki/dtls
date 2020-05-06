"use strict";

const assert = require("assert");
const Emitter = require("events");
const debug = require("../utils/debug")("dtls:retransmitter");

const PREPARING = "preparing";
const SENDING = "sending";
const WAITING = "waiting";
const FINISHED = "finished";

const _timer = Symbol("_timer");
const _state = Symbol("_state");
const _timeout = Symbol("_timeout");
const _initialTimeout = Symbol("_initial_timeout");
const _next = Symbol("_next_state");
const _queue = Symbol("_queue");
const _onTimeout = Symbol("_on_timeout");
const _stopTimer = Symbol("_stop_timer");
const _resetTimer = Symbol("_reset_timer");
const _tries = Symbol("tries");

/**
 * Allowed state transitions.
 * @see https://tools.ietf.org/html/rfc6347#section-4.2.4
 */
const transitions = {
  [PREPARING]: new Set([SENDING]),
  [SENDING]: new Set([WAITING, FINISHED]),
  [WAITING]: new Set([PREPARING, SENDING, FINISHED]),
  [FINISHED]: new Set([PREPARING]),
};

/**
 * Timeout and Retransmission State Machine.
 */
export class RetransmitMachine extends Emitter {
  /**
   * @class RetransmitMachine
   * @param {string} initialState
   */
  constructor(initialState) {
    super();

    this[_timer] = null;
    this[_initialTimeout] = 1e3; // Initial timer is 1s
    this[_timeout] = this[_initialTimeout];
    this[_state] = initialState;
    this[_tries] = 0;

    // Implementations SHOULD use an initial timer value
    // of 1 second and double the value at each retransmission,
    // up to no less than the RFC 6298 maximum of 60 seconds.
    this.maxTries = Math.log2(64) + 1;

    const queue = [];
    this[_queue] = queue;

    this.on("timeout", () => {
      if (queue.length === 0) {
        debug("empty queue, ignore");
        return;
      }

      if (this.state !== WAITING) {
        return;
      }

      debug("send stored messages again");
      queue.forEach((item) => this.emit("data", item));
      this.send();
    });
  }

  /**
   * Get the current state of the State Machine.
   */
  get state() {
    return this[_state];
  }

  /**
   * Change state to `FINISHED`.
   */
  finish() {
    this[_stopTimer]();
    this[_queue].length = 0;

    this[_next](FINISHED);
  }

  /**
   * Change state to `WAITING`.
   */
  wait() {
    this[_resetTimer]();
    this[_next](WAITING);
  }

  /**
   * Change state to `SENDING`.
   */
  send() {
    this[_next](SENDING);
  }

  /**
   * Change state to `PREPARING`.
   */
  prepare() {
    this[_stopTimer]();
    this[_queue].length = 0;

    // After every success data transfer reset timer to
    // it's initial value.
    this[_timeout] = this[_initialTimeout];

    this[_next](PREPARING);
  }

  /**
   * Create a new flight and buffer it.
   * @param {number} type
   * @param {number} epoch
   * @param {Buffer} packet Handshake messages.
   */
  append(type, epoch, packet) {
    assert(this.state === PREPARING);
    debug("save packet");

    this[_queue].push({ type, epoch, packet });
  }

  /**
   * @private
   * @param {RetransmitMachine} that
   */
  [_onTimeout](that) {
    const instance = that || this;
    instance[_tries] += 1;

    if (instance[_tries] > instance.maxTries) {
      debug("got timeout, max tries (%s) is reached, close", instance.maxTries);
      instance.close();
      return;
    }

    /**
     * Double the value at each retransmission
     * @see https://tools.ietf.org/html/rfc6347#section-4.2.4.1
     */
    const time = instance[_timeout] * 2;
    instance[_timeout] = time > 60e3 ? 60e3 : time;

    debug("got timeout, next time is %s ms", time);
    instance.emit("timeout");
  }

  /**
   * @private
   * @param {string} state New state.
   */
  [_next](state) {
    /** @type {Set} */
    const allowedStates = transitions[this.state];

    assert(
      allowedStates.has(state),
      `Forbidden transition from ${this.state} to ${state}`
    );

    debug("jump to %s state", state);
    this[_state] = state;
    this.emit(state);
  }

  /**
   * Stops the retransmission timer.
   * @private
   */
  [_stopTimer]() {
    if (this[_timer] !== null) {
      clearTimeout(this[_timer]);
    }

    this[_timer] = null;
  }

  /**
   * Restarts the retransmission timer.
   * @private
   */
  [_resetTimer]() {
    this[_stopTimer]();

    this[_timer] = setTimeout(this[_onTimeout], this[_timeout], this);
    this[_timer].unref();
  }

  /**
   * Close the State Machine.
   */
  close() {
    this[_stopTimer]();

    this.emit("close");
  }
}

/**
 * Create Timeout and Retransmission State Machine
 * for the clients.
 * @returns {RetransmitMachine}
 */
export function createRetransmitClient() {
  return new RetransmitMachine(PREPARING);
}

/**
 * Create Timeout and Retransmission State Machine
 * for the servers.
 * @returns {RetransmitMachine}
 */
export function createRetransmitServer() {
  return new RetransmitMachine(WAITING);
}



export const states= {
  PREPARING,
  SENDING,
  WAITING,
  FINISHED,
},