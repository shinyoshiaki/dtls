"use strict";

const { Transform } = require("readable-stream");
const sorter = require("sorted-array-functions");
const { contentType } = require("../lib/constants");
const debug = require("../utils/debug")("dtls:reorder");

const _session = Symbol("_session");
const _queue = Symbol("_queue");

/**
 * Insert comparator for ordered records queue.
 * @param {Object} recordLeft
 * @param {Object} recordRight
 * @returns {number}
 */
function comparator(recordLeft, recordRight) {
  return recordLeft.sequenceNumber > recordRight.sequenceNumber ? 1 : -1;
}

/**
 * Handles reordering of a handshake message.
 */
module.exports = class Reordering extends Transform {
  /**
   * @class Reordering
   * @param {AbstractSession} session
   */
  constructor(session) {
    super({ objectMode: true });

    this[_session] = session;
    this[_queue] = [];

    // 3.2
    session.retransmitter.on("timeout", () => {
      this[_queue].length = 0;
    });
  }

  /**
   * @returns {AbstractSession}
   */
  get session() {
    return this[_session];
  }

  /**
   * @returns {number}
   */
  get queueSize() {
    return this[_queue].length;
  }

  /**
   * @private
   * @param {Object} record Record / handshake message.
   * @param {string} enc
   * @param {Function} callback
   */
  _transform(record, enc, callback) {
    // 1. check epoch
    // 2. check sliding window
    // 3. if handshake and got handshake, check last received handshake number
    // 3.1 if handshake sequence number <= lastRvHandshake, drop
    // 3.2 if retransmit timeout have got, reset queue
    // 3.3 if expected handshake number equals to sequence number
    // 3.3.1 if packet without fragmentation, use it
    // 3.3.2 if fragmentation, add to the sorted queue
    // 3.3.3 if fragmentation and queue is not empty, check if we have full framented packet in queue
    // 3.3.4 if queue is not empty again, drain (future) messages
    // 3.4 if handshake sequence number > expected handshake number, add to the sorted queue
    // 3.5 check queue
    // 4. if handshake and got not handshake, use packet
    // the queue will be always empty in the last flight [CCS, FINISHED].
    // if we got Finished before CCS, it will be silently discarded due to mismatch epoches
    // 5. if not handshake, use packet
    // 6. reset queue after complete handshake
    // 7. ヘ(>_<ヘ)

    const isHandshake = record.type === contentType.HANDSHAKE;
    const isReplay =
      isHandshake && record.fragment.sequence <= this.session.lastRvHandshake;
    const expectedHandshake = this.session.lastRvHandshake + 1;

    // 1
    if (this.session.peerEpoch !== record.epoch) {
      debug(
        "mismatch epoch: got %s, expected %s",
        record.epoch,
        this.session.peerEpoch
      );
      callback();
      return;
    }

    // 2
    if (!this.session.window.check(record.sequenceNumber)) {
      const seq = record.sequenceNumber;

      debug("record layer replay probably, seq = %s", seq, this.session.window);
      callback();
      return;
    }

    // 3
    if (this.session.isHandshakeInProcess) {
      if (isHandshake) {
        // 3.1
        if (isReplay) {
          debug("handshake replay detected, drop");
          callback();
          return;
        }

        // 3.3
        if (expectedHandshake === record.fragment.sequence) {
          debug("success, matched handshake seq number");
          this.push(record);
        }
        // 3.4
        else if (expectedHandshake < record.fragment.sequence) {
          debug("save record to the queue, waiting for next packet");
          sorter.add(this[_queue], record, comparator);
        }

        // 3.5
        if (this[_queue].length > 0) {
          let i = 0;
          let touched = false;

          for (; i < this[_queue].length; i += 1) {
            const packet = this[_queue][i];
            const nextHandshake = this.session.lastRvHandshake + 1;

            if (nextHandshake === packet.fragment.sequence) {
              this.push(packet);
              touched = true;
            }
          }

          if (touched) {
            this[_queue].splice(0, i + 1);
          }
        }
      }
      // 4
      else {
        // !isHandshake
        debug("success, got message type = %s", record.type);
        this.push(record);
      }
    }
    // 5
    else {
      // !this.session.isHandshakeInProcess
      debug("success");
      this.push(record);
    }

    callback();
  }
};
