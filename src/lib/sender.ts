import AbstractSession from "../session/abstract";
import { constants as states, getProtocol } from "../fsm/states";
const { Readable } = require("readable-stream");
const debug = require("../utils/debug")("dtls:sender");
const { createEncode, encode, BinaryStream, types } = require("binary-data");
const {
  contentType,
  handshakeType,
  compressionMethod,
  extensionTypes,
  namedCurves,
  kxTypes,
  signTypes,
  keyTypes,
} = require("./constants");
const {
  Alert,
  ALPNProtocolNameList,
  Certificate,
  DTLSPlaintext,
  Handshake,
  ClientHello,
  EncryptedPreMasterSecret,
  ExtensionList,
  ECPublicKey,
  DigitallySigned,
  ServerPSKIdentityHint,
} = require("./protocol");
const { encryptPreMasterSecret } = require("../session/utils");
const {
  states: { SENDING },
} = require("../fsm/retransmitter");

const changeCipherSpecMessage = Buffer.alloc(1, 1);
const defaultCompressionMethods = [compressionMethod.NULL];

const {
  CLIENT_HELLO,
  FINISHED,
  CERTIFICATE,
  CHANGE_CIPHER_SPEC,
  CLIENT_KEY_EXCHANGE,
  HANDSHAKE,
  CERTIFICATE_VERIFY,
} = states;

const EMPTY_BUFFER = Buffer.alloc(0);

const namedCurvesExtension = Buffer.from([
  0,
  4, // length in bytes
  0,
  namedCurves.x25519, // namedCurveX25519
  0,
  namedCurves.secp256r1, // namedCurveP256
]);

const ecPointFormatExtension = Buffer.from([
  1, // length in bytes
  0, // uncompressed points format
]);

const DTLS_RECORD_SIZE = 13;
const DTLS_HANDSHAKE_SIZE = 12;

const senders = {
  [CLIENT_HELLO]: "_clientHello",
  [FINISHED]: "_finished",
  [CERTIFICATE]: "_certificate",
  [CHANGE_CIPHER_SPEC]: "_changeCipherSpec",
  [CLIENT_KEY_EXCHANGE]: "_clientKeyExchange",
  [CERTIFICATE_VERIFY]: "_certificateVerify",
};

export default class Sender extends (Readable as any) {
  _queue: Buffer[] = [];
  _output = {
    alert: createEncode(Alert),
    record: createEncode(DTLSPlaintext),
    handshake: createEncode(Handshake),
  };
  /**
   * @param {AbstractSession} session
   */
  constructor(private _session: AbstractSession) {
    super();

    this._output.alert.on("data", (packet: Buffer) => {
      this.sendRecord(packet, contentType.ALERT);
    });

    this._output.handshake.on("data", (packet: Buffer) => {
      this.session.retransmitter.append(
        HANDSHAKE,
        this.session.clientEpoch,
        packet
      );
      this.sendRecord(packet, contentType.HANDSHAKE);
    });

    this._output.record.on("data", (packet: Buffer) =>
      this._bufferDrain(packet)
    );

    this._nextPacketQueue = new BinaryStream();

    this._session.on("send", (state: number) => this[senders[state]]());

    this._session.on("send:appdata", (payload: Buffer) =>
      this._applicationData(payload)
    );
    this._session.on("send:alert", (description: number, level: number) =>
      this._alert(level, description)
    );

    // Merge outgoing handshake packets before send.
    this._session.retransmitter.on(SENDING, () => this._drain());

    // Send stored handshake message again.
    this._session.retransmitter.on("data", ({ type, epoch, packet }: any) =>
      this.sendRecord(packet, getProtocol(type), epoch)
    );
  }

  /**
   * @returns {{alert, record, handshake}}
   */
  get output() {
    return this._output;
  }

  /**
   * @returns {AbstractSession}
   */
  get session() {
    return this._session;
  }

  /**
   * @private
   */
  _read() {} // eslint-disable-line class-methods-use-this

  /**
   * @param {Buffer} message
   * @param {contentType} type
   * @param {number} [epoch]
   */
  sendRecord(message: Buffer, type: number, epoch?: number) {
    const outgoingEpoch = Number.isInteger(epoch!)
      ? epoch
      : this.session.clientEpoch;

    const record = {
      type,
      version: this.session.version,
      epoch: outgoingEpoch,
      sequenceNumber: this.session.nextRecordNumber(),
      length: message.length,
      fragment: message,
    };

    if (type !== contentType.ALERT && type !== contentType.CHANGE_CIPHER_SPEC) {
      const isPreviousEpoch = this.session.clientEpoch - outgoingEpoch === 1;
      const cipher = isPreviousEpoch
        ? this.session.prevCipher
        : this.session.cipher;

      debug("encrypt, cipher = %s", cipher.blockAlgorithm);
      this.session.encrypt(cipher, record);
      debug("success");
    }

    this.output.record.write(record);
    const test = encode(record, DTLSPlaintext).slice();
    test;
  }

  /**
   * @param {Buffer} message Packet payload.
   * @param {handshakeType} type
   */
  sendHandshake(message: Buffer, type: number) {
    const { mtu } = this.session;
    const packetLength = this._nextPacketQueue.length;

    const remainder = mtu - packetLength;
    const payloadRemainder = remainder - DTLS_RECORD_SIZE - DTLS_HANDSHAKE_SIZE;
    const isEnough = payloadRemainder - message.length;

    // Fragmented handshakes must have the same seq number.
    // Also, save this number between parts.
    const sequence = this.session.nextHandshakeNumber();

    /**
     * @private
     * @param {Buffer} payload
     * @param {number} offset
     * @returns {Object}
     */
    const createPacket = (payload: Buffer, offset = 0) => ({
      type,
      length: message.length,
      sequence,
      fragment: {
        offset,
        length: payload.length,
      },
      body: payload,
    });

    // Store unfragmented handshake message.
    this.session.appendHandshake(createPacket(message));

    if (isEnough >= 0) {
      this.output.handshake.write(createPacket(message));
      const test = encode(createPacket(message), Handshake).slice();
      console;
    } else {
      debug(
        "start handshake fragmentation, remainder = %s bytes, data = %s bytes",
        payloadRemainder,
        message.length
      );
      let payloadLength = message.length;
      let offset = 0;

      // Send first part
      this.output.handshake.write(
        createPacket(message.slice(0, payloadRemainder))
      );
      const test = encode(createPacket(message), Handshake).slice();
      offset += payloadRemainder;
      payloadLength -= payloadRemainder;
      debug(
        "enqueue %s bytes, %s bytes remaind",
        payloadRemainder,
        payloadLength
      );

      // Send next parts
      while (payloadLength > 0) {
        const dataLegth = mtu - DTLS_RECORD_SIZE - DTLS_HANDSHAKE_SIZE;

        this.output.handshake.write(
          createPacket(message.slice(offset, offset + dataLegth), offset)
        );
        const test = encode(createPacket(message), Handshake).slice();
        offset += dataLegth;
        payloadLength -= dataLegth;
        debug(
          "enqueue %s bytes, %s bytes remaind",
          dataLegth,
          Math.max(payloadLength, 0)
        );
      }
    }
  }

  /**
   * Send `Alert` message.
   * @param {number} level
   * @param {number} code
   */
  sendAlert(level: number, code: number) {
    debug("send Alert");

    const message = {
      level,
      description: code,
    };

    this.output.alert.write(message);
  }

  /**
   * Send `Client Hello` message.
   */
  _clientHello() {
    debug("send Client Hello");

    const clientHello = {
      clientVersion: this.session.version,
      random: this.session.clientRandom,
      sessionId: EMPTY_BUFFER, // We do not support resuming session. So, send empty id.
      cookie: this.session.cookie || EMPTY_BUFFER,
      cipherSuites: this.session.cipherSuites,
      compressionMethods: defaultCompressionMethods,
    };

    const output = createEncode();
    encode(clientHello, output, ClientHello);

    const extensions = [];

    // if (this.session.extendedMasterSecret) {
    //   extensions.push({
    //     type: extensionTypes.EXTENDED_MASTER_SECRET,
    //     data: EMPTY_BUFFER,
    //   });
    // }

    extensions.push({
      type: extensionTypes.ELLIPTIC_CURVES,
      data: namedCurvesExtension,
    });

    extensions.push({
      type: 13,
      data: Buffer.from(
        encode(
          [
            {
              hash: 4, // sha256
              signature: 3, // ecdsa
            },
          ],
          types.array(
            { hash: types.uint8, signature: types.uint8 },
            types.uint16be,
            "bytes"
          )
        ).slice()
      ),
    });

    // if (this.session.alpnProtocols.length > 0) {
    //   const alpnOutput = encode(
    //     this.session.alpnProtocols,
    //     ALPNProtocolNameList
    //   );

    //   extensions.push({
    //     type: extensionTypes.APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
    //     data: alpnOutput,
    //   });
    // }

    // extensions.push({
    //   type: extensionTypes.EC_POINT_FORMATS,
    //   data: ecPointFormatExtension,
    // });

    if (extensions.length > 0) {
      encode(extensions, output, ExtensionList);
    }

    this.sendHandshake(output.slice(), handshakeType.CLIENT_HELLO);
  }

  /**
   * Send `Client Key Exchange` message.
   */
  _clientKeyExchange() {
    debug("send Client Key Exchange");

    const { nextCipher } = this.session;
    const output = createEncode();

    if (nextCipher.kx.id === kxTypes.RSA) {
      const pubkey = this.session.serverPublicKey;
      const premaster = this.session.clientPremaster;
      const encryptedPremaster = encryptPreMasterSecret(pubkey, premaster);

      encode(encryptedPremaster, output, EncryptedPreMasterSecret);
    }

    if (nextCipher.kx.keyType === keyTypes.PSK) {
      const {
        serverPSKIdentityHint,
        ignorePSKIdentityHint,
        clientPSKIdentity,
      } = this.session;

      const useHint =
        !ignorePSKIdentityHint &&
        Buffer.isBuffer(serverPSKIdentityHint) &&
        serverPSKIdentityHint.length > 0;

      const pskIdentity = useHint ? serverPSKIdentityHint : clientPSKIdentity;
      encode(pskIdentity, output, ServerPSKIdentityHint);
    }

    // ECDHE_PSK send both ServerPSKIdentityHint and ECPublicKey
    if (nextCipher.kx.signType === signTypes.ECDHE) {
      const pubkey = this.session.ellipticPublicKey;

      encode(pubkey, output, ECPublicKey);
    }

    this.sendHandshake(output.slice(), handshakeType.CLIENT_KEY_EXCHANGE);
  }

  /**
   * Send `Change Cipher Spec` message.
   */
  _changeCipherSpec() {
    debug("send Change Cipher Spec");

    this.session.retransmitter.append(
      CHANGE_CIPHER_SPEC,
      this.session.clientEpoch,
      changeCipherSpecMessage
    );
    this.sendRecord(changeCipherSpecMessage, contentType.CHANGE_CIPHER_SPEC);
  }

  /**
   * Send `Certificate` message.
   */
  _certificate() {
    debug("send client certificate");

    const packet = {
      certificateList: [] as any,
    };

    if (this.session.clientCertificate !== null) {
      packet.certificateList.push(this.session.clientCertificate.raw);
    }

    const output = encode(packet, Certificate);

    this.sendHandshake(output.slice(), handshakeType.CERTIFICATE);
  }

  /**
   * Send `Certificate Verify` message.
   */
  _certificateVerify() {
    debug("send client certificate");

    const digitalSignature = {
      algorithm: this.session.clientCertificateSignatureAlgorithm,
      signature: this.session.clientCertificateSignature,
    };

    const output = encode(digitalSignature, DigitallySigned);

    this.sendHandshake(output.slice(), handshakeType.CERTIFICATE_VERIFY);
  }

  /**
   * Send `Finished` message.
   */
  _finished() {
    debug("send Finished");

    this.sendHandshake(this.session.clientFinished, handshakeType.FINISHED);
  }

  /**
   * Send `application data` message.
   * @param {Buffer} payload
   * @private
   */
  _applicationData(payload: Buffer) {
    this.sendRecord(payload, contentType.APPLICATION_DATA);
  }

  /**
   * Send `alert` message.
   * @private
   * @param {number} level
   * @param {number} description
   */
  _alert(level: number, description: number) {
    this.output.alert.write({
      level,
      description,
    });
  }

  /**
   * Clears internal message buffer and sends packets.
   * @private
   */
  _drain() {
    const nextPacketLength = this._nextPacketQueue.length;

    if (nextPacketLength > 0) {
      this._queue.push(this._nextPacketQueue.slice());
      this._nextPacketQueue.consume(nextPacketLength);
    }

    if (this._queue.length === 0) {
      debug("empty out queue");
      return;
    }

    debug("drain queue");
    this._queue.forEach((packet) => this.push(packet));
    this._queue.length = 0;

    this.session.retransmitter.wait();
  }

  /**
   * @param {Buffer} packet Record layer message.
   * @private
   */
  _bufferDrain(packet: Buffer) {
    if (this.session.isHandshakeInProcess) {
      debug("buffer packet");

      const { mtu } = this.session;
      const queueLength = this._nextPacketQueue.length;
      const probablyLength = mtu - queueLength - packet.length;

      if (probablyLength < 0) {
        this._queue.push(this._nextPacketQueue.slice());
        this._nextPacketQueue.consume(queueLength);
      }

      this._nextPacketQueue.append(packet);
    } else {
      debug("send packet");
      this.push(packet);
    }
  }
}
