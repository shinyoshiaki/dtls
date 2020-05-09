import AbstractSession from "../session/abstract";
import { createCipher } from "../cipher/create";
const assert = require("assert");
const crypto = require("crypto");
const { Writable } = require("readable-stream");
const { constants: states, createState } = require("./states");
const {
  contentType,
  alertDescription,
  maxSessionIdSize,
  extensionTypes,
  keyTypes,
  signTypes,
  namedCurves,
  signatureScheme,
  kxTypes,
} = require("../lib/constants");
const { decode, createDecode } = require("binary-data");
const {
  HelloVerifyRequest,
  ServerHello,
  Certificate,
  Alert,
  ALPNProtocolNameList,
  ExtensionList,
  ServerECDHParams,
  DigitallySigned,
  CertificateRequest,
  ServerPSKIdentityHint,
} = require("../lib/protocol");
const debug = require("../utils/debug")("dtls:protocol-reader");
const x509 = require("@fidm/x509");
const { ASN1 } = require("@fidm/asn1");
const {
  getHashNameBySignAlgo,
  getCertificateType,
  getCertificateSignatureAlgorithm,
} = require("../session/utils");

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
  CHANGE_CIPHER_SPEC,
} = states;

const FLAG_CLIENT = 2 ** 16 + 1;

const CLIENT_CERTIFICATE = CERTIFICATE | FLAG_CLIENT; // eslint-disable-line no-bitwise
const CLIENT_FINISHED = FINISHED | FLAG_CLIENT; // eslint-disable-line no-bitwise
const CLIENT_CHANGE_CIPHER_SPEC = CHANGE_CIPHER_SPEC | FLAG_CLIENT; // eslint-disable-line no-bitwise

// Transitions of state machine.
const transitions = {
  [CLIENT_HELLO]: new Set([HELLO_VERIFY_REQUEST, SERVER_HELLO]), // default state
  [HELLO_VERIFY_REQUEST]: new Set([CLIENT_HELLO]),
  [SERVER_HELLO]: new Set([
    CERTIFICATE,
    SERVER_KEY_EXCHANGE,
    SERVER_HELLO_DONE,
  ]),
  [CERTIFICATE]: new Set([
    SERVER_KEY_EXCHANGE,
    CERTIFICATE_REQUEST,
    SERVER_HELLO_DONE,
  ]),
  [CLIENT_CERTIFICATE]: new Set([
    CLIENT_KEY_EXCHANGE,
    CLIENT_CHANGE_CIPHER_SPEC,
  ]),
  [SERVER_KEY_EXCHANGE]: new Set([CERTIFICATE_REQUEST, SERVER_HELLO_DONE]),
  [CERTIFICATE_REQUEST]: new Set([SERVER_HELLO_DONE]),
  [SERVER_HELLO_DONE]: new Set([CLIENT_KEY_EXCHANGE, CLIENT_CERTIFICATE]),
  [CLIENT_KEY_EXCHANGE]: new Set([
    CERTIFICATE_VERIFY,
    CLIENT_CHANGE_CIPHER_SPEC,
  ]),
  [CERTIFICATE_VERIFY]: new Set([CLIENT_CHANGE_CIPHER_SPEC]),
  [CHANGE_CIPHER_SPEC]: new Set([FINISHED]),
  [CLIENT_CHANGE_CIPHER_SPEC]: new Set([CLIENT_FINISHED]),
  [FINISHED]: null,
  [CLIENT_FINISHED]: new Set([CHANGE_CIPHER_SPEC]),
};

const handlers = {
  [CLIENT_HELLO]: "clientHello",
  [HELLO_VERIFY_REQUEST]: "helloVerifyRequest",
  [SERVER_HELLO]: "serverHello",
  [CERTIFICATE]: "serverCertificate",
  [CERTIFICATE_REQUEST]: "certificateRequest",
  [SERVER_KEY_EXCHANGE]: "serverKeyExchange",
  [SERVER_HELLO_DONE]: "serverHelloDone",
  [CLIENT_CERTIFICATE]: "clientCertificate",
  [CLIENT_KEY_EXCHANGE]: "clientKeyExchange",
  [CERTIFICATE_VERIFY]: "certificateVerify",
  [CLIENT_CHANGE_CIPHER_SPEC]: "clientChangeCipherSpec",
  [CLIENT_FINISHED]: "clientFinished",
  [CHANGE_CIPHER_SPEC]: "serverChangeCipherSpec",
  [FINISHED]: "serverFinished",
};

// Human-readable states for better errors.
const stateNames = {
  [CLIENT_CERTIFICATE]: "CLIENT_CERTIFICATE",
  [CLIENT_FINISHED]: "CLIENT_FINISHED",
  [CLIENT_CHANGE_CIPHER_SPEC]: "CLIENT_CHANGE_CIPHER_SPEC",
};

Object.keys(states).forEach((name) => {
  const state = states[name];
  stateNames[state] = name;
});

const supportedCurves = Object.keys(namedCurves);

/**
 * This class implements DTLS v1.2 protocol using Finite State Mahcine.
 */
export default class Protocol12ReaderClient extends (Writable as any) {
  message?: any;

  /**
   * @class Protocol12ReaderClient
   * @param {ClientSession} session
   */
  constructor(private session: AbstractSession) {
    super({ objectMode: true, decodeStrings: false });

    session.handshakeProtocolReaderState = null;
  }

  /**
   * @returns {number|null}
   */
  get state() {
    return this.session.handshakeProtocolReaderState;
  }

  /**
   * Starts a new client-side handshake flow.
   */
  start() {
    this.session.startHandshake(() => this.next(CLIENT_HELLO));
  }

  /**
   * Switch to the next state.
   * @param {number} state
   */
  next(state: number) {
    if (this.state !== null) {
      const allowedStates = transitions[this.state]!;
      const from = stateNames[this.state];
      const to = stateNames[state];

      assert(
        allowedStates.has(state),
        `Forbidden transition from ${from} to ${to}`
      );
    }

    this.session.handshakeProtocolReaderState = state;
    this[handlers[state]]();
  }

  /**
   * @private
   * @param {Object} record
   * @param {string} encoding
   * @param {Function} callback
   */
  private _write(record: any, encoding: string, callback: () => void) {
    this.message = record;

    const protocol = record.type;

    const isAlert = protocol === contentType.ALERT;
    const isAppData = protocol === contentType.APPLICATION_DATA;
    const isHandshake = protocol === contentType.HANDSHAKE;

    if (isAlert) {
      this.alert();
    } else if (!this.session.isHandshakeInProcess && isAppData) {
      this.applicationData();
    } else {
      const type = isHandshake ? record.fragment.type : 0;
      const state = createState(protocol, type);

      this.next(state);

      if (isHandshake) {
        this.session.lastRvHandshake = record.fragment.sequence;
      }
    }

    if (protocol !== contentType.CHANGE_CIPHER_SPEC) {
      this.session.window.accept(record.sequenceNumber);
    }

    this.message = undefined;
    callback();
  }

  /**
   * @private
   */
  private _destroy() {
    this.session = undefined as any;
    this.message = undefined;
  }

  /**
   * Handles `client hello` out message.
   * @private
   */
  private clientHello() {
    debug("prepare client hello");
    this.session.send(this.state);
    this.session.retransmitter.send();
  }

  /**
   * Handles `hello verify request` incoming message.
   * @private
   */
  private helloVerifyRequest() {
    debug("got hello verify request");
    this.session.retransmitter.prepare();

    const handshake = this.message.fragment;

    // Initial `ClientHello` and `HelloVerifyRequest` must not
    // use for calculate finished checksum.
    this.session.resetHandshakeQueue();

    try {
      const packet = decode(handshake.body, HelloVerifyRequest);
      assert(decode.bytes === handshake.body.length);

      this.session.cookie = packet.cookie;
      debug("got cookie %h", packet.cookie);

      this.next(CLIENT_HELLO);
    } catch (error) {
      debug(error);
      this.session.error(alertDescription.DECODE_ERROR);
    }
  }

  /**
   * Handles `server hello` incoming message.
   * @private
   */
  private serverHello() {
    debug("got server hello");
    const handshake = this.message.fragment;

    if (handshake.body.length < 38) {
      this.session.error(alertDescription.DECODE_ERROR);
      return;
    }

    try {
      const istream = createDecode(handshake.body);
      const serverHello = decode(istream, ServerHello);

      if (serverHello.serverVersion !== this.session.version) {
        debug("mismatch protocol version");
        this.session.error(alertDescription.PROTOCOL_VERSION);
        return;
      }

      if (serverHello.sessionId.length > maxSessionIdSize) {
        this.session.error(alertDescription.ILLEGAL_PARAMETER);
        return;
      }

      this.session.serverRandom = serverHello.random;
      this.session.id = serverHello.sessionId;

      const clientCipher = this.session.cipherSuites.find(
        (cipherSuite) => cipherSuite === serverHello.cipherSuite
      );

      if (!clientCipher) {
        debug("server selected unknown cipher %s", serverHello.cipherSuite);
        this.session.error(alertDescription.HANDSHAKE_FAILURE);
        return;
      }

      const cipher = createCipher(clientCipher);

      // debug(`server selected ${cipher.name} cipher`);
      this.session.nextCipher = cipher;

      if (istream.length > 0) {
        const extensions = decode(istream, ExtensionList);

        this.serverHelloExtensions(extensions);
      }

      const { extendedMasterSecret, peerExtendedMasterSecret } = this.session;

      // If a client receives a ServerHello without the extension, it SHOULD
      // abort the handshake if it does not wish to interoperate with legacy
      // servers.
      if (extendedMasterSecret && !peerExtendedMasterSecret) {
        this.session.error(alertDescription.HANDSHAKE_FAILURE);
        return;
      }

      // Ignore server's choise of Supported Point Formats Extension.
      // Force use of uncompressed points.

      this.session.appendHandshake(handshake);
    } catch (error) {
      debug(error);
      this.session.error(alertDescription.DECODE_ERROR);
    }
  }

  /**
   * @private
   * @param {Array<Object>} extensions
   */
  private serverHelloExtensions(extensions: any[]) {
    for (const extension of extensions) {
      if (extension.type === extensionTypes.EXTENDED_MASTER_SECRET) {
        this.session.peerExtendedMasterSecret = true;
      }

      if (
        extension.type === extensionTypes.APPLICATION_LAYER_PROTOCOL_NEGOTIATION
      ) {
        const protocols = decode(extension.data, ALPNProtocolNameList);

        if (protocols.length === 1) {
          const [alpn] = protocols;

          this.session.selectedALPNProtocol = alpn;
        }
      }
    }
  }

  /**
   * Handles `certificate` incoming message.
   * @private
   */
  private serverCertificate() {
    debug("got server certificate");
    const handshake = this.message.fragment;

    // PSK key exchange don't need this message.
    if (this.session.nextCipher.kx.id === kxTypes.PSK) {
      throw new Error("Invalid message.");
    }

    try {
      const packet = decode(handshake.body, Certificate);

      if (packet.certificateList.length === 0) {
        this.session.error(alertDescription.CERTIFICATE_UNKNOWN);
        return;
      }

      // The sender's certificate MUST come first in the list.
      const serverCertificate = packet.certificateList[0];
      const certificate = new x509.Certificate(ASN1.fromDER(serverCertificate));

      const isValid = this.session.verifyCertificate(certificate);

      if (!isValid) {
        this.session.error(alertDescription.BAD_CERTIFICATE);
        return;
      }

      this.session.certificate(certificate);
      this.session.serverPublicKey = certificate.publicKey.toPEM();

      this.session.appendHandshake(handshake);
    } catch (error) {
      debug(error);
      this.session.error(alertDescription.DECODE_ERROR);
    }
  }

  /**
   * @private
   */
  private serverKeyExchange() {
    debug("got server key exchange");
    const { nextCipher } = this.session;

    const isECDHE = nextCipher.kx.signType === signTypes.ECDHE;
    const isPSK = nextCipher.kx.id === kxTypes.PSK;
    const isECDHE_PSK = nextCipher.kx.id === kxTypes.ECDHE_PSK; // eslint-disable-line camelcase

    // Only ECDHE_* and PSK may have this message.
    // eslint-disable-next-line camelcase
    if (isECDHE_PSK) {
      this.serverECDHEPSKKeyExchange();
    } else if (isECDHE) {
      this.serverECDHEKeyExchange();
    } else if (isPSK) {
      this.serverPSKKeyExchange();
    } else {
      throw new Error("Invalid message type.");
    }
  }

  /**
   * Process `ServerKeyExchange` message for ECDHE_* key exchange (except ECDHE_PSK).
   * @private
   */
  private serverECDHEKeyExchange() {
    debug("process server ECDHE key exchange");

    const handshake = this.message.fragment;
    const rstream = createDecode(handshake.body);

    const ecdheParams = decode(rstream, ServerECDHParams);
    const ecdheParamsSize = decode.bytes;
    const digitalSign = decode(rstream, DigitallySigned);

    // check curve
    const selectedCurve = supportedCurves.find(
      (curve) => namedCurves[curve] === ecdheParams.curve
    );

    if (selectedCurve === undefined) {
      throw new Error("Invalid curve name");
    }

    // Default sign algo is sha1 for rsa
    if (this.session.nextCipher.kx.keyType === keyTypes.RSA) {
      assert(digitalSign.algorithm === signatureScheme.rsa_pkcs1_sha1);
    }

    if (this.session.nextCipher.kx.keyType === keyTypes.ECDSA) {
      const isECDSA =
        digitalSign.algorithm === signatureScheme.ecdsa_sha1 ||
        digitalSign.algorithm === signatureScheme.ecdsa_secp256r1_sha256 ||
        digitalSign.algorithm === signatureScheme.ecdsa_secp384r1_sha384 ||
        digitalSign.algorithm === signatureScheme.ecdsa_secp521r1_sha512;
      assert(isECDSA);
    }

    const verifier = crypto.createVerify(
      getHashNameBySignAlgo(digitalSign.algorithm)
    );

    verifier.update(this.session.clientRandom);
    verifier.update(this.session.serverRandom);
    verifier.update(handshake.body.slice(0, ecdheParamsSize));

    const isSignValid = verifier.verify(
      { key: this.session.serverPublicKey },
      digitalSign.signature
    );

    if (!isSignValid) {
      throw new Error("Invalid sign");
    }

    debug("sign valid");

    this.session.appendHandshake(handshake);
    this.session.ellipticCurve = selectedCurve;
    this.session.peerEllipticPublicKey = ecdheParams.pubkey;
    this.session.createElliptic();
  }

  /**
   * Process `ServerKeyExchange` message for PSK key exchange.
   * @private
   */
  private serverPSKKeyExchange() {
    debug("process server PSK key exchange");

    const handshake = this.message.fragment;
    const rstream = createDecode(handshake.body);

    /**
     * In the absence of an application profile specification specifying
     * otherwise, servers SHOULD NOT provide an identity hint and clients
     * MUST ignore the identity hint field.
     */

    if (!this.session.ignorePSKIdentityHint) {
      const pskIdentityHint = decode(rstream, ServerPSKIdentityHint);

      this.session.serverPSKIdentityHint = pskIdentityHint;
    }

    this.session.appendHandshake(handshake);
  }

  /**
   * Process `ServerKeyExchange` message for ECDHE_PSK key exchange.
   */
  private serverECDHEPSKKeyExchange() {
    debug("process server ECDHE PSK key exchange");

    const handshake = this.message.fragment;
    const rstream = createDecode(handshake.body);

    const pskIdentityHint = decode(rstream, ServerPSKIdentityHint);
    const ecdheParams = decode(rstream, ServerECDHParams);

    if (!this.session.ignorePSKIdentityHint) {
      this.session.serverPSKIdentityHint = pskIdentityHint;
    }

    // check curve
    const selectedCurve = supportedCurves.find(
      (curve) => namedCurves[curve] === ecdheParams.curve
    );

    if (selectedCurve === undefined) {
      throw new Error("Invalid curve name");
    }

    this.session.appendHandshake(handshake);
    this.session.ellipticCurve = selectedCurve;
    this.session.peerEllipticPublicKey = ecdheParams.pubkey;
    this.session.createElliptic();
  }

  /**
   * Handles `certificate request` incoming message.
   * @private
   */
  private certificateRequest() {
    debug("got certificate request");
    const handshake = this.message.fragment;
    const { nextCipher } = this.session;

    // PSK key exchange don't need this message.
    if (nextCipher.kx.keyType === keyTypes.PSK) {
      throw new Error("Invalid message.");
    }

    const certificateRequest = decode(handshake.body, CertificateRequest);
    const { certificateTypes, signatures } = certificateRequest;

    this.session.isCertificateRequested = true;
    this.session.requestedCertificateTypes = certificateTypes;
    this.session.requestedSignatureAlgorithms = signatures;

    this.session.appendHandshake(handshake);
  }

  /**
   * Handles `server hello done` incoming message.
   * @private
   */
  private serverHelloDone() {
    debug("got server hello done");
    const handshake = this.message.fragment;
    const nextState = this.session.isCertificateRequested
      ? CLIENT_CERTIFICATE
      : CLIENT_KEY_EXCHANGE;

    this.session.appendHandshake(handshake);
    this.session.createPreMasterSecret(() => {
      debug("PREMASTER SECRET %h", this.session.clientPremaster);
      this.next(nextState);
    });
  }

  /**
   * @private
   */
  private clientCertificate() {
    debug("prepare client certificate");

    this.session.retransmitter.prepare();

    if (this.session.clientCertificate !== null) {
      // The end-entity certificate provided by the client MUST contain a
      // key that is compatible with certificate_types.
      const certType = getCertificateType(this.session.clientCertificate);
      const isCertificateAllowed = this.session.requestedCertificateTypes.includes(
        certType
      );

      if (!isCertificateAllowed) {
        throw new Error("Disallowed certificate type.");
      }

      // Any certificates provided by the client MUST be signed using a
      // hash/signature algorithm pair found in
      // supported_signature_algorithms.
      const signalgo = getCertificateSignatureAlgorithm(
        this.session.clientCertificate
      );
      const isCertificatSignatureAllowed = this.session.requestedSignatureAlgorithms.includes(
        signalgo
      );

      if (!isCertificatSignatureAllowed) {
        throw new Error("Disallowed certificate signature algorithm.");
      }

      this.session.clientCertificateSignatureAlgorithm = signalgo;
    }

    this.session.send(CERTIFICATE);
    this.next(CLIENT_KEY_EXCHANGE);
  }

  /**
   * @private
   */
  private clientKeyExchange() {
    debug("prepare client key exchange");
    const { isCertificateRequested, clientCertificate } = this.session;

    if (!isCertificateRequested) {
      this.session.retransmitter.prepare();
    }

    this.session.send(this.state);

    this.session.createMasterSecret();
    debug("MASTER SECRET %h", this.session.masterSecret);

    const isCertificateValid =
      isCertificateRequested && clientCertificate !== null;

    const nextState = isCertificateValid
      ? CERTIFICATE_VERIFY
      : CLIENT_CHANGE_CIPHER_SPEC;
    this.next(nextState);
  }

  /**
   * @private
   */
  private certificateVerify() {
    debug("prepare certificate verify");

    this.session.createSignature();
    this.session.send(CERTIFICATE_VERIFY);

    this.next(CLIENT_CHANGE_CIPHER_SPEC);
  }

  /**
   * @private
   */
  private clientChangeCipherSpec() {
    debug("prepare change cipher spec");
    this.session.send(CHANGE_CIPHER_SPEC);
    this.session.nextEpochClient();
    this.next(CLIENT_FINISHED);
  }

  /**
   * @private
   */
  private clientFinished() {
    debug("prepare client finished");
    this.session.createClientFinished();
    debug("client finished %h", this.session.clientFinished);

    this.session.send(FINISHED);
    this.session.retransmitter.send();
  }

  /**
   * @private
   */
  private serverChangeCipherSpec() {
    debug("got change cipher spec");
    this.session.nextEpochServer();
  }

  /**
   * @private
   */
  private serverFinished() {
    debug("got finished");
    const handshake = this.message.fragment;
    debug("received server finished %h", handshake.body);

    this.session.createServerFinished();
    debug("computed server finished %h", this.session.serverFinished);

    if (Buffer.compare(handshake.body, this.session.serverFinished) !== 0) {
      throw new Error("Mismatch server finished messages");
    }

    this.session.retransmitter.finish();
    this.session.finishHandshake();
  }

  /**
   * Handle incoming `alert` messages.
   * @private
   */
  private alert() {
    debug("got alert");
    const packet = this.message.fragment;
    const alert = decode(packet, Alert);
    debug("level %s, description %s", alert.level, alert.description);

    this.session.error(alert.description);
  }

  /**
   * Handle incoming `application data` message.
   * @private
   */
  private applicationData() {
    debug("got application data");

    const appdata = this.message.fragment;
    debug("packet: %h", appdata);

    this.session.packet(appdata);
  }
}
