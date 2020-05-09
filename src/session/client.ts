import * as crypto from "crypto";
import AbstractSession from "./abstract";
import { createRandom, createFinished, getHashNameBySignAlgo } from "./utils";
import { sessionType, randomSize } from "../lib/constants";
import { createRetransmitClient } from "../fsm/retransmitter";

/**
 * This class implements DTLS client-side session.
 */
export default class ClientSession extends AbstractSession {
  /**
   * @class ClientSession
   */
  constructor() {
    super();

    this.cookie = null;
    this.retransmitter = createRetransmitClient();

    // check if `CertificateRequest` message arrived
    this.isCertificateRequested = false;

    // possible certificate types from `CertificateRequest`
    this.requestedCertificateTypes = [];

    // possible signature algorithms from `CertificateRequest`
    this.requestedSignatureAlgorithms = [];

    // selected by client from offered options in `CertificateRequest`
    this.clientCertificateSignatureAlgorithm = null;

    // signed part of `ClientVerify` message
    this.clientCertificateSignature = null;

    // private key for client certificate
    this.clientCertificatePrivateKey = null;

    this.serverCertificateVerifyCallback = () => true;

    // the list of the supported alpn protocols
    this.alpnProtocols = [];

    // The name of the protocol selected by server
    this.selectedALPNProtocol = "";

    // auth credentials for PSK key exchange
    this.clientPSKIdentity = null;

    this.ignorePSKIdentityHint = true;
    this.serverPSKIdentityHint = null;
  }

  /**
   * Get type of the Session.
   * @returns {number}
   */
  get type() {
    return sessionType.CLIENT;
  }

  /**
   * Handles starting of handshake.
   * @param {Function} done
   */
  startHandshake(done: () => void) {
    super.startHandshake();

    this.clientRandom = Buffer.allocUnsafe(randomSize);
    createRandom(this.clientRandom, done);
  }

  /**
   * Create finished message checksum for client.
   */
  createClientFinished() {
    const queue = this.handshakeQueue.slice();

    this.clientFinished = createFinished(
      this.cipher,
      this.masterSecret,
      queue,
      "client finished"
    );
  }

  /**
   * Create finished message checksum for server.
   */
  createServerFinished() {
    const queue = this.handshakeQueue.slice();

    this.serverFinished = createFinished(
      this.cipher,
      this.masterSecret,
      queue,
      "server finished"
    );
  }

  /**
   * Starts next epoch for server.
   */
  nextEpochServer() {
    super.nextEpochServer();

    this.window.reset();
  }

  /**
   * The x509 Certificate.
   * An instance of @fidm/x509/Certificate.
   * @param {Certificate} certificate
   * @returns {bool}
   */
  verifyCertificate(certificate: any) {
    return Boolean(this.serverCertificateVerifyCallback(certificate));
  }

  /**
   * Create signature for `Certificate Verify` message.
   */
  createSignature() {
    const handshakeMessages = this.handshakeQueue.slice();
    const hash = getHashNameBySignAlgo(
      this.clientCertificateSignatureAlgorithm
    )!;

    const signature = crypto.createSign(hash).update(handshakeMessages);

    this.clientCertificateSignature = signature.sign(
      this.clientCertificatePrivateKey
    );
  }
}
