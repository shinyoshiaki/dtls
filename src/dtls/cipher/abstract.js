export default class AbstractCipher {
  /**
   * @class AbstractCipher
   */
  constructor() {
    this.id = 0;
    this.name = null;
    this.hash = null;
    this.verifyDataLength = 12;

    this.blockAlgorithm = null;
    this.kx = null;
  }

  /**
   * Init cipher.
   * @abstract
   */
  init() {}

  /**
   * Encrypts data.
   * @abstract
   */
  encrypt() {
    throw new Error("not implemented");
  }

  /**
   * Decrypts data.
   * @abstract
   */
  decrypt() {
    throw new Error("not implemented");
  }

  /**
   * @returns {string}
   */
  toString() {
    return this.name;
  }
}
