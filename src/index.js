"use strict";

const { connect } = require("./dtls/lib/socket");
const { cipherSuites } = require("./dtls/lib/constants");

module.exports = {
  connect,
  constants: {
    cipherSuites: Object.assign({}, cipherSuites),
  },
};
