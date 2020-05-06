"use strict";

const { connect } = require("./src/lib/socket");
const { cipherSuites } = require("./src/lib/constants");

module.exports = {
  connect,
  constants: {
    cipherSuites: Object.assign({}, cipherSuites),
  },
};
