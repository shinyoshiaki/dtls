"use strict";

const debug = require("debug");

debug.formatters.h = (v) => v.toString("hex");

module.exports = debug;
