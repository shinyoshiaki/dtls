"use strict";

import * as dtls from "./src";

setTimeout(() => {
  const socket = dtls.connect({
    type: "udp4",
    remotePort: 4445,
    remoteAddress: "127.0.0.1",
    maxHandshakeRetransmissions: 1,
    extendedMasterSecret: false,
  });

  socket.on("error", (err) => {
    console.error("client:", err);
  });

  socket.on("data", (data) => {
    console.log('client: got message "%s"', data.toString("ascii"));
    socket.close();
  });

  socket.once("connect", () => {
    socket.write("Hello from Node.js!");
  });

  socket.once("timeout", () => {
    console.log("client: got timeout");
  });
}, 100);
