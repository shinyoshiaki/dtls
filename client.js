"use strict";

const dtls = require("./src");

const { spawn } = require("child_process");

// const args = [
//   "s_server",
//   "-cert",
//   "./assets/cert.pem",
//   "-key",
//   "./assets/key.pem",
//   "-dtls1_2",
//   "-accept",
//   "127.0.0.1:56859",
//   "-debug",
//   "-msg",
// ];

// const server = spawn("openssl", args);
// server.stdout.setEncoding("ascii");
// server.stdout.on("data", (data) => {
//   if (data.includes("### node->openssl")) {
//     server.stdin.write("### openssl->node\n");
//   }
// });

setTimeout(() => {
  const socket = dtls.connect({
    type: "udp4",
    remotePort: 4445,
    remoteAddress: "127.0.0.1",
    maxHandshakeRetransmissions: 1,
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
