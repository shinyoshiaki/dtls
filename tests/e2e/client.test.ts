import { spawn } from "child_process";
import * as dtls from "../../src";
const args = [
  "s_server",
  "-cert",
  "./assets/cert.pem",
  "-key",
  "./assets/key.pem",
  "-dtls1_2",
  "-accept",
  "127.0.0.1:4445",
];

test("e2e/client", (done) => {
  const server = spawn("openssl", args);
  server.stdout.setEncoding("ascii");
  server.stdout.on("data", (data: string) => {
    if (data.includes("Hello from Node.js!")) {
      done();
    }
  });

  const socket = dtls.connect({
    type: "udp4",
    remotePort: 4445,
    remoteAddress: "127.0.0.1",
    maxHandshakeRetransmissions: 1,
  });

  socket.once("connect", () => {
    socket.write("Hello from Node.js!");
  });
});
