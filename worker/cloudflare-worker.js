// TeleWEB Gateway for Cloudflare Workers (cloudflare:sockets).
//
// Deploy this to Cloudflare Workers to bypass DPI blocking of Telegram WebSockets.
// When deployed, set your worker domain (e.g. worker.user.workers.dev) in TeleWEB WebUI.
//
// Contract:
//   wss://<worker-domain>/apiws?dst=<telegram-ip>&dc=<dc-id>
//   Sec-WebSocket-Protocol: binary

import { connect } from "cloudflare:sockets";

const ALLOWED_DESTINATIONS = new Set([
  "91.105.192.100",  // DC203 CDN
  "149.154.167.51",  // DC2
  "149.154.167.91",  // DC4
  "149.154.167.220", // DC2
  "149.154.171.5",   // DC5
  "149.154.175.50",  // DC1
  "149.154.175.100", // DC3
]);

const TELEGRAM_PORT = 443;
const CONNECT_TIMEOUT_MS = 3000;
const MAX_PENDING_BYTES = 1024 * 1024;
const MAX_PENDING_MESSAGES = 256;

export default {
  async fetch(request, env = {}) {
    const url = new URL(request.url);

    if (url.pathname !== "/apiws") {
      return new Response("not found", { status: 404 });
    }
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response("expected a websocket upgrade", { status: 426 });
    }
    const token = env.TELEWEB_TOKEN || env.TGOPEN_TOKEN;
    if (token && url.searchParams.get("token") !== token) {
      return new Response("forbidden", { status: 403 });
    }

    const destination = url.searchParams.get("dst");
    if (!destination || !ALLOWED_DESTINATIONS.has(destination)) {
      return new Response("destination not allowed", { status: 403 });
    }

    if (!request.headers.get("Sec-WebSocket-Protocol")?.split(",").some((p) => p.trim() === "binary")) {
      return new Response("binary websocket subprotocol required", { status: 400 });
    }

    let upstream;
    let timer;
    let timedOut = false;
    try {
      upstream = connect({ hostname: destination, port: TELEGRAM_PORT });
      upstream.closed.catch(() => {});
      await Promise.race([
        upstream.opened,
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            timedOut = true;
            reject(new Error("connect timeout"));
          }, CONNECT_TIMEOUT_MS);
        }),
      ]);
    } catch {
      if (upstream) await upstream.close().catch(() => {});
      return new Response(timedOut ? "Telegram TCP connect timeout" : "Telegram TCP connect failed", {
        status: timedOut ? 504 : 502,
      });
    } finally {
      clearTimeout(timer);
    }

    const [client, server] = Object.values(new WebSocketPair());
    server.binaryType = "arraybuffer";
    server.accept();

    const writer = upstream.writable.getWriter();
    let closed = false;

    const shutdown = (code = 1000, reason = "") => {
      if (closed) return;
      closed = true;
      upstream.close().catch(() => {});
      try {
        server.close(code, reason);
      } catch {}
    };

    let pending = Promise.resolve();
    let pendingBytes = 0;
    let pendingMessages = 0;

    server.addEventListener("message", (event) => {
      if (closed) return;
      const data = event.data;
      const blob = typeof Blob !== "undefined" && data instanceof Blob;
      if (!blob && !(data instanceof ArrayBuffer) && !ArrayBuffer.isView(data)) {
        shutdown(1003, "binary messages required");
        return;
      }
      const chunk = blob ? null : data instanceof ArrayBuffer
        ? new Uint8Array(data)
        : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
      const size = blob ? data.size : chunk.byteLength;
      if (pendingBytes + size > MAX_PENDING_BYTES || pendingMessages >= MAX_PENDING_MESSAGES) {
        shutdown(1009, "Telegram write queue full");
        return;
      }
      pendingBytes += size;
      pendingMessages += 1;
      pending = pending
        .then(async () => {
          if (closed) return;
          const bytes = chunk || new Uint8Array(await data.arrayBuffer());
          await writer.ready;
          if (!closed) await writer.write(bytes);
        })
        .catch(() => shutdown(1011, "Telegram write failed"))
        .finally(() => {
          pendingBytes -= size;
          pendingMessages -= 1;
        });
    });
    server.addEventListener("close", () => shutdown());
    server.addEventListener("error", () => shutdown(1011, "WebSocket failed"));
    upstream.closed.catch(() => shutdown(1011, "Telegram socket failed"));

    (async () => {
      const reader = upstream.readable.getReader();
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          server.send(value);
        }
      } catch {
        shutdown(1011, "Telegram read failed");
      } finally {
        reader.releaseLock();
      }
      shutdown();
    })();

    return new Response(null, {
      status: 101,
      webSocket: client,
      headers: { "Sec-WebSocket-Protocol": "binary" },
    });
  },
};
