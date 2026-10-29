# Linux end-to-end harness for TeleWEB: Go build + unit tests + privileged
# iptables E2E inside one image.
#
# Build (from repo root):  docker build -t teleweb-e2e -f desktop/linux/docker-e2e/Dockerfile .
# Run:                     docker run --rm --privileged teleweb-e2e
# Or use desktop/linux/docker-e2e/run.sh which mounts the log directory.
FROM golang:1.24-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends iptables iproute2 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY src/ /src/
RUN go mod download \
 && go vet ./... \
 && go test ./... \
 && CGO_ENABLED=0 go build -trimpath -o /out/tgws . \
 && CGO_ENABLED=0 go build -trimpath -o /out/e2eclient ./e2eclient

COPY webroot /out/webroot
COPY desktop/linux/docker-e2e/e2e.sh /usr/local/bin/e2e.sh
RUN chmod +x /usr/local/bin/e2e.sh && mkdir -p /out/logs

# The desktop iptables rules redirect every local TCP flow to Telegram except
# root (the daemon itself is excluded), so the test client must be non-root.
RUN useradd -m -u 1000 tester

ENTRYPOINT ["/usr/local/bin/e2e.sh"]
