#!/bin/sh
# TeleWEB Linux installer. Run as root from the extracted package directory:
#   sudo ./install.sh
set -e

PREFIX=/usr/local/bin
SHARE=/usr/local/share/teleweb
STATE=/var/lib/teleweb
UNIT=/etc/systemd/system/teleweb.service
SRC_DIR=$(cd "$(dirname "$0")" && pwd)

[ "$(id -u)" = "0" ] || { echo "error: run as root (sudo ./install.sh)" >&2; exit 1; }
[ -f "$SRC_DIR/tgws" ] || { echo "error: tgws binary not found next to install.sh" >&2; exit 1; }
command -v iptables >/dev/null 2>&1 || echo "warning: iptables not found; install iptables (or nftables with iptables-nft) first" >&2

install -Dm755 "$SRC_DIR/tgws" "$PREFIX/tgws"
mkdir -p "$SHARE" "$STATE"
if [ -d "$SRC_DIR/webroot" ]; then
  rm -rf "$SHARE/webroot"
  cp -r "$SRC_DIR/webroot" "$SHARE/webroot"
fi
chmod 700 "$STATE"

cat > "$UNIT" <<'EOF'
[Unit]
Description=TeleWEB transparent WSS transport for Telegram (DC1-DC5)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=TELEWEB_DIR=/var/lib/teleweb
Environment=TELEWEB_WEBROOT=/usr/local/share/teleweb/webroot
ExecStart=/usr/local/bin/tgws run
ExecStopPost=/usr/local/bin/tgws stop
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable teleweb.service
systemctl restart teleweb.service

echo "TeleWEB installed and started."
echo "  status:  tgws status"
echo "  logs:    journalctl -u teleweb -f   (or /var/lib/teleweb/tgws.log)"
echo "  webui:   tgws webui 127.0.0.1:17842  then open http://127.0.0.1:17842"
echo "  socks:   tgws socks 127.0.0.1:17845  (no-root alternative, set proxy in Telegram)"
