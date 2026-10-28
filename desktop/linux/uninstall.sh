#!/bin/sh
# TeleWEB Linux uninstaller. Run as root.
set -e
[ "$(id -u)" = "0" ] || { echo "error: run as root" >&2; exit 1; }

systemctl disable --now teleweb.service 2>/dev/null || true
rm -f /etc/systemd/system/teleweb.service
systemctl daemon-reload
rm -f /usr/local/bin/tgws
rm -rf /usr/local/share/teleweb
echo "TeleWEB removed. State kept in /var/lib/teleweb (delete manually if not needed)."
