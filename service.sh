#!/system/bin/sh
MODDIR=${0%/*}
[ -e "$MODDIR/disable" ] && exit 0
[ -e "$MODDIR/remove" ] && exit 0
umask 077
mkdir -p /data/adb/tgopen
chmod 700 /data/adb/tgopen 2>/dev/null
export TGOPEN_DIR=/data/adb/tgopen
export TGOPEN_MOD="$MODDIR"
# First attempt at boot, then keep checking idempotently. This also handles
# Android boot races where package manager or iptables is not ready yet.
"$MODDIR/bin/tgws" ensure >>/data/adb/tgopen/supervisor.log 2>&1
while [ ! -e "$MODDIR/disable" ] && [ ! -e "$MODDIR/remove" ]; do
  sleep 60
  [ -e "$MODDIR/disable" ] && break
  [ -e "$MODDIR/remove" ] && break
  "$MODDIR/bin/tgws" ensure >>/data/adb/tgopen/supervisor.log 2>&1
 done
