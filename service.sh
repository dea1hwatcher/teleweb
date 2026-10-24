#!/system/bin/sh
# TeleWEB - Transparent WSS proxy for Telegram
# Late-start service launcher and watchdog supervisor

MODDIR=${0%/*}
case "$MODDIR" in
  ""|"$0"|".")
    if [ -d "/data/adb/modules/teleweb" ]; then
      MODDIR="/data/adb/modules/teleweb"
    elif [ -d "/data/adb/modules_update/teleweb" ]; then
      MODDIR="/data/adb/modules_update/teleweb"
    else
      MODDIR="$(dirname "$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")")"
    fi
    ;;
esac

[ -f "$MODDIR/disable" ] && exit 0
[ -f "$MODDIR/remove" ] && exit 0

umask 077
mkdir -p /data/adb/teleweb
chmod 700 /data/adb/teleweb 2>/dev/null
export TELEWEB_DIR=/data/adb/teleweb
export TELEWEB_MOD="$MODDIR"

chmod 0755 "$MODDIR/bin/tgws" 2>/dev/null

# 1. Wait for Android boot completion before setting up redirection rules.
# This prevents race conditions with Package Manager Service (PMS) and netd/iptables.
count=0
while [ "$(getprop sys.boot_completed 2>/dev/null)" != "1" ] && [ $count -lt 45 ]; do
  sleep 2
  count=$((count + 1))
done

# 2. Wait until Package Manager is responsive (up to 30s)
count=0
while ! pm path android >/dev/null 2>&1 && [ $count -lt 15 ]; do
  sleep 2
  count=$((count + 1))
done

# 3. Boot TeleWEB service (iptables redirection + daemon + watchdog)
"$MODDIR/bin/tgws" boot >>/data/adb/teleweb/supervisor.log 2>&1

# 4. Supervisor loop to ensure daemon and rules stay active across network changes
while [ ! -f "$MODDIR/disable" ] && [ ! -f "$MODDIR/remove" ]; do
  sleep 60
  [ -f "$MODDIR/disable" ] && break
  [ -f "$MODDIR/remove" ] && break
  "$MODDIR/bin/tgws" ensure >>/data/adb/teleweb/supervisor.log 2>&1
done
