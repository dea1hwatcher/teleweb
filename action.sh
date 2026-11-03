#!/system/bin/sh
MODDIR=${0%/*}
export TELEWEB_DIR=/data/adb/teleweb
export TELEWEB_MOD="$MODDIR"

case "$1" in
  toggle|--toggle)
    if "$MODDIR/bin/tgws" status 2>/dev/null | grep -q '"running":true'; then
      echo "Stopping TeleWEB..."
      "$MODDIR/bin/tgws" stop
      echo "TeleWEB stopped ❌"
    else
      echo "Starting TeleWEB..."
      "$MODDIR/bin/tgws" boot
      echo "TeleWEB started ✅"
    fi
    exit 0
    ;;
  start|boot)
    "$MODDIR/bin/tgws" boot
    exit 0
    ;;
  stop)
    "$MODDIR/bin/tgws" stop
    exit 0
    ;;
esac

echo "TeleWEB $(grep -E '^version=' "$MODDIR/module.prop" 2>/dev/null | cut -d= -f2 || echo "module")"
echo "ABI: $(getprop ro.product.cpu.abi 2>/dev/null)"
echo
"$MODDIR/bin/tgws" status 2>&1
echo
echo "--- supervisor log ---"
tail -n 80 /data/adb/teleweb/supervisor.log 2>/dev/null || true
echo
echo "--- daemon log ---"
tail -n 80 /data/adb/teleweb/daemon.log 2>/dev/null || true
echo
echo "--- Watchdog log ---"
tail -n 120 /data/adb/teleweb/watchdog.log 2>/dev/null || true
echo
echo "--- WebSocket log ---"
tail -n 180 /data/adb/teleweb/tgws.log 2>/dev/null || true

echo
echo "--- Kernel/Android kill hints (logcat) ---"
logcat -b all -d -t 1500 2>/dev/null | grep -iE 'tgws|teleweb|lmkd|lowmemorykiller|killing.*process|killed process|out of memory|oom-kill' | tail -n 100 || true
