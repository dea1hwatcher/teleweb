#!/system/bin/sh
MODDIR=${0%/*}
export TELEWEB_DIR=/data/adb/teleweb
export TELEWEB_MOD="$MODDIR"
export TGOPEN_DIR=/data/adb/teleweb
export TGOPEN_MOD="$MODDIR"
echo "TeleWEB $(grep -E '^version=' "$MODDIR/module.prop" 2>/dev/null | cut -d= -f2 || echo "v2.1.48")"
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
logcat -b all -d -t 1500 2>/dev/null | grep -iE 'tgws|teleweb|tgopen|lmkd|lowmemorykiller|killing.*process|killed process|out of memory|oom-kill' | tail -n 100 || true
