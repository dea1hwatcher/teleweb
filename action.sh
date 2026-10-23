#!/system/bin/sh
MODDIR=${0%/*}
export TGOPEN_DIR=/data/adb/tgopen
export TGOPEN_MOD="$MODDIR"
echo "TG Open $(grep -E '^version=' "$MODDIR/module.prop" 2>/dev/null | cut -d= -f2 || echo "v2.1.47")"
echo "ABI: $(getprop ro.product.cpu.abi 2>/dev/null)"
echo
"$MODDIR/bin/tgws" status 2>&1
echo
echo "--- supervisor log ---"
tail -n 80 /data/adb/tgopen/supervisor.log 2>/dev/null || true
echo
echo "--- daemon log ---"
tail -n 80 /data/adb/tgopen/daemon.log 2>/dev/null || true
echo
echo "--- Watchdog log ---"
tail -n 120 /data/adb/tgopen/watchdog.log 2>/dev/null || true
echo
echo "--- WebSocket log ---"
tail -n 180 /data/adb/tgopen/tgws.log 2>/dev/null || true

echo
echo "--- Kernel/Android kill hints (logcat) ---"
logcat -b all -d -t 1500 2>/dev/null | grep -iE 'tgws|tgopen|lmkd|lowmemorykiller|killing.*process|killed process|out of memory|oom-kill' | tail -n 100 || true
