#!/system/bin/sh
MODDIR=${0%/*}
export TGOPEN_DIR=/data/adb/tgopen
export TGOPEN_MOD="$MODDIR"
[ -x "$MODDIR/bin/tgws" ] && "$MODDIR/bin/tgws" stop >/dev/null 2>&1
rm -rf /data/adb/tgopen
