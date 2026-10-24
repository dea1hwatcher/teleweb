#!/system/bin/sh
MODDIR=${0%/*}
export TELEWEB_DIR=/data/adb/teleweb
export TELEWEB_MOD="$MODDIR"
export TGOPEN_DIR=/data/adb/teleweb
export TGOPEN_MOD="$MODDIR"
[ -x "$MODDIR/bin/tgws" ] && "$MODDIR/bin/tgws" stop >/dev/null 2>&1
rm -rf /data/adb/teleweb
rm -rf /data/adb/tgopen 2>/dev/null
