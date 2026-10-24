#!/system/bin/sh
MODDIR=${0%/*}
export TELEWEB_DIR=/data/adb/teleweb
export TELEWEB_MOD="$MODDIR"
[ -x "$MODDIR/bin/tgws" ] && "$MODDIR/bin/tgws" stop >/dev/null 2>&1
rm -rf /data/adb/teleweb
