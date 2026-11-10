#!/system/bin/sh
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

if [ -f "$MODDIR/lib.sh" ]; then
  . "$MODDIR/lib.sh"
elif [ -f "/data/adb/modules/teleweb/lib.sh" ]; then
  . "/data/adb/modules/teleweb/lib.sh"
fi

umask 077
mkdir -p /data/adb/teleweb
chmod 700 /data/adb/teleweb 2>/dev/null

# Clean up stale PID files left from previous device boot to prevent PID collisions
rm -f /data/adb/teleweb/tgws.pid /data/adb/teleweb/watchdog.pid

# Early-stage root hiding & SELinux context hardening (SuSFS) before Zygote forks user apps
if command -v apply_susfs_hiding >/dev/null 2>&1; then
  apply_susfs_hiding "$MODDIR"
fi
