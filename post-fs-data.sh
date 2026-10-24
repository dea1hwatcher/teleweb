#!/system/bin/sh
umask 077
mkdir -p /data/adb/teleweb
chmod 700 /data/adb/teleweb 2>/dev/null

# Clean up stale PID files left from previous device boot to prevent PID collisions
rm -f /data/adb/teleweb/tgws.pid /data/adb/teleweb/watchdog.pid
