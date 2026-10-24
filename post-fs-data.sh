#!/system/bin/sh
umask 077
mkdir -p /data/adb/tgopen
chmod 700 /data/adb/tgopen 2>/dev/null

# Clean up stale PID files left from previous device boot to prevent PID collisions
rm -f /data/adb/tgopen/tgws.pid /data/adb/tgopen/watchdog.pid
