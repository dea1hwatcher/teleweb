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

DESC_BASE="TeleWEB: прозрачный WSS-транспорт для Telegram (DC1-DC5)"
update_description() { # running | stopped | error
  local prop="$MODDIR/module.prop" d tmp
  if [ ! -f "$prop" ] || [ ! -w "$prop" ]; then return 0; fi
  case "$1" in
    running)
      d="✅ Работает · WSS" ;;
    error)
      d="⚠️ Сбой службы" ;;
    *)
      d="⛔ Остановлено" ;;
  esac
  d=$(printf '%s' "$d | $DESC_BASE" | tr -d '\n\r')
  tmp="/data/adb/teleweb/module.prop.$$"
  # Atomic rename instead of in-place truncate: the Go supervisor updates the
  # same file concurrently, and a mid-write cat could clobber its content.
  if awk -v d="$d" 'BEGIN { done = 0 } /^description=/ { print "description=" d; done = 1; next } { print }
    END { if (!done) print "description=" d }' "$prop" > "$tmp" 2>/dev/null; then
    chmod 0644 "$tmp" 2>/dev/null
    mv -f "$tmp" "$prop" 2>/dev/null
  fi
  rm -f "$tmp" 2>/dev/null
  return 0
}

if [ -f "$MODDIR/disable" ] || [ -f "$MODDIR/remove" ]; then
  update_description stopped
  exit 0
fi

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
if "$MODDIR/bin/tgws" boot >>/data/adb/teleweb/supervisor.log 2>&1; then
  update_description running
else
  update_description error
fi

# 3.1 Protect Telegram voice and video calls (UDP STUN 3478, TURN 596-599) from DPI interception (Zapret / nfqws)
# Locally generated traffic traverses OUTPUT only; PREROUTING covers forwarded traffic (hotspot).
iptables -t mangle -C OUTPUT -p udp -m multiport --dports 3478,596:599 -m comment --comment "teleweb-calls" -j RETURN 2>/dev/null || \
iptables -t mangle -I OUTPUT 1 -p udp -m multiport --dports 3478,596:599 -m comment --comment "teleweb-calls" -j RETURN 2>/dev/null
ip6tables -t mangle -C OUTPUT -p udp -m multiport --dports 3478,596:599 -m comment --comment "teleweb-calls" -j RETURN 2>/dev/null || \
ip6tables -t mangle -I OUTPUT 1 -p udp -m multiport --dports 3478,596:599 -m comment --comment "teleweb-calls" -j RETURN 2>/dev/null
iptables -t mangle -C PREROUTING -p udp -m multiport --dports 3478,596:599 -m comment --comment "teleweb-calls" -j RETURN 2>/dev/null || \
iptables -t mangle -I PREROUTING 1 -p udp -m multiport --dports 3478,596:599 -m comment --comment "teleweb-calls" -j RETURN 2>/dev/null
ip6tables -t mangle -C PREROUTING -p udp -m multiport --dports 3478,596:599 -m comment --comment "teleweb-calls" -j RETURN 2>/dev/null || \
ip6tables -t mangle -I PREROUTING 1 -p udp -m multiport --dports 3478,596:599 -m comment --comment "teleweb-calls" -j RETURN 2>/dev/null

# 4. Supervisor loop to ensure daemon and rules stay active across network changes
while [ ! -f "$MODDIR/disable" ] && [ ! -f "$MODDIR/remove" ]; do
  sleep 60
  [ -f "$MODDIR/disable" ] && break
  [ -f "$MODDIR/remove" ] && break
  "$MODDIR/bin/tgws" ensure >>/data/adb/teleweb/supervisor.log 2>&1
done

update_description stopped
