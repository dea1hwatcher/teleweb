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

update_description() { # running | stopped | error
  local prop=""
  if [ -d "/data/adb/modules/teleweb" ]; then
    prop="/data/adb/modules/teleweb/module.prop"
  elif [ -d "$MODDIR" ]; then
    prop="$MODDIR/module.prop"
  fi
  [ -f "$prop" ] && [ -w "$prop" ] || return 0

  local d=""
  case "$1" in
    running|active)
      d="status: active ✅ | WSS · DC1-DC5" ;;
    error|failed)
      d="status: failed ⚠️" ;;
    *)
      d="status: disabled ❌" ;;
  esac

  local desc_current
  desc_current=$(grep "^description=" "$prop" 2>/dev/null)
  if [ "$desc_current" = "description=$d" ]; then
    return 0
  fi

  local tmp="/data/adb/teleweb/module.prop.$$"
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
# No GOMEMLIMIT here on purpose. A hard heap ceiling drove the collector into a
# death spiral on media bursts (the ~220% CPU incident on Realme), and the Go
# runtime honours this variable even though the code no longer sets it - so
# exporting it here would silently re-enable the regression the code fix removed.
export GOGC=50

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

# 4. Supervisor loop to ensure daemon and rules stay active across network changes
while [ ! -f "$MODDIR/disable" ] && [ ! -f "$MODDIR/remove" ]; do
  sleep 60
  [ -f "$MODDIR/disable" ] && break
  [ -f "$MODDIR/remove" ] && break
  "$MODDIR/bin/tgws" ensure >>/data/adb/teleweb/supervisor.log 2>&1
done

update_description stopped
