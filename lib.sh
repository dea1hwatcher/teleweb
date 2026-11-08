#!/system/bin/sh
# TeleWEB - Transparent WSS proxy for Telegram
# Shared shell library for Magisk / KernelSU / APatch

MOD_ID="teleweb"
TELEWEB_DIR="/data/adb/teleweb"
export TELEWEB_DIR
export PATH=/system/bin:/system/xbin:/data/adb/ap/bin:/data/adb/ksu/bin:/data/adb/magisk:$PATH
export GOGC=50

LOCK_DIR="$TELEWEB_DIR/supervisor.lock"
SUP_PID_FILE="$TELEWEB_DIR/supervisor.pid"
BOOT_ID_FILE="$TELEWEB_DIR/boot.id"
SUPERVISOR_LOG="$TELEWEB_DIR/supervisor.log"
DAEMON_LOG="$TELEWEB_DIR/daemon.log"
TGWS_LOG="$TELEWEB_DIR/tgws.log"
WATCHDOG_LOG="$TELEWEB_DIR/watchdog.log"

# Resolve absolute path to module directory
resolve_moddir() {
  local src="$1"
  local d="${src%/*}"
  case "$d" in
    ""|"$src"|".")
      if [ -d "/data/adb/modules/teleweb" ]; then
        echo "/data/adb/modules/teleweb"
      elif [ -d "/data/adb/modules_update/teleweb" ]; then
        echo "/data/adb/modules_update/teleweb"
      else
        echo "$(cd "$d" 2>/dev/null && pwd || echo "/data/adb/modules/teleweb")"
      fi
      ;;
    /*) echo "$d" ;;
    *)  echo "$(cd "$d" 2>/dev/null && pwd || echo "/data/adb/modules/teleweb")" ;;
  esac
}

# Timestamped logging to supervisor log
log_msg() {
  local lvl="$1"
  shift
  mkdir -p "$TELEWEB_DIR" 2>/dev/null
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$lvl] $*" >> "$SUPERVISOR_LOG"
}

# Verify if a given PID matches the expected executable/script
proc_matches() {
  local p="$1"
  local pat="$2"
  [ -n "$p" ] && [ -d "/proc/$p" ] || return 1
  grep -a -q "$pat" "/proc/$p/cmdline" 2>/dev/null
}

# Return verified PID of running supervisor
supervisor_pid() {
  if [ -f "$SUP_PID_FILE" ]; then
    local p
    p="$(cat "$SUP_PID_FILE" 2>/dev/null | tr -d '\r\n ')"
    if proc_matches "$p" "service.sh"; then
      echo "$p"
      return 0
    fi
    rm -f "$SUP_PID_FILE"
  fi
  return 1
}

# Atomic supervisor lock acquisition (prevents multiple parallel supervisors)
acquire_supervisor_lock() {
  local i=0
  while [ "$i" -lt 10 ]; do
    if mkdir "$LOCK_DIR" 2>/dev/null; then
      echo $$ > "$LOCK_DIR/pid"
      echo $$ > "$SUP_PID_FILE"
      return 0
    fi
    local lp
    lp="$(cat "$LOCK_DIR/pid" 2>/dev/null | tr -d '\r\n ')"
    if [ -n "$lp" ] && ! proc_matches "$lp" "service.sh"; then
      log_msg "WARN" "Удаление устаревшей блокировки супервизора (PID $lp не активен)"
      rm -rf "$LOCK_DIR"
    else
      return 1
    fi
    i=$((i + 1))
    sleep 1
  done
  return 1
}

# Release supervisor lock
release_supervisor_lock() {
  rm -rf "$LOCK_DIR"
  rm -f "$SUP_PID_FILE"
}

# Detect kernel reboot via boot_id and purge stale PIDs and locks
reset_stale_boot_state() {
  local cur_boot=""
  if [ -f "/proc/sys/kernel/random/boot_id" ]; then
    cur_boot="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d '\r\n ')"
  fi
  local old_boot=""
  [ -f "$BOOT_ID_FILE" ] && old_boot="$(cat "$BOOT_ID_FILE" 2>/dev/null | tr -d '\r\n ')"

  if [ -n "$cur_boot" ] && [ "$cur_boot" != "$old_boot" ]; then
    log_msg "INFO" "Обнаружен новый boot_id ($cur_boot != $old_boot). Сброс устаревших PID и блокировок..."
    rm -rf "$LOCK_DIR"
    rm -f "$SUP_PID_FILE" "$TELEWEB_DIR/tgws.pid" "$TELEWEB_DIR/watchdog.pid"
    mkdir -p "$TELEWEB_DIR" 2>/dev/null
    echo "$cur_boot" > "$BOOT_ID_FILE"
    chmod 0600 "$BOOT_ID_FILE" 2>/dev/null
  fi
}

# Atomically update description in module.prop
update_description() { # running | active | error | failed | stopped | disabled
  local prop=""
  if [ -d "/data/adb/modules/teleweb" ]; then
    prop="/data/adb/modules/teleweb/module.prop"
  elif [ -n "$MODDIR" ] && [ -d "$MODDIR" ]; then
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

  local tmp="$TELEWEB_DIR/module.prop.$$"
  if awk -v d="$d" 'BEGIN { done = 0 } /^description=/ { print "description=" d; done = 1; next } { print }
    END { if (!done) print "description=" d }' "$prop" > "$tmp" 2>/dev/null; then
    chmod 0644 "$tmp" 2>/dev/null
    mv -f "$tmp" "$prop" 2>/dev/null
  fi
  rm -f "$tmp" 2>/dev/null
  return 0
}

# Wait for system boot completion and Package Manager availability
wait_for_boot() {
  local count=0
  while [ "$(getprop sys.boot_completed 2>/dev/null)" != "1" ] && [ "$count" -lt 45 ]; do
    sleep 2
    count=$((count + 1))
  done

  count=0
  while ! pm path android >/dev/null 2>&1 && [ "$count" -lt 15 ]; do
    sleep 2
    count=$((count + 1))
  done
}

# Attempt to launch WebUI via standalone managers
launch_webui() {
  if pm path io.github.a13e300.ksuwebui >/dev/null 2>&1; then
    am start -n "io.github.a13e300.ksuwebui/.WebUIActivity" -e id "teleweb" >/dev/null 2>&1
    return 0
  elif pm path com.dergoogler.mmrl.wx >/dev/null 2>&1; then
    am start -n "com.dergoogler.mmrl.wx/.ui.activity.webui.WebUIActivity" -e MOD_ID "teleweb" >/dev/null 2>&1
    return 0
  fi
  return 1
}

# Quick on-demand network latency (RTT) measurement
check_latency() {
  local targets="1.1.1.1 cloudflare.com dns.google"
  if [ -f "$TELEWEB_DIR/config.json" ]; then
    local w
    w=$(grep -o '"custom_worker_url"[[:space:]]*:[[:space:]]*"[^"]*"' "$TELEWEB_DIR/config.json" 2>/dev/null | cut -d'"' -f4)
    if [ -n "$w" ]; then
      w=$(echo "$w" | sed -e 's|^https\?://||' -e 's|/.*||')
      [ -n "$w" ] && targets="$w $targets"
    fi
  fi

  for host in $targets; do
    [ -z "$host" ] && continue
    local ping_out rtt
    ping_out="$(ping -c 1 -W 2 "$host" 2>/dev/null | tail -n 1)"
    case "$ping_out" in
      *rtt*|*round-trip*|*min/avg/max*)
        rtt="$(echo "$ping_out" | awk -F'/' '{print $5}' | cut -d'.' -f1)"
        if [ -n "$rtt" ]; then
          printf '%-24s %s ms\n' "$host" "$rtt"
        else
          printf '%-24s online\n' "$host"
        fi
        ;;
      *)
        printf '%-24s timeout ❌\n' "$host"
        ;;
    esac
  done
}
