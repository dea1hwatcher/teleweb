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

# Android 13+ BPF tether offload detachment
# Strips schedcls_tether_* from ingress queues so forwarded hotspot traffic
# is evaluated by iptables PREROUTING/FORWARD rather than bypassed by BPF.
bpf_tether_offload_detach() {
  local tc_bin=""
  for b in /system/bin/tc /system/xbin/tc /data/adb/ap/bin/tc /data/adb/ksu/bin/tc /data/adb/magisk/busybox; do
    if [ -x "$b" ]; then
      tc_bin="$b"
      break
    fi
  done
  [ -z "$tc_bin" ] && command -v tc >/dev/null 2>&1 && tc_bin="tc"

  settings put global tether_offload_disabled 1 2>/dev/null
  device_config put tethering override_bpf_offload false 2>/dev/null

  [ -n "$tc_bin" ] || return 0

  local ifaces
  ifaces="$(ls /sys/class/net 2>/dev/null)"
  for d in $ifaces; do
    local out
    out="$("$tc_bin" filter show dev "$d" ingress 2>/dev/null)"
    case "$out" in
      *schedcls_tether_*)
        for spec in $(printf '%s\n' "$out" | awk '/schedcls_tether_/ {
            p = ""; r = ""
            for (i = 1; i < NF; i++) { if ($i == "protocol") p = $(i+1); if ($i == "pref") r = $(i+1) }
            if (p != "" && r != "") print p ":" r }' 2>/dev/null | sort -u); do
          "$tc_bin" filter del dev "$d" ingress protocol "${spec%%:*}" pref "${spec#*:}" 2>/dev/null
        done
        ;;
    esac
  done
}

# System network tweaks for low-latency Telegram MTProto and hotspot routing
apply_network_tweaks() {
  # Allow REDIRECT to localhost from incoming tether interfaces
  sysctl -w net.ipv4.conf.all.route_localnet=1 2>/dev/null || true
  sysctl -w net.ipv4.conf.default.route_localnet=1 2>/dev/null || true
  # Disable TCP autocorking to prevent 20-40ms latency spikes for MTProto message packets
  sysctl -w net.ipv4.tcp_autocorking=0 2>/dev/null || true
}

# Targeted conntrack flush: flush flows only for Telegram destination CIDRs
targeted_conntrack_flush() {
  local ct=""
  for b in /system/bin/conntrack /data/adb/ap/bin/conntrack /data/adb/ksu/bin/conntrack /data/adb/magisk/conntrack; do
    if [ -x "$b" ]; then
      ct="$b"
      break
    fi
  done
  [ -z "$ct" ] && command -v conntrack >/dev/null 2>&1 && ct="conntrack"
  [ -n "$ct" ] || return 0

  for cidr in 149.154.160.0/20 91.108.4.0/22 91.108.8.0/22 91.108.12.0/22 91.108.16.0/22 \
              91.108.20.0/22 91.108.56.0/22 95.161.64.0/20 185.76.151.0/24 91.105.192.0/23 \
              172.121.110.0/24 142.252.58.0/24 194.221.250.50/32; do
    "$ct" -D -p tcp --orig-dst "$cidr" >/dev/null 2>&1 || true
  done
}

# Log size limiter to protect device flash storage from excessive wear
rotate_log_file() {
  local f="$1"
  [ -f "$f" ] || return 0
  local sz
  sz="$(wc -c < "$f" 2>/dev/null || echo 0)"
  # 512 KB = 524288 bytes
  if [ "$sz" -gt 524288 ]; then
    local tmp="$f.tmp.$$"
    tail -n 1000 "$f" > "$tmp" 2>/dev/null && mv -f "$tmp" "$f" 2>/dev/null
    rm -f "$tmp" 2>/dev/null
  fi
}

rotate_all_logs() {
  rotate_log_file "$SUPERVISOR_LOG"
  rotate_log_file "$DAEMON_LOG"
  rotate_log_file "$WATCHDOG_LOG"
  rotate_log_file "$TGWS_LOG"
}

# Cellular external IP renewal via transient RAT toggle (LTE/5G -> GSM/2G -> LTE/5G).
# Drops PDP context at the cell tower and acquires a new carrier IP without disabling Wi-Fi hotspot.
mobile_net_renew() {
  if [ ! -f "/system/bin/cmd" ] && ! command -v cmd >/dev/null 2>&1; then
    echo "[!] Ошибка: утилита 'cmd' не найдена (поддерживается только на Android)"
    return 1
  fi

  local rb="$TELEWEB_DIR/rat_back"
  local lock="$TELEWEB_DIR/rat.lock"
  mkdir -p "$TELEWEB_DIR" 2>/dev/null

  if ! mkdir "$lock" 2>/dev/null; then
    echo "[!] Операция обновления IP уже выполняется другим процессом."
    return 1
  fi
  unlock() { rmdir "$lock" 2>/dev/null; }
  trap unlock EXIT INT TERM

  # Determine active data sub-id / slot
  local sub=""
  sub="$(dumpsys connectivity 2>/dev/null | grep -E "SubscriptionIds: " | head -n 1 | sed -n 's/.*SubscriptionIds: {\([0-9][0-9]*\)}.*/\1/p')"
  [ -z "$sub" ] && sub="$(settings get global multi_sim_data_call 2>/dev/null)"
  local sims
  sims="$(content query --uri content://telephony/siminfo --projection _id:sim_id 2>/dev/null)"
  local slot=""
  if [ -n "$sub" ]; then
    slot="$(echo "$sims" | sed -n "s/.*[ ]_id=$sub, sim_id=\([0-9][0-9]*\).*/\1/p" | head -n 1)"
  fi
  if [ -z "$slot" ]; then
    slot="0"
  fi

  echo "Определение параметров мобильной сети (SIM slot $slot)..."
  local orig_types
  orig_types="$(cmd phone get-allowed-network-types-for-users -s "$slot" 2>/dev/null)"
  if [ -z "$orig_types" ]; then
    echo "[!] Не удалось получить текущий профиль сети для SIM $slot."
    unlock
    return 1
  fi

  echo "Текущий профиль сети: $orig_types"
  echo "$slot" > "$rb"
  echo "$orig_types" >> "$rb"

  rat_restore() {
    local count=0
    while [ "$count" -lt 6 ]; do
      cmd phone set-allowed-network-types-for-users -s "$slot" "$orig_types" >/dev/null 2>&1
      local cur
      cur="$(cmd phone get-allowed-network-types-for-users -s "$slot" 2>/dev/null)"
      if [ "$cur" = "$orig_types" ]; then
        rm -f "$rb"
        return 0
      fi
      count=$((count + 1))
      sleep 2
    done
    return 1
  }

  echo "Временное переключение на 2G/GSM для сброса сотовой сессии..."
  cmd phone set-allowed-network-types-for-users -s "$slot" 32768 >/dev/null 2>&1 || \
    cmd phone set-allowed-network-types-for-users -s "$slot" "GSM|GPRS|EDGE" >/dev/null 2>&1

  sleep 3

  echo "Восстановление исходного скоростного профиля сети (LTE/5G)..."
  if rat_restore; then
    echo "Профиль сети успешно восстановлен! Новый IP получен от базовой станции."
    targeted_conntrack_flush
    unlock
    return 0
  else
    echo "[!] Внимание: не удалось автоматически подтвердить возврат профиля сети."
    unlock
    return 1
  fi
}

# Android Private DNS (DoT) configuration management
get_private_dns_mode() {
  settings get global private_dns_mode 2>/dev/null || echo "off"
}

get_private_dns_specifier() {
  settings get global private_dns_specifier 2>/dev/null || echo ""
}

apply_private_dns() {
  local mode="$1"
  local specifier="$2"
  case "$mode" in
    off|opportunistic)
      settings put global private_dns_mode "$mode" 2>/dev/null
      ;;
    hostname)
      if [ -n "$specifier" ]; then
        settings put global private_dns_specifier "$specifier" 2>/dev/null
        settings put global private_dns_mode "hostname" 2>/dev/null
      fi
      ;;
    *)
      return 1
      ;;
  esac
}

# Idempotently drain duplicate iptables rules until none remain (up to 16 iterations)
drain_iptables_rule() {
  local count=0
  while [ "$count" -lt 16 ]; do
    "$@" >/dev/null 2>&1 || break
    count=$((count + 1))
  done
}

