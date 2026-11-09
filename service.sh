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

. "$MODDIR/lib.sh"

if [ -f "$MODDIR/disable" ] || [ -f "$MODDIR/remove" ]; then
  update_description stopped
  exit 0
fi

umask 077
mkdir -p "$TELEWEB_DIR" 2>/dev/null
chmod 700 "$TELEWEB_DIR" 2>/dev/null
export TELEWEB_MOD="$MODDIR"
# No GOMEMLIMIT here on purpose. A hard heap ceiling drove the collector into a
# death spiral on media bursts (the ~220% CPU incident on Realme), and the Go
# runtime honours this variable even though the code no longer sets it - so
# exporting it here would silently re-enable the regression the code fix removed.
export GOGC=50

chmod 0755 "$MODDIR/bin/tgws" 2>/dev/null

# 1. Reset stale boot state if kernel rebooted
reset_stale_boot_state

# 2. Acquire atomic supervisor lock
if ! acquire_supervisor_lock; then
  log_msg "INFO" "Супервизор уже запущен или заблокирован другим процессом. Выход."
  exit 0
fi
trap 'release_supervisor_lock' EXIT INT TERM

# 3. Wait for Android boot completion and Package Manager availability
wait_for_boot

# Check again for disable/remove after boot wait
if [ -f "$MODDIR/disable" ] || [ -f "$MODDIR/remove" ]; then
  update_description stopped
  release_supervisor_lock
  exit 0
fi

# 4. Boot TeleWEB service (iptables redirection + daemon + watchdog)
apply_network_tweaks
bpf_tether_offload_detach
targeted_conntrack_flush
log_msg "INFO" "Первичный запуск службы TeleWEB (boot)..."
if "$MODDIR/bin/tgws" boot >>"$SUPERVISOR_LOG" 2>&1; then
  update_description running
  notify_user "TeleWEB" "Служба активна: WSS · DC1-DC5"
else
  update_description error
  notify_user "TeleWEB" "Ошибка запуска службы! Проверьте логи."
fi

# 5. Supervisor loop with battery-saving backoff upon recurring failures
FAILS=0
INTERVAL=60

while [ ! -f "$MODDIR/disable" ] && [ ! -f "$MODDIR/remove" ]; do
  sleep "$INTERVAL"
  [ -f "$MODDIR/disable" ] && break
  [ -f "$MODDIR/remove" ] && break

  if "$MODDIR/bin/tgws" ensure >>"$SUPERVISOR_LOG" 2>&1; then
    bpf_tether_offload_detach
    rotate_all_logs
    if [ "$FAILS" -gt 0 ]; then
      log_msg "INFO" "Служба TeleWEB восстановилась после сбоев. Возврат к стандартному интервалу проверок (60c)."
      notify_user "TeleWEB" "Служба успешно восстановилась после сбоев"
    fi
    FAILS=0
    INTERVAL=60
    update_description running
  else
    FAILS=$((FAILS + 1))
    log_msg "WARN" "Ошибка runtime ensure (сбой #$FAILS)"
    update_description error

    if [ "$FAILS" -ge 5 ]; then
      if [ "$INTERVAL" -ne 300 ]; then
        log_msg "ERROR" "Превышен лимит сбоев ($FAILS попыток подряд). Переход в замедленный режим (раз в 5 минут для экономии батареи)..."
        INTERVAL=300
        notify_user "TeleWEB" "Внимание: повторяющиеся сбои ($FAILS подряд)"
      fi
    else
      INTERVAL=60
    fi
  fi
done

update_description stopped
release_supervisor_lock
