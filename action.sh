#!/system/bin/sh
# TeleWEB - Transparent WSS proxy for Telegram
# Interactive Action script for KernelSU / Magisk / APatch Manager

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
export TELEWEB_MOD="$MODDIR"

CMD="$1"

# When clicked without arguments in root manager:
# Try to launch WebUI in KsuWebUI or MMRL first.
if [ -z "$CMD" ]; then
  if launch_webui; then
    echo "Запуск TeleWEB WebUI..."
    exit 0
  fi
  CMD="status"
fi

case "$CMD" in
  webui|open|ui)
    if launch_webui; then
      echo "TeleWEB WebUI открыт!"
    else
      echo "[!] Standalone WebUI (KsuWebUI / MMRL) не найден."
      echo "    Откройте WebUI во встроенной вкладке менеджера."
    fi
    exit 0
    ;;
  toggle|--toggle)
    if "$MODDIR/bin/tgws" status 2>/dev/null | grep -q '"running":true'; then
      echo "Остановка TeleWEB..."
      "$MODDIR/bin/tgws" stop
      echo "TeleWEB остановлен ❌"
    else
      echo "Запуск TeleWEB..."
      "$MODDIR/bin/tgws" boot
      echo "TeleWEB запущен ✅"
    fi
    exit 0
    ;;
  start|boot)
    "$MODDIR/bin/tgws" boot
    exit 0
    ;;
  stop)
    "$MODDIR/bin/tgws" stop
    exit 0
    ;;
  restart)
    echo "Перезапуск службы TeleWEB..."
    "$MODDIR/bin/tgws" stop >/dev/null 2>&1
    sleep 1
    "$MODDIR/bin/tgws" boot
    exit 0
    ;;
  status_json)
    "$MODDIR/bin/tgws" status 2>/dev/null
    exit 0
    ;;
  ping|rtt|latency)
    echo "=== Проверка задержки (RTT) до узлов сети ==="
    check_latency
    exit 0
    ;;
  net-renew|renew-ip|rat-renew)
    echo "=== Перезапрос IP мобильного оператора (RAT Switch) ==="
    mobile_net_renew
    exit 0
    ;;
  dns)
    case "$2" in
      get|status|"")
        echo "Private DNS mode: $(get_private_dns_mode)"
        echo "Private DNS host: $(get_private_dns_specifier)"
        ;;
      set)
        if apply_private_dns "$3" "$4"; then
          echo "Private DNS обновлен: mode=$3 host=$4"
        else
          echo "Использование: action.sh dns set <off|opportunistic|hostname> [specifier]"
        fi
        ;;
    esac
    exit 0
    ;;
  logs|log|dump)
    echo "=========================================="
    echo "        TeleWEB - Системные журналы       "
    echo "=========================================="
    echo "--- Supervisor log ---"
    tail -n 80 "$SUPERVISOR_LOG" 2>/dev/null || true
    echo
    echo "--- Daemon log ---"
    tail -n 80 "$DAEMON_LOG" 2>/dev/null || true
    echo
    echo "--- Watchdog log ---"
    tail -n 120 "$WATCHDOG_LOG" 2>/dev/null || true
    echo
    echo "--- WebSocket log ---"
    tail -n 180 "$TGWS_LOG" 2>/dev/null || true
    echo
    echo "--- Kernel/Android kill hints (logcat) ---"
    logcat -b all -d -t 1500 2>/dev/null | grep -iE 'tgws|teleweb|lmkd|lowmemorykiller|killing.*process|killed process|out of memory|oom-kill' | tail -n 100 || true
    exit 0
    ;;
  stealth|hide)
    if is_stealth_enabled; then
      rm -f "$TELEWEB_DIR/stealth"
      touch "$TELEWEB_DIR/no_stealth"
      echo "Режим скрытия (Stealth) принудительно отключён ❌"
    else
      rm -f "$TELEWEB_DIR/no_stealth"
      touch "$TELEWEB_DIR/stealth"
      reset_description_to_default
      apply_susfs_hiding "$MODDIR"
      echo "Режим скрытия (Stealth / SuSFS) активирован 🛡️"
    fi
    exit 0
    ;;
  status|*)
    ;;
esac

echo "=========================================="
echo "          TeleWEB Transparent WSS         "
echo "=========================================="
VER=$(grep -E '^version=' "$MODDIR/module.prop" 2>/dev/null | cut -d= -f2 || echo "модуль")
echo " Версия модуля:    $VER"
echo " Архитектура ABI:  $(getprop ro.product.cpu.abi 2>/dev/null)"

STATUS_JSON=$("$MODDIR/bin/tgws" status 2>/dev/null)
RUNNING=0
if echo "$STATUS_JSON" | grep -q '"running":true'; then
  RUNNING=1
fi

SPID=$(supervisor_pid)

if [ "$RUNNING" = "1" ]; then
  echo " Статус службы:    [ АКТИВНА ✅ ]"
  echo " Супервизор PID:   ${SPID:-нет}"
  echo " Режим перехвата:  Прозрачный (iptables)"
  echo " Дата-центры:      DC1 - DC5 (WSS)"
  if is_stealth_enabled; then
    echo " Скрытие (Stealth): [ ВКЛЮЧЕНО 🛡️ (SuSFS) ]"
  else
    echo " Скрытие (Stealth): [ ВЫКЛЮЧЕНО ]"
  fi
  echo "------------------------------------------"
  echo " Трафик Telegram перехватывается автоматически."
  echo " Дополнительных настроек в приложении не требуется."
else
  echo " Статус службы:    [ ОСТАНОВЛЕНА ❌ ]"
  echo " Супервизор PID:   ${SPID:-нет}"
  if is_stealth_enabled; then
    echo " Скрытие (Stealth): [ ВКЛЮЧЕНО 🛡️ (SuSFS) ]"
  else
    echo " Скрытие (Stealth): [ ВЫКЛЮЧЕНО ]"
  fi
  echo "------------------------------------------"
  echo " Запуск службы: su -c sh $MODDIR/action.sh start"
fi
echo "=========================================="
echo " Команды:"
echo "  sh $MODDIR/action.sh toggle   - Вкл / Выкл службу"
echo "  sh $MODDIR/action.sh restart  - Перезапустить службу"
echo "  sh $MODDIR/action.sh ping     - Проверить пинг до Cloudflare/DoH"
echo "  sh $MODDIR/action.sh logs     - Показать подробные системные логи"
echo "  sh $MODDIR/action.sh webui    - Открыть интерфейс WebUI"
echo "  sh $MODDIR/action.sh stealth  - Переключить режим скрытия (Stealth / SuSFS)"
echo "=========================================="
