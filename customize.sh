#!/system/bin/sh
type ui_print >/dev/null 2>&1 || ui_print() { printf '%s\n' "$1"; }
type abort >/dev/null 2>&1 || abort() { ui_print "$1"; exit 1; }

umask 077

# Определение архитектуры устройства (ARM64, ARM, x86, x86_64)
ABI=""
case "$ARCH" in
  arm64) ABI="arm64" ;;
  arm) ABI="arm" ;;
  x86) ABI="x86" ;;
  x64) ABI="x86_64" ;;
  *)
    raw_abi=$(getprop ro.product.cpu.abi 2>/dev/null)
    case "$raw_abi" in
      arm64*|aarch64*) ABI="arm64" ;;
      armeabi*|armv7*) ABI="arm" ;;
      x86_64*|amd64*) ABI="x86_64" ;;
      x86*|i*86*) ABI="x86" ;;
      *)
        uname_m=$(uname -m 2>/dev/null)
        case "$uname_m" in
          aarch64*) ABI="arm64" ;;
          armv*|arm*) ABI="arm" ;;
          x86_64*) ABI="x86_64" ;;
          i*86*) ABI="x86" ;;
          *) abort "! Неподдерживаемая архитектура устройства: ${raw_abi:-$uname_m}" ;;
        esac
        ;;
    esac
    ;;
esac

ui_print "- Архитектура устройства: $ABI"

if [ -f "$MODPATH/bin/$ABI/tgws" ]; then
  mv -f "$MODPATH/bin/$ABI/tgws" "$MODPATH/bin/tgws"
else
  abort "! Ошибка: бинарник tgws для архитектуры $ABI не найден в модуле"
fi

# Удаляем остальные архитектуры для экономии места на устройстве
rm -rf "$MODPATH/bin/arm64" "$MODPATH/bin/arm" "$MODPATH/bin/x86" "$MODPATH/bin/x86_64"

chmod 0755 "$MODPATH/service.sh" "$MODPATH/post-fs-data.sh" \
  "$MODPATH/action.sh" "$MODPATH/uninstall.sh" "$MODPATH/bin/tgws" 2>/dev/null

mkdir -p /data/adb/teleweb

# Остановка предыдущего процесса tgws перед запуском
export TELEWEB_DIR=/data/adb/teleweb
export TELEWEB_MOD="$MODPATH"
export TGOPEN_DIR=/data/adb/teleweb
export TGOPEN_MOD="$MODPATH"
[ -x "$MODPATH/bin/tgws" ] && "$MODPATH/bin/tgws" stop >/dev/null 2>&1

ui_print "TeleWEB: прозрачный WSS-транспорт для Telegram (DC1-DC5)"
ui_print "Успешно установлен бинарник для архитектуры $ABI"
