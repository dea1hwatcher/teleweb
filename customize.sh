#!/system/bin/sh
type ui_print >/dev/null 2>&1 || ui_print() { printf '%s\n' "$1"; }
type abort >/dev/null 2>&1 || abort() { ui_print "$1"; exit 1; }

umask 077

version=$(sed -n 's/^version=//p' "$MODPATH/module.prop" | tr -d '\r')
ui_print "*******************************************"
ui_print "- TeleWEB"
ui_print "- $version"
ui_print "*******************************************"

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

# Очистка сервисных файлов репозитория
rm -rf "$MODPATH/.git" "$MODPATH/.github" "$MODPATH/.gitattributes" \
       "$MODPATH/update.json" "$MODPATH/changelog.md"
rm -f "$MODPATH"/*.zip

# Иконка модуля для Magisk / KernelSU / APatch / MMRL
if [ -f "$MODPATH/webroot/module_icon.png" ] && [ ! -f "$MODPATH/icon.png" ]; then
  cp -f "$MODPATH/webroot/module_icon.png" "$MODPATH/icon.png" 2>/dev/null || true
fi

chmod 0755 "$MODPATH/service.sh" "$MODPATH/post-fs-data.sh" \
  "$MODPATH/action.sh" "$MODPATH/uninstall.sh" "$MODPATH/bin/tgws" 2>/dev/null

if [ -d /data/adb/teleweb ]; then
  ui_print "- Сохранение существующих настроек: /data/adb/teleweb"
  # Очищаем устаревший динамический кэш конечных точек для исключения старых отравленных записей
  rm -f /data/adb/teleweb/dc-learned.json 2>/dev/null || true
else
  mkdir -p /data/adb/teleweb
  ui_print "- Создан каталог настроек: /data/adb/teleweb"
fi

# Остановка запущенной службы предыдущей версии модуля перед обновлением
export TELEWEB_DIR=/data/adb/teleweb
if [ -x "/data/adb/modules/teleweb/bin/tgws" ]; then
  /data/adb/modules/teleweb/bin/tgws stop >/dev/null 2>&1 || true
fi

# Гарантируем чистое базовое описание в module.prop при установке (как в bindhosts)
sed -i "s|^description=.*|description=Прозрачный WSS-транспорт для Telegram (DC1-DC5)|g" "$MODPATH/module.prop" 2>/dev/null || true

ui_print "TeleWEB: прозрачный WSS-транспорт для Telegram (DC1-DC5)"
ui_print "Успешно установлен бинарник для архитектуры $ABI"
