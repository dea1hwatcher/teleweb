#!/system/bin/sh
type ui_print >/dev/null 2>&1 || ui_print() { printf '%s\n' "$1"; }
umask 077
chmod 0755 "$MODPATH/service.sh" "$MODPATH/post-fs-data.sh" \
  "$MODPATH/action.sh" "$MODPATH/uninstall.sh" "$MODPATH/bin/tgws" 2>/dev/null
mkdir -p /data/adb/tgopen
# Kill the previous v1.2 tgws process before the new binary claims the same port.
export TGOPEN_DIR=/data/adb/tgopen
export TGOPEN_MOD="$MODPATH"
[ -x "$MODPATH/bin/tgws" ] && "$MODPATH/bin/tgws" stop >/dev/null 2>&1
ui_print "TG Open: экспериментальный собственный WSS-транспорт для DC1–DC5."
ui_print "Проверка выполнена на хосте; реальная работа требует теста на устройстве."
arch=$(getprop ro.product.cpu.abi 2>/dev/null)
case "$arch" in arm64*|arm64-v8a*) ;; *) ui_print "! ABI устройства: $arch. Бинарник собран под arm64." ;; esac
