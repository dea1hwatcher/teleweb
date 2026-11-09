#!/system/bin/sh
MODDIR=${0%/*}
export TELEWEB_DIR=/data/adb/teleweb
export TELEWEB_MOD="$MODDIR"
[ -x "$MODDIR/bin/tgws" ] && "$MODDIR/bin/tgws" stop >/dev/null 2>&1
for i in 1 2 3 4; do
  iptables -t mangle -D OUTPUT -p udp -m multiport --dports 3478,596:599 -m comment --comment "teleweb-calls" -j RETURN 2>/dev/null || break
done
for i in 1 2 3 4; do
  ip6tables -t mangle -D OUTPUT -p udp -m multiport --dports 3478,596:599 -m comment --comment "teleweb-calls" -j RETURN 2>/dev/null || break
done
for i in 1 2 3 4; do
  iptables -t mangle -D PREROUTING -p udp -m multiport --dports 3478,596:599 -m comment --comment "teleweb-calls" -j RETURN 2>/dev/null || break
done
for i in 1 2 3 4; do
  ip6tables -t mangle -D PREROUTING -p udp -m multiport --dports 3478,596:599 -m comment --comment "teleweb-calls" -j RETURN 2>/dev/null || break
done
rm -rf /data/adb/teleweb

