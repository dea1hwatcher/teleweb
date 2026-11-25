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
for i in 1 2 3 4; do
  iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -m comment --comment "teleweb-mss" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || break
done
for i in 1 2 3 4; do
  ip6tables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -m comment --comment "teleweb-mss" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || break
done
for cidr in 2001:b28::/32 2001:67c:4e8::/48 2a0a:f280::/32 2001:b88::/32; do
  for i in 1 2 3 4; do
    ip6tables -t filter -D OUTPUT -p tcp -d "$cidr" -j REJECT --reject-with tcp-reset 2>/dev/null || break
  done
  for i in 1 2 3 4; do
    ip6tables -t filter -D OUTPUT -p tcp -d "$cidr" -j DROP 2>/dev/null || break
  done
done
rm -rf /data/adb/teleweb

