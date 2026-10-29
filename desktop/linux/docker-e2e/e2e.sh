#!/bin/bash
# Privileged end-to-end test: iptables REDIRECT -> tgws (root) -> WSS -> DC2.
# Requires --privileged (CAP_NET_ADMIN inside its own network namespace).
set -u

OUT_DIR=${E2E_LOG_DIR:-/out/logs}
mkdir -p "$OUT_DIR"
exec &> >(tee -a "$OUT_DIR/e2e.log")

export TELEWEB_DIR=/var/lib/teleweb
export TELEWEB_WEBROOT=/out/webroot
LOG=$TELEWEB_DIR/tgws.log
mkdir -p "$TELEWEB_DIR"

fail() {
    echo "E2E RESULT: FAIL ($1)"
    cp "$LOG" "$OUT_DIR/tgws.log" 2>/dev/null || true
    exit 1
}

echo "== environment =="
iptables -V || fail "iptables missing"
id

# Docker Desktop's kernel may lack the nft nat table; fall back to legacy.
if ! iptables -t nat -L OUTPUT >/dev/null 2>&1; then
    echo "nft backend unusable, switching to iptables-legacy"
    update-alternatives --set iptables /usr/sbin/iptables-legacy || true
    update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy || true
    iptables -t nat -L OUTPUT >/dev/null 2>&1 || fail "nat table unavailable even with legacy backend"
fi

echo "== engine self-checks =="
/out/tgws check || fail "tgws check"

echo "== start desktop runtime (root) =="
/out/tgws run >/tmp/run.out 2>&1 &
RUNPID=$!
for _ in $(seq 1 60); do
    grep -q "local proxy listening" "$LOG" 2>/dev/null && break
    sleep 0.5
done
grep -q "local proxy listening" "$LOG" 2>/dev/null || { cat /tmp/run.out; fail "daemon listener did not start"; }

echo "== redirection rules =="
iptables -t nat -L OUTPUT -v -n || true
iptables -t nat -L TELEWEB -v -n || true

echo "== transparent client as uid 1000 =="
setpriv --reuid=1000 --regid=1000 --clear-groups /out/e2eclient direct 149.154.167.220:443 || true

sleep 1
echo "== daemon log tail =="
tail -n 15 "$LOG" || true

echo "== stop =="
/out/tgws stop >/dev/null 2>&1 || true
kill "$RUNPID" 2>/dev/null || true
sleep 1
echo "-- nat OUTPUT after stop --"
iptables -t nat -S OUTPUT || true

cp "$LOG" "$OUT_DIR/tgws.log" 2>/dev/null || true
if grep -q "149.154.167.220:443 -> DC2" "$LOG"; then
    echo "E2E RESULT: PASS"
    exit 0
fi
echo "E2E RESULT: FAIL (no DC2 tunnel line in daemon log)"
exit 1
