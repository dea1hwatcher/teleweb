#!/bin/bash
# Privileged end-to-end test: offline CircumVolve DPI dual-validation +
# iptables REDIRECT -> tgws (root) -> WSS -> DC2.
# Requires --privileged (CAP_NET_ADMIN inside its own network namespace).
set -u

OUT_DIR=${E2E_LOG_DIR:-/out/logs}
mkdir -p "$OUT_DIR"
exec &> >(tee -a "$OUT_DIR/e2e.log")

# The container writes logs as root into a bind mount owned by the runner
# user; hand ownership back so artifact upload can read them.
return_ownership() {
    local uid gid
    uid=$(stat -c %u "$OUT_DIR" 2>/dev/null || echo 0)
    gid=$(stat -c %g "$OUT_DIR" 2>/dev/null || echo 0)
    chown -R "$uid:$gid" "$OUT_DIR" 2>/dev/null || true
}
trap return_ownership EXIT

export TELEWEB_DIR=/var/lib/teleweb
export TELEWEB_WEBROOT=/out/webroot
LOG=$TELEWEB_DIR/tgws.log
mkdir -p "$TELEWEB_DIR"

DPI_PID=""
cleanup_dpi() {
    if [ -n "$DPI_PID" ]; then
        kill "$DPI_PID" 2>/dev/null || true
    fi
}
trap 'cleanup_dpi; return_ownership' EXIT

fail() {
    echo "E2E RESULT: FAIL ($1)"
    cp "$LOG" "$OUT_DIR/tgws.log" 2>/dev/null || true
    cp /tmp/dpi.out "$OUT_DIR/dpi.log" 2>/dev/null || true
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

echo "== offline CircumVolve DPI dual-validation =="
DPI_HOST="kws2.dpi-e2e.test"
/out/e2eclient dpi-proxy 127.0.0.2:443 "$DPI_HOST" /usr/local/share/ca-certificates/teleweb-dpi-e2e.crt >/tmp/dpi.out 2>&1 &
DPI_PID=$!
for _ in $(seq 1 40); do
    grep -q "DPI_PROXY_READY" /tmp/dpi.out 2>/dev/null && break
    sleep 0.25
done
grep -q "DPI_PROXY_READY" /tmp/dpi.out 2>/dev/null || { cat /tmp/dpi.out; fail "dpi-proxy did not start"; }
update-ca-certificates >/dev/null 2>&1 || fail "update-ca-certificates failed"
grep -q "$DPI_HOST" /etc/hosts || echo "127.0.0.2 $DPI_HOST" >> /etc/hosts

# 1. Negative control: unfragmented ClientHello must trigger simulated DPI RST.
printf 'off\n' > "$TELEWEB_DIR/tls_evasion"
printf '0\n' > "$TELEWEB_DIR/doh_enabled"
OFF_RES=$(/out/tgws cftest "$DPI_HOST" || true)
echo "cftest(off): $OFF_RES"
echo "$OFF_RES" | grep -q '"reachable":false' || fail "DPI baseline expected block when tls_evasion=off"
grep -q "DPI_DROP" /tmp/dpi.out || fail "dpi-proxy did not log DPI_DROP on baseline"

# 2. Split & aggressive profiles + live X.509 CA verification must bypass DPI.
for mode in auto split aggressive; do
    printf '%s\n' "$mode" > "$TELEWEB_DIR/tls_evasion"
    PASS_RES=$(/out/tgws cftest "$DPI_HOST" || true)
    echo "cftest($mode): $PASS_RES"
    echo "$PASS_RES" | grep -q '"reachable":true' || { cat /tmp/dpi.out; fail "DPI evasion failed in mode=$mode"; }
    echo "$PASS_RES" | grep -q '"pop":"FRA"' || { cat /tmp/dpi.out; fail "missing CF-Ray PoP in mode=$mode"; }
done
printf 'auto\n' > "$TELEWEB_DIR/tls_evasion"
printf '1\n' > "$TELEWEB_DIR/doh_enabled"
cp /tmp/dpi.out "$OUT_DIR/dpi.log" 2>/dev/null || true

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
