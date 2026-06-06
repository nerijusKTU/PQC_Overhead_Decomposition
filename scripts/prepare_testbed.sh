#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# prepare_testbed.sh
#
# Paruošia QUARTIC testbed prieš matavimus.
# Paleisti po kiekvieno VM reboot arba prieš naują eksperimentų sesiją.
#
# Naudojimas:
#   chmod +x ~/quartic/scripts/prepare_testbed.sh
#   sudo ~/quartic/scripts/prepare_testbed.sh
# ═══════════════════════════════════════════════════════════════════

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}  ✓ $1${NC}"; }
fail() { echo -e "${RED}  ✗ $1${NC}"; exit 1; }
info() { echo -e "${YELLOW}  ► $1${NC}"; }

LAB_HOME="/home/lab"
OPENSSL_BIN="$LAB_HOME/quartic/build/openssl/bin/openssl"
NGINX_BIN="$LAB_HOME/quartic/build/nginx/sbin/nginx"
NGINX_CONF="$LAB_HOME/quartic/config/nginx.conf"
OQS_MODULE="$LAB_HOME/quartic/build/openssl/lib/ossl-modules/oqsprovider.so"

export LD_LIBRARY_PATH="$LAB_HOME/quartic/build/openssl/lib64:$LAB_HOME/quartic/build/liboqs/lib"
export OPENSSL_CONF="$LAB_HOME/quartic/config/openssl-oqs.cnf"
export OPENSSL_MODULES="$LAB_HOME/quartic/build/openssl/lib/ossl-modules"

echo ""
echo "═══════════════════════════════════════════════════"
echo "  QUARTIC Testbed — Paruošimas"
echo "═══════════════════════════════════════════════════"
echo ""

# ═══ 1. OQS Provider konfigūracija ═══
info "1. OQS Provider konfigūracija..."

mkdir -p "$LAB_HOME/quartic/config"

cat > "$LAB_HOME/quartic/config/openssl-oqs.cnf" << EOF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
module = $OQS_MODULE
EOF

ok "OQS konfigūracija sukurta"

# ═══ 2. Tinklo namespace'ai ═══
info "2. Tinklo namespace'ų sukūrimas..."

ip netns del ns_client 2>/dev/null || true
ip netns del ns_server 2>/dev/null || true
ip link del veth-cli 2>/dev/null || true

ip netns add ns_client
ip netns add ns_server
ip link add veth-cli type veth peer name veth-srv
ip link set veth-cli netns ns_client
ip link set veth-srv netns ns_server
ip netns exec ns_client ip addr add 10.0.0.2/24 dev veth-cli
ip netns exec ns_server ip addr add 10.0.0.1/24 dev veth-srv
ip netns exec ns_client ip link set veth-cli up
ip netns exec ns_client ip link set lo up
ip netns exec ns_server ip link set veth-srv up
ip netns exec ns_server ip link set lo up

if ip netns exec ns_client ping -c 1 -W 2 10.0.0.1 >/dev/null 2>&1; then
    ok "Namespace'ai sukurti, ryšys veikia (10.0.0.2 ↔ 10.0.0.1)"
else
    fail "Ping nepavyko!"
fi

# ═══ 3. Nginx konfigūracija ═══
info "3. Nginx konfigūracija..."

cat > "$NGINX_CONF" << 'EOF'
worker_processes 1;
pid /tmp/nginx_quartic.pid;
error_log /tmp/nginx_quartic_error.log;
events {
    worker_connections 128;
}
http {
    access_log /tmp/nginx_quartic_access.log;
    server {
        listen 10.0.0.1:4433 ssl;
        server_name localhost;
        ssl_protocols TLSv1.3;
        ssl_ecdh_curve X25519MLKEM768:x25519:secp256r1:secp384r1;
        ssl_certificate     /home/lab/quartic/certs/server.crt;
        ssl_certificate_key /home/lab/quartic/certs/server.key;
        location / {
            return 200 'OK';
            add_header Content-Type text/plain;
        }
    }
}
EOF

ok "Nginx konfigūracija sukurta (su ssl_ecdh_curve PQC)"

# ═══ 4. Sertifikatai ═══
info "4. Sertifikatų tikrinimas..."

if [ -f "$LAB_HOME/quartic/certs/server.crt" ] && [ -f "$LAB_HOME/quartic/certs/server.key" ]; then
    ok "Sertifikatai egzistuoja"
else
    info "Generuojami nauji sertifikatai..."
    mkdir -p "$LAB_HOME/quartic/certs"
    $OPENSSL_BIN req -x509 -newkey rsa:2048 \
        -keyout "$LAB_HOME/quartic/certs/server.key" \
        -out "$LAB_HOME/quartic/certs/server.crt" \
        -days 365 -nodes -subj "/CN=localhost" 2>/dev/null
    ok "Sertifikatai sugeneruoti"
fi

# ═══ 5. Nginx paleidimas ═══
info "5. Nginx paleidimas su OQS Provider..."

ip netns exec ns_server killall nginx 2>/dev/null || true
sleep 1

ip netns exec ns_server \
    env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
    OPENSSL_CONF="$OPENSSL_CONF" \
    OPENSSL_MODULES="$OPENSSL_MODULES" \
    "$NGINX_BIN" -c "$NGINX_CONF"

sleep 1
ok "Nginx paleistas"

# ═══ 6. Handshake patikrinimas ═══
info "6. Handshake patikrinimas..."

CLASSIC_OUT=$(ip netns exec ns_client \
    env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
    OPENSSL_CONF="$OPENSSL_CONF" \
    OPENSSL_MODULES="$OPENSSL_MODULES" \
    "$OPENSSL_BIN" s_client -groups x25519 \
    -connect 10.0.0.1:4433 </dev/null 2>&1)

if echo "$CLASSIC_OUT" | grep -q "TLSv1.3"; then
    ok "Klasikinis (x25519): $(echo "$CLASSIC_OUT" | grep 'SSL handshake has read')"
else
    fail "Klasikinis handshake nepavyko!"
fi

HYBRID_OUT=$(ip netns exec ns_client \
    env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
    OPENSSL_CONF="$OPENSSL_CONF" \
    OPENSSL_MODULES="$OPENSSL_MODULES" \
    "$OPENSSL_BIN" s_client -groups X25519MLKEM768 \
    -connect 10.0.0.1:4433 </dev/null 2>&1)

if echo "$HYBRID_OUT" | grep -q "TLSv1.3"; then
    ok "Hibridinis (X25519MLKEM768): $(echo "$HYBRID_OUT" | grep 'SSL handshake has read')"
else
    fail "Hibridinis handshake nepavyko!"
fi

# ═══ 7. fast_measure.sh ═══
info "7. fast_measure.sh tikrinimas..."

MEASURE_SCRIPT="$LAB_HOME/quartic/scripts/fast_measure.sh"
if [ -f "$MEASURE_SCRIPT" ] && grep -q '/home/lab' "$MEASURE_SCRIPT"; then
    ok "fast_measure.sh egzistuoja su teisingais keliais"
else
    info "Kuriamas/taisomas fast_measure.sh..."
    cat > "$MEASURE_SCRIPT" << 'SCRIPT'
#!/bin/bash
GROUP=$1
ITERS=$2
OUTPUT=$3

export LD_LIBRARY_PATH=/home/lab/quartic/build/openssl/lib64:/home/lab/quartic/build/liboqs/lib
export OPENSSL_CONF=/home/lab/quartic/config/openssl-oqs.cnf
export OPENSSL_MODULES=/home/lab/quartic/build/openssl/lib/ossl-modules

echo "iteration,time_ms" > "$OUTPUT"
for i in $(seq 1 $ITERS); do
    START=$(date +%s%N)
    /home/lab/quartic/build/openssl/bin/openssl s_client \
        -groups "$GROUP" \
        -connect 10.0.0.1:4433 \
        -servername localhost \
        </dev/null >/dev/null 2>&1
    END=$(date +%s%N)
    TIME_MS=$(echo "scale=3; ($END - $START) / 1000000" | bc)
    echo "$i,$TIME_MS" >> "$OUTPUT"
    if [ $((i % 10)) -eq 0 ]; then
        printf "  %d/%d\r" "$i" "$ITERS"
    fi
done
echo ""
echo "Done: $OUTPUT ($ITERS measurements)"
SCRIPT
    chmod +x "$MEASURE_SCRIPT"
    ok "fast_measure.sh sukurtas"
fi

echo ""
echo "═══════════════════════════════════════════════════"
echo -e "  ${GREEN}TESTBED PARUOŠTAS ✓${NC}"
echo "═══════════════════════════════════════════════════"
echo ""
echo "  Dabar galite paleisti matavimus:"
echo "    sudo ~/quartic/scripts/run_measurements.sh"
echo ""
