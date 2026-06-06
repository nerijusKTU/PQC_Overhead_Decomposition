#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# run_measurements.sh
#
# Renka duomenis VISOMS 5 straipsnio lentelėms:
#   Table 1: Network Scenarios (ping RTT, netem parametrai)
#   Table 2: Cryptographic Operation Benchmarks (speed_kem, openssl speed)
#   Table 3: TLS Handshake Latency (fast_measure.sh, 500 iteracijų)
#   Table 4: Packet Fragmentation (tcpdump/tshark)
#   Table 5: Overhead Decomposition (skaičiuojama iš Table 2 + Table 3)
#
# Prieš paleidžiant: sudo ~/quartic/scripts/prepare_testbed.sh
#
# Naudojimas:
#   sudo ~/quartic/scripts/run_measurements.sh
# ═══════════════════════════════════════════════════════════════════

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

ok()   { echo -e "${GREEN}  ✓ $1${NC}"; }
info() { echo -e "${YELLOW}  ► $1${NC}"; }
step() { echo -e "\n${CYAN}═══════════════════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}═══════════════════════════════════════════════════${NC}\n"; }

MEASURE="/home/lab/quartic/scripts/fast_measure.sh"
SPEED_KEM="/home/lab/quartic/src/liboqs/build/tests/speed_kem"
OPENSSL="/home/lab/quartic/build/openssl/bin/openssl"
RESULTS="/home/lab/quartic/results"
CAPTURES="/home/lab/quartic/captures"
ITERS=500
KEM_DURATION=5
OPENSSL_SPEED_DURATION=10

export LD_LIBRARY_PATH="/home/lab/quartic/build/openssl/lib64:/home/lab/quartic/build/liboqs/lib"
export OPENSSL_CONF="/home/lab/quartic/config/openssl-oqs.cnf"
export OPENSSL_MODULES="/home/lab/quartic/build/openssl/lib/ossl-modules"

mkdir -p "$RESULTS"
mkdir -p "$CAPTURES"

# Patikrinti ar testbed paruoštas
if ! ip netns exec ns_client ping -c 1 -W 2 10.0.0.1 >/dev/null 2>&1; then
    echo -e "${RED}  ✗ Testbed neparuoštas! Pirma paleiskite:${NC}"
    echo "    sudo ~/quartic/scripts/prepare_testbed.sh"
    exit 1
fi

START_TIME=$(date)
echo ""
echo "═══════════════════════════════════════════════════"
echo "  QUARTIC — Pilnas eksperimentų paleidimas"
echo "  Visos 5 lentelės (Tables 1–5)"
echo "═══════════════════════════════════════════════════"
echo ""
echo "  Pradžia: $START_TIME"
echo "  Iteracijos (Table 3): $ITERS"
echo "  KEM benchmark trukmė: ${KEM_DURATION}s"
echo ""

# ═══════════════════════════════════════════════════════════════════
# TABLE 1: NETWORK SCENARIOS (ping RTT matavimas)
# ═══════════════════════════════════════════════════════════════════
step "TABLE 1: Network Scenarios — RTT matavimas"

TABLE1_FILE="$RESULTS/table1_network_scenarios.csv"
echo "scenario,description,configured_delay_ms,configured_loss_pct,configured_rate,ping_rtt_min_ms,ping_rtt_avg_ms,ping_rtt_max_ms,ping_loss_pct" > "$TABLE1_FILE"

measure_ping() {
    local SCENARIO=$1
    local DESCRIPTION=$2
    local DELAY=$3
    local LOSS=$4
    local RATE=$5

    info "$SCENARIO: $DESCRIPTION — ping matavimas..."
    PING_OUT=$(ip netns exec ns_client ping -c 10 -q 10.0.0.1 2>&1)
    PING_RTT=$(echo "$PING_OUT" | grep 'rtt\|round-trip' | grep -oP '[\d.]+/[\d.]+/[\d.]+' | head -1)
    PING_LOSS=$(echo "$PING_OUT" | grep -oP '(\d+)% packet loss' | grep -oP '\d+')

    RTT_MIN=$(echo "$PING_RTT" | cut -d'/' -f1)
    RTT_AVG=$(echo "$PING_RTT" | cut -d'/' -f2)
    RTT_MAX=$(echo "$PING_RTT" | cut -d'/' -f3)

    echo "$SCENARIO,$DESCRIPTION,$DELAY,$LOSS,$RATE,$RTT_MIN,$RTT_AVG,$RTT_MAX,$PING_LOSS" >> "$TABLE1_FILE"
    ok "$SCENARIO: RTT min/avg/max = ${RTT_MIN}/${RTT_AVG}/${RTT_MAX} ms, loss = ${PING_LOSS}%"
}

# S0: Direct
ip netns exec ns_client tc qdisc del dev veth-cli root 2>/dev/null || true
ip netns exec ns_server tc qdisc del dev veth-srv root 2>/dev/null || true
measure_ping "S0" "Direct veth" "0" "0" "unlimited"

# S1: Datacenter
ip netns exec ns_client tc qdisc add dev veth-cli root netem delay 0.5ms rate 1gbit
ip netns exec ns_server tc qdisc add dev veth-srv root netem delay 0.5ms rate 1gbit
sleep 2
measure_ping "S1" "Datacenter" "0.5" "0" "1gbit"
ip netns exec ns_client tc qdisc del dev veth-cli root
ip netns exec ns_server tc qdisc del dev veth-srv root

# S2: Broadband
ip netns exec ns_client tc qdisc add dev veth-cli root netem delay 17.5ms loss 0.1% rate 10mbit
ip netns exec ns_server tc qdisc add dev veth-srv root netem delay 17.5ms loss 0.1% rate 10mbit
sleep 2
measure_ping "S2" "Broadband" "17.5" "0.1" "10mbit"
ip netns exec ns_client tc qdisc del dev veth-cli root
ip netns exec ns_server tc qdisc del dev veth-srv root

# S3: Mobile
ip netns exec ns_client tc qdisc add dev veth-cli root netem delay 35ms loss 3% rate 10mbit
ip netns exec ns_server tc qdisc add dev veth-srv root netem delay 35ms loss 3% rate 10mbit
sleep 2
measure_ping "S3" "Mobile 4G" "35" "3" "10mbit"
ip netns exec ns_client tc qdisc del dev veth-cli root
ip netns exec ns_server tc qdisc del dev veth-srv root

ok "Table 1 duomenys: $TABLE1_FILE"

# ═══════════════════════════════════════════════════════════════════
# TABLE 2: CRYPTOGRAPHIC OPERATION BENCHMARKS
# ═══════════════════════════════════════════════════════════════════
step "TABLE 2: Cryptographic Operation Benchmarks"

info "ML-KEM-768 (KeyGen, Encaps, Decaps) — ${KEM_DURATION}s"
LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
    "$SPEED_KEM" 'ML-KEM-768' --duration "$KEM_DURATION" \
    2>&1 | tee "$RESULTS/speed_mlkem768.txt"
ok "ML-KEM-768 išsaugotas"

info "HQC-192 (KeyGen, Encaps, Decaps) — ${KEM_DURATION}s"
LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
    "$SPEED_KEM" 'HQC-192' --duration "$KEM_DURATION" \
    2>&1 | tee "$RESULTS/speed_hqc192.txt"
ok "HQC-192 išsaugotas"

info "X25519 ECDH"
"$OPENSSL" speed -seconds 5 ecdhx25519 2>&1 | tee "$RESULTS/speed_x25519.txt"
ok "X25519 išsaugotas"

info "P-256 ECDH"
"$OPENSSL" speed -seconds 5 ecdhp256 2>&1 | tee "$RESULTS/speed_p256.txt"
ok "P-256 išsaugotas"

info "Atminties profiliavimas — ML-KEM-768"
/usr/bin/time -v \
    env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
    "$SPEED_KEM" 'ML-KEM-768' --duration 2 \
    2>&1 | grep -E 'Maximum resident|wall clock|CPU' \
    | tee "$RESULTS/memory_mlkem768.txt"

info "Atminties profiliavimas — HQC-192"
/usr/bin/time -v \
    env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
    "$SPEED_KEM" 'HQC-192' --duration 2 \
    2>&1 | grep -E 'Maximum resident|wall clock|CPU' \
    | tee "$RESULTS/memory_hqc192.txt"

ok "Table 2 duomenys surinkti"

# ═══════════════════════════════════════════════════════════════════
# TABLE 3: TLS HANDSHAKE LATENCY (500 iteracijų × 4 scenarijai × 2 config)
# ═══════════════════════════════════════════════════════════════════
step "TABLE 3: TLS Handshake Latency ($ITERS iteracijų)"

# ── S0: Direct veth ──
info "═══ S0: Direct veth ═══"
ip netns exec ns_client tc qdisc del dev veth-cli root 2>/dev/null || true
ip netns exec ns_server tc qdisc del dev veth-srv root 2>/dev/null || true

info "S0 Klasikinis (x25519)"
ip netns exec ns_client "$MEASURE" x25519 $ITERS "$RESULTS/S0_C1_classic.csv"
info "S0 Hibridinis (X25519MLKEM768)"
ip netns exec ns_client "$MEASURE" X25519MLKEM768 $ITERS "$RESULTS/S0_H1_hybrid.csv"
ok "S0 baigtas"

# ── S1: Datacenter ──
info "═══ S1: Datacenter (~2.5ms RTT) ═══"
ip netns exec ns_client tc qdisc add dev veth-cli root netem delay 0.5ms rate 1gbit
ip netns exec ns_server tc qdisc add dev veth-srv root netem delay 0.5ms rate 1gbit
sleep 2

info "S1 Klasikinis (x25519)"
ip netns exec ns_client "$MEASURE" x25519 $ITERS "$RESULTS/S1_C1_classic.csv"
info "S1 Hibridinis (X25519MLKEM768)"
ip netns exec ns_client "$MEASURE" X25519MLKEM768 $ITERS "$RESULTS/S1_H1_hybrid.csv"

ip netns exec ns_client tc qdisc del dev veth-cli root
ip netns exec ns_server tc qdisc del dev veth-srv root
ok "S1 baigtas"

# ── S2: Broadband ──
info "═══ S2: Broadband (~36ms RTT) ═══"
ip netns exec ns_client tc qdisc add dev veth-cli root netem delay 17.5ms loss 0.1% rate 10mbit
ip netns exec ns_server tc qdisc add dev veth-srv root netem delay 17.5ms loss 0.1% rate 10mbit
sleep 2

info "S2 Klasikinis (x25519)"
ip netns exec ns_client "$MEASURE" x25519 $ITERS "$RESULTS/S2_C1_classic.csv"
info "S2 Hibridinis (X25519MLKEM768)"
ip netns exec ns_client "$MEASURE" X25519MLKEM768 $ITERS "$RESULTS/S2_H1_hybrid.csv"

ip netns exec ns_client tc qdisc del dev veth-cli root
ip netns exec ns_server tc qdisc del dev veth-srv root
ok "S2 baigtas"

# ── S3: Mobile ──
info "═══ S3: Mobile (~71ms RTT) ═══"
ip netns exec ns_client tc qdisc add dev veth-cli root netem delay 35ms loss 3% rate 10mbit
ip netns exec ns_server tc qdisc add dev veth-srv root netem delay 35ms loss 3% rate 10mbit
sleep 2

info "S3 Klasikinis (x25519)"
ip netns exec ns_client "$MEASURE" x25519 $ITERS "$RESULTS/S3_C1_classic.csv"
info "S3 Hibridinis (X25519MLKEM768)"
ip netns exec ns_client "$MEASURE" X25519MLKEM768 $ITERS "$RESULTS/S3_H1_hybrid.csv"

ip netns exec ns_client tc qdisc del dev veth-cli root
ip netns exec ns_server tc qdisc del dev veth-srv root
ok "S3 baigtas"

# ═══════════════════════════════════════════════════════════════════
# TABLE 4: PACKET FRAGMENTATION (pcapng captures)
# ═══════════════════════════════════════════════════════════════════
step "TABLE 4: Packet Fragmentation (pcapng captures)"

# Pašalinti netem
ip netns exec ns_client tc qdisc del dev veth-cli root 2>/dev/null || true
ip netns exec ns_server tc qdisc del dev veth-srv root 2>/dev/null || true

# ── Klasikinis capture ──
info "Klasikinis handshake capture..."
ip netns exec ns_client \
    tcpdump -Z root -i veth-cli -w /tmp/C1_classic.pcapng -c 30 &
TCPDUMP_PID=$!
sleep 2

ip netns exec ns_client \
    env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
    OPENSSL_CONF="$OPENSSL_CONF" \
    OPENSSL_MODULES="$OPENSSL_MODULES" \
    "$OPENSSL" s_client \
    -groups x25519 \
    -connect 10.0.0.1:4433 </dev/null >/dev/null 2>&1 || true

sleep 2
kill $TCPDUMP_PID 2>/dev/null || killall tcpdump 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true
sleep 1
cp /tmp/C1_classic.pcapng "$CAPTURES/"
ok "Klasikinis capture išsaugotas"

# ── Hibridinis capture ──
info "Hibridinis handshake capture..."
ip netns exec ns_client \
    tcpdump -Z root -i veth-cli -w /tmp/H1_hybrid.pcapng -c 30 &
TCPDUMP_PID=$!
sleep 2

ip netns exec ns_client \
    env LD_LIBRARY_PATH="$LD_LIBRARY_PATH" \
    OPENSSL_CONF="$OPENSSL_CONF" \
    OPENSSL_MODULES="$OPENSSL_MODULES" \
    "$OPENSSL" s_client \
    -groups X25519MLKEM768 \
    -connect 10.0.0.1:4433 </dev/null >/dev/null 2>&1 || true

sleep 2
kill $TCPDUMP_PID 2>/dev/null || killall tcpdump 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true
sleep 1
cp /tmp/H1_hybrid.pcapng "$CAPTURES/"
ok "Hibridinis capture išsaugotas"

# Išsaugoti fragmentacijos duomenis kaip CSV
TABLE4_FILE="$RESULTS/table4_fragmentation.csv"
C1_CH=$(tshark -r "$CAPTURES/C1_classic.pcapng" -Y "tls.handshake.type == 1" -T fields -e frame.len 2>/dev/null | head -1)
H1_CH=$(tshark -r "$CAPTURES/H1_hybrid.pcapng" -Y "tls.handshake.type == 1" -T fields -e frame.len 2>/dev/null | head -1)
C1_SH=$(tshark -r "$CAPTURES/C1_classic.pcapng" -Y "tls.handshake.type == 2" -T fields -e frame.len 2>/dev/null | head -1)
H1_SH=$(tshark -r "$CAPTURES/H1_hybrid.pcapng" -Y "tls.handshake.type == 2" -T fields -e frame.len 2>/dev/null | head -1)
C1_PKTS=$(tshark -r "$CAPTURES/C1_classic.pcapng" 2>/dev/null | wc -l)
H1_PKTS=$(tshark -r "$CAPTURES/H1_hybrid.pcapng" 2>/dev/null | wc -l)

echo "metric,x25519,x25519mlkem768,delta" > "$TABLE4_FILE"
echo "clienthello_bytes,$C1_CH,$H1_CH,$((H1_CH - C1_CH))" >> "$TABLE4_FILE"
echo "serverhello_bytes,$C1_SH,$H1_SH,$((H1_SH - C1_SH))" >> "$TABLE4_FILE"
echo "total_overhead,0,0,$((H1_CH - C1_CH + H1_SH - C1_SH))" >> "$TABLE4_FILE"
echo "total_packets,$C1_PKTS,$H1_PKTS,$((H1_PKTS - C1_PKTS))" >> "$TABLE4_FILE"
echo "mss_exceeded,no,yes,$((H1_CH - 1460))" >> "$TABLE4_FILE"

ok "Table 4 duomenys: $TABLE4_FILE"

# ═══════════════════════════════════════════════════════════════════
# SUVESTINĖ — VISOS 5 LENTELĖS
# ═══════════════════════════════════════════════════════════════════
step "SUVESTINĖ — Visos 5 lentelės"

python3 /home/lab/quartic/scripts/tables.py

END_TIME=$(date)
echo ""
echo "═══════════════════════════════════════════════════"
echo -e "  ${GREEN}VISI EKSPERIMENTAI BAIGTI ✓${NC}"
echo "═══════════════════════════════════════════════════"
echo ""
echo "  Pradžia: $START_TIME"
echo "  Pabaiga: $END_TIME"
echo ""
echo "  Rezultatų failai:"
echo "    $RESULTS/table1_network_scenarios.csv"
echo "    $RESULTS/speed_mlkem768.txt"
echo "    $RESULTS/speed_hqc192.txt"
echo "    $RESULTS/speed_x25519.txt"
echo "    $RESULTS/speed_p256.txt"
echo "    $RESULTS/memory_mlkem768.txt"
echo "    $RESULTS/memory_hqc192.txt"
echo "    $RESULTS/S0_C1_classic.csv ... S3_H1_hybrid.csv"
echo "    $RESULTS/table4_fragmentation.csv"
echo "    $CAPTURES/C1_classic.pcapng"
echo "    $CAPTURES/H1_hybrid.pcapng"
echo ""
