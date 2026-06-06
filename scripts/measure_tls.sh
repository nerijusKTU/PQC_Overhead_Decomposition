#!/bin/bash
GROUP=$1
ITERS=$2
OUTPUT=$3

export LD_LIBRARY_PATH=/home/lab/quartic/build/openssl/lib64:/home/lab/quartic/build/liboqs/lib
export OPENSSL_CONF=/home/lab/quartic/config/openssl-oqs.cnf
export OPENSSL_MODULES=/home/lab/quartic/build/openssl/lib/ossl-modules
OPENSSL=/home/lab/quartic/build/openssl/bin/openssl

echo "iteration,time_ms" > "$OUTPUT"
for i in $(seq 1 $ITERS); do
    # openssl s_client -connect ... pats praneša "SSL handshake has read X bytes and written Y bytes"
    # Naudojame time tik TLS connection daliai
    TIME_OUTPUT=$($OPENSSL s_client \
        -groups "$GROUP" \
        -connect 10.0.0.1:4433 \
        -servername localhost \
        -msg -quiet \
        </dev/null 2>&1)
    
    # Iš openssl output paimame connect time
    CONNECT_MS=$(echo "$TIME_OUTPUT" | grep -oP 'connect:(\d+\.\d+)s' | head -1 | grep -oP '[\d.]+')
    
    if [ -z "$CONNECT_MS" ]; then
        # Fallback: matuojame su date
        START=$(date +%s%N)
        $OPENSSL s_client -groups "$GROUP" -connect 10.0.0.1:4433 </dev/null >/dev/null 2>&1
        END=$(date +%s%N)
        CONNECT_MS=$(echo "scale=3; ($END - $START) / 1000000" | bc)
    fi
    
    echo "$i,$CONNECT_MS" >> "$OUTPUT"
    if [ $((i % 10)) -eq 0 ]; then printf "  %d/%d\r" "$i" "$ITERS"; fi
done
echo ""
echo "Done: $OUTPUT"
