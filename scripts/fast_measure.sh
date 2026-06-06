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
