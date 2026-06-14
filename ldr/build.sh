#!/bin/sh
# Build script for PIC payloads
# Outputs: out/<name>.bin (raw shellcode), out/<name>.h (C header for embedding)
set -eu

CC="gcc"
BASE_FLAGS="-m64 -O2 -ffreestanding -fno-asynchronous-unwind-tables \
            -fno-ident -fpic -nostdlib -fno-stack-protector \
            -mno-red-zone -mno-sse -Wno-implicit-function-declaration"

OUTDIR="out"
mkdir -p "$OUTDIR"

for name in payload_loader payload_thread; do
    echo "=== Building ${name} ==="

    # Step 1: compile to object file
    $CC $BASE_FLAGS -c "${name}.c" -o "${OUTDIR}/${name}.o"
    echo "  [OK] Compiled."

    # Step 2: extract .text.entry + .text into a single flat binary
    #   .text.entry contains payload_entry (must be at offset 0)
    #   .text contains all static helper functions
    objcopy -j .text.entry -j .text -O binary \
        "${OUTDIR}/${name}.o" "${OUTDIR}/${name}.bin"
    sz=$(wc -c < "${OUTDIR}/${name}.bin")
    echo "  [OK] Shellcode: ${sz} bytes"

    # Step 3: generate C header for embedding
    xxd -i "${OUTDIR}/${name}.bin" > "${OUTDIR}/${name}.h"
    echo "  [OK] Header: ${OUTDIR}/${name}.h"
    echo ""
done

echo "=== Done ==="
ls -lh "${OUTDIR}/"
