#!/bin/sh
# Rebuilds cfa32.out: i386, DWARF 3, no .eh_frame, so the CFA pass reads .debug_frame, whose CIEs state no
# address size; no libc, linked where it runs.
set -e
cd "$(dirname "$0")"
gcc -m32 -g -gdwarf-3 -O0 -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-pie -no-pie -nostdlib -static \
    -fno-stack-protector -Wall -Wextra -Wl,-e,main -Wl,--build-id=none -o cfa32.out app.c
