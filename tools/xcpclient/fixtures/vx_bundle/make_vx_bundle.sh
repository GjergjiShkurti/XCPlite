#!/bin/sh
# Rebuilds vx_bundle.out, the stand-in VX1000 firmware xcpclient's tests read: x86-64, no libc, linked where it runs (no PIE), so the
# records hold the addresses the A2L states; the sections in source order, and the bundle's enums in the debug information of both units.
set -e
cd "$(dirname "$0")"
gcc -g -O0 -fno-toplevel-reorder -fno-eliminate-unused-debug-types -fno-pie -no-pie -nostdlib -static -fno-stack-protector \
    -Wall -Wextra -Wl,-e,main -Wl,--build-id=none -o vx_bundle.out app.c bundle.c
