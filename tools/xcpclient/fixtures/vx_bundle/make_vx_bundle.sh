#!/bin/sh
# Rebuilds vx_bundle.out, the stand-in VX1000 firmware xcpclient's tests read: x86-64, no libc, linked where it runs (no PIE), so the
# records hold the addresses the A2L states; the sections in source order, and the bundle's enums in the debug information of both units.
# vx_bundle_off.out is the same firmware with nothing switched on, no entries of its own and the bundle not linked;
# vx_bundle_ghost.out has an event record with no name pointer first.
set -e
cd "$(dirname "$0")"
flags="-g -O0 -fno-toplevel-reorder -fno-eliminate-unused-debug-types -fno-pie -no-pie -nostdlib -static -fno-stack-protector -Wall -Wextra -Wl,-e,main -Wl,--build-id=none"
gcc $flags -o vx_bundle.out app.c bundle.c
gcc $flags -DSWITCHED_OFF -o vx_bundle_off.out app.c
gcc $flags -DGHOST -o vx_bundle_ghost.out app.c bundle.c
