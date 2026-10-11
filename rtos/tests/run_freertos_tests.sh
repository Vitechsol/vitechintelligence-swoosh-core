#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ $# != 1 ]]; then echo 'usage: run_freertos_tests.sh /path/to/FreeRTOS-Kernel' >&2; exit 2; fi
KERNEL="$(cd "$1" && pwd)"
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
PORT="$KERNEL/portable/ThirdParty/GCC/Posix"
cc -std=c11 -D_GNU_SOURCE -O2 -pthread -I"$KERNEL/include" -I"$PORT" \
  -I"$ROOT/rtos/include" -I"$ROOT/rtos/ports/freertos" -I"$ROOT/rtos/tests/freertos" \
  "$KERNEL/tasks.c" "$KERNEL/queue.c" "$KERNEL/list.c" "$KERNEL/portable/MemMang/heap_4.c" \
  "$PORT/port.c" "$PORT/utils/wait_for_event.c" "$ROOT/rtos/src/swoosh_gate.c" \
  "$ROOT/rtos/ports/freertos/swoosh_freertos_gate.c" "$ROOT/rtos/tests/freertos/main.c" -o "$BUILD/freertos-gate"
timeout 15 "$BUILD/freertos-gate"
